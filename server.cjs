/* server.cjs
 * TCPP Ideas Backend — ideas + uploads + likes + comments
 * + price/status engine (EL/SL/TP) + email triggers + SSE
 */

'use strict';

const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const nodemailer = require('nodemailer');
const https = require('https');
const http = require('http');
const { nanoid } = require('nanoid');

/* ------------------------- ENV ------------------------- */
const PORT      = Number(process.env.PORT || 8080);
const NODE_ENV  = process.env.NODE_ENV || 'production';

const API_TOKEN = (process.env.API_TOKEN || '').trim();

const CORS_ORIGINS = String(
  process.env.CORS_ORIGINS || process.env.CORS_ALLOW_ORIGINS || '*'
).split(',').map(s => s.trim()).filter(Boolean);

const DATA_DIR   = process.env.DATA_DIR   || '/data';
const DATA_FILE  = path.join(DATA_DIR, 'ideas.json');
const SUBS_FILE  = path.join(DATA_DIR, 'subscribers.json');
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(DATA_DIR, 'uploads');

const UPLOADS_PUBLIC_BASE_URL = (process.env.UPLOADS_PUBLIC_BASE_URL || '').replace(/\/+$/,'');

const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 10);
const ALLOWED_UPLOAD_TYPES = String(
  process.env.ALLOWED_UPLOAD_TYPES || 'image/png,image/jpeg,image/webp,image/gif'
).split(',').map(s => s.trim());

const PRICE_STALE_SEC   = Number(process.env.PRICE_STALE_SEC || 90);
const POLL_INTERVAL_MS  = Number(process.env.POLL_INTERVAL_MS || 20000);
const AUTO_SET_STATUS   = /^true$/i.test(String(process.env.AUTO_SET_STATUS || 'true'));

const SITE_NAME = process.env.SITE_NAME || 'Trade Chart Patterns — Pro';
const SITE_URL  = process.env.SITE_URL  || 'https://www.tradechartpatternslikethepros.com';

const LOGO_URL  = process.env.EMAIL_LOGO_URL
  || process.env.LOGO_URL
  || 'https://static.wixstatic.com/media/e09166_90ddc4c3b20d4b4b83461681f85d9dd8~mv2.png';

/* ------------------------ EMAIL ------------------------ */
const SMTP_HOST   = process.env.SMTP_HOST   || '';
const SMTP_PORT   = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = /^true$/i.test(String(process.env.SMTP_SECURE || '')) || SMTP_PORT === 465;
const SMTP_USER   = process.env.SMTP_USER   || '';
const SMTP_PASS   = process.env.SMTP_PASS   || '';

const MAIL_FROM         = process.env.MAIL_FROM || '';
const MAIL_FROM_NAME    = process.env.MAIL_FROM_NAME || 'Trade Chart Patterns Like The Pros';
const EMAIL_FROM_INLINE = process.env.EMAIL_FROM || '';
const EMAIL_REPLY_TO    = (process.env.EMAIL_REPLY_TO || '').trim();
const EMAIL_BCC_ADMIN   = String(process.env.EMAIL_BCC_ADMIN || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const EMAIL_FORCE_ALL_TO = (process.env.EMAIL_FORCE_ALL_TO || '').trim().toLowerCase();

/* Optional webhook fallback (e.g., your Wix function or a Zapier hook) */
const EMAIL_HTTP_FALLBACK_URL = (process.env.EMAIL_HTTP_FALLBACK_URL || '').trim();
const EMAIL_THEME = (process.env.EMAIL_THEME || 'dark').toLowerCase();

/* ------------------------- UTIL ------------------------ */
const nowISO = () => new Date().toISOString();
async function ensureDir(p) { await fsp.mkdir(p, { recursive: true }).catch(()=>{}); }
function ok(res, data) { res.json(data); }
function err(res, code, message='Error') { res.status(code).json({ status:'error', code, message }); }
const EMAIL_RX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const uniq = a => Array.from(new Set((a||[]).filter(Boolean)));

function absUrl(u){
  const s = String(u || '').trim();
  if (!s) return '';
  if (/^https?:\/\//i.test(s)) return s;
  const base = (UPLOADS_PUBLIC_BASE_URL || SITE_URL || '').replace(/\/+$/,'');
  return base + (s.startsWith('/') ? s : `/${s}`);
}

function nnum(v){
  if (v == null) return null;
  const n = Number(String(v).replace(/[^\d.\-]/g,''));
  return Number.isFinite(n) ? n : null;
}
function parseTargets(v){
  if (Array.isArray(v)) return v.map(nnum).filter(Number.isFinite);
  const s = String(v || '');
  const m = s.match(/-?\d+(\.\d+)?/g) || [];
  return m.map(Number).filter(Number.isFinite);
}

/* ----------------------- STORAGE ----------------------- */
const blankDB   = () => ({ ideas: [] });
const blankSubs = () => ({ subs: [] });

async function loadDB(){
  try{
    await ensureDir(DATA_DIR);
    const raw = await fsp.readFile(DATA_FILE, 'utf8').catch(()=> '');
    if (!raw) return blankDB();
    const j = JSON.parse(raw);
    return (j && Array.isArray(j.ideas)) ? j : blankDB();
  }catch{ return blankDB(); }
}
async function saveDB(db){
  await ensureDir(DATA_DIR);
  const tmp = DATA_FILE + '.tmp';
  await fsp.writeFile(tmp, JSON.stringify(db,null,2), 'utf8');
  await fsp.rename(tmp, DATA_FILE);
}

async function loadSubs(){
  try{
    await ensureDir(DATA_DIR);
    const raw = await fsp.readFile(SUBS_FILE, 'utf8').catch(()=> '');
    if (!raw) return blankSubs();
    const j = JSON.parse(raw);
    return (j && Array.isArray(j.subs)) ? j : blankSubs();
  }catch{ return blankSubs(); }
}
async function saveSubs(s){ await ensureDir(DATA_DIR); const tmp=SUBS_FILE+'.tmp'; await fsp.writeFile(tmp, JSON.stringify(s,null,2),'utf8'); await fsp.rename(tmp,SUBS_FILE); }

/* ------------------------ UPLOADS ---------------------- */
let upload;
function buildMulter(){
  upload = multer({
    storage: multer.diskStorage({
      destination: (_req,_file,cb)=> cb(null, UPLOAD_DIR),
      filename: (_req,file,cb)=>{
        const ext = ({ 'image/png':'.png', 'image/jpeg':'.jpg', 'image/webp':'.webp', 'image/gif':'.gif' }[file.mimetype]) || '';
        cb(null, `${Date.now()}_${nanoid(8)}${ext}`);
      }
    }),
    fileFilter: (_req,file,cb)=>{
      if (ALLOWED_UPLOAD_TYPES.includes(file.mimetype)) cb(null,true);
      else cb(new Error('Unsupported file type'));
    },
    limits: { fileSize: MAX_UPLOAD_MB*1024*1024 }
  });
}

/* ------------------------- AUTH ------------------------ */
function readBearer(req){
  const h = req.headers['authorization'] || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : '';
}
function readQueryToken(req){ return String(req.query?.token || '').trim(); }
function requireAuth(req,res,next){
  if (!API_TOKEN) return next();
  const tok = readBearer(req) || readQueryToken(req);
  if (tok !== API_TOKEN) return err(res, 401, 'Unauthorized');
  next();
}
function sseAuthOK(req){ if (!API_TOKEN) return true; return readQueryToken(req) === API_TOKEN; }

/* -------------------------- SSE ----------------------- */
const clients = new Set(); // { id, res, ping }
function sseSend(event, data){
  const line = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of clients) { try{ c.res.write(line); }catch{} }
}
function sseTo(res, event, data){ res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`); }

/* --------------------- NORMALIZATION ------------------- */
function normalizeDirection(v){
  const s = String(v || '').toLowerCase();
  if (s === 'long' || s === 'buy')  return 'long';
  if (s === 'short' || s === 'sell') return 'short';
  return 'neutral';
}
function firstImageUrl(item){
  const raw = item?.imageUrl || (Array.isArray(item?.media) && item.media[0]?.url) || '';
  return absUrl(raw);
}
function normalizeIdea(input){
  const now = nowISO();
  const dir = normalizeDirection(input.direction || input.bias);
  const entry = nnum(input.entryLevel ?? input.entry ?? input.el);
  const stop  = nnum(input.stopLevel  ?? input.stop  ?? input.sl);
  const targets = parseTargets(input.targets ?? input.targetText ?? input.tps ?? input.tp);

  return {
    id: input.id || nanoid(12),
    type: String(input.type || 'post'),
    status: String(input.status || 'live'),
    title:  String(input.title  || '').slice(0,240),
    symbol: String(input.symbol || '').slice(0,64),
    levelText: String(input.levelText || input.levels || '').slice(0,2000),
    take:  String(input.take  || input.content || '').slice(0,4000),
    link:  String(input.link  || '').slice(0,1024),
    imageUrl: String(input.imageUrl || input.img || ''),
    media: Array.isArray(input.media) ? input.media.map(m=>({ kind:String(m.kind||'image'), url:String(m.url||'') })) : [],
    direction: dir,
    metrics: {
      entry: entry ?? null,
      stop:  stop  ?? null,
      targets,
      last: null,
      lastAt: null,
      statusLight: 'gray',
      statusNote: '',
      hitStop: false,
      hitTargetIndex: null,
      notified: { stop:false, targets:{} }
    },
    authorId: String(input.authorId || ''),
    authorName: String(input.authorName || 'Member'),
    authorEmail: String(input.authorEmail || ''),
    likes: input.likes || { count: 0, by: {} },
    comments: input.comments || { items: [] },
    createdAt: input.createdAt || now,
    updatedAt: now
  };
}
function publicIdea(it){
  return {
    id: it.id, type: it.type, status: it.status,
    title: it.title, symbol: it.symbol, levelText: it.levelText, take: it.take, link: it.link,
    imageUrl: it.imageUrl, media: it.media,
    direction: it.direction || 'neutral',
    metrics: it.metrics ? {
      entry: it.metrics.entry ?? null,
      stop: it.metrics.stop ?? null,
      targets: Array.isArray(it.metrics.targets) ? it.metrics.targets : [],
      last: it.metrics.last ?? null,
      lastAt: it.metrics.lastAt ?? null,
      statusLight: it.metrics.statusLight || 'gray',
      statusNote: it.metrics.statusNote || '',
      hitStop: !!it.metrics.hitStop,
      hitTargetIndex: Number.isFinite(it.metrics.hitTargetIndex) ? it.metrics.hitTargetIndex : null
    } : undefined,
    authorName: it.authorName, authorEmail: it.authorEmail,
    createdAt: it.createdAt, updatedAt: it.updatedAt,
    likeCount: Number(it.likes?.count || 0),
    likes: { count: Number(it.likes?.count || 0) },
    comments: { items: (it.comments?.items || []).map(c=>({
      id:c.id, authorName:c.authorName, text:c.text, createdAt:c.createdAt, updatedAt:c.updatedAt
    })) }
  };
}

/* --------------------- STATUS ENGINE ------------------- */
function evalStatus(idea){
  const m = idea.metrics ||= {};
  const dir = idea.direction || 'neutral';
  const p = Number(m.last);
  const el = Number(m.entry);
  const sl = Number(m.stop);
  const tgs = Array.isArray(m.targets) ? m.targets.map(Number) : [];

  if (!Number.isFinite(p) || !Number.isFinite(el)) {
    m.statusLight = 'gray'; m.statusNote = 'No price/entry'; return m;
  }

  const firstTarget = tgs.length ? tgs[0] : null;

  if (dir === 'long') {
    if (Number.isFinite(sl) && p <= sl) { m.statusLight='red';  m.statusNote='Stop hit'; m.hitStop = true; }
    else if (Number.isFinite(firstTarget) && p >= firstTarget) { m.statusLight='blue'; m.statusNote='Target reached'; if (m.hitTargetIndex == null) m.hitTargetIndex = 0; }
    else if (p >= el) { m.statusLight='green'; m.statusNote='Above EL'; }
    else { m.statusLight='orange'; m.statusNote='Below EL'; }
  } else if (dir === 'short') {
    if (Number.isFinite(sl) && p >= sl) { m.statusLight='red';  m.statusNote='Stop hit'; m.hitStop = true; }
    else if (Number.isFinite(firstTarget) && p <= firstTarget) { m.statusLight='blue'; m.statusNote='Target reached'; if (m.hitTargetIndex == null) m.hitTargetIndex = 0; }
    else if (p <= el) { m.statusLight='green'; m.statusNote='Below EL'; }
    else { m.statusLight='orange'; m.statusNote='Above EL'; }
  } else {
    m.statusLight='orange'; m.statusNote='Neutral';
  }
  return m;
}

/* --------------------- PRICE ENGINE -------------------- */
const priceCache = new Map(); // key -> { price, at }
function httpJSON(url){
  return new Promise((resolve,reject)=>{
    const lib = url.startsWith('https:') ? https : http;
    const req = lib.get(url, { timeout: 12000 }, res=>{
      if (res.statusCode >= 400) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
      let data = '';
      res.setEncoding('utf8');
      res.on('data', d => data += d);
      res.on('end', ()=>{ try{ resolve(JSON.parse(data)); }catch(e){ reject(e); } });
    });
    req.on('error', reject);
    req.on('timeout', ()=> req.destroy(new Error('Timeout')));
  });
}

function mapSymbol(raw){
  const s = String(raw || '').toUpperCase().trim();
  if (!s) return { kind:'yahoo', y:'XAUUSD=X' };
  const patch = {
    'US500':'OANDA:SPX500USD', 'SPX500':'OANDA:SPX500USD', 'SPX500USD':'OANDA:SPX500USD',
    'SPXUSD':'FOREXCOM:SPXUSD', 'XAU':'OANDA:XAUUSD', 'XAG':'OANDA:XAGUSD'
  };
  const norm = patch[s] || s;
  const [ex, code] = norm.includes(':') ? norm.split(':') : ['OANDA', norm];
  if (ex === 'BINANCE') return { kind:'binance', b: code.replace('USD','USDT') };
  if (/^[A-Z]{6}$/.test(code)) return { kind:'yahoo', y:`${code}=X` }; // FX pair → Yahoo
  return { kind:'yahoo', y: code };
}

async function fetchPrice(symbol){
  const m = mapSymbol(symbol);
  const key = JSON.stringify(m);
  const c = priceCache.get(key);
  if (c && (Date.now()-c.at) < PRICE_STALE_SEC*1000) return c.price;

  let price = NaN;

  if (m.kind === 'binance') {
    try{
      const j = await httpJSON(`https://api.binance.com/api/v3/ticker/price?symbol=${encodeURIComponent(m.b)}`);
      price = Number(j.price);
    }catch{}
  }
  if (!Number.isFinite(price)) {
    try{
      const y = await httpJSON(`https://query1.finance.yahoo.com/v7/finance/quote?symbols=${encodeURIComponent(m.y)}`);
      const r = y?.quoteResponse?.result?.[0];
      price = Number(r?.regularMarketPrice ?? r?.postMarketPrice);
    }catch{}
  }

  if (!Number.isFinite(price)) return null;
  priceCache.set(key, { price, at: Date.now() });
  return price;
}

/* -------------------- EMAIL HELPERS -------------------- */
function smtpReady(){ return !!(SMTP_HOST && SMTP_PORT && (SMTP_USER ? SMTP_PASS : true)); }
let transporter = null;
function getTransporter(){
  if (!smtpReady()) return null;
  if (transporter) return transporter;
  transporter = nodemailer.createTransport({
    host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_SECURE,
    auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
    connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 15000
  });
  return transporter;
}
function fromHeader(){
  if (EMAIL_FROM_INLINE) return EMAIL_FROM_INLINE;
  if (MAIL_FROM) return `"${MAIL_FROM_NAME}" <${MAIL_FROM}>`;
  if (SMTP_USER) return `"${MAIL_FROM_NAME}" <${SMTP_USER}>`;
  return `"${MAIL_FROM_NAME}" <no-reply@localhost>`;
}
function splitEmails(list){
  return String(list||'').split(/[,\s;]+/).map(s=>s.trim().toLowerCase()).filter(Boolean).filter(e=>EMAIL_RX.test(e));
}
function recipientsFor(kind, item){
  const forced = splitEmails(EMAIL_FORCE_ALL_TO);
  if (forced.length) return { to: forced[0], bcc: forced.slice(1) };
  const author = (item?.authorEmail||'').toLowerCase();
  const to = EMAIL_RX.test(author) ? author : (EMAIL_BCC_ADMIN[0] || undefined);
  const bcc = EMAIL_BCC_ADMIN.slice(1);
  return { to, bcc };
}
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function bullets(s){
  const parts = String(s||'').split(/\r?\n|[;•]\s*/g).map(x=>x.trim()).filter(Boolean);
  if (!parts.length) return '';
  return `<ul style="margin:8px 0 0 20px;padding:0">${parts.map(li=>`<li style="margin:6px 0;line-height:1.45">${esc(li)}</li>`).join('')}</ul>`;
}
function emailShell({ title, symbol, levelsHTML, planHTML, imgUrl, ctaHref, badgeText }){
  const logo = absUrl(LOGO_URL); const isDark = EMAIL_THEME !== 'light';
  const bodyBg = isDark ? 'background:#0a0f1a;' : 'background:#f7fbff;';
  const cardBg = isDark ? '#0b1220' : '#ffffff';
  const text   = isDark ? '#e8eefc' : '#102033';
  const titleC = isDark ? '#f5f8ff' : '#0b1220';
  const border = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.08)';
  const chipBg = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.05)';
  return `<!doctype html><html><body style="margin:0;padding:0;${bodyBg}">
  <table width="100%" cellpadding="0" cellspacing="0" style="padding:22px 14px">
  <tr><td align="center">
    <table width="100%" cellpadding="0" cellspacing="0" style="max-width:680px;background:${cardBg};border:1px solid ${border};border-radius:18px;overflow:hidden">
      <tr><td align="center" style="padding:18px 18px 8px">
        <img src="${esc(logo)}" width="220" style="display:block;width:220px;max-width:220px;height:auto" alt="">
        ${badgeText ? `<div style="margin:12px auto 0;display:inline-block;padding:6px 12px;border-radius:999px;background:${chipBg};font-weight:800;font-size:12px">${esc(badgeText)}</div>` : ''}
      </td></tr>
      ${imgUrl ? `<tr><td style="padding:8px 18px 0"><img src="${esc(imgUrl)}" width="640" style="display:block;width:100%;max-width:640px;border:1px solid ${border};border-radius:14px" alt=""></td></tr>` : ''}
      <tr><td style="padding:16px 18px;color:${text};font-family:Inter,Segoe UI,Roboto,Arial">
        <h1 style="margin:0 0 8px 0;color:${titleC};font-size:22px;line-height:1.3">${esc(title||'')}</h1>
        ${symbol ? `<div style="margin:2px 0 10px 0"><span style="display:inline-block;background:#0fd5ff12;color:#0fd5ff;border:1px solid #0fd5ff38;padding:6px 10px;border-radius:999px;font-weight:800;font-size:12px;letter-spacing:.2px">${esc(symbol)}</span></div>`:''}
        ${levelsHTML ? `<div style="margin:12px 0 10px 0;padding:12px 14px;border-radius:12px;border:1px dashed ${border}">${levelsHTML}</div>`:''}
        ${planHTML ? `<div style="margin:12px 0 0 0">${planHTML}</div>`:''}
      </td></tr>
      <tr><td style="padding:8px 18px 22px">
        <a href="${esc(ctaHref||SITE_URL)}" style="display:inline-block;padding:12px 18px;background:#00d0ff;color:#001018;text-decoration:none;border-radius:999px;font-weight:900;font-size:14px">Open Dashboard</a>
      </td></tr>
      <tr><td style="padding:14px 18px;border-top:1px solid ${border};color:${isDark?'#8fa0c6':'#3a4358'};font-size:12px;font-family:Inter,Segoe UI,Roboto,Arial">
        ${esc(SITE_NAME)} — ${esc(SITE_URL)}
      </td></tr>
    </table>
  </td></tr></table></body></html>`;
}
function levelsHTMLFromIdea(it){
  const m = it.metrics || {};
  const parts = [];
  if (it.levelText) parts.push(it.levelText);
  if (m.entry != null) parts.push(`EL: ${m.entry}`);
  if (m.stop  != null) parts.push(`SL: ${m.stop}`);
  if (Array.isArray(m.targets) && m.targets.length) parts.push(`TPs: ${m.targets.join(', ')}`);
  return bullets(parts.join('; '));
}
function planHTMLFromIdea(it){ const s = String(it.take||'').trim(); return s ? `<p style="margin:0;line-height:1.55">${esc(s)}</p>`:''; }
async function smtpSend({ subject, html, to, bcc }){
  const t = getTransporter(); if (!t) throw new Error('SMTP not configured');
  const info = await t.sendMail({ from: fromHeader(), to, bcc: (bcc&&bcc.length)?bcc:undefined, subject, html, replyTo: EMAIL_REPLY_TO || undefined });
  return { ok:true, id: info.messageId };
}
async function httpFallbackSend(payload){
  if (!EMAIL_HTTP_FALLBACK_URL) throw new Error('HTTP fallback not configured');
  return new Promise((resolve,reject)=>{
    const url = new URL(EMAIL_HTTP_FALLBACK_URL);
    const lib = url.protocol === 'https:' ? https : http;
    const data = JSON.stringify(payload);
    const req = lib.request(EMAIL_HTTP_FALLBACK_URL, { method:'POST', headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)}}, res=>{
      (res.statusCode>=200 && res.statusCode<300) ? resolve({ok:true}) : reject(new Error(`HTTP ${res.statusCode}`));
    });
    req.on('error', reject); req.write(data); req.end();
  });
}
async function sendEmailSmart(kind, item){
  const { to, bcc } = recipientsFor(kind, item);
  const title = kind==='post'
    ? `New Idea: ${item.symbol ? `${item.symbol} — ` : ''}${item.title||'Post'}`
    : (kind==='stop' ? `STOP hit — ${item.symbol}` : `TARGET hit — ${item.symbol}`);
  const html = emailShell({
    title, symbol:item.symbol||'', levelsHTML:levelsHTMLFromIdea(item), planHTML:planHTMLFromIdea(item),
    imgUrl:firstImageUrl(item), ctaHref:`${SITE_URL}/trading-dashboard?idea=${encodeURIComponent(item.id)}`,
    badgeText: kind==='post' ? 'New Post' : (kind==='stop' ? 'STOP' : 'TARGET')
  });
  try{ return await smtpSend({ subject:title, html, to, bcc }); }
  catch(e){ if (EMAIL_HTTP_FALLBACK_URL) { try{ return await httpFallbackSend({ kind, item }); }catch{} } throw e; }
}

/* Trigger emails on transitions */
async function maybeTriggerEmails(prev, curr){
  const pm = prev.metrics || {};
  const cm = curr.metrics || {};
  if (cm.hitStop && !pm.hitStop && !cm.notified?.stop) {
    cm.notified ||= { stop:false, targets:{} };
    try{ await sendEmailSmart('stop', curr); }catch{}
    cm.notified.stop = true;
  }
  const prevIdx = Number.isFinite(pm.hitTargetIndex) ? pm.hitTargetIndex : -1;
  const currIdx = Number.isFinite(cm.hitTargetIndex) ? cm.hitTargetIndex : -1;
  if (currIdx >=0 && currIdx > prevIdx) {
    cm.notified ||= { stop:false, targets:{} };
    cm.notified.targets ||= {};
    if (!cm.notified.targets[currIdx]) {
      try{ await sendEmailSmart('target', curr); }catch{}
      cm.notified.targets[currIdx] = true;
    }
  }
}

/* ------------------------- APP ------------------------ */
const app = express();

function isOriginAllowed(origin){
  if (!origin) return true;
  if (CORS_ORIGINS.includes('*') || CORS_ORIGINS.includes(origin)) return true;
  try{
    const u = new URL(origin);
    if (/^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(u.host)) return true;
    for (const pat of CORS_ORIGINS) {
      if (!pat.includes('*')) continue;
      const m = pat.match(/^https?:\/\/\*\.(.+)$/i);
      if (m && u.host.endsWith(m[1])) return u.protocol === 'https:';
    }
  }catch{}
  return false;
}
app.use(cors({ origin:(origin,cb)=> cb(null, isOriginAllowed(origin)), credentials:false }));
app.use(express.json({ limit:'1mb' }));
app.use('/uploads', express.static(UPLOAD_DIR, { index:false, maxAge:'30d', setHeaders:res=>res.setHeader('Cross-Origin-Resource-Policy','cross-origin') }));

/* HEALTH */
app.get('/health', (_req,res)=> ok(res,{ ok:true, env:NODE_ENV, time:nowISO() }));

/* EVENTS (SSE) */
app.get('/events', (req,res)=>{
  if (!sseAuthOK(req)) return err(res, 401, 'Unauthorized');
  res.set({'Content-Type':'text/event-stream','Cache-Control':'no-cache, no-transform','Connection':'keep-alive','X-Accel-Buffering':'no'});
  res.flushHeaders?.();
  const id = nanoid(10);
  const client = { id, res, ping: null };
  clients.add(client);
  sseTo(res, 'hello', { id, at: nowISO() });
  client.ping = setInterval(()=>{ try{ res.write(': ping\n\n'); }catch{} }, 25000);
  req.on('close', ()=>{ clearInterval(client.ping); clients.delete(client); });
});

/* PRICE proxy */
app.get('/price', async (req,res)=>{
  try{
    const raw = String(req.query.symbol||'').toUpperCase();
    const p = await fetchPrice(raw);
    ok(res, { price: Number.isFinite(p) ? p : null });
  }catch(e){ err(res, 500, String(e.message||e)); }
});

/* IDEAS CRUD */
app.get('/ideas/latest', async (req,res)=>{
  const limit = Math.min(Number(req.query.limit||30), 100);
  const db = await loadDB();
  const items = [...db.ideas].sort((a,b)=> new Date(b.createdAt)-new Date(a.createdAt)).slice(0,limit).map(publicIdea);
  ok(res, { items, ideas: items });
});
app.get('/ideas/:id', async (req,res)=>{
  const db = await loadDB();
  const it = db.ideas.find(x=> String(x.id)===String(req.params.id));
  if (!it) return err(res, 404, 'Not found');
  ok(res, { item: publicIdea(it) });
});
app.post('/ideas', requireAuth, async (req,res)=>{
  const db = await loadDB();
  const it = normalizeIdea(req.body || {});
  if (!it.imageUrl && it.media?.[0]?.url) it.imageUrl = it.media[0].url;
  db.ideas.unshift(it);
  await saveDB(db);
  const pub = publicIdea(it);
  sseSend('idea:new', pub);
  ok(res, { item: pub });
});
app.patch('/ideas/:id', requireAuth, async (req,res)=>{
  const db = await loadDB();
  const idx = db.ideas.findIndex(x=> String(x.id)===String(req.params.id));
  if (idx<0) return err(res, 404, 'Not found');
  const it = db.ideas[idx];
  const prev = JSON.parse(JSON.stringify(it));

  Object.assign(it, {
    type:      req.body.type      ?? it.type,
    status:    req.body.status    ?? it.status,
    title:     req.body.title     ?? it.title,
    symbol:    req.body.symbol    ?? it.symbol,
    levelText: req.body.levelText ?? it.levelText,
    take:      req.body.take      ?? it.take,
    link:      req.body.link      ?? it.link,
    imageUrl:  (typeof req.body.imageUrl === 'string' ? req.body.imageUrl : it.imageUrl),
    media:     Array.isArray(req.body.media) ? req.body.media : it.media,
    direction: normalizeDirection(req.body.direction ?? req.body.bias ?? it.direction),
    updatedAt: nowISO()
  });

  it.metrics ||= {};
  if (req.body.entryLevel!=null || req.body.entry!=null || req.body.el!=null)
    it.metrics.entry = nnum(req.body.entryLevel ?? req.body.entry ?? req.body.el);
  if (req.body.stopLevel!=null || req.body.stop!=null || req.body.sl!=null)
    it.metrics.stop = nnum(req.body.stopLevel ?? req.body.stop ?? req.body.sl);
  if (req.body.targets!=null || req.body.targetText!=null || req.body.tp!=null || req.body.tps!=null)
    it.metrics.targets = parseTargets(req.body.targets ?? req.body.targetText ?? req.body.tp ?? req.body.tps);

  evalStatus(it);

  await saveDB(db);
  const pub = publicIdea(it);
  sseSend('idea:update', pub);

  await maybeTriggerEmails(prev, it).catch(()=>{});

  ok(res, { item: pub });
});
app.delete('/ideas/:id', requireAuth, async (req,res)=>{
  const db = await loadDB();
  const idx = db.ideas.findIndex(x=> String(x.id)===String(req.params.id));
  if (idx<0) return err(res, 404, 'Not found');
  const id = db.ideas[idx].id;
  db.ideas.splice(idx,1);
  await saveDB(db);
  sseSend('idea:delete', { id });
  ok(res, { ok:true });
});

/* LIKES (multi-user; userId required) */
async function likeHandler(req,res){
  const action      = String(req.body?.action || req.body?.op || '').toLowerCase(); // like|unlike
  const userId      = String(req.body?.userId || req.body?.by || '').slice(0,120) || 'device';
  const displayName = String(req.body?.displayName || req.body?.name || 'Member').slice(0,120);
  if (!['like','unlike'].includes(action)) return err(res, 400, 'Invalid action');
  const db = await loadDB();
  const it = db.ideas.find(x=> String(x.id)===String(req.params.id));
  if (!it) return err(res, 404, 'Not found');

  it.likes ||= { count:0, by:{} };
  it.likes.by ||= {};
  const was = !!it.likes.by[userId];

  if (action==='like' && !was) {
    it.likes.by[userId] = { at: nowISO(), name: displayName };
  } else if (action==='unlike' && was) {
    delete it.likes.by[userId];
  }
  it.likes.count = Object.keys(it.likes.by).length;

  await saveDB(db);
  const out = { id: it.id, likeCount: it.likes.count };
  sseSend('likes:update', out);
  ok(res, { likeCount: it.likes.count, likes:{ count: it.likes.count } });
}
app.put('/ideas/:id/likes', requireAuth, likeHandler);
app.post('/ideas/:id/likes', requireAuth, likeHandler);

/* COMMENTS */
async function commentAdd(req,res){
  const db = await loadDB();
  const it = db.ideas.find(x=> String(x.id)===String(req.params.id));
  if (!it) return err(res, 404, 'Not found');
  const text = String(req.body?.text || '').trim();
  if (!text) return err(res, 400, 'text required');
  const authorId   = String(req.body?.authorId || '').slice(0,120);
  const authorName = String(req.body?.authorName || 'Member').slice(0,120);
  const c = { id:nanoid(10), authorId, authorName, text, createdAt: nowISO(), updatedAt: nowISO() };
  it.comments ||= { items: [] };
  it.comments.items.push(c);
  await saveDB(db);
  const items = it.comments.items.map(x=>({ id:x.id, authorName:x.authorName, text:x.text, createdAt:x.createdAt, updatedAt:x.updatedAt }));
  sseSend('comments:update', { id: it.id, items });
  ok(res, { items });
}
async function commentEdit(req,res){
  const db = await loadDB();
  const it = db.ideas.find(x=> String(x.id)===String(req.params.id));
  if (!it) return err(res, 404, 'Not found');
  const c = (it.comments?.items || []).find(x=> String(x.id)===String(req.params.cid));
  if (!c) return err(res, 404, 'comment not found');
  const text = String(req.body?.text || '').trim();
  if (!text) return err(res, 400, 'text required');
  c.text = text; c.updatedAt = nowISO();
  await saveDB(db);
  const items = it.comments.items.map(x=>({ id:x.id, authorName:x.authorName, text:x.text, createdAt:x.createdAt, updatedAt:x.updatedAt }));
  sseSend('comments:update', { id: it.id, items });
  ok(res, { items });
}
async function commentDelete(req,res){
  const db = await loadDB();
  const it = db.ideas.find(x=> String(x.id)===String(req.params.id));
  if (!it) return err(res, 404, 'Not found');
  const before = it.comments?.items?.length || 0;
  it.comments.items = (it.comments?.items || []).filter(x=> String(x.id)!==String(req.params.cid));
  if ((it.comments.items.length || 0) === before) return err(res, 404, 'comment not found');
  await saveDB(db);
  const items = it.comments.items.map(x=>({ id:x.id, authorName:x.authorName, text:x.text, createdAt:x.createdAt, updatedAt:x.updatedAt }));
  sseSend('comments:update', { id: it.id, items });
  ok(res, { items });
}
app.post('/ideas/:id/comments', requireAuth, commentAdd);
app.patch('/ideas/:id/comments/:cid', requireAuth, commentEdit);
app.delete('/ideas/:id/comments/:cid', requireAuth, commentDelete);

/* EMAIL endpoints */
app.post('/email/post', requireAuth, async (req,res)=>{
  try{ const item = req.body?.item || req.body || {}; await sendEmailSmart('post', item); ok(res,{ok:true}); }
  catch(e){ err(res, 500, String(e.message||e)); }
});
app.post('/email/signal', requireAuth, async (req,res)=>{
  try{
    const kind = String(req.body?.kind || 'target').toLowerCase();
    const item = req.body?.item || {};
    await sendEmailSmart(kind==='stop'?'stop':'target', item);
    ok(res,{ok:true});
  }catch(e){ err(res, 500, String(e.message||e)); }
});

/* SUBSCRIBE */
app.post(['/subscribe','/api/subscribe','/email/subscribe'], requireAuth, async (req,res)=>{
  try{
    const name  = String(req.body?.name || 'Member').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    if (!EMAIL_RX.test(email)) return err(res, 400, 'Invalid email');
    const subs = await loadSubs();
    if (!subs.subs.find(s=> s.email===email)) subs.subs.push({ email, name, at: nowISO() });
    await saveSubs(subs);
    ok(res,{ok:true});
  }catch(e){ err(res, 500, String(e.message||e)); }
});

/* UPLOAD */
app.post('/upload', requireAuth, (req,res,next)=> upload.single('file')(req,res, async (e)=>{
  if (e) return err(res, 400, e.message || 'Upload failed');
  try{
    const file = req.file; if (!file) return err(res, 400, 'No file');
    const rel = `/uploads/${file.filename}`;
    const url = absUrl(rel);
    ok(res, { ok:true, url, path: rel });
  }catch(ex){ err(res, 500, String(ex.message||ex)); }
}));

/* -------------------- PRICE POLLER --------------------- */
let _polling = false;
async function maybeAutoSetStatus(it){
  if (!AUTO_SET_STATUS) return false;
  const m = it.metrics || {};
  let changed = false;
  if (m.hitStop && it.status!=='lost') { it.status='lost'; changed = true; }
  else if (Number.isFinite(m.hitTargetIndex) && m.hitTargetIndex>=0 && it.status!=='won') { it.status='won'; changed = true; }
  else if (m.last!=null && m.entry!=null && it.status!=='live') { it.status='live'; changed = true; }
  return changed;
}
async function pollOnce(){
  if (_polling) return;
  _polling = true;
  try{
    const db = await loadDB();
    let changedAny = false;

    for (const it of db.ideas) {
      if (!it.symbol) continue;
      it.metrics ||= {};
      const watch = (it.metrics.entry != null) || (it.metrics.stop != null) || ((it.metrics.targets||[]).length>0);
      if (!watch) continue;

      const p = await fetchPrice(it.symbol).catch(()=> null);
      if (p == null) continue;

      const prev = JSON.parse(JSON.stringify(it));

      it.metrics.last = p;
      it.metrics.lastAt = nowISO();
      evalStatus(it);

      await maybeTriggerEmails(prev, it).catch(()=>{});
      const statusChanged = await maybeAutoSetStatus(it);

      const diff =
        statusChanged ||
        (prev.metrics?.statusLight !== it.metrics.statusLight) ||
        (prev.metrics?.hitStop !== it.metrics.hitStop) ||
        (prev.metrics?.hitTargetIndex !== it.metrics.hitTargetIndex);

      if (diff) {
        sseSend('idea:update', publicIdea(it));
        changedAny = true;
      }
    }

    if (changedAny) await saveDB(db);
  }catch{} finally{ _polling = false; }
}
setInterval(pollOnce, POLL_INTERVAL_MS);

/* ------------------------- START ---------------------- */
(async function start(){
  await ensureDir(DATA_DIR);
  await ensureDir(UPLOAD_DIR);
  buildMulter();
  app.listen(PORT, ()=> console.log(`[ideas-backend] listening on :${PORT} env=${NODE_ENV} data=${DATA_FILE}`));
})();
