/* server.cjs
 * TCPP Ideas Backend (Express) + Email + Subscribers
 * Storage: JSON files on disk (/data)
 * Auth: All writes & /email/* require API_TOKEN via Bearer header OR ?token=
 * SSE events: idea:new, idea:update, idea:delete, comments:update, likes:update
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
const { nanoid } = require('nanoid');

/* ---------------------- ENV ---------------------- */
const PORT      = process.env.PORT || 8080;
const NODE_ENV  = process.env.NODE_ENV || 'production';

const API_TOKEN = process.env.API_TOKEN || ''; // required for writes in prod

/* Support either CORS_ORIGINS or CORS_ALLOW_ORIGINS (comma list) */
const _corsEnv  = process.env.CORS_ORIGINS || process.env.CORS_ALLOW_ORIGINS || '*';
const CORS_ORIGINS = _corsEnv.split(',').map(s => s.trim()).filter(Boolean);

const DATA_DIR    = process.env.DATA_DIR   || '/data';
const DATA_FILE   = path.join(DATA_DIR, 'ideas.json');
const SUBS_FILE   = path.join(DATA_DIR, 'subscribers.json');
const UPLOAD_DIR  = process.env.UPLOAD_DIR || path.join(DATA_DIR, 'uploads');

const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 8);
const ALLOWED_UPLOAD_TYPES = (process.env.ALLOWED_UPLOAD_TYPES
  || 'image/png,image/jpeg,image/webp').split(',').map(s => s.trim());

/* ---------------------- EMAIL -------------------- */
const SMTP_HOST   = process.env.SMTP_HOST   || '';
const SMTP_PORT   = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true' || SMTP_PORT === 465;
const SMTP_USER   = process.env.SMTP_USER   || '';
const SMTP_PASS   = process.env.SMTP_PASS   || '';

/* From / Reply / Admin controls */
const MAIL_FROM         = process.env.MAIL_FROM || '';
const MAIL_FROM_NAME    = process.env.MAIL_FROM_NAME || 'Trade Chart Patterns Like The Pros';
const EMAIL_FROM_INLINE = process.env.EMAIL_FROM || '';
const EMAIL_REPLY_TO    = (process.env.EMAIL_REPLY_TO || '').trim();
const EMAIL_BCC_ADMIN   = (process.env.EMAIL_BCC_ADMIN || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const EMAIL_FORCE_ALL_TO = (process.env.EMAIL_FORCE_ALL_TO || '').trim().toLowerCase();

/* Branding */
const SITE_NAME   = process.env.SITE_NAME   || 'Trade Chart Patterns — Pro';
const SITE_URL    = process.env.SITE_URL    || 'https://www.tradechartpatternslikethepros.com';
const LOGO_URL    = process.env.EMAIL_LOGO_URL
  || process.env.LOGO_URL
  || 'https://static.wixstatic.com/media/e09166_90ddc4c3b20d4b4b83461681f85d9dd8~mv2.png';

/* Theme + asset base (absolute URLs for images in emails) */
const ASSET_BASE_URL = process.env.ASSET_BASE_URL || SITE_URL;   // e.g. https://www.tradechartpatternslikethepros.com
const UPLOADS_PUBLIC_BASE_URL = process.env.UPLOADS_PUBLIC_BASE_URL || ASSET_BASE_URL; // e.g. https://ideas-backend-production.up.railway.app
const EMAIL_THEME    = (process.env.EMAIL_THEME || 'clear').toLowerCase(); // 'dark' | 'clear' | 'white'  (default clear/transparent)
const EMAIL_BODY_BG  = (process.env.EMAIL_BODY_BG || '').trim(); // optional CSS color override
const EMAIL_LAYOUT   = (process.env.EMAIL_LAYOUT || 'hero-first').toLowerCase(); // 'hero-first' puts chart first

/* ---------------------- UTIL ---------------------- */
const nowISO = () => new Date().toISOString();
async function ensureDir(p) { await fsp.mkdir(p, { recursive: true }).catch(() => {}); }
function ok(res, data) { res.json(data); }
function err(res, code, msg) { res.status(code).json({ status:'error', code, message: msg || 'Error' }); }

/* Make absolute HTTPS URLs for email clients */
function absUrl(u) {
  const s = String(u || '').trim();
  if (!s) return '';
  if (/^data:image\//i.test(s)) return s;
  if (/^https?:\/\//i.test(s)) return s;
  if (s.startsWith('/uploads/')) {
    const baseU = (UPLOADS_PUBLIC_BASE_URL || ASSET_BASE_URL || SITE_URL).replace(/\/+$/,'');
    return baseU + s;
  }
  const base = (ASSET_BASE_URL || SITE_URL || '').replace(/\/+$/,'');
  return base + (s.startsWith('/') ? s : `/${s}`);
}

/* -------------------- STORAGE -------------------- */
const blankDB   = () => ({ ideas: [] });
const blankSubs = () => ({ subs: [] });

async function loadDB() {
  try {
    await ensureDir(DATA_DIR);
    const raw = await fsp.readFile(DATA_FILE, 'utf8').catch(() => '');
    if (!raw) return blankDB();
    const j = JSON.parse(raw);
    return (j && Array.isArray(j.ideas)) ? j : blankDB();
  } catch { return blankDB(); }
}
async function saveDB(db) {
  await ensureDir(DATA_DIR);
  const tmp = DATA_FILE + '.tmp';
  await fsp.writeFile(tmp, JSON.stringify(db, null, 2), 'utf8');
  await fsp.rename(tmp, DATA_FILE);
}

async function loadSubs() {
  try {
    await ensureDir(DATA_DIR);
    const raw = await fsp.readFile(SUBS_FILE, 'utf8').catch(() => '');
    if (!raw) return blankSubs();
    const j = JSON.parse(raw);
    return (j && Array.isArray(j.subs)) ? j : blankSubs();
  } catch { return blankSubs(); }
}
async function saveSubs(db) {
  await ensureDir(DATA_DIR);
  const tmp = SUBS_FILE + '.tmp';
  await fsp.writeFile(tmp, JSON.stringify(db, null, 2), 'utf8');
  await fsp.rename(tmp, SUBS_FILE);
}

/* -------------------- UPLOADS -------------------- */
let upload;
function buildMulter() {
  upload = multer({
    storage: multer.diskStorage({
      destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
      filename: (_req, file, cb) => {
        const ext = ({ 'image/png': '.png', 'image/jpeg': '.jpg', 'image/webp': '.webp' }[file.mimetype]) || '';
        cb(null, `${Date.now()}_${nanoid(8)}${ext}`);
      }
    }),
    fileFilter: (_req, file, cb) => {
      if (ALLOWED_UPLOAD_TYPES.includes(file.mimetype)) cb(null, true);
      else cb(new Error('Unsupported file type'));
    },
    limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 }
  });
}

/* ---------------------- AUTH ---------------------- */
function readBearer(req) {
  const h = req.headers['authorization'];
  if (h && /^Bearer\s+/i.test(h)) return h.replace(/^Bearer\s+/i, '').trim();
  return '';
}
function readQueryToken(req) {
  return (req.query && String(req.query.token || '').trim()) || '';
}
function requireAuth(req, res, next) {
  if (!API_TOKEN) return next();
  const tok = readBearer(req) || readQueryToken(req);
  if (tok !== API_TOKEN) return err(res, 401, 'Unauthorized');
  next();
}
function sseAuthOK(req) {
  if (!API_TOKEN) return true;
  const tok = readQueryToken(req);
  return tok === API_TOKEN;
}

/* ----------------------- SSE ---------------------- */
const clients = new Set(); // { id, res, ping }
function sseSend(event, data) {
  const line = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of clients) { try { c.res.write(line); } catch {} }
}
function sseSendTo(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

/* ----------------------- APP --------------------- */
const app = express();

/* CORS with wildcards (e.g. https://*.wixsite.com) */
function isOriginAllowed(origin) {
  if (!origin) return true;
  if (CORS_ORIGINS.includes('*') || CORS_ORIGINS.includes(origin)) return true;
  try {
    const { protocol, host } = new URL(origin);
    if (host.endsWith('.wixsite.com')) return protocol === 'https:';
    if (host.endsWith('.filesusr.com')) return protocol === 'https:';
    for (const pat of CORS_ORIGINS) {
      if (!pat.includes('*')) continue;
      const m = pat.match(/^https?:\/\/\*\.(.+)$/i);
      if (m && host.endsWith(m[1])) return protocol === 'https:';
    }
    if (/^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(host)) return true;
  } catch {}
  return false;
}
app.use(cors({ origin: (origin, cb) => cb(null, isOriginAllowed(origin)), credentials: false }));

/* JSON body */
app.use(express.json({ limit: '1mb' }));

/* Static uploads */
app.use('/uploads', express.static(UPLOAD_DIR, {
  index: false,
  maxAge: '30d',
  setHeaders: res => res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin')
}));

/* ---------------------- HEALTH ------------------- */
app.get('/health', (_req, res) => ok(res, { ok: true, env: NODE_ENV, time: nowISO() }));

/* ---------------------- EVENTS (SSE) ------------- */
app.get('/events', (req, res) => {
  if (!sseAuthOK(req)) return err(res, 401, 'Unauthorized');
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders?.();
  const id = nanoid(10);
  const client = { id, res, ping: null };
  clients.add(client);
  sseSendTo(res, 'hello', { id, at: nowISO() });
  client.ping = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 25000);
  req.on('close', () => { clearInterval(client.ping); clients.delete(client); });
});

/* -------------------- NORMALIZATION -------------- */
function normalizeIdea(input) {
  const now = nowISO();
  return {
    id: input.id || nanoid(12),
    type: String(input.type || 'post'),
    status: String(input.status || 'live'),
    title: String(input.title || '').slice(0, 240),
    symbol: String(input.symbol || '').slice(0, 64),
    levelText: String(input.levelText || input.levels || '').slice(0, 2000),
    take: String(input.take || input.content || '').slice(0, 4000),
    link: String(input.link || '').slice(0, 1024),
    imageUrl: String(input.imageUrl || ''),       // optional
    chartUrl: String(input.chartUrl || ''),       // NEW: allow direct chart URL (live feed/screenshot)
    media: Array.isArray(input.media) ? input.media.map(m => ({
      kind: String(m.kind || 'image'), url: String(m.url || '')
    })) : [],
    authorId: String(input.authorId || ''),
    authorName: String(input.authorName || 'Member'),
    authorEmail: String(input.authorEmail || ''),
    likes: input.likes || { count: 0, by: {} },
    comments: input.comments || { items: [] },
    createdAt: input.createdAt || now,
    updatedAt: now
  };
}

function ideaPublic(it) {
  return {
    id: it.id, type: it.type, status: it.status,
    title: it.title, symbol: it.symbol,
    levelText: it.levelText, take: it.take,
    link: it.link, imageUrl: it.imageUrl, chartUrl: it.chartUrl, media: it.media,
    authorName: it.authorName, authorEmail: it.authorEmail,
    createdAt: it.createdAt, updatedAt: it.updatedAt,
    likeCount: it.likes?.count || 0,
    likes: { count: it.likes?.count || 0 },
    comments: {
      items: (it.comments?.items || []).map(c => ({
        id: c.id, authorName: c.authorName, text: c.text,
        createdAt: c.createdAt, updatedAt: c.updatedAt
      }))
    }
  };
}

/* -------------------- IDEAS CRUD ------------------ */
app.get('/ideas/latest', async (req, res) => {
  const limit = Math.min(Number(req.query.limit || 30), 100);
  const db = await loadDB();
  const items = [...db.ideas]
    .sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, limit)
    .map(ideaPublic);
  ok(res, { items, ideas: items });
});

app.get('/ideas/:id', async (req, res) => {
  const db = await loadDB();
  const it = db.ideas.find(x => String(x.id) === String(req.params.id));
  if (!it) return err(res, 404, 'Not found');
  const pub = ideaPublic(it);
  ok(res, { item: pub, idea: pub });
});

app.post('/ideas', requireAuth, async (req, res) => {
  const db = await loadDB();
  const it = normalizeIdea(req.body || {});
  db.ideas.unshift(it);
  await saveDB(db);
  const pub = ideaPublic(it);
  sseSend('idea:new', pub);
  ok(res, { item: pub, idea: pub });
});

app.patch('/ideas/:id', requireAuth, async (req, res) => {
  const db = await loadDB();
  const idx = db.ideas.findIndex(x => String(x.id) === String(req.params.id));
  if (idx < 0) return err(res, 404, 'Not found');
  const it = db.ideas[idx];
  Object.assign(it, {
    type:      req.body.type      ?? it.type,
    status:    req.body.status    ?? it.status,
    title:     req.body.title     ?? it.title,
    symbol:    req.body.symbol    ?? it.symbol,
    levelText: req.body.levelText ?? it.levelText,
    take:      req.body.take      ?? it.take,
    link:      req.body.link      ?? it.link,
    imageUrl:  (typeof req.body.imageUrl === 'string' ? req.body.imageUrl : it.imageUrl),
    chartUrl:  (typeof req.body.chartUrl === 'string' ? req.body.chartUrl : it.chartUrl),
    media: Array.isArray(req.body.media) ? req.body.media : it.media,
    updatedAt: nowISO()
  });
  await saveDB(db);
  const pub = ideaPublic(it);
  sseSend('idea:update', pub);
  ok(res, { item: pub, idea: pub });
});

app.delete('/ideas/:id', requireAuth, async (req, res) => {
  const db = await loadDB();
  const idx = db.ideas.findIndex(x => String(x.id) === String(req.params.id));
  if (idx < 0) return err(res, 404, 'Not found');
  const id = db.ideas[idx].id;
  db.ideas.splice(idx, 1);
  await saveDB(db);
  sseSend('idea:delete', { id });
  ok(res, { ok: true });
});

/* ---------------------- LIKES --------------------- */
async function likeHandler(req, res) {
  const action      = String(req.body?.action || req.body?.op || '').toLowerCase();
  const userId      = String(req.body?.userId || req.body?.by || '').slice(0, 120);
  const displayName = String(req.body?.displayName || req.body?.name || 'Member').slice(0, 120);
  if (!['like', 'unlike'].includes(action)) return err(res, 400, 'Invalid action');
  if (!userId) return err(res, 400, 'userId required');
  const db = await loadDB();
  const it = db.ideas.find(x => String(x.id) === String(req.params.id));
  if (!it) return err(res, 404, 'Not found');
  it.likes ||= { count: 0, by: {} };
  it.likes.by ||= {};
  const was = !!it.likes.by[userId];
  if (action === 'like' && !was) {
    it.likes.by[userId] = { at: nowISO(), name: displayName };
    it.likes.count = Math.max(0, Number(it.likes.count || 0)) + 1;
  }
  if (action === 'unlike' && was) {
    delete it.likes.by[userId];
    it.likes.count = Math.max(0, Number(it.likes.count || 1) - 1);
  }
  await saveDB(db);
  sseSend('likes:update', { id: it.id, likeCount: it.likes.count });
  ok(res, { likeCount: it.likes.count, likes: { count: it.likes.count } });
}
app.put('/ideas/:id/likes', requireAuth, likeHandler);
app.post('/ideas/:id/likes', requireAuth, likeHandler);
app.put('/ideas/:id/likes/toggle', requireAuth, likeHandler);
app.post('/ideas/:id/likes/toggle', requireAuth, likeHandler);

/* -------------------- COMMENTS -------------------- */
async function _commentAdd(req, res) {
  const db = await loadDB();
  const it = db.ideas.find(x => String(x.id) === String(req.params.id));
  if (!it) return err(res, 404, 'Not found');
  const text       = String(req.body?.text || '').trim();
  const authorId   = String(req.body?.authorId || '').slice(0, 120);
  const authorName = String(req.body?.authorName || 'Member').slice(0, 120);
  if (!text) return err(res, 400, 'text required');
  const c = { id: nanoid(10), authorId, authorName, text, createdAt: nowISO(), updatedAt: nowISO() };
  it.comments ||= { items: [] };
  it.comments.items.push(c);
  await saveDB(db);
  const items = it.comments.items.map(x => ({
    id: x.id, authorName: x.authorName, text: x.text, createdAt: x.createdAt, updatedAt: x.updatedAt
  }));
  sseSend('comments:update', { id: it.id, items });
  ok(res, { items });
}
async function _commentEdit(req, res) {
  const db = await loadDB();
  const it = db.ideas.find(x => String(x.id) === String(req.params.id));
  if (!it) return err(res, 404, 'Not found');
  const c = (it.comments?.items || []).find(x => String(x.id) === String(req.params.cid));
  if (!c) return err(res, 404, 'comment not found');
  const text = String(req.body?.text || '').trim();
  if (!text) return err(res, 400, 'text required');
  c.text = text;
  c.updatedAt = nowISO();
  await saveDB(db);
  const items = it.comments.items.map(x => ({
    id: x.id, authorName: x.authorName, text: x.text, createdAt: x.createdAt, updatedAt: x.updatedAt
  }));
  sseSend('comments:update', { id: it.id, items });
  ok(res, { items });
}
async function _commentDelete(req, res) {
  const db = await loadDB();
  const it = db.ideas.find(x => String(x.id) === String(req.params.id));
  if (!it) return err(res, 404, 'Not found');
  const before = (it.comments?.items || []).length;
  it.comments.items = (it.comments?.items || []).filter(x => String(x.id) !== String(req.params.cid));
  const after = it.comments.items.length;
  if (before === after) return err(res, 404, 'comment not found');
  await saveDB(db);
  const items = it.comments.items.map(x => ({
    id: x.id, authorName: x.authorName, text: x.text, createdAt: x.createdAt, updatedAt: x.updatedAt
  }));
  sseSend('comments:update', { id: it.id, items });
  ok(res, { items });
}
app.post('/ideas/:id/comments', requireAuth, _commentAdd);
app.patch('/ideas/:id/comments/:cid', requireAuth, _commentEdit);
app.put  ('/ideas/:id/comments/:cid', requireAuth, _commentEdit);
app.delete('/ideas/:id/comments/:cid', requireAuth, _commentDelete);

/* --------------------- EMAIL CORE ----------------- */
function smtpReady() {
  return !!(SMTP_HOST && SMTP_PORT && (SMTP_USER ? SMTP_PASS : true));
}
let transporter = null;
function getTransporter() {
  if (!smtpReady()) return null;
  if (transporter) return transporter;
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000
  });
  return transporter;
}
function fromHeader() {
  if (EMAIL_FROM_INLINE) return EMAIL_FROM_INLINE;
  if (MAIL_FROM) return `"${MAIL_FROM_NAME}" <${MAIL_FROM}>`;
  if (SMTP_USER) return `"${MAIL_FROM_NAME}" <${SMTP_USER}>`;
  return `"${MAIL_FROM_NAME}" <no-reply@localhost>`;
}

const EMAIL_RX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
function splitEmails(list) {
  return String(list || '')
    .split(/[,\s;]+/)
    .map(s => s.trim().toLowerCase())
    .filter(Boolean)
    .filter(e => EMAIL_RX.test(e));
}
function uniq(arr) { const s=new Set(); const out=[]; for (const v of arr) if (!s.has(v)) { s.add(v); out.push(v); } return out; }
function packToBcc(all) {
  const uniqd = uniq(all);
  if (uniqd.length <= 1) return { to: uniqd[0] || undefined, bcc: undefined };
  return { to: uniqd[0], bcc: uniqd.slice(1) };
}

/* ===================== EMAIL TEMPLATE (HERO-FIRST, TRANSPARENT) ===================== */
function _esc(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
function _bullets(s) {
  const parts = String(s || '')
    .split(/\r?\n|[;•]\s*/g)
    .map(x => x.trim())
    .filter(Boolean);
  if (!parts.length) return '';
  return `<ul style="margin:8px 0 0 20px;padding:0">
    ${parts.map(li => `<li style="margin:6px 0;line-height:1.45">${_esc(li)}</li>`).join('')}
  </ul>`;
}
function _firstImage(item) {
  const raw =
    item?.chartUrl ||
    item?.chartImage ||
    item?.imageUrl ||
    (Array.isArray(item?.media) && item.media[0] && item.media[0].url) ||
    '';
  return absUrl(raw);
}
function ideaDeepLink(item) {
  const base = `${SITE_URL}/trading-dashboard`;
  const id   = String(item?.id || '').trim();
  if (!id) return base;
  const q    = `?idea=${encodeURIComponent(id)}&utm_source=email&utm_medium=notification&utm_campaign=${encodeURIComponent(item?.symbol ? 'idea-'+item.symbol : 'idea')}`;
  return `${base}${q}`;
}

/* Theme + layout engine */
function _themeVars() {
  const t = (EMAIL_THEME || 'clear').toLowerCase();
  const layout = EMAIL_LAYOUT || 'hero-first';
  const isWhite = t === 'white';
  const isClear = t === 'clear' || t === 'transparent' || t === 'none' || t === 'minimal';
  const isDark  = !isWhite && !isClear;

  const bodyBg   = EMAIL_BODY_BG || (isWhite ? '#ffffff' : (isClear ? '' : '#0a0f1a'));
  const wrapBg   = isWhite ? '#ffffff' : (isClear ? 'transparent' : '#0b1220');
  const wrapBor  = isWhite ? '1px solid rgba(0,0,0,0.06)' : (isClear ? 'none' : '1px solid rgba(255,255,255,0.06)');
  const text     = isWhite ? '#1a2233' : (isClear ? '#0b1220' : '#e8eefc');
  const title    = isWhite ? '#0b1220' : (isClear ? '#0b1220' : '#f5f8ff');
  const badgeBg  = isWhite ? 'rgba(0,0,0,0.05)' : (isClear ? 'rgba(0,0,0,0.05)' : 'rgba(255,255,255,0.06)');
  const badgeTx  = isWhite ? '#0b1220' : (isClear ? '#0b1220' : '#dce6ff');
  const pillBg   = isWhite ? 'rgba(0,122,255,0.10)' : (isClear ? 'rgba(0,208,255,0.10)' : '#0fd5ff12');
  const pillBor  = isWhite ? '1px solid rgba(0,122,255,0.25)' : (isClear ? '1px solid rgba(0,208,255,0.35)' : '1px solid #0fd5ff38');
  const pillTx   = isWhite ? '#08467a' : (isClear ? '#005a6a' : '#9be8ff');
  const secBg    = isWhite ? 'rgba(0,0,0,0.03)' : (isClear ? 'rgba(0,0,0,0.03)' : 'rgba(255,255,255,0.03)');
  const secBor   = isWhite ? '1px dashed rgba(0,0,0,0.08)' : (isClear ? '1px dashed rgba(0,0,0,0.08)' : '1px dashed rgba(255,255,255,0.08)');
  const footBor  = isWhite ? '1px solid rgba(0,0,0,0.06)' : (isClear ? '1px solid rgba(0,0,0,0.06)' : '1px solid rgba(255,255,255,0.06)');
  const footTx   = isWhite ? '#44526e' : (isClear ? '#3a4358' : '#8fa0c6');
  const visitTx  = isWhite ? '#164a76' : (isClear ? '#164a76' : '#cfe8ff');
  const visitBor = isWhite ? '1px solid rgba(0,0,0,0.12)' : (isClear ? '1px solid rgba(0,0,0,0.14)' : '1px solid rgba(255,255,255,0.14)');
  const cardBor  = isWhite ? 'rgba(0,0,0,0.08)' : (isClear ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.08)');

  return { layout, bodyBg, wrapBg, wrapBor, text, title, badgeBg, badgeTx, pillBg, pillBor, pillTx, secBg, secBor, footBor, footTx, visitTx, visitBor, cardBor, isClear, isWhite, isDark };
}

/* Shell: Chart first → Brand row (logo + name) → Title → Symbol pill → Sections → CTAs */
/* Transparent/clear keeps the page background empty. */
function _emailShell({ preheader, title, symbol, levelsHTML, planHTML, imgUrl, ctaHref, ctaText, badgeText }) {
  const v = _themeVars();
  const logo = absUrl(LOGO_URL);
  const brand = MAIL_FROM_NAME || 'Trade Chart Patterns Like The Pros';
  const hasImg = !!imgUrl;
  const showHeroFirst = (v.layout === 'hero-first');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="x-apple-disable-message-reformatting">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${_esc(title)}</title>
</head>
<body style="margin:0;padding:0;${v.bodyBg ? `background:${v.bodyBg};` : ''}">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">
    ${_esc(preheader || title)}
  </div>

  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="${v.isDark ? 'background:#0a0f1a;' : ''}padding:24px 14px">
    <tr><td align="center">

      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:740px;background:${v.wrapBg};${v.wrapBor ? `border:${v.wrapBor};` : ''}border-radius:${v.isClear ? '0' : '18px'};overflow:hidden;box-shadow:${v.isWhite ? '0 6px 26px rgba(14,26,57,0.08)' : (v.isClear ? 'none' : '0 6px 28px rgba(0,0,0,0.35)')}">

        ${showHeroFirst && hasImg ? `
        <tr>
          <td style="padding:0">
            <img src="${_esc(imgUrl)}" alt="Chart" width="740"
                 style="display:block;width:100%;max-width:740px;height:auto;${v.isClear ? '' : `border-bottom:1px solid ${v.cardBor};`}">
          </td>
        </tr>` : ''}

        <tr>
          <td style="padding:18px 22px 4px 22px;color:${v.text};font-family:Inter,Segoe UI,Roboto,Arial,sans-serif;">
            ${!showHeroFirst && hasImg ? `
              <div style="margin-bottom:12px">
                <img src="${_esc(imgUrl)}" alt="Chart" width="740"
                     style="display:block;width:100%;max-width:740px;height:auto;border-radius:14px;border:1px solid ${v.cardBor}">
              </div>` : ''}

            <!-- Brand row (logo + brand) -->
            <div style="display:flex;align-items:center;gap:10px;margin:0 0 8px 0">
              <a href="${_esc(SITE_URL)}" target="_blank" rel="noopener" style="text-decoration:none;display:inline-flex;align-items:center;gap:10px">
                <img src="${_esc(logo)}" alt="${_esc(brand)}" width="28" height="28"
                     style="display:block;border-radius:8px;width:28px;height:28px;">
                <span style="color:${v.text};font-weight:700;font-size:14px">${_esc(brand)}</span>
              </a>
              ${badgeText ? `<span style="margin-left:auto;display:inline-block;padding:6px 10px;border-radius:999px;background:${v.badgeBg};color:${v.badgeTx};font-weight:700;font-size:11px;letter-spacing:.35px;text-transform:uppercase;">${_esc(badgeText)}</span>` : ''}
            </div>

            <h1 style="margin:0 0 10px 0;font-size:24px;line-height:1.28;color:${v.title};font-weight:850;">
              ${_esc(title)}
            </h1>

            ${symbol ? `
              <div style="margin:6px 0 14px 0">
                <span style="display:inline-block;background:${v.pillBg};color:${v.pillTx};border:${v.pillBor};
                            padding:6px 10px;border-radius:999px;font-weight:800;font-size:12px;letter-spacing:.2px;">
                  ${_esc(symbol)}
                </span>
              </div>` : ''}

            ${levelsHTML ? `
              <div style="margin:12px 0 10px 0;padding:12px 14px;border-radius:12px;background:${v.secBg};border:${v.secBor};">
                <div style="font-size:12px;color:${v.isWhite ? '#5b6a8a' : '#99a6c7'};letter-spacing:.3px;text-transform:uppercase;font-weight:800;margin-bottom:6px">Levels</div>
                ${levelsHTML}
              </div>` : ''}

            ${planHTML ? `
              <div style="margin:12px 0 0 0;">
                <div style="font-size:12px;color:${v.isWhite ? '#5b6a8a' : '#99a6c7'};letter-spacing:.3px;text-transform:uppercase;font-weight:800;margin-bottom:6px">Plan</div>
                ${planHTML}
              </div>` : ''}

          </td>
        </tr>

        <tr>
          <td align="left" style="padding:10px 22px 22px 22px">
            <table role="presentation" cellpadding="0" cellspacing="0"><tr>
              <td>
                <a href="${_esc(ctaHref)}"
                   style="display:inline-block;padding:12px 18px;background:#00d0ff;color:#001018;text-decoration:none;border-radius:999px;font-weight:900;font-size:14px"
                   target="_blank" rel="noopener">${_esc(ctaText || 'Open on Dashboard')}</a>
              </td>
              <td width="12"></td>
              <td>
                <a href="${_esc(SITE_URL)}"
                   style="display:inline-block;padding:12px 16px;background:transparent;color:${v.visitTx};text-decoration:none;border-radius:999px;font-weight:800;font-size:14px;border:${v.visitBor}"
                   target="_blank" rel="noopener">Visit Site</a>
              </td>
            </tr></table>
          </td>
        </tr>

        <tr>
          <td style="padding:14px 22px 20px 22px;color:${v.footTx};font-size:12px;${v.footBor ? `border-top:${v.footBor};` : ''}">
            <div style="opacity:.9">You’re receiving this update from ${_esc(brand)}.</div>
            <div style="opacity:.65;margin-top:6px">This notification links to your dashboard and will <em>auto-scroll</em> to the idea.</div>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;
}

/* Post + Signal wrappers */
function emailTemplatePost(item) {
  const title   = item?.title || 'New Idea';
  const symbol  = item?.symbol || '';
  const levels  = _bullets(item?.levelText || item?.levels || '');
  const plan    = _bullets(item?.take || item?.content || '');
  const imgUrl  = _firstImage(item);
  const deepURL = ideaDeepLink(item);
  const pre     = `${symbol ? symbol + ' • ' : ''}${title}`;
  return _emailShell({
    preheader: `New Idea — ${pre}`,
    title,
    symbol,
    levelsHTML: levels,
    planHTML: plan,
    imgUrl,
    ctaHref: deepURL,
    ctaText: 'Open on Dashboard',
    badgeText: '🔔 New Idea'
  });
}
function emailTemplateSignal(item) {
  const title   = item?.title || 'New Signal';
  const symbol  = item?.symbol || '';
  const levels  = _bullets(item?.levelText || '');
  const plan    = _bullets(item?.take || '');
  const imgUrl  = _firstImage(item);
  const deepURL = ideaDeepLink(item);
  const pre     = `${symbol ? symbol + ' • ' : ''}${title}`;
  return _emailShell({
    preheader: `Signal — ${pre}`,
    title,
    symbol,
    levelsHTML: levels,
    planHTML: plan,
    imgUrl,
    ctaHref: deepURL,
    ctaText: 'View Signal',
    badgeText: '⚡️ Signal'
  });
}

/* Recipient resolution with admin fallback */
async function resolveRecipients(reqBody) {
  const forced = splitEmails(EMAIL_FORCE_ALL_TO);
  if (forced.length) return { list: forced, note: 'forced' };

  const subs = await loadSubs().catch(() => blankSubs());
  const subList = uniq((subs?.subs || [])
    .map(s => String(s.email || '').toLowerCase())
    .filter(e => EMAIL_RX.test(e)));
  if (subList.length) return { list: subList, note: 'subscribers' };

  const actorEmail = String(reqBody?.actor?.email || reqBody?.actorEmail || '').trim().toLowerCase();
  if (EMAIL_RX.test(actorEmail)) return { list: [actorEmail], note: 'actor' };

  const admins = (EMAIL_BCC_ADMIN || []).filter(e => EMAIL_RX.test(e));
  if (admins.length) return { list: admins, note: 'admin-fallback' };

  return { list: [], note: 'none' };
}

/* SMTP first, then Mailjet HTTP fallback (v3.1) */
async function sendEmailBlast({ subject, html, toList }) {
  try{
    const tx = getTransporter();
    if (tx && toList.length){
      const from    = fromHeader();
      const replyTo = EMAIL_REPLY_TO || undefined;
      const adminBcc = EMAIL_BCC_ADMIN;
      const { to, bcc } = packToBcc(toList);
      const finalBcc = uniq([...(bcc || []), ...adminBcc]);
      const info = await tx.sendMail({ from, to: to || undefined, bcc: finalBcc.length ? finalBcc : undefined, subject, html, replyTo });
      return { sent: toList.length, messageId: info?.messageId || '', via:'smtp' };
    }
  }catch(e){
    console.warn('[email][smtp] failed, trying HTTP fallback:', e?.message || e);
  }
  if (!(SMTP_USER && SMTP_PASS)) throw new Error('No SMTP creds for HTTP fallback');
  if (!toList.length) return { sent:0, via:'http' };

  const payload = {
    Messages: [{
      From: { Email: (MAIL_FROM || SMTP_USER), Name: MAIL_FROM_NAME || 'Notifier' },
      To: toList.map(e => ({ Email: e })),
      Subject: subject,
      HTMLPart: html,
      Headers: EMAIL_REPLY_TO ? { 'Reply-To': EMAIL_REPLY_TO } : undefined
    }]
  };
  const auth = Buffer.from(`${SMTP_USER}:${SMTP_PASS}`).toString('base64');
  const body = JSON.stringify(payload);

  const httpResult = await new Promise((resolve, reject)=>{
    const req = https.request({
      method: 'POST',
      host: 'api.mailjet.com',
      path: '/v3.1/send',
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      },
      timeout: 12000
    }, res=>{
      let data=''; res.on('data', c=> data+=c);
      res.on('end', ()=>{
        if (res.statusCode >= 200 && res.statusCode < 300) return resolve({ ok:true, status: res.statusCode, body: data });
        return reject(new Error(`Mailjet HTTP ${res.statusCode} ${data.slice(0,200)}`));
      });
    });
    req.on('timeout', ()=>{ req.destroy(new Error('Mailjet HTTP timeout')); });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
  return { sent: toList.length, via: 'http', raw: httpResult.status };
}

/* ---------------------- EMAIL ROUTES ------------- */
app.post('/email/post', requireAuth, async (req, res) => {
  try{
    const item = req.body?.item || req.body?.data || null;
    if (!item) return err(res, 400, 'item required');

    console.log('[email][post] imgUrl=', _firstImage(item));
    const { list, note } = await resolveRecipients(req.body || {});
    console.log('[email][post] recipients:', note, list.length, list.slice(0, 3));
    if (!list.length) return ok(res, { ok:true, sent:0, info:'no recipients (set EMAIL_FORCE_ALL_TO or add subscribers)' });

    const subject = `🔔 New Idea: ${item.symbol ? `${item.symbol} — `:''}${item.title||'Update'}`;
    const html = emailTemplatePost(item);
    const result = await sendEmailBlast({ subject, html, toList:list });
    ok(res, { ok:true, sent: result.sent, mode: note, via: result.via });
  }catch(e){ err(res, 500, e.message || 'Email failed'); }
});

app.post('/email/signal', requireAuth, async (req, res) => {
  try{
    const item = req.body?.item || req.body?.data || null;
    if (!item) return err(res, 400, 'item required');

    console.log('[email][signal] imgUrl=', _firstImage(item));
    const { list, note } = await resolveRecipients(req.body || {});
    console.log('[email][signal] recipients:', note, list.length, list.slice(0, 3));
    if (!list.length) return ok(res, { ok:true, sent:0, info:'no recipients (set EMAIL_FORCE_ALL_TO or add subscribers)' });

    const subject = `⚡️ Signal: ${item.symbol ? `${item.symbol} — `:''}${item.title||'Update'}`;
    const html = emailTemplateSignal(item);
    const result = await sendEmailBlast({ subject, html, toList:list });
    ok(res, { ok:true, sent: result.sent, mode: note, via: result.via });
  }catch(e){ err(res, 500, e.message || 'Email failed'); }
});

/* ---------------------- DEBUG EMAIL -------------- */
app.get('/debug/email/status', requireAuth, (_req, res) => {
  ok(res, {
    smtp: {
      ready: !!(SMTP_HOST && SMTP_PORT && (SMTP_USER ? SMTP_PASS : true)),
      host: SMTP_HOST || null,
      port: SMTP_PORT || null,
      secure: SMTP_SECURE,
      hasUser: !!SMTP_USER,
      hasPass: !!SMTP_PASS,
    },
    branding: {
      siteUrl: SITE_URL,
      logo: LOGO_URL,
      from: fromHeader(),
      bccAdmins: EMAIL_BCC_ADMIN,
      forceTo: EMAIL_FORCE_ALL_TO || null,
      assetBaseUrl: ASSET_BASE_URL,
      uploadsPublicBaseUrl: UPLOADS_PUBLIC_BASE_URL,
      emailTheme: EMAIL_THEME,
      emailLayout: EMAIL_LAYOUT,
      emailBodyBg: EMAIL_BODY_BG || null
    }
  });
});

app.post('/debug/email/test', requireAuth, async (req, res) => {
  try {
    const rawTo = req.query.to || req.body?.to || EMAIL_FORCE_ALL_TO || (EMAIL_BCC_ADMIN || []).join(',');
    const toList = splitEmails(rawTo);
    if (!toList.length) return err(res, 400, 'provide ?to= or set EMAIL_FORCE_ALL_TO or EMAIL_BCC_ADMIN');

    const imgParam = req.query.img || req.body?.img || '';
    const imgUrl   = absUrl(imgParam);

    const html = _emailShell({
      preheader: 'Test notification from Ideas Backend',
      title: `Test Email — ${EMAIL_THEME}`,
      symbol: 'OANDA:TEST',
      levelsHTML: _bullets('PRZ 2345–2351; T1 2321; SL 2359'),
      planHTML: _bullets('Short on rejection; Risk ≤1%'),
      imgUrl,
      ctaHref: `${SITE_URL}/trading-dashboard`,
      ctaText: 'Open Dashboard',
      badgeText: 'Test'
    });

    const result = await sendEmailBlast({
      subject: 'Test — Ideas Backend Email',
      html,
      toList
    });
    ok(res, { ok:true, sent: result.sent, via: result.via, img: imgUrl });
  } catch (e) {
    err(res, 500, e.message || 'Test email failed');
  }
});

/* ----------------------- UPLOAD ------------------- */
app.post('/upload', requireAuth, (req, res) => {
  if (!upload) return err(res, 500, 'Upload not initialized');
  upload.single('file')(req, res, e => {
    if (e) return err(res, 400, e.message || 'Upload failed');
    const file = req.file;
    if (!file) return err(res, 400, 'No file');
    ok(res, { url: `/uploads/${file.filename}` });
  });
});

/* ----------------------- START -------------------- */
async function start() {
  await ensureDir(DATA_DIR);
  await ensureDir(UPLOAD_DIR);
  buildMulter();
  app.listen(PORT, () => {
    console.log(`[tcpp-ideas-backend] listening on :${PORT} env=${NODE_ENV} data=${DATA_FILE}`);
    console.log(`SSE: /events  CRUD: /ideas  Latest: /ideas/latest  Upload: /upload  Subs: /subscribe`);
    console.log(`Email: /email/post, /email/signal  Debug: /debug/email/status, /debug/email/test`);
  });
}
start();
