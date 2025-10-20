/* server/server.cjs
 * TCPP Ideas Backend (Express) + Email + Subscribers
 * - Storage: JSON files on disk (/data)
 * - Auth: All writes & /email/* require Bearer API_TOKEN. SSE accepts ?token=
 * - SSE events: idea:new, idea:update, idea:delete, comments:update, likes:update
 */

'use strict';

const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const nodemailer = require('nodemailer');
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
const MAIL_FROM         = process.env.MAIL_FROM || '';                    // e.g. "noreply@domain.com"
const MAIL_FROM_NAME    = process.env.MAIL_FROM_NAME || 'Trade Chart Patterns Like The Pros';
const EMAIL_FROM_INLINE = process.env.EMAIL_FROM || '';                   // e.g. "Brand <noreply@domain.com>"
const EMAIL_REPLY_TO    = (process.env.EMAIL_REPLY_TO || '').trim();
const EMAIL_BCC_ADMIN   = (process.env.EMAIL_BCC_ADMIN || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const EMAIL_FORCE_ALL_TO = (process.env.EMAIL_FORCE_ALL_TO || '').trim().toLowerCase(); // for staging/tests

/* Branding */
const SITE_NAME   = process.env.SITE_NAME   || 'Trade Chart Patterns — Pro';
const SITE_URL    = process.env.SITE_URL    || 'https://www.tradechartpatternslikethepros.com';
const LOGO_URL    = process.env.EMAIL_LOGO_URL
  || process.env.LOGO_URL
  || 'https://static.wixstatic.com/media/e09166_90ddc4c3b20d4b4b83461681f85d9dd8~mv2.png';

/* ---------------------- UTIL ---------------------- */
const nowISO = () => new Date().toISOString();
async function ensureDir(p) { await fsp.mkdir(p, { recursive: true }).catch(() => {}); }
function ok(res, data) { res.json(data); }
function err(res, code, msg) { res.status(code).json({ status:'error', code, message: msg || 'Error' }); }

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
function requireAuth(req, res, next) {
  if (!API_TOKEN) return next(); // allowed, but set API_TOKEN in production
  const tok = readBearer(req);
  if (tok !== API_TOKEN) return err(res, 401, 'Unauthorized');
  next();
}
function sseAuthOK(req) {
  if (!API_TOKEN) return true;
  const tok = String(req.query.token || '');
  return tok === API_TOKEN;
}

/* ----------------------- SSE ---------------------- */
const clients = new Set(); // { id, res, ping }

function sseSend(event, data) {
  const line = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of clients) {
    try { c.res.write(line); } catch { /* ignore */ }
  }
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
    // Allow Wix + filesusr wildcards explicitly
    if (host.endsWith('.wixsite.com')) return protocol === 'https:';
    if (host.endsWith('.filesusr.com')) return protocol === 'https:';

    // Support entries like "https://*.example.com"
    for (const pat of CORS_ORIGINS) {
      if (!pat.includes('*')) continue;
      const m = pat.match(/^https?:\/\/\*\.(.+)$/i);
      if (m && host.endsWith(m[1])) return true;
    }

    // Local dev convenience
    if (/^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(host)) return true;
  } catch { /* fall through */ }
  return false;
}
app.use(cors({
  origin: (origin, cb) => cb(null, isOriginAllowed(origin)),
  credentials: false
}));

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

  // greet + keepalive pings
  sseSendTo(res, 'hello', { id, at: nowISO() });
  client.ping = setInterval(() => {
    try { res.write(': ping\n\n'); } catch { /* ignore */ }
  }, 25000);

  req.on('close', () => {
    clearInterval(client.ping);
    clients.delete(client);
  });
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
    imageUrl: String(input.imageUrl || ''),
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
    link: it.link, imageUrl: it.imageUrl, media: it.media,
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
  ok(res, { items, ideas: items }); // compat
});

app.get('/ideas/:id', async (req, res) => {
  const db = await loadDB();
  const it = db.ideas.find(x => String(x.id) === String(req.params.id));
  if (!it) return err(res, 404, 'Not found');
  const pub = ideaPublic(it);
  ok(res, { item: pub, idea: pub }); // compat
});

app.post('/ideas', requireAuth, async (req, res) => {
  const db = await loadDB();
  const it = normalizeIdea(req.body || {});
  db.ideas.unshift(it);
  await saveDB(db);
  const pub = ideaPublic(it);
  sseSend('idea:new', pub);
  ok(res, { item: pub, idea: pub }); // compat
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
    media: Array.isArray(req.body.media) ? req.body.media : it.media,
    updatedAt: nowISO()
  });

  await saveDB(db);
  const pub = ideaPublic(it);
  sseSend('idea:update', pub);
  ok(res, { item: pub, idea: pub }); // compat
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
app.put('/ideas/:id/likes', requireAuth, async (req, res) => {
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
});

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

/* ------------------ SUBSCRIBERS ------------------- */
app.get('/subscribers', requireAuth, async (_req, res) => {
  const s = await loadSubs();
  ok(res, { count: s.subs.length, items: s.subs });
});

app.post('/subscribe', requireAuth, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const name  = String(req.body?.name || 'Member').trim();
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return err(res, 400, 'Valid email required');

  const s = await loadSubs();
  const exists = (s.subs || []).find(x => x.email === email);
  if (!exists) (s.subs ||= []).push({ email, name, createdAt: nowISO(), status: 'active' });
  await saveSubs(s);
  ok(res, { ok: true });
});

app.post('/unsubscribe', requireAuth, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const s = await loadSubs();
  s.subs = (s.subs || []).filter(x => x.email !== email);
  await saveSubs(s);
  ok(res, { ok: true });
});

/* --------------------- EMAIL ---------------------- */
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
    auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined
  });
  return transporter;
}

/* Construct "from" */
function fromHeader() {
  if (EMAIL_FROM_INLINE) return EMAIL_FROM_INLINE; // "Brand <noreply@…>"
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

function emailTemplatePost(item) {
  const title  = item.title || 'New idea';
  const symbol = item.symbol || '';
  const levels = item.levelText || '';
  const take   = item.take || '';
  const link   = item.link || '';
  const imgUrl = item.imageUrl || (Array.isArray(item.media) && item.media[0] && item.media[0].url) || '';
  const viewUrl = link || `${SITE_URL}`;
  return `
  <div style="font-family:Inter,Arial,Helvetica,sans-serif;max-width:660px;margin:0 auto;color:#0b1220">
    <div style="padding:18px 0;text-align:center">
      <img src="${LOGO_URL}" alt="${SITE_NAME}" style="height:42px"/>
    </div>
    <div style="background:#0b1220;color:#e9eefb;border-radius:14px;padding:18px;border:1px solid rgba(255,255,255,.08)">
      <div style="font-size:14px;opacity:.8;margin-bottom:8px">${SITE_NAME}</div>
      <h2 style="margin:0 0 8px 0">${title}</h2>
      ${symbol ? `<div style="margin:4px 0 12px 0;font-weight:700">${symbol}</div>` : ''}
      ${levels ? `<div style="margin:8px 0 12px 0"><strong>Levels:</strong><br>${levels.replace(/;/g,'; ')}</div>`:''}
      ${take   ? `<div style="margin:8px 0 12px 0"><strong>Plan:</strong><br>${take}</div>`:''}
      ${imgUrl ? `<div style="margin:10px 0"><img src="${imgUrl}" alt="Chart" style="max-width:100%;border-radius:10px;border:1px solid rgba(255,255,255,.12)"/></div>`:''}
      <a href="${viewUrl}" style="display:inline-block;margin-top:4px;padding:10px 14px;background:#00d0ff;color:#001018;text-decoration:none;border-radius:999px;font-weight:800">Open idea</a>
    </div>
    <div style="text-align:center;font-size:12px;color:#445;opacity:.8;margin-top:12px">
      You’re receiving this update from ${SITE_NAME}.
    </div>
  </div>`;
}
function emailTemplateSignal(item) {
  const title = item.title || 'New signal';
  const base  = emailTemplatePost(item);
  return base.replace('New idea:', 'Signal:');
}

/* Recipient resolution:
 * 1) If EMAIL_FORCE_ALL_TO set → send only there (great for testing)
 * 2) Else if subscribers exist → send to subscribers
 * 3) Else if actor.email exists in request → send to actor
 * Always BCC admin(s) if configured
 */
async function resolveRecipients(reqBody) {
  const forced = splitEmails(EMAIL_FORCE_ALL_TO);
  if (forced.length) return { list: forced, note: 'forced' };

  const subs = await loadSubs().catch(() => blankSubs());
  const subList = uniq((subs?.subs || [])
    .map(s => String(s.email || '').toLowerCase())
    .filter(e => EMAIL_RX.test(e)));

  if (subList.length) return { list: subList, note: 'subscribers' };

  const actorEmail = String(reqBody?.actor?.email || '').trim().toLowerCase();
  if (EMAIL_RX.test(actorEmail)) return { list: [actorEmail], note: 'actor' };

  return { list: [], note: 'none' };
}

async function sendEmailBlast({ subject, html, toList }) {
  const tx = getTransporter();
  if (!tx) throw new Error('SMTP not configured');

  if (!toList.length) return { sent: 0 };

  const from = fromHeader();
  const replyTo = EMAIL_REPLY_TO || undefined;

  const adminBcc = EMAIL_BCC_ADMIN;
  const { to, bcc } = packToBcc(toList);
  const finalBcc = uniq([...(bcc || []), ...adminBcc]);

  const info = await tx.sendMail({
    from,
    to: to || undefined,
    bcc: finalBcc.length ? finalBcc : undefined,
    subject,
    html,
    replyTo
  });

  return { sent: toList.length, messageId: info?.messageId || '' };
}

/* ---------------------- EMAIL ROUTES ------------- */
app.post('/email/post', requireAuth, async (req, res) => {
  try{
    if (!smtpReady()) return err(res, 501, 'SMTP not configured');

    const item = req.body?.item || req.body?.data || null;
    if (!item) return err(res, 400, 'item required');

    const { list, note } = await resolveRecipients(req.body || {});
    if (!list.length) return ok(res, { ok:true, sent:0, info:'no recipients' });

    const subject = `New idea: ${item.symbol ? `${item.symbol} — `:''}${item.title||'Update'}`;
    const html = emailTemplatePost(item);

    const result = await sendEmailBlast({ subject, html, toList:list });
    ok(res, { ok:true, sent: result.sent, mode: note });
  }catch(e){ err(res, 500, e.message || 'Email failed'); }
});

app.post('/email/signal', requireAuth, async (req, res) => {
  try{
    if (!smtpReady()) return err(res, 501, 'SMTP not configured');

    const item = req.body?.item || req.body?.data || null;
    if (!item) return err(res, 400, 'item required');

    const { list, note } = await resolveRecipients(req.body || {});
    if (!list.length) return ok(res, { ok:true, sent:0, info:'no recipients' });

    const subject = `Signal: ${item.symbol ? `${item.symbol} — `:''}${item.title||'Update'}`;
    const html = emailTemplateSignal(item);

    const result = await sendEmailBlast({ subject, html, toList:list });
    ok(res, { ok:true, sent: result.sent, mode: note });
  }catch(e){ err(res, 500, e.message || 'Email failed'); }
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
    console.log(`SSE: /events  CRUD: /ideas  Latest: /ideas/latest  Upload: /upload  Subs: /subscribe  Email: /email/post,/email/signal`);
  });
}
start();
