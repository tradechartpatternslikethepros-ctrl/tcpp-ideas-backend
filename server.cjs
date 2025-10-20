/* server.cjs
 * TCPP Ideas Backend (Express) + Email + Subscribers
 * - Storage: JSON files on disk (/data)
 * - Auth: All writes & /email/* require API_TOKEN via Bearer header OR ?token=
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
function readQueryToken(req) {
  return (req.query && String(req.query.token || '').trim()) || '';
}
function requireAuth(req, res, next) {
  if (!API_TOKEN) return next(); // allowed, but set API_TOKEN in production
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
      if (m && host.endsWith(m[1])) return protocol === 'https:';
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

/* ------------------ SUBSCRIBERS ------------------- */
app.get('/subscribers', requireAuth, async (_req, res) => {
  const s = await loadSubs();
  ok(res, { count: s.subs.length, items: s.subs });
});

async function subscribeCore(email, name) {
  const s = await loadSubs();
  const exists = (s.subs || []).find(x => x.email === email);
  if (!exists) (s.subs ||= []).push({ email, name, createdAt: nowISO(), status: 'active' });
  await saveSubs(s);
  return { ok: true };
}
async function unsubscribeCore(email) {
  const s = await loadSubs();
  s.subs = (s.subs || []).filter(x => x.email !== email);
  await saveSubs(s);
  return { ok: true };
}

app.post('/subscribe', requireAuth, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const name  = String(req.body?.name || 'Member').trim();
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return err(res, 400, 'Valid email required');
  const out = await subscribeCore(email, name);
  ok(res, out);
});
app.post('/api/subscribe', requireAuth, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const name  = String(req.body?.name || 'Member').trim();
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return err(res, 400, 'Valid email required');
  const out = await subscribeCore(email, name);
  ok(res, out);
});
app.post('/email/subscribe', requireAuth, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const name  = String(req.body?.name || 'Member').trim();
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return err(res, 400, 'Valid email required');
  const out = await subscribeCore(email, name);
  ok(res, out);
});

app.post('/unsubscribe', requireAuth, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!email) return err(res, 400, 'email required');
  const out = await unsubscribeCore(email);
  ok(res, out);
});
app.post('/api/unsubscribe', requireAuth, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!email) return err(res, 400, 'email required');
  const out = await unsubscribeCore(email);
  ok(res, out);
});
app.post('/email/unsubscribe', requireAuth, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (!email) return err(res, 400, 'email required');
  const out = await unsubscribeCore(email);
  ok(res, out);
});

/* --------------------- EMAIL (SMTP + HTTP fallback) --------------------- */
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
    secure: SMTP_SECURE,               // true => 465 SSL; false => 587 STARTTLS
    auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000
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

/* ===================== EMAIL TEMPLATE (PREMIUM) ===================== */

/** Escape HTML (safe text in emails) */
function _esc(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Turn "a; b; c" or newlines into a compact bullet list */
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

/** Prefer item.imageUrl, else first media url */
function _firstImage(item) {
  return item?.imageUrl ||
    (Array.isArray(item?.media) && item.media[0] && item.media[0].url) || '';
}

/** Build deep link to dashboard that scrolls to the idea */
function ideaDeepLink(item) {
  const base = `${SITE_URL}/trading-dashboard`;
  const id   = String(item?.id || '').trim();
  if (!id) return base;
  const q    = `?idea=${encodeURIComponent(id)}&utm_source=email&utm_medium=notification&utm_campaign=${encodeURIComponent(item?.symbol ? 'idea-'+item.symbol : 'idea')}`;
  return `${base}${q}`;
}

/** Premium, minimalist email shell */
function _emailShell({ preheader, title, symbol, levelsHTML, planHTML, imgUrl, ctaHref, ctaText, badgeText }) {
  const logo = LOGO_URL;
  const brand = MAIL_FROM_NAME || 'Trade Chart Patterns Like The Pros';
  const hasImg = !!imgUrl;

  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="x-apple-disable-message-reformatting">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${_esc(title)}</title>
  </head>
  <body style="margin:0;padding:0;background:#0a0f1a;">
    <!-- Preheader (hidden) -->
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">
      ${_esc(preheader || title)}
    </div>

    <!-- Outer wrapper -->
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0a0f1a;padding:24px 14px">
      <tr>
        <td align="center">

          <!-- Container -->
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:680px;background:#0b1220;border-radius:18px;border:1px solid rgba(255,255,255,0.06);box-shadow:0 6px 28px rgba(0,0,0,0.35);overflow:hidden">
            <!-- Header -->
            <tr>
              <td align="center" style="padding:22px 20px 8px 20px;background:linear-gradient(180deg,rgba(255,255,255,0.02),rgba(255,255,255,0));">
                <a href="${_esc(SITE_URL)}" style="text-decoration:none;display:inline-block" target="_blank" rel="noopener">
                  <img src="${_esc(logo)}" alt="${_esc(brand)}" width="220" style="display:block;width:220px;max-width:220px;height:auto;">
                </a>
                ${badgeText ? `
                <div style="margin:14px auto 0 auto;display:inline-block;padding:6px 12px;border-radius:999px;
                            background:rgba(255,255,255,0.06);color:#dce6ff;font-weight:700;font-size:12px;letter-spacing:.35px;
                            text-transform:uppercase;">
                  ${_esc(badgeText)}
                </div>` : ''}
              </td>
            </tr>

            <!-- Hero image (optional) -->
            ${hasImg ? `
            <tr>
              <td style="padding:8px 20px 0 20px">
                <img src="${_esc(imgUrl)}" alt="Chart" width="640"
                     style="display:block;width:100%;max-width:640px;height:auto;border-radius:14px;
                            border:1px solid rgba(255,255,255,0.08);">
              </td>
            </tr>` : ''}

            <!-- Content -->
            <tr>
              <td style="padding:18px 20px 8px 20px;color:#e8eefc;font-family:Inter,Segoe UI,Roboto,Arial,sans-serif;">
                ${symbol ? `
                  <div style="margin:2px 0 10px 0">
                    <span style="display:inline-block;background:#0fd5ff12;color:#9be8ff;border:1px solid #0fd5ff38;
                                padding:6px 10px;border-radius:999px;font-weight:700;font-size:12px;letter-spacing:.2px;">
                      ${_esc(symbol)}
                    </span>
                  </div>` : ''}

                <h1 style="margin:0 0 8px 0;font-size:22px;line-height:1.3;color:#f5f8ff;font-weight:800;">
                  ${_esc(title)}
                </h1>

                ${levelsHTML ? `
                  <div style="margin:12px 0 10px 0;padding:12px 14px;border-radius:12px;background:rgba(255,255,255,0.03);
                              border:1px dashed rgba(255,255,255,0.08);">
                    <div style="font-size:12px;color:#99a6c7;letter-spacing:.3px;text-transform:uppercase;font-weight:700;margin-bottom:6px">
                      Levels
                    </div>
                    ${levelsHTML}
                  </div>` : ''}

                ${planHTML ? `
                  <div style="margin:12px 0 0 0;">
                    <div style="font-size:12px;color:#99a6c7;letter-spacing:.3px;text-transform:uppercase;font-weight:700;margin-bottom:6px">
                      Plan
                    </div>
                    ${planHTML}
                  </div>` : ''}
              </td>
            </tr>

            <!-- CTA -->
            <tr>
              <td align="left" style="padding:8px 20px 24px 20px">
                <table role="presentation" cellpadding="0" cellspacing="0">
                  <tr>
                    <td>
                      <a href="${_esc(ctaHref)}"
                         style="display:inline-block;padding:12px 18px;background:#00d0ff;color:#001018;
                                text-decoration:none;border-radius:999px;font-weight:900;font-size:14px"
                         target="_blank" rel="noopener">
                        ${_esc(ctaText || 'Open on Dashboard')}
                      </a>
                    </td>
                    <td width="12"></td>
                    <td>
                      <a href="${_esc(SITE_URL)}"
                         style="display:inline-block;padding:12px 16px;background:transparent;color:#cfe8ff;
                                text-decoration:none;border-radius:999px;font-weight:700;font-size:14px;
                                border:1px solid rgba(255,255,255,0.14)"
                         target="_blank" rel="noopener">
                        Visit Site
                      </a>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <!-- Footer -->
            <tr>
              <td style="padding:14px 20px 20px 20px;color:#8fa0c6;font-size:12px;border-top:1px solid rgba(255,255,255,0.06);">
                <div style="opacity:.9">
                  You’re receiving this update from ${_esc(brand)}.
                </div>
                <div style="opacity:.6;margin-top:6px">
                  This notification links to your dashboard and will <em>auto-scroll</em> to the idea.
                </div>
              </td>
            </tr>

          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`;
}

/** Build a premium "Idea" email */
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

/** Build a premium "Signal" email */
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

/* SMTP first, then Mailjet HTTP fallback (v3.1) */
async function sendEmailBlast({ subject, html, toList }) {
  // Try SMTP first
  try{
    const tx = getTransporter();
    if (tx && toList.length){
      const from    = fromHeader();
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
      return { sent: toList.length, messageId: info?.messageId || '', via:'smtp' };
    }
  }catch(e){
    console.warn('[email][smtp] failed, trying HTTP fallback:', e?.message || e);
  }

  // HTTP fallback via Mailjet (SMTP_USER/PASS are Mailjet API key/secret)
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

    const { list, note } = await resolveRecipients(req.body || {});
    if (!list.length) return ok(res, { ok:true, sent:0, info:'no recipients' });

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

    const { list, note } = await resolveRecipients(req.body || {});
    if (!list.length) return ok(res, { ok:true, sent:0, info:'no recipients' });

    const subject = `⚡️ Signal: ${item.symbol ? `${item.symbol} — `:''}${item.title||'Update'}`;
    const html = emailTemplateSignal(item);

    const result = await sendEmailBlast({ subject, html, toList:list });
    ok(res, { ok:true, sent: result.sent, mode: note, via: result.via });
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
