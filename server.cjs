/* server.cjs
 * TCPP Ideas Backend — ideas + uploads + likes + comments
 * + email blast + SSE updates
 *
 * This version (price features removed):
 * - NO /price/ping route
 * - NO referer allowlist/checker for price
 * - Kept ideas CRUD, uploads, likes, comments, SSE, and email blast
 * - JWT (Wix member token) or API_TOKEN auth supported
 * - Comments store {authorId, authorName}; edit/delete gated by author or admin
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
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

/* ---------------------- ID HELPER ----------------- */
/* generate short url-safe IDs similar to nanoid */
function nanoid(size = 12) {
  return crypto.randomBytes(size).toString('base64url').slice(0, size);
}

/* ---------------------- ENV ---------------------- */
const PORT      = process.env.PORT || 8080;
const NODE_ENV  = process.env.NODE_ENV || 'production';

const API_TOKEN  = process.env.API_TOKEN  || '';
const JWT_SECRET = process.env.JWT_SECRET || '';

const _corsEnv  = process.env.CORS_ORIGINS || process.env.CORS_ALLOW_ORIGINS || '*';
const CORS_ORIGINS = _corsEnv.split(',').map(s => s.trim()).filter(Boolean);

const DATA_DIR    = process.env.DATA_DIR   || '/data';
const DATA_FILE   = path.join(DATA_DIR, 'ideas.json');
const SUBS_FILE   = path.join(DATA_DIR, 'subscribers.json');
const UPLOAD_DIR  = process.env.UPLOAD_DIR || path.join(DATA_DIR, 'uploads');

const UPLOADS_PUBLIC_BASE_URL = (process.env.UPLOADS_PUBLIC_BASE_URL || '').replace(/\/+$/,'');

const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 8);
const ALLOWED_UPLOAD_TYPES = (process.env.ALLOWED_UPLOAD_TYPES
  || 'image/png,image/jpeg,image/webp,image/gif').split(',').map(s => s.trim());

/* ---------------------- EMAIL -------------------- */
const SMTP_HOST   = process.env.SMTP_HOST   || '';
const SMTP_PORT   = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = String(process.env.SMTP_SECURE || '').toLowerCase() === 'true' || SMTP_PORT === 465;
const SMTP_USER   = process.env.SMTP_USER   || '';
const SMTP_PASS   = process.env.SMTP_PASS   || '';

const MAIL_FROM         = process.env.MAIL_FROM || '';
const MAIL_FROM_NAME    = process.env.MAIL_FROM_NAME || 'Trade Chart Patterns Like The Pros';
const EMAIL_FROM        = process.env.EMAIL_FROM || ''; // inline "Name <email>"
const EMAIL_REPLY_TO    = (process.env.EMAIL_REPLY_TO || '').trim();

const EMAIL_BCC_ADMIN   = (process.env.EMAIL_BCC_ADMIN || '')
  .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

const EMAIL_FORCE_ALL_TO = (process.env.EMAIL_FORCE_ALL_TO || '').trim().toLowerCase();

const SITE_NAME   = process.env.SITE_NAME   || 'Trade Chart Patterns — Pro';
const SITE_URL    = process.env.SITE_URL    || 'https://www.tradechartpatternslikethepros.com';
const LOGO_URL    = process.env.EMAIL_LOGO_URL
  || process.env.LOGO_URL
  || 'https://static.wixstatic.com/media/e09166_90ddc4c3b20d4b4b83461681f85d9dd8~mv2.png';

const ASSET_BASE_URL = process.env.ASSET_BASE_URL || SITE_URL;
const EMAIL_THEME    = (process.env.EMAIL_THEME || 'dark').toLowerCase();
const EMAIL_LAYOUT   = (process.env.EMAIL_LAYOUT || 'hero-first').toLowerCase();
const EMAIL_BODY_BG  = process.env.EMAIL_BODY_BG || '';

/* ---------------------- UTIL ---------------------- */
const nowISO = () => new Date().toISOString();

async function ensureDir(p) {
  await fsp.mkdir(p, { recursive: true }).catch(() => {});
}

function ok(res, data) {
  res.json(data);
}
function err(res, code, msg) {
  res.status(code).json({ status:'error', code, message: msg || 'Error' });
}

function absUrl(u) {
  const s = String(u || '').trim();
  if (!s) return '';
  if (/^https?:\/\//i.test(s)) return s;
  const base = (UPLOADS_PUBLIC_BASE_URL || ASSET_BASE_URL || SITE_URL || '').replace(/\/+$/,'');
  return base + (s.startsWith('/') ? s : `/${s}`);
}

const EMAIL_RX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const uniq = a => Array.from(new Set(a || []));

function nnum(v){
  if (v == null) return null;
  const n = Number(String(v).replace(/[^\d.\-]/g, ''));
  return Number.isFinite(n) ? n : null;
}
function parseTargets(v){
  if (Array.isArray(v)) return v.map(nnum).filter(Number.isFinite);
  const s = String(v || '');
  const m = s.match(/-?\d+(\.\d+)?/g) || [];
  return m.map(Number).filter(Number.isFinite);
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
        const ext = ({
          'image/png': '.png',
          'image/jpeg': '.jpg',
          'image/webp': '.webp',
          'image/gif': '.gif'
        }[file.mimetype]) || '';
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

// read token from header or ?token=
function readBearer(req) {
  const h = req.headers['authorization'] || req.headers['Authorization'];
  if (h && /^Bearer\s+/i.test(h)) return h.replace(/^Bearer\s+/i, '').trim();
  return '';
}
function readQueryToken(req) {
  return (req.query && String(req.query.token || '').trim()) || '';
}

// decode token -> user object OR null
function decodeToken(tok) {
  if (!tok) return null;

  // direct API token = god mode/admin
  if (API_TOKEN && tok === API_TOKEN) {
    return {
      id: 'api',
      email: '',
      name: 'api',
      isAdmin: true
    };
  }

  // signed Wix member JWT (from getDashboardJWT)
  if (JWT_SECRET) {
    try {
      const decoded = jwt.verify(tok, JWT_SECRET) || {};
      return {
        id: decoded.id || '',
        email: decoded.email || '',
        name: decoded.name || '',
        isAdmin: !!decoded.isAdmin
      };
    } catch (_) {
      // bad jwt
    }
  }

  return null;
}

// middleware: attach req.user (and block if invalid)
// if neither API_TOKEN nor JWT_SECRET is set -> open mode for dev
function requireAuth(req, res, next) {
  if (!API_TOKEN && !JWT_SECRET) {
    req.user = { id:'open', email:'', name:'open', isAdmin:true };
    return next();
  }

  const tok = readBearer(req) || readQueryToken(req);
  const u = decodeToken(tok);
  if (!u) return err(res, 401, 'Unauthorized');

  req.user = u;
  next();
}

// helper: for routes that only admins should hit
function requireAdmin(req, res, next) {
  if (!req.user || !req.user.isAdmin) {
    return err(res, 403, 'forbidden');
  }
  next();
}

// SSE auth check (query token only)
function sseAuthOK(req) {
  if (!API_TOKEN && !JWT_SECRET) return true;
  const tok = readQueryToken(req);
  return !!decodeToken(tok);
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

/* ----- CORS allow logic ----- */
function isOriginAllowed(origin) {
  if (!origin) return true; // no Origin header -> allow (curl / server2server)

  if (CORS_ORIGINS.includes('*') || CORS_ORIGINS.includes(origin)) return true;

  try {
    const { protocol, host } = new URL(origin);

    // wix editor/preview
    if (host.endsWith('.wixsite.com')) {
      return protocol === 'https:';
    }

    // Wix CDN/media
    if (host.endsWith('.filesusr.com')) {
      return protocol === 'https:';
    }

    // wildcard like https://*.wixsite.com
    for (const pat of CORS_ORIGINS) {
      if (!pat.includes('*')) continue;
      const m = pat.match(/^https?:\/\/\*\.(.+)$/i);
      if (m && host.endsWith(m[1])) {
        return protocol === 'https:';
      }
    }

    // localhost dev
    if (/^(localhost|127\.0\.0\.1)(:\d+)?$/i.test(host)) return true;
  } catch {
    return false;
  }
  return false;
}

/* CORS middleware */
app.use(cors({
  origin: (origin, cb) => {
    const allowed = isOriginAllowed(origin);
    if (!allowed) {
      console.error(`CORS blocked: ${origin}`);
    }
    cb(null, allowed);
  },
  credentials: false
}));

/* body parsing */
app.use(express.json({ limit: '1mb' }));

/* static uploads */
app.use('/uploads', express.static(UPLOAD_DIR, {
  index: false,
  maxAge: '30d',
  setHeaders: res => {
    // so images can be embedded on wix site etc
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  }
}));

/* ---------------------- HEALTH ------------------- */
app.get('/health', (_req, res) => ok(res, {
  ok: true,
  env: NODE_ENV,
  time: nowISO()
}));

/* ---------------------- EVENTS (SSE) ------------- */
app.get('/events', (req, res) => {
  if (!sseAuthOK(req)) return err(res, 401, 'Unauthorized');

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });

  if (res.flushHeaders) res.flushHeaders();

  const id = nanoid(10);
  const client = { id, res, ping: null };
  clients.add(client);

  sseSendTo(res, 'hello', { id, at: nowISO() });

  client.ping = setInterval(() => {
    try { res.write(': ping\n\n'); } catch {}
  }, 25000);

  req.on('close', () => {
    clearInterval(client.ping);
    clients.delete(client);
  });
});

/* -------------------- NORMALIZATION -------------- */
function normalizeDirection(v) {
  const s = String(v || '').toLowerCase();
  if (s === 'long'  || s === 'buy')  return 'long';
  if (s === 'short' || s === 'sell') return 'short';
  return 'neutral';
}

function firstImageUrl(item) {
  const raw = item?.imageUrl ||
    (Array.isArray(item?.media) && item.media[0] && item.media[0].url) || '';
  return absUrl(raw);
}

function ideaDeepLink(item) {
  const base = `${SITE_URL}/trading-dashboard`;
  const id   = String(item?.id || '').trim();
  if (!id) return base;
  const campaign = item?.symbol ? `idea-${item.symbol}` : 'idea';
  const q = `?idea=${encodeURIComponent(id)}&utm_source=email&utm_medium=notification&utm_campaign=${encodeURIComponent(campaign)}`;
  return `${base}${q}`;
}

function normalizeIdea(input) {
  const now = nowISO();
  const dir = normalizeDirection(input.direction || input.bias);
  const entry = nnum(input.entryLevel ?? input.entry ?? input.el);
  const stop  = nnum(input.stopLevel  ?? input.stop  ?? input.sl);
  const targets = parseTargets(input.targets ?? input.targetText ?? input.tps ?? input.tp);

  return {
    id: input.id || nanoid(12),
    type: String(input.type || 'post'),
    status: String(input.status || 'live'),
    title: String(input.title || '').slice(0, 240),
    symbol: String(input.symbol || '').slice(0, 64),
    levelText: String(input.levelText || input.levels || '').slice(0, 2000),
    take: String(input.take || input.content || '').slice(0, 4000),
    link: String(input.link || '').slice(0, 1024),
    imageUrl: String(input.imageUrl || input.img || ''),
    media: Array.isArray(input.media)
      ? input.media.map(m => ({ kind: String(m.kind || 'image'), url: String(m.url || '') }))
      : [],
    direction: dir,
    metrics: {
      entry: entry ?? null,
      stop:  stop  ?? null,
      targets: targets,
      last: null,
      lastAt: null,
      statusLight: 'gray', // gray|green|orange|red|blue
      statusNote: '',
      hitStop: false,
      hitTargetIndex: null
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

// sanitize idea for public / frontend
function ideaPublic(it) {
  return {
    id: it.id,
    type: it.type,
    status: it.status,
    title: it.title,
    symbol: it.symbol,
    levelText: it.levelText,
    take: it.take,
    link: it.link,
    imageUrl: it.imageUrl,
    media: it.media,
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
      hitTargetIndex: Number.isFinite(it.metrics.hitTargetIndex)
        ? it.metrics.hitTargetIndex
        : null
    } : undefined,
    authorName: it.authorName,
    authorEmail: it.authorEmail,
    createdAt: it.createdAt,
    updatedAt: it.updatedAt,
    likeCount: it.likes?.count || 0,
    likes: { count: it.likes?.count || 0 },
    comments: {
      items: (it.comments?.items || []).map(c => ({
        id: c.id,
        authorId: c.authorId || '',
        authorName: c.authorName || 'Member',
        text: c.text,
        createdAt: c.createdAt,
        updatedAt: c.updatedAt
      }))
    }
  };
}

/* -------------------- STATUS ENGINE -------------- */
/* Note: left in place; metrics.last can be set by future features or manual processes. */
function evalStatus(idea){
  const m = idea.metrics ||= {};
  const dir = idea.direction || 'neutral';
  const p = Number(m.last);
  const el = Number(m.entry);
  const sl = Number(m.stop);
  const tgs = Array.isArray(m.targets) ? m.targets.map(Number) : [];

  let statusLight = 'gray';
  let statusNote  = 'No price/entry';

  if (!Number.isFinite(p) || !Number.isFinite(el)) {
    m.statusLight = 'gray';
    m.statusNote  = statusNote;
    return m;
  }

  const firstTarget = tgs.length ? tgs[0] : null;

  if (dir === 'long') {
    if (Number.isFinite(sl) && p <= sl) {
      statusLight='red';  statusNote='Stop hit'; m.hitStop = true;
    } else if (Number.isFinite(firstTarget) && p >= firstTarget) {
      statusLight='blue'; statusNote='Target reached';
      if (m.hitTargetIndex == null) m.hitTargetIndex = 0;
    } else if (p >= el) {
      statusLight='green'; statusNote='Above EL';
    } else {
      statusLight='orange'; statusNote='Below EL';
    }
  } else if (dir === 'short') {
    if (Number.isFinite(sl) && p >= sl) {
      statusLight='red';  statusNote='Stop hit'; m.hitStop = true;
    } else if (Number.isFinite(firstTarget) && p <= firstTarget) {
      statusLight='blue'; statusNote='Target reached';
      if (m.hitTargetIndex == null) m.hitTargetIndex = 0;
    } else if (p <= el) {
      statusLight='green'; statusNote='Below EL';
    } else {
      statusLight='orange'; statusNote='Above EL';
    }
  } else {
    statusLight='orange'; statusNote='Neutral';
  }

  m.statusLight = statusLight;
  m.statusNote  = statusNote;
  return m;
}

/* -------------------- IDEAS CRUD ------------------ */

// public latest feed
app.get('/ideas/latest', async (req, res) => {
  const limit = Math.min(Number(req.query.limit || 30), 100);
  const db = await loadDB();
  const items = [...db.ideas]
    .sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, limit)
    .map(ideaPublic);
  ok(res, { items, ideas: items });
});

// public single idea
app.get('/ideas/:id', async (req, res) => {
  const db = await loadDB();
  const it = db.ideas.find(x => String(x.id) === String(req.params.id));
  if (!it) return err(res, 404, 'Not found');
  ok(res, { item: ideaPublic(it) });
});

// create idea (admin only)
app.post('/ideas', requireAuth, requireAdmin, async (req, res) => {
  const db = await loadDB();

  // normalize and force author from req.user, not client
  const it = normalizeIdea({
    ...req.body,
    authorId: req.user.id,
    authorName: req.user.name || 'Member',
    authorEmail: req.user.email || ''
  });

  if (!it.imageUrl && Array.isArray(it.media) && it.media[0]?.url) {
    it.imageUrl = it.media[0].url;
  }

  db.ideas.unshift(it);
  await saveDB(db);

  const pub = ideaPublic(it);
  sseSend('idea:new', pub);
  ok(res, { item: pub });
});

// update idea (admin only)
app.patch('/ideas/:id', requireAuth, requireAdmin, async (req, res) => {
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
    direction: normalizeDirection(req.body.direction ?? req.body.bias ?? it.direction),
    updatedAt: nowISO()
  });

  it.metrics ||= {};
  if (req.body.entryLevel!=null || req.body.entry!=null || req.body.el!=null)
    it.metrics.entry = nnum(req.body.entryLevel ?? req.body.entry ?? req.body.el);
  if (req.body.stopLevel!=null || req.body.stop!=null || req.body.sl!=null)
    it.metrics.stop  = nnum(req.body.stopLevel ?? req.body.stop ?? req.body.sl);
  if (req.body.targets!=null || req.body.targetText!=null || req.body.tp!=null || req.body.tps!=null)
    it.metrics.targets = parseTargets(req.body.targets ?? req.body.targetText ?? req.body.tp ?? req.body.tps);

  evalStatus(it);

  await saveDB(db);

  const pub = ideaPublic(it);
  sseSend('idea:update', pub);
  ok(res, { item: pub });
});

// delete idea (admin only)
app.delete('/ideas/:id', requireAuth, requireAdmin, async (req, res) => {
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
  const db = await loadDB();
  const it = db.ideas.find(x => String(x.id) === String(req.params.id));
  if (!it) return err(res, 404, 'Not found');

  const action = String(req.body?.action || req.body?.op || '').toLowerCase();

  // prefer trusted identity from req.user
  const fallbackUserId = (req.user?.email || req.user?.id || 'device').slice(0,120);
  const fallbackName   = (req.user?.name || 'Member').slice(0,120);

  const userId      = (String(req.body?.userId || req.body?.by || '').slice(0, 120)) || fallbackUserId;
  const displayName = (String(req.body?.displayName || req.body?.name || '').slice(0,120)) || fallbackName;

  if (!['like', 'unlike'].includes(action)) return err(res, 400, 'Invalid action');

  it.likes ||= { count: 0, by: {} };
  it.likes.by ||= {};

  const was = !!it.likes.by[userId];
  if (action === 'like' && !was) {
    it.likes.by[userId] = { at: nowISO(), name: displayName };
    it.likes.count = Math.max(0, Number(it.likes.count || 0)) + 1;
  } else if (action === 'unlike' && was) {
    delete it.likes.by[userId];
    it.likes.count = Math.max(0, Number(it.likes.count || 1) - 1);
  }

  await saveDB(db);

  const out = { id: it.id, likeCount: it.likes.count };
  sseSend('likes:update', out);

  ok(res, {
    likeCount: it.likes.count,
    likes: { count: it.likes.count }
  });
}

app.put('/ideas/:id/likes', requireAuth, likeHandler);
app.post('/ideas/:id/likes', requireAuth, likeHandler);
app.put('/ideas/:id/likes/toggle', requireAuth, likeHandler);
app.post('/ideas/:id/likes/toggle', requireAuth, likeHandler);

/* -------------------- COMMENTS --------------------
   - We store both authorId and authorName on each comment.
   - authorName priority:
        req.body.displayName / req.body.name
     -> req.headers['x-user-name']
     -> req.user.name
     -> "Member"
   - authorId priority:
        req.user.id
     -> req.user.email
     -> fallback anon-<nanoid>
   We NEVER overwrite authorId/authorName on edit. We only let the
   same authorId (or admin) edit/delete.
---------------------------------------------------*/

function sanitizeCommentsArray(arr) {
  return (arr || []).map(x => ({
    id: x.id,
    authorId: x.authorId || '',
    authorName: x.authorName || 'Member',
    text: x.text,
    createdAt: x.createdAt,
    updatedAt: x.updatedAt
  }));
}

async function _commentAdd(req, res) {
  const db = await loadDB();
  const it = db.ideas.find(x => String(x.id) === String(req.params.id));
  if (!it) return err(res, 404, 'Not found');

  const rawText = (
    (req.body && (req.body.text || req.body.body || req.body.comment || req.body.msg)) ||
    ''
  ).toString().trim();
  if (!rawText) return err(res, 400, 'text required');

  // derive identity
  const headerName  = (req.headers['x-user-name']  || '').toString().trim();
  const headerEmail = (req.headers['x-user-email'] || '').toString().trim();

  // stable authorId primarily from req.user
  const authorId = (
    (req.user?.id || req.user?.email || headerEmail || '')
      .toString()
      .slice(0,120)
  ) || ('anon-' + nanoid(6));

  // display name priority (client wins for label, but perms still use authorId)
  const derivedName = (
    (req.body?.displayName || req.body?.name || headerName || req.user?.name || 'Member')
      .toString()
      .trim()
  ).slice(0,120) || 'Member';

  const now = nowISO();
  const c = {
    id: nanoid(10),
    authorId,
    authorName: derivedName,
    text: rawText,
    createdAt: now,
    updatedAt: now
  };

  it.comments ||= { items: [] };
  it.comments.items.push(c);

  await saveDB(db);

  const items = sanitizeCommentsArray(it.comments.items);

  // SSE update with sanitized items
  sseSend('comments:update', { id: it.id, items });

  ok(res, { items });
}

async function _commentEdit(req, res) {
  const db = await loadDB();
  const it = db.ideas.find(x => String(x.id) === String(req.params.id));
  if (!it) return err(res, 404, 'Not found');

  const all = (it.comments?.items || []);
  theLoop: {
    // pass
  }
  const c = all.find(x => String(x.id) === String(req.params.cid));
  if (!c) return err(res, 404, 'comment not found');

  // authz: admin OR same author
  const canEdit = (req.user?.isAdmin || (req.user?.id && req.user.id === c.authorId));
  if (!canEdit) return err(res, 403, 'forbidden');

  const rawText = (
    (req.body && (req.body.text || req.body.body || req.body.comment || req.body.msg)) ||
    ''
  ).toString().trim();
  if (!rawText) return err(res, 400, 'text required');

  c.text = rawText;
  c.updatedAt = nowISO();

  await saveDB(db);

  const items = sanitizeCommentsArray(it.comments.items);

  sseSend('comments:update', { id: it.id, items });
  ok(res, { items });
}

async function _commentDelete(req, res) {
  const db = await loadDB();
  const it = db.ideas.find(x => String(x.id) === String(req.params.id));
  if (!it) return err(res, 404, 'Not found');

  const beforeList = it.comments?.items || [];
  const target = beforeList.find(x => String(x.id) === String(req.params.cid));
  if (!target) return err(res, 404, 'comment not found');

  // authz: admin OR same author
  const canDelete = (req.user?.isAdmin || (req.user?.id && req.user.id === target.authorId));
  if (!canDelete) return err(res, 403, 'forbidden');

  it.comments.items = beforeList.filter(x => String(x.id) !== String(req.params.cid));

  await saveDB(db);

  const items = sanitizeCommentsArray(it.comments.items);

  sseSend('comments:update', { id: it.id, items });
  ok(res, { items });
}

app.post('/ideas/:id/comments', requireAuth, _commentAdd);
app.patch('/ideas/:id/comments/:cid', requireAuth, _commentEdit);
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
  if (EMAIL_FROM) return EMAIL_FROM;
  if (MAIL_FROM) return `"${MAIL_FROM_NAME}" <${MAIL_FROM}>`;
  if (SMTP_USER) return `"${MAIL_FROM_NAME}" <${SMTP_USER}>`;
  return `"${MAIL_FROM_NAME}" <no-reply@localhost>`;
}

const EMAIL_RX_LOCAL = EMAIL_RX;
function splitEmails(list) {
  return String(list || '')
    .split(/[,\s;]+/)
    .map(s => s.trim().toLowerCase())
    .filter(Boolean)
    .filter(e => EMAIL_RX_LOCAL.test(e));
}

function packToBcc(all) {
  const uniqd = uniq(all);
  if (uniqd.length <= 1) {
    return { to: uniqd[0] || undefined, bcc: undefined };
  }
  return { to: uniqd[0], bcc: uniqd.slice(1) };
}

function _esc(s) {
  return String(s || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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

function _emailShell({
  preheader,
  title,
  symbol,
  levelsHTML,
  planHTML,
  imgUrl,
  ctaHref,
  ctaText,
  badgeText,
  theme,
  statusColor
}) {
  const isClear = ['clear','transparent','none','minimal','white'].includes(theme);
  const logo = absUrl(LOGO_URL);
  const brand = MAIL_FROM_NAME || 'Trade Chart Patterns Like The Pros';
  const hasImg = !!imgUrl;

  const bodyBg     = isClear ? '' : 'background:#0a0f1a;';
  const container  = isClear
    ? 'background:transparent;border:none;box-shadow:none;'
    : 'background:#0b1220;border:1px solid rgba(255,255,255,0.06);box-shadow:0 6px 28px rgba(0,0,0,0.35);';
  const headGrad   = isClear ? '' : 'background:linear-gradient(180deg,rgba(255,255,255,0.02),rgba(255,255,255,0));';
  const textColor  = isClear ? '#0b1220' : '#e8eefc';
  const titleColor = isClear ? '#0b1220' : '#f5f8ff';
  const badgeBg    = isClear ? 'rgba(0,0,0,0.05)' : 'rgba(255,255,255,0.06)';
  const badgeColor = isClear ? '#0b1220' : '#dce6ff';
  const secBg      = isClear ? 'rgba(0,0,0,0.03)' : 'rgba(255,255,255,0.03)';
  const secBor     = isClear ? '1px dashed rgba(0,0,0,0.08)' : '1px dashed rgba(255,255,255,0.08)';
  const footerBor  = isClear ? '1px solid rgba(0,0,0,0.06)' : '1px solid rgba(255,255,255,0.06)';
  const footerTxt  = isClear ? '#3a4358' : '#8fa0c6';
  const visitColor = isClear ? '#164a76' : '#cfe8ff';
  const visitBor   = isClear ? '1px solid rgba(0,0,0,0.12)' : '1px solid rgba(255,255,255,0.14)';

  const dot = statusColor
    ? `<span style="display:inline-block;width:10px;height:10px;border-radius:999px;margin-right:8px;vertical-align:middle;background:${statusColor}"></span>`
    : '';

  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${_esc(title)}</title></head>
<body style="margin:0;padding:0;${bodyBg}">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">${_esc(preheader || title)}</div>
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="${isClear ? '' : 'background:#0a0f1a;'}padding:24px 14px">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:680px;${container}border-radius:18px;overflow:hidden">
        <tr><td align="center" style="padding:22px 20px 8px 20px;${headGrad}">
          <a href="${_esc(SITE_URL)}" style="text-decoration:none;display:inline-block" target="_blank" rel="noopener">
            <img src="${_esc(logo)}" alt="${_esc(brand)}" width="220" style="display:block;width:220px;max-width:220px;height:auto;">
          </a>
          ${badgeText ? `
          <div style="margin:14px auto 0 auto;display:inline-block;padding:6px 12px;border-radius:999px;
                      background:${badgeBg};color:${badgeColor};font-weight:700;font-size:12px;letter-spacing:.35px;text-transform:uppercase;">
            ${dot}${_esc(badgeText)}
          </div>` : ''}
        </td></tr>

        ${hasImg ? `
        <tr><td style="padding:8px 20px 0 20px">
          <img src="${_esc(imgUrl)}" alt="Chart" width="640"
               style="display:block;width:100%;max-width:640px;height:auto;border-radius:14px;
                      border:1px solid ${isClear ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.08)'};">
        </td></tr>` : ''}

        <tr><td style="padding:18px 20px 8px 20px;color:${textColor};font-family:Inter,Segoe UI,Roboto,Arial,sans-serif;">
          <h1 style="margin:0 0 8px 0;font-size:22px;line-height:1.3;color:${titleColor};font-weight:800;">${_esc(title)}</h1>
          ${symbol ? `<div style="margin:2px 0 10px 0"><span style="display:inline-block;background:#0fd5ff12;color:#9be8ff;border:1px solid #0fd5ff38;padding:6px 10px;border-radius:999px;font-weight:700;font-size:12px;letter-spacing:.2px;">${_esc(symbol)}</span></div>` : ''}

          ${levelsHTML ? `
            <div style="margin:12px 0 10px 0;padding:12px 14px;border-radius:12px;background:${secBg};border:${secBor};">
              <div style="font-size:12px;color:${isClear ? '#5a6a8a' : '#99a6c7'};letter-spacing:.3px;text-transform:uppercase;font-weight:700;margin-bottom:6px">Levels</div>
              ${levelsHTML}
            </div>` : ''}

          ${planHTML ? `
            <div style="margin:12px 0 0 0;">
              <div style="font-size:12px;color:${isClear ? '#5a6a8a' : '#99a6c7'};letter-spacing:.3px;text-transform:uppercase;font-weight:700;margin-bottom:6px">Plan</div>
              ${planHTML}
            </div>` : ''}
        </td></tr>

        <tr><td align="left" style="padding:8px 20px 24px 20px">
          <table role="presentation" cellpadding="0" cellspacing="0"><tr>
            <td><a href="${_esc(ctaHref)}" style="display:inline-block;padding:12px 18px;background:#00d0ff;color:#001018;text-decoration:none;border-radius:999px;font-weight:900;font-size:14px" target="_blank" rel="noopener">${_esc(ctaText || 'Open on Dashboard')}</a></td>
            <td width="12"></td>
            <td><a href="${_esc(SITE_URL)}" style="display:inline-block;padding:12px 16px;background:transparent;color:${visitColor};text-decoration:none;border-radius:999px;font-weight:700;font-size:14px;border:${visitBor}" target="_blank" rel="noopener">Visit Site</a></td>
          </tr></table>
        </td></tr>

        <tr><td style="padding:14px 20px 20px 20px;color:${footerTxt};font-size:12px;border-top:${footerBor};">
          <div>You’re receiving this update from ${_esc(brand)}.</div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

function emailTemplatePost(item) {
  const title   = item?.title || 'New Idea';
  const symbol  = item?.symbol || '';
  const levels  = _bullets(item?.levelText || item?.levels || '');
  const plan    = _bullets(item?.take || item?.content || '');
  const imgUrl  = firstImageUrl(item);
  const deepURL = ideaDeepLink(item);
  const pre     = `${symbol ? symbol + ' • ' : ''}${title}`;

  const html = _emailShell({
    preheader: `New Idea — ${pre}`,
    title,
    symbol,
    levelsHTML: levels,
    planHTML: plan,
    imgUrl,
    ctaHref: deepURL,
    ctaText: 'Open on Dashboard',
    badgeText: '🔔 New Idea',
    theme: EMAIL_THEME
  });

  const subject = `🔔 New Idea: ${symbol ? `${symbol} — `:''}${title || 'Update'}`;

  return { subject, html };
}

async function recipientsFor(reqBody){
  // 1. EMAIL_FORCE_ALL_TO overrides everything (great for testing)
  const forced = splitEmails(EMAIL_FORCE_ALL_TO);
  if (forced.length) return { list: forced, mode:'forced' };

  // 2. active subscribers
  const subs = await loadSubs().catch(()=>blankSubs());
  const list = uniq((subs.subs||[])
    .map(s=>String(s.email||'').toLowerCase())
    .filter(e=>EMAIL_RX_LOCAL.test(e)));
  if (list.length) return { list, mode:'subs' };

  // 3. actor email (fallback for manual post)
  const actorEmail = String(reqBody?.actor?.email || reqBody?.actorEmail || '')
    .trim()
    .toLowerCase();
  if (EMAIL_RX_LOCAL.test(actorEmail)) return { list:[actorEmail], mode:'actor' };

  // 4. admin BCC only
  const admins = (EMAIL_BCC_ADMIN || []).filter(e => EMAIL_RX_LOCAL.test(e));
  return admins.length
    ? { list: admins, mode:'admin' }
    : { list: [], mode:'none' };
}

function getMailer(){
  if (!smtpReady()) return null;
  return getTransporter();
}

async function sendEmailBlast({ subject, html, toList }){
  // Try SMTP first
  try{
    const tx = getMailer();
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

      return {
        sent: toList.length,
        messageId: info?.messageId || '',
        via:'smtp'
      };
    }
  }catch(e){
    console.warn('[email][smtp] failed, trying HTTP fallback:', e?.message || e);
  }

  // Fallback: Mailjet REST API using SMTP_USER/SMTP_PASS
  if (!(SMTP_USER && SMTP_PASS)) throw new Error('No SMTP creds for HTTP fallback');
  if (!toList.length) return { sent:0, via:'http' };

  const payload = {
    Messages: [{
      From: {
        Email: (MAIL_FROM || SMTP_USER),
        Name: MAIL_FROM_NAME || 'Notifier'
      },
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
      let data='';
      res.on('data', c=> data+=c);
      res.on('end', ()=>{
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ ok:true, status: res.statusCode, body: data });
        } else {
          reject(new Error(`Mailjet HTTP ${res.statusCode} ${data.slice(0,200)}`));
        }
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
// email blast to subs (admin only)
app.post('/email/post', requireAuth, requireAdmin, async (req, res) => {
  try{
    const item = req.body?.item || req.body?.data || null;
    if (!item) return err(res, 400, 'item required');

    const { list, mode } = await recipientsFor(req.body || {});
    if (!list.length) {
      return ok(res, {
        ok:true,
        sent:0,
        info:'no recipients (set EMAIL_FORCE_ALL_TO or add subscribers)'
      });
    }

    const tpl = emailTemplatePost(item);
    const result = await sendEmailBlast({
      subject: tpl.subject,
      html: tpl.html,
      toList:list
    });

    ok(res, { ok:true, sent: result.sent, mode, via: result.via });
  }catch(e){
    err(res, 500, e.message || 'Email failed');
  }
});

/* ----------------------- SUBSCRIBERS -------------- */
async function subscribeCore(email, name) {
  const s = await loadSubs();
  const exists = (s.subs || []).find(x => x.email === email);
  if (!exists) {
    (s.subs ||= []).push({
      email,
      name,
      createdAt: nowISO(),
      status: 'active'
    });
  }
  await saveSubs(s);
  return { ok: true };
}

app.post('/subscribe', requireAuth, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const name  = String(req.body?.name || 'Member').trim();
  if (!email || !EMAIL_RX_LOCAL.test(email)) {
    return err(res, 400, 'Valid email required');
  }
  const out = await subscribeCore(email, name);
  ok(res, out);
});

/* ----------------------- UPLOAD ------------------- */
app.post('/upload', requireAuth, requireAdmin, (req, res) => {
  if (!upload) return err(res, 500, 'Upload not initialized');
  upload.single('file')(req, res, e => {
    if (e) return err(res, 400, e.message || 'Upload failed');
    const file = req.file;
    if (!file) return err(res, 400, 'No file');
    ok(res, { url: `/uploads/${file.filename}` });
  });
});

/* ----------------------- DEBUG -------------------- */
// lock these behind admin so random members can't poke email config
app.get('/debug/email/status', requireAuth, requireAdmin, (_req, res) => {
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
      uploadsPublicBaseUrl: UPLOADS_PUBLIC_BASE_URL || null,
      assetBaseUrl: ASSET_BASE_URL,
      emailTheme: EMAIL_THEME
    }
  });
});

app.post('/debug/email/test', requireAuth, requireAdmin, async (req, res) => {
  try {
    const rawTo = req.query.to
      || req.body?.to
      || EMAIL_FORCE_ALL_TO
      || (EMAIL_BCC_ADMIN || []).join(',');

    const toList = splitEmails(rawTo);
    if (!toList.length) {
      return err(res, 400,
        'provide ?to= or set EMAIL_FORCE_ALL_TO or EMAIL_BCC_ADMIN'
      );
    }

    const imgParam = req.query.img || req.body?.img || '';
    const imgUrl   = absUrl(imgParam);

    const html = _emailShell({
      preheader: 'Test notification from Ideas Backend',
      title: `Test Email — ${EMAIL_THEME}`,
      symbol: 'OANDA:TEST',
      levelsHTML: _bullets('EL 2345; SL 2359; T1 2321'),
      planHTML: _bullets('Short on rejection; Risk ≤1%'),
      imgUrl,
      ctaHref: `${SITE_URL}/trading-dashboard`,
      ctaText: 'Open Dashboard',
      badgeText: 'Test',
      theme: EMAIL_THEME
    });

    const result = await sendEmailBlast({
      subject: 'Test — Ideas Backend Email',
      html,
      toList
    });

    ok(res, {
      ok:true,
      sent: result.sent,
      via: result.via,
      img: imgUrl
    });
  } catch (e) {
    err(res, 500, e.message || 'Test email failed');
  }
});

/* ----------------------- START -------------------- */
async function start() {
  await ensureDir(DATA_DIR);
  await ensureDir(UPLOAD_DIR);
  buildMulter();
  app.listen(PORT, () => {
    console.log(`[tcpp-ideas-backend] listening on :${PORT} env=${NODE_ENV} data=${DATA_FILE}`);
    console.log(`SSE: /events  CRUD: /ideas  Latest: /ideas/latest  Upload: /upload`);
    console.log(`Email: /email/post  Debug: /debug/email/status, /debug/email/test`);
  });
}
start();