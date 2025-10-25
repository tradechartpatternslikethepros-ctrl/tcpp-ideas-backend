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
const http = require('http');
const { nanoid } = require('nanoid');
const jwt = require('jsonwebtoken');

/* ------------------------- ENV ------------------------- */
const PORT      = Number(process.env.PORT || 8080);
const NODE_ENV  = process.env.NODE_ENV || 'production';

// Legacy single-token auth (admin only fallback)
const API_TOKEN = (process.env.API_TOKEN || '').trim();

// New per-user token secret (must match Wix JWT_SECRET)
const JWT_SECRET = (process.env.JWT_SECRET || '').trim();
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET missing in env');
  process.exit(1);
}

// CORS whitelist. Comma-separated origins or "*"
const CORS_ORIGINS = String(
  process.env.CORS_ORIGINS || process.env.CORS_ALLOW_ORIGINS || '*'
).split(',')
 .map(s => s.trim())
 .filter(Boolean);

// Data / uploads
const DATA_DIR    = process.env.DATA_DIR || '/data';
const DATA_FILE   = path.join(DATA_DIR, 'ideas-data.json');
const UPLOAD_DIR  = path.join(DATA_DIR, 'uploads');

// Mail / notify
const MAILJET_API_KEY    = (process.env.MAILJET_API_KEY || '').trim();
const MAILJET_API_SECRET = (process.env.MAILJET_API_SECRET || '').trim();
const MAILJET_SENDER     = (process.env.MAILJET_SENDER || '').trim();     // e.g. noreply@tradechartpatterns...
const PRO_NOTIFY_TO      = (process.env.PRO_NOTIFY_TO || '').trim();     // where alerts land

const MAIL_ENABLED = (
  MAILJET_API_KEY &&
  MAILJET_API_SECRET &&
  MAILJET_SENDER &&
  PRO_NOTIFY_TO
);

/* ------------------------- STORAGE HELPERS ------------------------- */

async function ensureStorage() {
  await fsp.mkdir(DATA_DIR,   { recursive: true });
  await fsp.mkdir(UPLOAD_DIR, { recursive: true });

  try {
    await fsp.access(DATA_FILE, fs.constants.F_OK);
  } catch (err) {
    const initData = { ideas: [] };
    await fsp.writeFile(DATA_FILE, JSON.stringify(initData, null, 2), 'utf8');
  }
}

let memData = null;

async function loadData() {
  if (!memData) {
    await ensureStorage();
    const raw = await fsp.readFile(DATA_FILE, 'utf8').catch(() => '{"ideas":[]}');
    try {
      memData = JSON.parse(raw);
    } catch (e) {
      memData = { ideas: [] };
    }
    if (!Array.isArray(memData.ideas)) {
      memData.ideas = [];
    }
  }
  return memData;
}

async function saveData(data) {
  memData = data;
  await fsp.writeFile(DATA_FILE, JSON.stringify(memData, null, 2), 'utf8');
}

function findIdea(data, id) {
  return data.ideas.find(i => i.id === id);
}

/* ------------------------- AUTH ------------------------- */

/**
 * resolveUserFromToken()
 * - Accepts Authorization: Bearer <token>
 * - First tries JWT (per-user from Wix)
 * - Falls back to legacy static API_TOKEN (treat as admin)
 */
function resolveUserFromToken(authHeader) {
  if (!authHeader) return null;
  if (!authHeader.startsWith('Bearer ')) return null;

  const raw = authHeader.slice(7).trim();
  if (!raw) return null;

  // 1. Try JWT from Wix
  try {
    const decoded = jwt.verify(raw, JWT_SECRET);
    return {
      id:    decoded.sub || decoded.id || decoded.email || 'user',
      email: decoded.email || '',
      name:  decoded.name  || 'Trader',
      role:  decoded.role  || 'user',
      authType: 'jwt'
    };
  } catch (err) {
    // not a valid JWT, maybe legacy token
  }

  // 2. Legacy static admin token fallback
  if (API_TOKEN && raw === API_TOKEN) {
    return {
      id:    'admin-legacy',
      email: PRO_NOTIFY_TO || MAILJET_SENDER || 'noreply@example.com',
      name:  'Trade Chart Patterns Like The Pros',
      role:  'admin',
      authType: 'legacy'
    };
  }

  // no valid auth
  return null;
}

function authRequired(req, res, next) {
  const u = resolveUserFromToken(req.headers.authorization || '');
  if (!u) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.user = u;
  next();
}

function adminRequired(req, res, next) {
  const u = resolveUserFromToken(req.headers.authorization || '');
  if (!u) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (u.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  req.user = u;
  next();
}

/* ------------------------- CORS ------------------------- */

const corsOptions = {
  origin: function(origin, cb) {
    if (!origin) return cb(null, true); // allow curl / server-to-server
    if (
      CORS_ORIGINS.includes('*') ||
      CORS_ORIGINS.includes(origin)
    ) {
      return cb(null, true);
    }
    return cb(new Error('Blocked by CORS: ' + origin));
  },
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
};

/* ------------------------- APP / SERVER ------------------------- */

const app = express();
app.disable('x-powered-by');

app.use(cors(corsOptions));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// serve uploaded images
app.use('/uploads', express.static(UPLOAD_DIR, {
  maxAge: '365d',
  immutable: true
}));

/* ------------------------- MULTER (UPLOADS) ------------------------- */

const storage = multer.diskStorage({
  destination: function(req, file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename: function(req, file, cb) {
    const ext = path.extname(file.originalname || '').toLowerCase();
    cb(null, nanoid() + ext);
  }
});

const upload = multer({ storage });

/* ------------------------- SSE ------------------------- */

const sseClients = new Set();

function pushEvent(type, payload) {
  const evt = Object.assign({ type, ts: Date.now() }, payload || {});
  const line =
    `event: ${type}\n` +
    `data: ${JSON.stringify(evt)}\n\n`;

  for (const res of sseClients) {
    try {
      res.write(line);
    } catch (err) {
      // ignore broken pipes
    }
  }
}

app.get('/events', (req, res) => {
  // basic SSE headers
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',   'keep-alive');

  if (res.flushHeaders) res.flushHeaders();

  sseClients.add(res);

  // greet immediately
  res.write(
    `event: hello\n` +
    `data: ${JSON.stringify({ type: 'hello', ts: Date.now() })}\n\n`
  );

  // keep-alive ping so proxies don't kill the stream
  const heartbeat = setInterval(() => {
    if (res.writableEnded) return;
    res.write(
      `event: ping\n` +
      `data: ${JSON.stringify({ ts: Date.now() })}\n\n`
    );
  }, 25000);

  req.on('close', () => {
    clearInterval(heartbeat);
    sseClients.delete(res);
  });
});

/* ------------------------- IDEAS CRUD ------------------------- */

/**
 * GET /ideas/latest?limit=N
 * Returns newest N ideas
 */
app.get('/ideas/latest', async (req, res) => {
  const data = await loadData();
  let limit = parseInt(req.query.limit, 10);
  if (Number.isNaN(limit) || limit <= 0) limit = 15;
  if (limit > 50) limit = 50;

  const items = [...data.ideas]
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, limit);

  res.json({ items });
});

/**
 * GET /ideas
 * Returns all ideas (sorted newest first)
 */
app.get('/ideas', async (req, res) => {
  const data = await loadData();
  const items = [...data.ideas]
    .sort((a, b) => b.createdAt - a.createdAt);
  res.json({ items });
});

/**
 * GET /ideas/:id
 * Return a single idea
 */
app.get('/ideas/:id', async (req, res) => {
  const data = await loadData();
  const idea = findIdea(data, req.params.id);
  if (!idea) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.json({ item: idea });
});

/**
 * POST /ideas
 * Body can include:
 * - title
 * - symbol
 * - link (TradingView link or whatever)
 * - levels (PCZ / PRZ / SL / T1 / T2 etc)
 * - context (market context / breakdown)
 * - plan (My Take: ...)
 * - imageUrl (chart screenshot URL)
 * - status {el, sl, tp, active...}   // optional tracking block
 */
app.post('/ideas', authRequired, async (req, res) => {
  const body = req.body || {};
  const now  = Date.now();
  const data = await loadData();

  const newIdea = {
    id:        nanoid(),
    title:     String(body.title  || '').trim(),
    symbol:    String(body.symbol || '').trim(),
    link:      String(body.link   || '').trim(),
    levels:    body.levels  || String(body.levels  || '').trim(),
    context:   body.context || String(body.context || '').trim(),
    plan:      body.plan    || String(body.plan    || '').trim(),
    imageUrl:  String(body.imageUrl || '').trim(),
    status:    (typeof body.status === 'object' && body.status) || {},
    createdAt: now,
    updatedAt: now,
    author: {
      id:    req.user.id,
      name:  req.user.name,
      email: req.user.email,
      role:  req.user.role
    },
    likes:    {},     // userId -> timestamp
    comments: []      // array of {id,text,user,...}
  };

  // newest first
  data.ideas.unshift(newIdea);
  await saveData(data);

  pushEvent('idea:new', { idea: newIdea });

  res.json({ ok: true, item: newIdea });
});

/**
 * PUT /ideas/:id
 * Only owner OR admin can edit
 */
app.put('/ideas/:id', authRequired, async (req, res) => {
  const data = await loadData();
  const idea = findIdea(data, req.params.id);
  if (!idea) {
    return res.status(404).json({ error: 'Not found' });
  }

  const isOwner =
    (idea.author && idea.author.id === req.user.id) ||
    req.user.role === 'admin';

  if (!isOwner) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const body = req.body || {};
  if (body.title     !== undefined) idea.title    = String(body.title).trim();
  if (body.symbol    !== undefined) idea.symbol   = String(body.symbol).trim();
  if (body.link      !== undefined) idea.link     = String(body.link).trim();
  if (body.levels    !== undefined) idea.levels   = body.levels || String(body.levels || '').trim();
  if (body.context   !== undefined) idea.context  = body.context || String(body.context || '').trim();
  if (body.plan      !== undefined) idea.plan     = body.plan || String(body.plan || '').trim();
  if (body.imageUrl  !== undefined) idea.imageUrl = String(body.imageUrl || '').trim();
  if (body.status    !== undefined && typeof body.status === 'object') {
    idea.status = body.status;
  }

  idea.updatedAt = Date.now();

  await saveData(data);

  pushEvent('idea:update', { idea });

  res.json({ ok: true, item: idea });
});

/**
 * DELETE /ideas/:id
 * Admin only
 */
app.delete('/ideas/:id', adminRequired, async (req, res) => {
  const data = await loadData();
  const idx = data.ideas.findIndex(i => i.id === req.params.id);
  if (idx === -1) {
    return res.status(404).json({ error: 'Not found' });
  }
  const [removed] = data.ideas.splice(idx, 1);
  await saveData(data);

  pushEvent('idea:delete', { id: removed.id });

  res.json({ ok: true, deleted: removed.id });
});

/* ------------------------- LIKES ------------------------- */
/**
 * PUT /ideas/:id/likes
 * Body: { action: "like" | "unlike" }
 * Any logged-in member can like/unlike.
 * We store likes[userId] = timestamp
 */
app.put('/ideas/:id/likes', authRequired, async (req, res) => {
  const data = await loadData();
  const idea = findIdea(data, req.params.id);
  if (!idea) {
    return res.status(404).json({ error: 'Idea not found' });
  }

  if (!idea.likes) {
    idea.likes = {};
  }

  const { action } = req.body || {};
  const userKey = req.user.id || req.user.email;

  if (action === 'like') {
    idea.likes[userKey] = Date.now();
  } else if (action === 'unlike') {
    delete idea.likes[userKey];
  } else {
    return res.status(400).json({ error: 'Bad action' });
  }

  await saveData(data);

  const likeCount = Object.keys(idea.likes).length;

  pushEvent('idea:likes', {
    id: idea.id,
    likes: likeCount,
    user: {
      id: req.user.id,
      name: req.user.name
    }
  });

  res.json({
    ok: true,
    likes: likeCount,
    youLike: !!idea.likes[userKey],
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email
    }
  });
});

/* ------------------------- COMMENTS ------------------------- */
/**
 * POST /ideas/:id/comments
 * Body: { text: "..." }
 */
app.post('/ideas/:id/comments', authRequired, async (req, res) => {
  const data = await loadData();
  const idea = findIdea(data, req.params.id);
  if (!idea) {
    return res.status(404).json({ error: 'Idea not found' });
  }

  if (!idea.comments) {
    idea.comments = [];
  }

  const text = String((req.body && req.body.text) || '').trim();
  if (!text) {
    return res.status(400).json({ error: 'Empty comment' });
  }

  const now = Date.now();
  const newComment = {
    id: nanoid(),
    text,
    createdAt: now,
    updatedAt: now,
    user: {
      id:    req.user.id,
      name:  req.user.name,
      email: req.user.email,
      role:  req.user.role
    }
  };

  idea.comments.push(newComment);
  await saveData(data);

  pushEvent('comment:new', {
    ideaId: idea.id,
    comment: newComment
  });

  res.json({ ok: true, comment: newComment });
});

/**
 * PUT /ideas/:id/comments/:cid
 * Body: { text: "..." }
 * Only comment owner OR admin can edit.
 */
app.put('/ideas/:id/comments/:cid', authRequired, async (req, res) => {
  const data = await loadData();
  const idea = findIdea(data, req.params.id);
  if (!idea) {
    return res.status(404).json({ error: 'Idea not found' });
  }

  const comment = (idea.comments || []).find(c => c.id === req.params.cid);
  if (!comment) {
    return res.status(404).json({ error: 'Comment not found' });
  }

  const isOwner =
    (comment.user && comment.user.id === req.user.id) ||
    req.user.role === 'admin';

  if (!isOwner) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const newText = String((req.body && req.body.text) || '').trim();
  if (!newText) {
    return res.status(400).json({ error: 'Empty comment' });
  }

  comment.text = newText;
  comment.updatedAt = Date.now();

  await saveData(data);

  pushEvent('comment:update', {
    ideaId: idea.id,
    comment
  });

  res.json({ ok: true, comment });
});

/**
 * DELETE /ideas/:id/comments/:cid
 * Only comment owner OR admin can delete.
 */
app.delete('/ideas/:id/comments/:cid', authRequired, async (req, res) => {
  const data = await loadData();
  const idea = findIdea(data, req.params.id);
  if (!idea) {
    return res.status(404).json({ error: 'Idea not found' });
  }

  if (!idea.comments) {
    idea.comments = [];
  }

  const idx = idea.comments.findIndex(c => c.id === req.params.cid);
  if (idx === -1) {
    return res.status(404).json({ error: 'Comment not found' });
  }

  const comment = idea.comments[idx];

  const isOwner =
    (comment.user && comment.user.id === req.user.id) ||
    req.user.role === 'admin';

  if (!isOwner) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  idea.comments.splice(idx, 1);
  await saveData(data);

  pushEvent('comment:delete', {
    ideaId: idea.id,
    commentId: comment.id
  });

  res.json({ ok: true, deleted: comment.id });
});

/* ------------------------- UPLOAD ------------------------- */
/**
 * POST /upload
 * multipart/form-data  field: "image"
 * Returns { url: "/uploads/<file>" }
 */
app.post('/upload', authRequired, upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file' });
  }
  const fileUrl = `/uploads/${req.file.filename}`;

  pushEvent('upload:new', {
    fileUrl,
    user: {
      id: req.user.id,
      name: req.user.name
    }
  });

  res.json({ ok: true, url: fileUrl });
});

/* ------------------------- EMAIL / NOTIFY ------------------------- */

const mailTransport = MAIL_ENABLED
  ? nodemailer.createTransport({
      host: 'in-v3.mailjet.com',
      port: 587,
      secure: false,
      auth: {
        user: MAILJET_API_KEY,
        pass: MAILJET_API_SECRET
      }
    })
  : null;

async function sendNotifyEmail({ reqUser, subject, messageText }) {
  if (!MAIL_ENABLED) {
    throw new Error('Mail not configured');
  }

  const finalSubject = subject || `[Notification] ${reqUser.name}`;
  const finalText = [
    `User: ${reqUser.name} <${reqUser.email}>`,
    '',
    messageText || ''
  ].join('\n');

  const mailOpts = {
    from: `"${reqUser.name}" <${MAILJET_SENDER}>`,
    to: PRO_NOTIFY_TO,
    bcc:
      reqUser.email && reqUser.email !== PRO_NOTIFY_TO
        ? reqUser.email
        : undefined,
    subject: finalSubject,
    text: finalText
  };

  const info = await mailTransport.sendMail(mailOpts);
  return info.messageId || null;
}

/**
 * POST /email/post
 * Body: { ideaId?, subject?, message? }
 * Sends "new post / update" style emails
 */
app.post('/email/post', authRequired, async (req, res) => {
  if (!MAIL_ENABLED) {
    return res.status(500).json({ error: 'Mail not configured' });
  }

  const { ideaId, subject, message } = req.body || {};

  let ideaInfo = '';
  if (ideaId) {
    const data = await loadData();
    const idea = findIdea(data, ideaId);
    if (idea) {
      ideaInfo = [
        `Idea: ${idea.title} (${idea.symbol})`,
        `Levels: ${idea.levels || ''}`,
        `Plan: ${idea.plan || ''}`,
        `Link: ${idea.link || ''}`
      ].join('\n');
    }
  }

  const txt = [
    message || '',
    '',
    ideaInfo || ''
  ].join('\n').trim();

  try {
    const mid = await sendNotifyEmail({
      reqUser: req.user,
      subject: subject || `[New Post] ${req.user.name}`,
      messageText: txt
    });
    res.json({ ok: true, messageId: mid });
  } catch (err) {
    console.error('email/post error', err);
    res.status(500).json({ error: 'Email send failed' });
  }
});

/**
 * POST /email/signal
 * Body: { subject?, message? }
 * Sends urgent "signal" style emails
 */
app.post('/email/signal', authRequired, async (req, res) => {
  if (!MAIL_ENABLED) {
    return res.status(500).json({ error: 'Mail not configured' });
  }

  const { subject, message } = req.body || {};

  const txt = (message || '').trim();

  try {
    const mid = await sendNotifyEmail({
      reqUser: req.user,
      subject: subject || `[Signal] ${req.user.name}`,
      messageText: txt
    });
    res.json({ ok: true, messageId: mid });
  } catch (err) {
    console.error('email/signal error', err);
    res.status(500).json({ error: 'Email send failed' });
  }
});

/* ------------------------- DEBUG ------------------------- */

/**
 * GET /debug/whoami
 * Shows decoded user from Authorization
 */
app.get('/debug/whoami', authRequired, (req, res) => {
  res.json({
    ok: true,
    user: req.user
  });
});

/**
 * GET /debug/token
 * Quick sanity check that env is wired
 */
app.get('/debug/token', (req, res) => {
  res.json({
    ok: true,
    hasLegacyToken: !!API_TOKEN,
    hasJwtSecret: !!JWT_SECRET,
    mailEnabled:  !!MAIL_ENABLED
  });
});

/* ------------------------- START SERVER ------------------------- */

const server = http.createServer(app);

ensureStorage()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`[ideas-backend] ${NODE_ENV} listening on ${PORT}`);
    });
  })
  .catch(err => {
    console.error('Startup error', err);
    process.exit(1);
  });
