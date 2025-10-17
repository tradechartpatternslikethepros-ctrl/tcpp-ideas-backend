/* server.cjs
 * Trade Chart Patterns Like The Pros — Ideas Backend (Express)
 * Single-file, production-ready. SSE + Ideas CRUD + Likes + Comments + Uploads.
 * Storage: JSON file persisted to DATA_DIR (attach a Railway Volume at /data).
 * Auth: Bearer token or ?token= on /events. All mutating routes require the token.
 */

'use strict';

const path   = require('path');
const fs     = require('fs');
const fsp    = fs.promises;
const express= require('express');
const cors   = require('cors');
const multer = require('multer');
const { nanoid } = require('nanoid');

// ---------- ENV ----------
const PORT            = process.env.PORT || 8080;
const NODE_ENV        = process.env.NODE_ENV || 'production';
const API_TOKEN       = process.env.API_TOKEN || ''; // REQUIRED for writes in production
const ADMIN_NAME      = process.env.ADMIN_NAME || 'Trade Chart Patterns Like The Pros';
const CORS_ORIGINS    = (process.env.CORS_ORIGINS || '*').split(',').map(s=>s.trim()).filter(Boolean);
const DATA_DIR        = process.env.DATA_DIR || '/data';
const DATA_FILE       = path.join(DATA_DIR, 'ideas.json');
const UPLOAD_DIR      = process.env.UPLOAD_DIR || path.join(DATA_DIR, 'uploads');
const MAX_UPLOAD_MB   = Number(process.env.MAX_UPLOAD_MB || 8);
const ALLOWED_UPLOADS = (process.env.ALLOWED_UPLOAD_TYPES || 'image/png,image/jpeg,image/webp').split(',').map(s=>s.trim());

// ---------- UTIL ----------
async function ensureDir(p){ await fsp.mkdir(p, { recursive: true }).catch(()=>{}); }
function nowISO(){ return new Date().toISOString(); }
function ok(res, data){ res.json(data); }
function err(res, code, msg){ res.status(code).json({ error: msg || 'Error' }); }

// ---------- STORAGE (JSON on disk) ----------
const blankDB = ()=>({ ideas: [] });

async function loadDB(){
  try{
    await ensureDir(DATA_DIR);
    const raw = await fsp.readFile(DATA_FILE, 'utf8').catch(()=> '');
    if (!raw) return blankDB();
    const j = JSON.parse(raw);
    if (!j || typeof j !== 'object' || !Array.isArray(j.ideas)) return blankDB();
    return j;
  }catch(_){ return blankDB(); }
}
async function saveDB(db){
  await ensureDir(DATA_DIR);
  const tmp = DATA_FILE + '.tmp';
  await fsp.writeFile(tmp, JSON.stringify(db, null, 2), 'utf8');
  await fsp.rename(tmp, DATA_FILE);
}

// ---------- MULTER (uploads) ----------
let upload;
function buildMulter(){
  upload = multer({
    storage: multer.diskStorage({
      destination: (_req, _file, cb)=> cb(null, UPLOAD_DIR),
      filename: (_req, file, cb)=> {
        const ext = ({
          'image/png':  '.png',
          'image/jpeg': '.jpg',
          'image/webp': '.webp'
        })[file.mimetype] || '';
        cb(null, `${Date.now()}_${nanoid(8)}${ext}`);
      }
    }),
    fileFilter: (_req, file, cb)=>{
      if (ALLOWED_UPLOADS.includes(file.mimetype)) cb(null,true);
      else cb(new Error('Unsupported file type'));
    },
    limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 }
  });
}

// ---------- AUTH ----------
function readBearer(req){
  const h = req.headers['authorization'];
  if (h && /^Bearer\s+/i.test(h)) return h.replace(/^Bearer\s+/i,'').trim();
  return '';
}
function readTokenAny(req){
  return readBearer(req) || (req.query && String(req.query.token||'')) || '';
}
function requireAuth(req, res, next){
  const tok = readBearer(req);
  if (API_TOKEN && tok !== API_TOKEN) return err(res, 401, 'Unauthorized');
  if (!API_TOKEN) return next(); // no token set -> open writes (not recommended)
  next();
}
function sseAuthOK(req){
  if (!API_TOKEN) return true; // if you run without token, public stream
  const tok = String(req.query.token||'');
  return tok === API_TOKEN;
}

// ---------- SSE ----------
const clients = new Set(); // { id, res }
function sseSend(event, data){
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const c of clients) {
    try { c.res.write(payload); } catch(_) {}
  }
}
function sseSendTo(res, event, data){
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

// ---------- APP ----------
const app = express();

// CORS
app.use(cors({
  origin: (origin, cb)=>{
    if (!origin || CORS_ORIGINS.includes('*') || CORS_ORIGINS.includes(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: false
}));
app.use(express.json({ limit: '1mb' }));

// ---------- STATIC for uploads ----------
app.use('/uploads', express.static(UPLOAD_DIR, {
  index: false,
  maxAge: '30d',
  setHeaders: (res)=> res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin')
}));

// ---------- HEALTH ----------
app.get('/health', async (_req,res)=>{
  ok(res, { ok:true, time: nowISO(), env: NODE_ENV });
});

// ---------- EVENTS (SSE) ----------
app.get('/events', (req,res)=>{
  if (!sseAuthOK(req)) return err(res, 401, 'Unauthorized');

  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders?.();

  const id = nanoid(10);
  const client = { id, res };
  clients.add(client);

  // Warm greet
  sseSendTo(res, 'hello', { id, hello: true, at: nowISO() });

  req.on('close', ()=> clients.delete(client));
});

// ---------- HELPERS (DB adapters) ----------
function normalizeIdea(input){
  const now = nowISO();
  const id = input.id || nanoid(12);
  return {
    id,
    type: input.type || 'post',
    status: input.status || 'live',
    title: String(input.title||'').slice(0, 240),
    symbol: String(input.symbol||'').slice(0, 64),
    levelText: String(input.levelText||input.levels||'').slice(0, 2000),
    take: String(input.take||input.content||'').slice(0, 4000),
    link: String(input.link||'').slice(0, 1024),
    imageUrl: input.imageUrl || '',
    media: Array.isArray(input.media) ? input.media.map(m=>({kind: m.kind||'image', url: m.url||''})) : [],
    authorId: String(input.authorId||''),
    authorName: String(input.authorName||'Member'),
    authorEmail: String(input.authorEmail||''),
    likes: input.likes || { count: 0, by: {} },
    comments: input.comments || { items: [] },
    createdAt: input.createdAt || now,
    updatedAt: now
  };
}
function ideaPublic(it){
  return {
    id: it.id, type: it.type, status: it.status,
    title: it.title, symbol: it.symbol,
    levelText: it.levelText, take: it.take,
    link: it.link, imageUrl: it.imageUrl, media: it.media,
    authorName: it.authorName, createdAt: it.createdAt, updatedAt: it.updatedAt,
    likeCount: it.likes?.count || 0,
    likes: { count: it.likes?.count || 0 },
    comments: { items: (it.comments?.items || []).map(c=>({
      id: c.id, authorName: c.authorName, text: c.text, createdAt: c.createdAt, updatedAt: c.updatedAt
    })) }
  };
}

// ---------- IDEAS CRUD ----------
app.get('/ideas/latest', async (req,res)=>{
  const limit = Math.min( Number(req.query.limit || 30), 100 );
  const db = await loadDB();
  const items = [...db.ideas]
    .sort((a,b)=> new Date(b.createdAt)-new Date(a.createdAt))
    .slice(0, limit)
    .map(ideaPublic);
  ok(res, { items });
});

app.get('/ideas/:id', async (req,res)=>{
  const db = await loadDB();
  const it = db.ideas.find(x=> String(x.id)===String(req.params.id));
  if (!it) return err(res, 404, 'Not found');
  ok(res, ideaPublic(it));
});

app.post('/ideas', requireAuth, async (req,res)=>{
  const db = await loadDB();
  const it = normalizeIdea(req.body || {});
  db.ideas.unshift(it);
  await saveDB(db);
  const pub = ideaPublic(it);
  sseSend('idea:new', pub);
  ok(res, { idea: pub });
});

app.patch('/ideas/:id', requireAuth, async (req,res)=>{
  const db = await loadDB();
  const i = db.ideas.findIndex(x=> String(x.id)===String(req.params.id));
  if (i<0) return err(res,404,'Not found');
  const it = db.ideas[i];
  Object.assign(it, {
    type: req.body.type ?? it.type,
    status: req.body.status ?? it.status,
    title: req.body.title ?? it.title,
    symbol: req.body.symbol ?? it.symbol,
    levelText: req.body.levelText ?? it.levelText,
    take: req.body.take ?? it.take,
    link: req.body.link ?? it.link,
    imageUrl: req.body.imageUrl ?? it.imageUrl,
    media: Array.isArray(req.body.media) ? req.body.media : it.media,
    updatedAt: nowISO()
  });
  await saveDB(db);
  const pub = ideaPublic(it);
  sseSend('idea:update', pub);
  ok(res, pub);
});

app.delete('/ideas/:id', requireAuth, async (req,res)=>{
  const db = await loadDB();
  const idx = db.ideas.findIndex(x=> String(x.id)===String(req.params.id));
  if (idx<0) return err(res,404,'Not found');
  const id = db.ideas[idx].id;
  db.ideas.splice(idx,1);
  await saveDB(db);
  sseSend('idea:delete', { id });
  ok(res, { ok:true });
});

// ---------- LIKES ----------
app.put('/ideas/:id/likes', requireAuth, async (req,res)=>{
  const action = String(req.body?.action||'').toLowerCase(); // 'like' | 'unlike'
  const userId = String(req.body?.userId||'').slice(0,120);
  const displayName = String(req.body?.displayName||'Member').slice(0,120);

  if (!['like','unlike'].includes(action)) return err(res,400,'Invalid action');
  if (!userId) return err(res,400,'userId required');

  const db = await loadDB();
  const it = db.ideas.find(x=> String(x.id)===String(req.params.id));
  if (!it) return err(res,404,'Not found');

  it.likes ||= { count:0, by:{} };
  it.likes.by ||= {};
  const was = !!it.likes.by[userId];

  if (action==='like' && !was){
    it.likes.by[userId] = { at: nowISO(), name: displayName };
    it.likes.count = Math.max(0, Number(it.likes.count||0)) + 1;
  } else if (action==='unlike' && was){
    delete it.likes.by[userId];
    it.likes.count = Math.max(0, Number(it.likes.count||1) - 1);
  }

  await saveDB(db);
  sseSend('likes:update', { id: it.id, likeCount: it.likes.count });
  ok(res, { likeCount: it.likes.count, likes: { count: it.likes.count } });
});

// ---------- COMMENTS ----------
app.post('/ideas/:id/comments', requireAuth, async (req,res)=>{
  const db = await loadDB();
  const it = db.ideas.find(x=> String(x.id)===String(req.params.id));
  if (!it) return err(res,404,'Not found');
  const text = String(req.body?.text||'').trim();
  const authorId = String(req.body?.authorId||'').slice(0,120);
  const authorName = String(req.body?.authorName||'Member').slice(0,120);
  if (!text) return err(res,400,'text required');

  const c = { id: nanoid(10), authorId, authorName, text, createdAt: nowISO(), updatedAt: nowISO() };
  it.comments ||= { items: [] };
  it.comments.items.push(c);
  await saveDB(db);
  const items = it.comments.items.map(x=>({ id:x.id, authorName:x.authorName, text:x.text, createdAt:x.createdAt, updatedAt:x.updatedAt }));
  sseSend('comments:update', { id: it.id, items });
  ok(res, { items });
});

app.patch('/ideas/:id/comments/:cid', requireAuth, async (req,res)=>{
  const db = await loadDB();
  const it = db.ideas.find(x=> String(x.id)===String(req.params.id));
  if (!it) return err(res,404,'Not found');
  const c = (it.comments?.items||[]).find(x=> String(x.id)===String(req.params.cid));
  if (!c) return err(res,404,'comment not found');

  const text = String(req.body?.text||'').trim();
  if (!text) return err(res,400,'text required');
  c.text = text;
  c.updatedAt = nowISO();
  await saveDB(db);
  const items = it.comments.items.map(x=>({ id:x.id, authorName:x.authorName, text:x.text, createdAt:x.createdAt, updatedAt:x.updatedAt }));
  sseSend('comments:update', { id: it.id, items });
  ok(res, { items });
});

app.delete('/ideas/:id/comments/:cid', requireAuth, async (req,res)=>{
  const db = await loadDB();
  const it = db.ideas.find(x=> String(x.id)===String(req.params.id));
  if (!it) return err(res,404,'Not found');
  const before = (it.comments?.items||[]).length;
  it.comments.items = (it.comments?.items||[]).filter(x=> String(x.id)!==String(req.params.cid));
  const after = it.comments.items.length;
  if (before===after) return err(res,404,'comment not found');
  await saveDB(db);
  const items = it.comments.items.map(x=>({ id:x.id, authorName:x.authorName, text:x.text, createdAt:x.createdAt, updatedAt:x.updatedAt }));
  sseSend('comments:update', { id: it.id, items });
  ok(res, { items });
});

// ---------- UPLOAD ----------
app.post('/upload', requireAuth, (req,res)=>{
  if (!upload) return err(res,500,'Upload not initialized');
  upload.single('file')(req,res, async (e)=>{
    if (e) return err(res,400, e.message || 'Upload failed');
    const file = req.file;
    if (!file) return err(res,400,'No file');
    const url = `/uploads/${file.filename}`;
    ok(res, { url });
  });
});

// ---------- LISTEN ----------
async function start(){
  await ensureDir(DATA_DIR);
  await ensureDir(UPLOAD_DIR);
  buildMulter();
  app.listen(PORT, ()=>{
    console.log(`[ideas-backend] listening on :${PORT} env=${NODE_ENV} data=${DATA_FILE}`);
  });
}
start();
