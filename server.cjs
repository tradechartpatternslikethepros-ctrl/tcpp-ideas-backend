// Trade Chart Patterns Like The Pros
// Full production backend (Express + SSE + Upload + Email)
//
// Endpoints:
//   GET    /health
//   GET    /events                        (SSE stream for realtime feed/likes/comments/status)
//   GET    /ideas/latest?limit=50
//   GET    /ideas/:id
//   POST   /ideas                         (auth)
//   PATCH  /ideas/:id                     (auth)
//   DELETE /ideas/:id                     (auth)
//   PUT    /ideas/:id/likes
//   POST   /ideas/:id/comments
//   PATCH  /ideas/:id/comments/:cid
//   DELETE /ideas/:id/comments/:cid
//   POST   /upload                        (auth, multipart/form-data `file`)
//   POST   /email/post                    (auth, send broadcast email / alert email)
//   POST   /subscribe
//   /api/subscribe, /email/subscribe      (aliases)
// Static:
//   GET    /uploads/*                     (serves uploaded chart images)
//
// Persists data to disk (DATA_DIR) so it survives restarts if volume is mounted.

import fs from "fs";
import fsp from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import cors from "cors";
import multer from "multer";
import nodemailer from "nodemailer";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();

// ---------- path helpers ----------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ---------- env ----------
const PORT = process.env.PORT || "8080";
const NODE_ENV = process.env.NODE_ENV || "development";

const API_TOKEN = process.env.API_TOKEN || ""; // bearer token the dashboard uses

// we'll allow either CORS_ALLOW_ORIGINS or CORS_ORIGINS
const corsEnvRaw =
  process.env.CORS_ALLOW_ORIGINS ||
  process.env.CORS_ORIGINS ||
  "";
const CORS_ALLOW = corsEnvRaw
  .split(",")
  .map((o) => o.trim())
  .filter(Boolean);

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const UPLOAD_DIR =
  process.env.UPLOAD_DIR || path.join(DATA_DIR, "uploads");

const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || "8");
const MAX_REMOTE_IMAGE_MB = Number(
  process.env.MAX_REMOTE_IMAGE_MB || "5"
);
// note: MAX_REMOTE_IMAGE_MB is available if you later add remote-import, not currently enforced below

const ALLOWED_UPLOAD_TYPES = (process.env.ALLOWED_UPLOAD_TYPES ||
  "image/png,image/jpeg,image/webp")
  .split(",")
  .map((x) => x.trim().toLowerCase())
  .filter(Boolean);

// email + branding
const SMTP_HOST = process.env.SMTP_HOST || "";
const SMTP_PORT = Number(process.env.SMTP_PORT || "465");
const SMTP_SECURE =
  (process.env.SMTP_SECURE || "true").toLowerCase() === "true";
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";

const MAIL_FROM =
  process.env.MAIL_FROM || "noreply@example.com";
const MAIL_FROM_NAME =
  process.env.MAIL_FROM_NAME ||
  "Trade Chart Patterns Like The Pros";

const EMAIL_FROM =
  process.env.EMAIL_FROM ||
  `${MAIL_FROM_NAME} <${MAIL_FROM}>`;

const EMAIL_BCC_ADMIN =
  process.env.EMAIL_BCC_ADMIN || "admin@example.com";
const EMAIL_FORCE_ALL_TO =
  process.env.EMAIL_FORCE_ALL_TO || ""; // comma list. if set, we send every alert here

const SITE_NAME =
  process.env.SITE_NAME || "Trade Chart Patterns — Pro";
const SITE_URL =
  process.env.SITE_URL ||
  "https://www.tradechartpatternslikethepros.com";

const EMAIL_LOGO_URL =
  process.env.EMAIL_LOGO_URL ||
  "https://static.wixstatic.com/media/e09166_90ddc4c3b20d4b4b83461681f85d9dd8~mv2.png";

const ASSET_BASE_URL =
  process.env.ASSET_BASE_URL ||
  "https://www.tradechartpatternslikethepros.com";

const UPLOADS_PUBLIC_BASE_URL =
  process.env.UPLOADS_PUBLIC_BASE_URL ||
  ""; // e.g. https://tcpp-ideas-backend-production.up.railway.app

const EMAIL_THEME = process.env.EMAIL_THEME || "white";
const EMAIL_LAYOUT = process.env.EMAIL_LAYOUT || "hero-first";
const EMAIL_BODY_BG = process.env.EMAIL_BODY_BG || "";

const ALLOW_FETCH_REFERERS = (process.env.ALLOW_FETCH_REFERERS ||
  "")
  .split(",")
  .map((x) => x.trim().toLowerCase())
  .filter(Boolean);

// ---------- tiny log helper ----------
function log(...args) {
  console.log(new Date().toISOString(), "-", ...args);
}

// ---------- make sure data dirs exist ----------
async function ensureDir(dir) {
  try {
    await fsp.mkdir(dir, { recursive: true });
  } catch (_) {}
}
await ensureDir(DATA_DIR);
await ensureDir(UPLOAD_DIR);

// ---------- data file paths ----------
const IDEAS_FILE = path.join(DATA_DIR, "ideas.json");
const SUBSCRIBERS_FILE = path.join(
  DATA_DIR,
  "subscribers.json"
);

// ---------- in-memory state ----------
let ideas = [];
let subscribers = [];
const sseClients = new Set(); // live EventSource connections

// load any persisted data
async function loadJSON(file, fallback) {
  try {
    const raw = await fsp.readFile(file, "utf8");
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}
async function saveJSON(file, data) {
  await fsp.writeFile(file, JSON.stringify(data, null, 2), "utf8");
}

ideas = await loadJSON(IDEAS_FILE, []);
subscribers = await loadJSON(SUBSCRIBERS_FILE, []);

// ---------- helpers ----------
function uid() {
  return crypto.randomUUID
    ? crypto.randomUUID()
    : "id_" +
        Math.random().toString(36).slice(2) +
        Date.now().toString(36);
}

function publicIdea(i) {
  // currently we return everything; frontend masks emails client-side
  return i;
}

function findIdea(id) {
  return ideas.find((i) => String(i.id) === String(id));
}

function saveIdeasAsync() {
  // fire and forget
  saveJSON(IDEAS_FILE, ideas).catch((err) =>
    log("ERR saving ideas.json", err)
  );
}

function pruneDeleted() {
  ideas = ideas.filter((i) => !i.deletedAt);
  saveIdeasAsync();
}

// broadcast to all SSE listeners
function broadcastSSE(event, payloadObj) {
  const data = JSON.stringify(payloadObj || {});
  for (const res of sseClients) {
    try {
      res.write(`event: ${event}\n`);
      res.write(`data: ${data}\n\n`);
    } catch (err) {
      // client went away
      sseClients.delete(res);
      try {
        res.end();
      } catch (_) {}
    }
  }
}

// bearer auth middleware for protected routes
function requireAuth(req, res, next) {
  const hdr = req.get("Authorization") || "";
  const m = hdr.match(/^Bearer\s+(.+)$/i);
  const token = m ? m[1].trim() : "";
  // if there's no API_TOKEN set at all, treat as open
  if (!API_TOKEN || token === API_TOKEN) {
    return next();
  }
  return res.status(403).json({ error: "Forbidden" });
}

// CORS allowlist matcher w/ wildcard like https://*.wixsite.com
function originAllowed(origin) {
  if (!origin) return true; // curl / same-origin / server-side fetch
  if (CORS_ALLOW.length === 0) return true;
  const low = origin.toLowerCase();
  for (const ruleRaw of CORS_ALLOW) {
    const rule = ruleRaw.toLowerCase();

    if (rule.includes("*")) {
      // convert "*.domain.com" style into regex
      const re = new RegExp(
        "^" +
          rule
            .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
            .replace("\\*\\.", ".*\\.")
            .replace("\\*", ".*") +
          "$"
      );
      if (re.test(low)) return true;
    } else {
      if (low === rule) return true;
    }
  }
  return false;
}

// (optional) soft referer checker — logs if request comes from some rando
function checkReferer(req, res, next) {
  if (!ALLOW_FETCH_REFERERS.length) return next();
  const ref = (req.get("Referer") || "").toLowerCase();
  if (!ref) return next();
  const ok = ALLOW_FETCH_REFERERS.some((allowed) => {
    if (allowed.includes("*")) {
      const re = new RegExp(
        "^" +
          allowed
            .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
            .replace("\\*\\.", ".*\\.")
            .replace("\\*", ".*") +
          "$"
      );
      return re.test(ref);
    }
    // loose contains if no wildcard (so "tradingview.com" hits subpages)
    return ref.includes(
      allowed.replace(/^\*+/, "").replace(/\/+$/, "")
    );
  });
  if (!ok) {
    log("WARN referer not allowed-ish:", ref);
  }
  return next();
}

// ---------- express app ----------
const app = express();

app.use(
  cors({
    origin: (origin, cb) => {
      if (originAllowed(origin)) return cb(null, true);
      cb(new Error("CORS blocked: " + origin));
    },
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Accept",
      "Origin",
      "X-Requested-With",
    ],
    credentials: false,
  })
);

app.use(
  express.json({
    limit: "1mb",
  })
);

// serve uploaded images publicly
app.use(
  "/uploads",
  express.static(UPLOAD_DIR, {
    maxAge: "7d",
    immutable: NODE_ENV === "production",
  })
);

// ---------- health ----------
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    env: NODE_ENV,
    ideas: ideas.length,
    now: new Date().toISOString(),
  });
});

// ---------- realtime SSE (/events) ----------
app.get("/events", (req, res) => {
  // dashboard might append ?token=... so we soft-check
  const queryToken = (req.query && req.query.token) || "";
  if (API_TOKEN && queryToken && queryToken !== API_TOKEN) {
    return res.status(403).end();
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  sseClients.add(res);

  // hello packet
  res.write(`event: hello\n`);
  res.write(
    `data: ${JSON.stringify({
      msg: "connected",
      now: Date.now(),
    })}\n\n`
  );

  req.on("close", () => {
    sseClients.delete(res);
    try {
      res.end();
    } catch (_) {}
  });
});

// ---------- ideas feed ----------

// GET /ideas/latest?limit=50
app.get("/ideas/latest", checkReferer, (req, res) => {
  const limit = Math.min(
    200,
    Number(req.query.limit || "50") || 50
  );
  const out = [...ideas]
    .filter((i) => !i.deletedAt)
    .sort(
      (a, b) =>
        new Date(b.createdAt).getTime() -
        new Date(a.createdAt).getTime()
    )
    .slice(0, limit)
    .map(publicIdea);

  res.json(out);
});

// GET /ideas/:id
app.get("/ideas/:id", checkReferer, (req, res) => {
  const idea = findIdea(req.params.id);
  if (!idea || idea.deletedAt) {
    return res.status(404).json({ error: "Not found" });
  }
  res.json({ item: publicIdea(idea) });
});

// POST /ideas (auth)
app.post("/ideas", requireAuth, (req, res) => {
  const {
    title = "",
    symbol = "",
    link = "",
    levelText = "",
    take = "",
    type = "post", // "post" | "signal" | "idea"
    status = "live", // live | won | lost | etc
    authorId = "",
    authorName = "Member",
    authorEmail = "",
    media = [],
    metrics = {},
  } = req.body || {};

  const nowIso = new Date().toISOString();
  const id = uid();

  const likes = { by: {}, count: 0 };
  const comments = [];

  const idea = {
    id,
    title,
    symbol,
    link,
    levelText,
    take,
    type,
    status,
    authorId,
    authorName,
    authorEmail,
    media,
    metrics,
    likes,
    comments,
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  // convenience field for frontend thumbnail
  const firstImg = media.find((m) => m.kind === "image");
  if (firstImg) {
    idea.imageUrl = firstImg.url;
  }

  ideas.unshift(idea);
  saveIdeasAsync();

  broadcastSSE("idea:new", { item: publicIdea(idea) });

  res.json({ ok: true, item: publicIdea(idea) });
});

// PATCH /ideas/:id (auth)
app.patch("/ideas/:id", requireAuth, (req, res) => {
  const idea = findIdea(req.params.id);
  if (!idea || idea.deletedAt) {
    return res.status(404).json({ error: "Not found" });
  }

  const {
    title,
    symbol,
    link,
    levelText,
    take,
    status,
    media,
    metrics,
  } = req.body || {};

  if (title !== undefined) idea.title = title;
  if (symbol !== undefined) idea.symbol = symbol;
  if (link !== undefined) idea.link = link;
  if (levelText !== undefined) idea.levelText = levelText;
  if (take !== undefined) idea.take = take;
  if (status !== undefined) idea.status = status;
  if (metrics !== undefined) idea.metrics = metrics;

  if (Array.isArray(media) && media.length > 0) {
    idea.media = media;
    const firstImg = media.find((m) => m.kind === "image");
    if (firstImg) idea.imageUrl = firstImg.url;
  }

  idea.updatedAt = new Date().toISOString();
  saveIdeasAsync();

  broadcastSSE("idea:update", { item: publicIdea(idea) });

  res.json({ ok: true, item: publicIdea(idea) });
});

// DELETE /ideas/:id (auth)
app.delete("/ideas/:id", requireAuth, (req, res) => {
  const idea = findIdea(req.params.id);
  if (!idea || idea.deletedAt)
    return res.status(404).json({ error: "Not found" });

  idea.deletedAt = new Date().toISOString();
  saveIdeasAsync();

  broadcastSSE("idea:delete", {
    id: idea.id,
    item: { id: idea.id },
  });

  pruneDeleted();

  res.status(204).end();
});

// PUT /ideas/:id/likes
// body: { action: "like"|"unlike", userId, displayName }
app.put("/ideas/:id/likes", (req, res) => {
  const idea = findIdea(req.params.id);
  if (!idea || idea.deletedAt)
    return res.status(404).json({ error: "Not found" });

  if (!idea.likes) {
    idea.likes = { by: {}, count: 0 };
  }

  const { action, userId, displayName } = req.body || {};
  const uidKey = String(userId || "").trim();
  const disp = String(displayName || "Member").trim();

  if (!uidKey) {
    return res
      .status(400)
      .json({ error: "userId required" });
  }

  if (action === "like") {
    idea.likes.by[uidKey] = disp || "Member";
  } else if (action === "unlike") {
    delete idea.likes.by[uidKey];
  }

  idea.likes.count = Object.keys(idea.likes.by).length;
  idea.updatedAt = new Date().toISOString();
  saveIdeasAsync();

  broadcastSSE("likes:update", {
    id: idea.id,
    item: {
      id: idea.id,
      likeCount: idea.likes.count,
      likes: { count: idea.likes.count },
    },
  });

  res.json({
    ok: true,
    likeCount: idea.likes.count,
    item: {
      id: idea.id,
      likeCount: idea.likes.count,
      likes: { count: idea.likes.count },
    },
  });
});

// ---------- comments ----------

// POST /ideas/:id/comments
// body: { text, authorName, authorEmail }
app.post("/ideas/:id/comments", (req, res) => {
  const idea = findIdea(req.params.id);
  if (!idea || idea.deletedAt)
    return res.status(404).json({ error: "Not found" });

  const {
    text = "",
    authorName = "Member",
    authorEmail = "",
  } = req.body || {};

  if (!idea.comments) idea.comments = [];
  const cid = uid();
  const nowIso = new Date().toISOString();

  const comment = {
    id: cid,
    text,
    authorName,
    authorEmail,
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  idea.comments.push(comment);
  idea.updatedAt = nowIso;
  saveIdeasAsync();

  broadcastSSE("comments:update", {
    id: idea.id,
    item: publicIdea(idea),
  });

  res.json({
    ok: true,
    comment,
    item: publicIdea(idea),
  });
});

// PATCH /ideas/:id/comments/:cid
// body: { text }
app.patch("/ideas/:id/comments/:cid", (req, res) => {
  const idea = findIdea(req.params.id);
  if (!idea || idea.deletedAt)
    return res.status(404).json({ error: "Not found" });

  const cid = req.params.cid;
  const c = idea.comments?.find(
    (cm) => String(cm.id) === String(cid)
  );
  if (!c)
    return res
      .status(404)
      .json({ error: "Comment not found" });

  if (req.body.text !== undefined) {
    c.text = req.body.text;
  }
  c.updatedAt = new Date().toISOString();
  idea.updatedAt = c.updatedAt;
  saveIdeasAsync();

  broadcastSSE("comments:update", {
    id: idea.id,
    item: publicIdea(idea),
  });

  res.json({
    ok: true,
    comment: c,
    item: publicIdea(idea),
  });
});

// DELETE /ideas/:id/comments/:cid
app.delete("/ideas/:id/comments/:cid", (req, res) => {
  const idea = findIdea(req.params.id);
  if (!idea || idea.deletedAt)
    return res.status(404).json({ error: "Not found" });

  const cid = req.params.cid;
  const before = idea.comments?.length || 0;
  idea.comments = (idea.comments || []).filter(
    (cm) => String(cm.id) !== String(cid)
  );
  if (idea.comments.length === before) {
    return res
      .status(404)
      .json({ error: "Comment not found" });
  }
  idea.updatedAt = new Date().toISOString();
  saveIdeasAsync();

  broadcastSSE("comments:update", {
    id: idea.id,
    item: publicIdea(idea),
  });

  res.json({ ok: true });
});

// ---------- upload (chart screenshots etc.) ----------

// configure multer disk storage
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname || "");
    const name = crypto
      .randomUUID()
      .replace(/-/g, "")
      .slice(0, 24);
    cb(null, `${name}${ext || ".png"}`);
  },
});

const uploadMw = multer({
  storage,
  limits: {
    fileSize: MAX_UPLOAD_MB * 1024 * 1024,
  },
  fileFilter: (req, file, cb) => {
    const type = (file.mimetype || "").toLowerCase();
    if (!ALLOWED_UPLOAD_TYPES.includes(type)) {
      return cb(new Error("Invalid file type"));
    }
    cb(null, true);
  },
});

// POST /upload  (auth)
// form-data: file=<image>
app.post(
  "/upload",
  requireAuth,
  uploadMw.single("file"),
  (req, res) => {
    if (!req.file) {
      return res
        .status(400)
        .json({ error: "No file uploaded" });
    }

    const basePublic =
      UPLOADS_PUBLIC_BASE_URL ||
      `${req.protocol}://${req.get("host")}`;
    const publicUrl = `${basePublic}/uploads/${req.file.filename}`;

    res.json({
      ok: true,
      url: publicUrl,
      filename: req.file.filename,
      size: req.file.size,
    });
  }
);

// ---------- email notify ----------

// nodemailer transport
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_SECURE,
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS,
  },
});

// escape html util
function escapeHtml(v) {
  if (v === undefined || v === null) return "";
  return String(v).replace(
    /[&<>"']/g,
    (m) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[m])
  );
}

// build the email body for /email/post
function buildEmailHTML({ item = {}, actor = {}, kind = "post" }) {
  const sym = item.symbol || "";
  const title = item.title || "(no title)";
  const take = item.take || item.content || "";
  const levelText = item.levelText || item.levels || "";
  const createdAt =
    item.createdAt || new Date().toISOString();

  const heroColor =
    kind === "signal"
      ? "#20d6a7"
      : kind === "idea"
      ? "#00d0ff"
      : "#111827";

  return `
  <div style="background:${EMAIL_BODY_BG ||
    "#ffffff"};font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial,sans-serif;padding:20px;color:#111;border-top:4px solid ${heroColor};max-width:480px;margin:0 auto;">
    <div style="text-align:center;margin-bottom:16px;">
      <img src="${EMAIL_LOGO_URL}" alt="${SITE_NAME}" style="max-width:120px;border-radius:8px;border:1px solid #ccc;background:#fff"/>
      <div style="font-size:12px;color:#666;margin-top:4px;">${SITE_NAME}</div>
    </div>

    <h2 style="font-size:18px;margin:0 0 8px;line-height:1.4;">
      ${sym ? `<span style="color:${heroColor};font-weight:600;">${sym}</span> — ` : ""}${escapeHtml(
    title
  )}
    </h2>

    <div style="font-size:13px;color:#444;line-height:1.5;white-space:pre-line;border:1px solid #ddd;border-radius:8px;padding:12px;margin-bottom:12px;background:#fafafa;">
      ${
        take
          ? `<div style="margin-bottom:8px;"><strong>Plan / Take:</strong><br/>${escapeHtml(
              take
            )}</div>`
          : ""
      }
      ${
        levelText
          ? `<div><strong>Levels:</strong><br/>${escapeHtml(
              levelText
            )}</div>`
          : ""
      }
    </div>

    <div style="font-size:12px;color:#555;line-height:1.4;margin-bottom:10px;">
      Posted ${new Date(
        createdAt
      ).toLocaleString()}<br/>
      Triggered by ${escapeHtml(
        actor.name || "Member"
      )} (${escapeHtml(actor.email || "")})
    </div>

    ${
      item.imageUrl
        ? `<div style="text-align:center;margin-bottom:12px;">
            <img src="${item.imageUrl}" alt="chart" style="max-width:100%;border:1px solid #ddd;border-radius:8px"/>
          </div>`
        : ""
    }

    <div style="font-size:12px;color:#999;text-align:center;border-top:1px solid #eee;padding-top:12px;">
      <div>${SITE_NAME}</div>
      <div><a href="${SITE_URL}" style="color:#666;text-decoration:none;">${SITE_URL}</a></div>
    </div>
  </div>
  `;
}

// POST /email/post (auth)
// body: { kind, item, actor }
// kind: "post" | "signal" | "idea"
app.post("/email/post", requireAuth, async (req, res) => {
  const { kind = "post", item = {}, actor = {} } =
    req.body || {};

  // who do we send it to?
  // if EMAIL_FORCE_ALL_TO is set, that overrides and we shotgun to that list.
  let toList = [];
  if (EMAIL_FORCE_ALL_TO) {
    toList = EMAIL_FORCE_ALL_TO.split(",")
      .map((x) => x.trim())
      .filter(Boolean);
  } else {
    if (actor.email) {
      toList.push(String(actor.email).trim());
    }
  }

  // also BCC admin(s)
  const bccList = EMAIL_BCC_ADMIN
    ? EMAIL_BCC_ADMIN.split(",")
        .map((x) => x.trim())
        .filter(Boolean)
    : [];

  if (toList.length === 0 && bccList.length === 0) {
    return res.status(400).json({
      error:
        "No recipients configured (EMAIL_FORCE_ALL_TO / actor.email / EMAIL_BCC_ADMIN)",
    });
  }

  const subjectPieces = [];
  if (item.symbol) subjectPieces.push(`[${item.symbol}]`);
  subjectPieces.push(item.title || "New Update");
  const subject = subjectPieces.join(" ");

  const html = buildEmailHTML({ item, actor, kind });

  try {
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: toList,
      bcc: bccList,
      subject,
      html,
    });

    res.json({ ok: true, sent: true });
  } catch (err) {
    log("EMAIL ERROR", err);
    res
      .status(500)
      .json({ ok: false, error: "Email send failed" });
  }
});

// ---------- email capture / subscribe ----------

// shared handler for /subscribe, /api/subscribe, /email/subscribe
async function handleSubscribe(req, res) {
  const { name = "Member", email = "" } = req.body || {};
  const e = String(email || "").trim().toLowerCase();
  if (!e || !/.+@.+\..+/.test(e)) {
    return res
      .status(400)
      .json({ error: "valid email required" });
  }

  // dedupe
  if (!subscribers.find((s) => s.email === e)) {
    subscribers.push({
      id: uid(),
      name: String(name || "Member"),
      email: e,
      addedAt: new Date().toISOString(),
    });
    await saveJSON(SUBSCRIBERS_FILE, subscribers);
    log("Subscribed:", e);
  }

  res.json({ ok: true });
}

app.post("/subscribe", handleSubscribe);
app.post("/api/subscribe", handleSubscribe);
app.post("/email/subscribe", handleSubscribe);

// ---------- start server ----------
app.listen(PORT, () => {
  log(
    `TCPP backend listening on ${PORT} (${NODE_ENV}) ideas=${ideas.length}`
  );
});
