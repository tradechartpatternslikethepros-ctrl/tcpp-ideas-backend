// Trade Chart Patterns Like The Pros
// Full production backend (Express + SSE + Upload + Email)
// CommonJS build for Railway (node server.cjs)
//
// Endpoints exposed:
//   GET    /health
//   GET    /events                        (SSE realtime)
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
//   POST   /email/post                    (auth, broadcast email alert)
//   POST   /subscribe (/api/subscribe, /email/subscribe aliases)
//   GET    /uploads/*                     (serves uploaded charts)
//
// Persistence:
//   DATA_DIR/ideas.json
//   DATA_DIR/subscribers.json
//
// Auth model:
//   Requests that mutate (/ideas POST/PATCH/DELETE, /upload, /email/post)
//   must send header: Authorization: Bearer <API_TOKEN>

const fs = require("fs");
const fsPromises = require("fs/promises");
const path = require("path");
const express = require("express");
const cors = require("cors");
const multer = require("multer");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const dotenv = require("dotenv");

dotenv.config();

// ---------- env / config ----------
const PORT = process.env.PORT || "8080";
const NODE_ENV = process.env.NODE_ENV || "development";

const API_TOKEN = process.env.API_TOKEN || "";

// CORS allowlist (supports wildcards like https://*.wixsite.com)
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
); // reserved for future remote-import logic

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
  process.env.EMAIL_FORCE_ALL_TO || ""; // comma list. if set, every alert goes here

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
  process.env.UPLOADS_PUBLIC_BASE_URL || ""; // e.g. https://tcpp-ideas-backend-production.up.railway.app

const EMAIL_THEME = process.env.EMAIL_THEME || "white";
const EMAIL_LAYOUT = process.env.EMAIL_LAYOUT || "hero-first";
const EMAIL_BODY_BG = process.env.EMAIL_BODY_BG || "";

const ALLOW_FETCH_REFERERS = (process.env.ALLOW_FETCH_REFERERS ||
  "")
  .split(",")
  .map((x) => x.trim().toLowerCase())
  .filter(Boolean);

// ---------- tiny logger ----------
function log() {
  const args = Array.from(arguments);
  console.log(new Date().toISOString() + " -", ...args);
}

// ---------- make sure data dirs exist ----------
function ensureDirSync(dir) {
  try {
    fs.mkdirSync(dir, { recursive: true });
  } catch (e) {
    // ignore
  }
}
ensureDirSync(DATA_DIR);
ensureDirSync(UPLOAD_DIR);

// ---------- data file paths ----------
const IDEAS_FILE = path.join(DATA_DIR, "ideas.json");
const SUBSCRIBERS_FILE = path.join(DATA_DIR, "subscribers.json");

// ---------- load persisted state (sync on boot so we start "warm") ----------
function loadJSONSync(file, fallbackVal) {
  try {
    const raw = fs.readFileSync(file, "utf8");
    return JSON.parse(raw);
  } catch (e) {
    return fallbackVal;
  }
}

let ideas = loadJSONSync(IDEAS_FILE, []);
let subscribers = loadJSONSync(SUBSCRIBERS_FILE, []);

// ---------- runtime state ----------
const sseClients = new Set(); // all active EventSource connections

// ---------- helpers ----------
function uid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return (
    "id_" +
    Math.random().toString(36).slice(2) +
    Date.now().toString(36)
  );
}

function saveJSONAsync(file, data) {
  fsPromises
    .writeFile(file, JSON.stringify(data, null, 2), "utf8")
    .catch((err) => log("ERR saving", file, err));
}

function publicIdea(i) {
  // For now we return full object. Client handles privacy masking.
  return i;
}

function findIdea(id) {
  return ideas.find((i) => String(i.id) === String(id));
}

function pruneDeleted() {
  ideas = ideas.filter((i) => !i.deletedAt);
  saveJSONAsync(IDEAS_FILE, ideas);
}

// broadcast event to all SSE listeners
function broadcastSSE(event, payloadObj) {
  const data = JSON.stringify(payloadObj || {});
  for (const res of sseClients) {
    try {
      res.write("event: " + event + "\n");
      res.write("data: " + data + "\n\n");
    } catch (err) {
      // connection is probably gone
      sseClients.delete(res);
      try {
        res.end();
      } catch (_) {}
    }
  }
}

// Bearer auth middleware
function requireAuth(req, res, next) {
  const hdr = req.get("Authorization") || "";
  const m = hdr.match(/^Bearer\s+(.+)$/i);
  const token = m ? m[1].trim() : "";
  // If API_TOKEN isn't set, effectively open
  if (!API_TOKEN || token === API_TOKEN) return next();
  return res.status(403).json({ error: "Forbidden" });
}

// wildcard-aware origin matcher for CORS
function originAllowed(origin) {
  if (!origin) return true; // e.g. curl / internal
  if (!CORS_ALLOW.length) return true;
  const low = origin.toLowerCase();
  for (const ruleRaw of CORS_ALLOW) {
    const rule = ruleRaw.toLowerCase();
    if (rule.includes("*")) {
      // turn "https://*.wixsite.com" into a regex
      const safe = rule
        .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
        .replace("\\*\\.", ".*\\.")
        .replace("\\*", ".*");
      const re = new RegExp("^" + safe + "$");
      if (re.test(low)) return true;
    } else {
      if (low === rule) return true;
    }
  }
  return false;
}

// SAFE referer checker (no regex crash).
// We don't hard-block if not allowed — we just warn and continue.
// This protects you from breaking prod just because of a funky pattern.
function checkReferer(req, res, next) {
  if (!ALLOW_FETCH_REFERERS.length) return next();

  const ref = (req.get("Referer") || "").toLowerCase();
  if (!ref) return next();

  const ok = ALLOW_FETCH_REFERERS.some((ruleRaw) => {
    const rule = ruleRaw.toLowerCase();

    // if rule has a wildcard, we just do substring check
    //   "*.tradingview.com" -> "tradingview.com"
    //   "*foo*"             -> "foo"
    if (rule.includes("*")) {
      const core = rule.replace(/\*/g, "");
      if (!core) return true; // "*" means allow any
      return ref.includes(core);
    }

    // no wildcard:
    // we accept if referer contains the rule anywhere
    // ("https://www.tradingview.com/..." includes "tradingview.com")
    return ref.includes(rule);
  });

  if (!ok) {
    log("WARN referer not allowed-ish:", ref);
  }
  return next();
}

// ---------- express setup ----------
const app = express();

// trust proxy so req.protocol is correct behind Railway's HTTPS proxy
app.set("trust proxy", true);

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

// serve uploaded images back out
app.use(
  "/uploads",
  express.static(UPLOAD_DIR, {
    maxAge: "7d",
    immutable: NODE_ENV === "production",
  })
);

// ---------- /health ----------
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    env: NODE_ENV,
    ideas: ideas.length,
    now: new Date().toISOString(),
  });
});

// ---------- /events (SSE realtime) ----------
app.get("/events", (req, res) => {
  // dashboard may pass ?token=... ; honor it if API_TOKEN is set
  const queryToken = (req.query && req.query.token) || "";
  if (API_TOKEN && queryToken && queryToken !== API_TOKEN) {
    return res.status(403).end();
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  if (res.flushHeaders) res.flushHeaders();

  sseClients.add(res);

  // initial hello packet
  res.write("event: hello\n");
  res.write(
    "data: " +
      JSON.stringify({
        msg: "connected",
        now: Date.now(),
      }) +
      "\n\n"
  );

  req.on("close", function () {
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
  const out = []
    .concat(ideas)
    .filter((i) => !i.deletedAt)
    .sort(function (a, b) {
      return (
        new Date(b.createdAt).getTime() -
        new Date(a.createdAt).getTime()
      );
    })
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

// POST /ideas  (auth)
app.post("/ideas", requireAuth, (req, res) => {
  const body = req.body || {};

  const nowIso = new Date().toISOString();
  const idVal = uid();

  const likes = { by: {}, count: 0 };
  const comments = [];

  const mediaArr = Array.isArray(body.media) ? body.media : [];

  const idea = {
    id: idVal,

    title: body.title || "",
    symbol: body.symbol || "",
    link: body.link || "",
    levelText: body.levelText || "",
    take: body.take || "",
    type: body.type || "post", // "post" | "signal" | "idea"
    status: body.status || "live",

    authorId: body.authorId || "",
    authorName: body.authorName || "Member",
    authorEmail: body.authorEmail || "",

    media: mediaArr,
    metrics: body.metrics || {},

    likes,
    comments,

    createdAt: nowIso,
    updatedAt: nowIso,
  };

  // convenience: first image => idea.imageUrl
  const firstImg = mediaArr.find((m) => m.kind === "image");
  if (firstImg) {
    idea.imageUrl = firstImg.url;
  }

  ideas.unshift(idea);
  saveJSONAsync(IDEAS_FILE, ideas);

  broadcastSSE("idea:new", { item: publicIdea(idea) });

  res.json({ ok: true, item: publicIdea(idea) });
});

// PATCH /ideas/:id  (auth)
app.patch("/ideas/:id", requireAuth, (req, res) => {
  const idea = findIdea(req.params.id);
  if (!idea || idea.deletedAt) {
    return res.status(404).json({ error: "Not found" });
  }
  const body = req.body || {};

  if (body.title !== undefined) idea.title = body.title;
  if (body.symbol !== undefined) idea.symbol = body.symbol;
  if (body.link !== undefined) idea.link = body.link;
  if (body.levelText !== undefined)
    idea.levelText = body.levelText;
  if (body.take !== undefined) idea.take = body.take;
  if (body.status !== undefined) idea.status = body.status;
  if (body.metrics !== undefined) idea.metrics = body.metrics;

  if (Array.isArray(body.media) && body.media.length > 0) {
    idea.media = body.media;
    const f = body.media.find((m) => m.kind === "image");
    if (f) idea.imageUrl = f.url;
  }

  idea.updatedAt = new Date().toISOString();
  saveJSONAsync(IDEAS_FILE, ideas);

  broadcastSSE("idea:update", { item: publicIdea(idea) });

  res.json({ ok: true, item: publicIdea(idea) });
});

// DELETE /ideas/:id  (auth)
app.delete("/ideas/:id", requireAuth, (req, res) => {
  const idea = findIdea(req.params.id);
  if (!idea || idea.deletedAt) {
    return res.status(404).json({ error: "Not found" });
  }

  idea.deletedAt = new Date().toISOString();
  saveJSONAsync(IDEAS_FILE, ideas);

  broadcastSSE("idea:delete", {
    id: idea.id,
    item: { id: idea.id },
  });

  pruneDeleted(); // also persists

  res.status(204).end();
});

// PUT /ideas/:id/likes
// body: { action: "like"|"unlike", userId, displayName }
app.put("/ideas/:id/likes", (req, res) => {
  const idea = findIdea(req.params.id);
  if (!idea || idea.deletedAt) {
    return res.status(404).json({ error: "Not found" });
  }

  if (!idea.likes) {
    idea.likes = { by: {}, count: 0 };
  }

  const body = req.body || {};
  const action = body.action;
  const userId = (body.userId || "").trim();
  const displayName = (body.displayName || "Member").trim();

  if (!userId) {
    return res
      .status(400)
      .json({ error: "userId required" });
  }

  if (action === "like") {
    idea.likes.by[userId] = displayName || "Member";
  } else if (action === "unlike") {
    delete idea.likes.by[userId];
  }

  idea.likes.count = Object.keys(idea.likes.by).length;
  idea.updatedAt = new Date().toISOString();
  saveJSONAsync(IDEAS_FILE, ideas);

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
  if (!idea || idea.deletedAt) {
    return res.status(404).json({ error: "Not found" });
  }

  const body = req.body || {};
  const text = body.text || "";
  const authorName = body.authorName || "Member";
  const authorEmail = body.authorEmail || "";

  if (!idea.comments) idea.comments = [];

  const cid = uid();
  const nowIso = new Date().toISOString();

  const commentObj = {
    id: cid,
    text: text,
    authorName: authorName,
    authorEmail: authorEmail,
    createdAt: nowIso,
    updatedAt: nowIso,
  };

  idea.comments.push(commentObj);
  idea.updatedAt = nowIso;
  saveJSONAsync(IDEAS_FILE, ideas);

  broadcastSSE("comments:update", {
    id: idea.id,
    item: publicIdea(idea),
  });

  res.json({
    ok: true,
    comment: commentObj,
    item: publicIdea(idea),
  });
});

// PATCH /ideas/:id/comments/:cid
// body: { text }
app.patch("/ideas/:id/comments/:cid", (req, res) => {
  const idea = findIdea(req.params.id);
  if (!idea || idea.deletedAt) {
    return res.status(404).json({ error: "Not found" });
  }

  const cid = req.params.cid;
  const c = (idea.comments || []).find(function (cm) {
    return String(cm.id) === String(cid);
  });
  if (!c) {
    return res
      .status(404)
      .json({ error: "Comment not found" });
  }

  if (req.body && req.body.text !== undefined) {
    c.text = req.body.text;
  }
  c.updatedAt = new Date().toISOString();
  idea.updatedAt = c.updatedAt;
  saveJSONAsync(IDEAS_FILE, ideas);

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
  if (!idea || idea.deletedAt) {
    return res.status(404).json({ error: "Not found" });
  }

  const beforeLen = (idea.comments || []).length;
  idea.comments = (idea.comments || []).filter(function (cm) {
    return String(cm.id) !== String(req.params.cid);
  });
  if (idea.comments.length === beforeLen) {
    return res
      .status(404)
      .json({ error: "Comment not found" });
  }

  idea.updatedAt = new Date().toISOString();
  saveJSONAsync(IDEAS_FILE, ideas);

  broadcastSSE("comments:update", {
    id: idea.id,
    item: publicIdea(idea),
  });

  res.json({ ok: true });
});

// ---------- upload (chart screenshots etc.) ----------

// multer storage on disk
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
    cb(null, name + (ext || ".png"));
  },
});

const uploadMw = multer({
  storage: storage,
  limits: {
    fileSize: MAX_UPLOAD_MB * 1024 * 1024,
  },
  fileFilter: function (req, file, cb) {
    const type = (file.mimetype || "").toLowerCase();
    if (!ALLOWED_UPLOAD_TYPES.includes(type)) {
      return cb(new Error("Invalid file type"));
    }
    cb(null, true);
  },
});

// POST /upload (auth)
// multipart/form-data with field `file`
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
      req.protocol + "://" + req.get("host");
    const publicUrl =
      basePublic + "/uploads/" + req.file.filename;

    res.json({
      ok: true,
      url: publicUrl,
      filename: req.file.filename,
      size: req.file.size,
    });
  }
);

// ---------- email alerts ----------

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
  return String(v).replace(/[&<>"']/g, function (m) {
    return {
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[m];
  });
}

// builds the HTML email body for /email/post
function buildEmailHTML(params) {
  params = params || {};
  const item = params.item || {};
  const actor = params.actor || {};
  const kind = params.kind || "post";

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

  return (
    '<div style="background:' +
    (EMAIL_BODY_BG || "#ffffff") +
    ';font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Arial,sans-serif;padding:20px;color:#111;border-top:4px solid ' +
    heroColor +
    ';max-width:480px;margin:0 auto;">' +
    '<div style="text-align:center;margin-bottom:16px;">' +
    '<img src="' +
    EMAIL_LOGO_URL +
    '" alt="' +
    SITE_NAME +
    '" style="max-width:120px;border-radius:8px;border:1px solid #ccc;background:#fff"/>' +
    '<div style="font-size:12px;color:#666;margin-top:4px;">' +
    SITE_NAME +
    "</div>" +
    "</div>" +
    '<h2 style="font-size:18px;margin:0 0 8px;line-height:1.4;">' +
    (sym
      ? '<span style="color:' +
        heroColor +
        ';font-weight:600;">' +
        sym +
        "</span> — "
      : "") +
    escapeHtml(title) +
    "</h2>" +
    '<div style="font-size:13px;color:#444;line-height:1.5;white-space:pre-line;border:1px solid #ddd;border-radius:8px;padding:12px;margin-bottom:12px;background:#fafafa;">' +
    (take
      ? '<div style="margin-bottom:8px;"><strong>Plan / Take:</strong><br/>' +
        escapeHtml(take) +
        "</div>"
      : "") +
    (levelText
      ? '<div><strong>Levels:</strong><br/>' +
        escapeHtml(levelText) +
        "</div>"
      : "") +
    "</div>" +
    '<div style="font-size:12px;color:#555;line-height:1.4;margin-bottom:10px;">' +
    "Posted " +
    new Date(createdAt).toLocaleString() +
    "<br/>" +
    "Triggered by " +
    escapeHtml(actor.name || "Member") +
    " (" +
    escapeHtml(actor.email || "") +
    ")" +
    "</div>" +
    (item.imageUrl
      ? '<div style="text-align:center;margin-bottom:12px;">' +
        '<img src="' +
        item.imageUrl +
        '" alt="chart" style="max-width:100%;border:1px solid #ddd;border-radius:8px"/>' +
        "</div>"
      : "") +
    '<div style="font-size:12px;color:#999;text-align:center;border-top:1px solid #eee;padding-top:12px;">' +
    "<div>" +
    SITE_NAME +
    "</div>" +
    '<div><a href="' +
    SITE_URL +
    '" style="color:#666;text-decoration:none;">' +
    SITE_URL +
    "</a></div>" +
    "</div>" +
    "</div>"
  );
}

// POST /email/post (auth)
// body: { kind, item, actor }
app.post("/email/post", requireAuth, async (req, res) => {
  const body = req.body || {};
  const kind = body.kind || "post";
  const item = body.item || {};
  const actor = body.actor || {};

  // recipients:
  // priority 1: EMAIL_FORCE_ALL_TO if set
  // fallback: actor.email (the person posting)
  // always BCC admin list if configured
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
  if (item.symbol) subjectPieces.push("[" + item.symbol + "]");
  subjectPieces.push(item.title || "New Update");
  const subject = subjectPieces.join(" ");

  const html = buildEmailHTML({
    item: item,
    actor: actor,
    kind: kind,
  });

  try {
    await transporter.sendMail({
      from: EMAIL_FROM,
      to: toList,
      bcc: bccList,
      subject: subject,
      html: html,
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

async function handleSubscribe(req, res) {
  const body = req.body || {};
  const name = body.name || "Member";
  const email = (body.email || "").trim().toLowerCase();

  if (!email || !/.+@.+\..+/.test(email)) {
    return res
      .status(400)
      .json({ error: "valid email required" });
  }

  // dedupe
  const exists = subscribers.find(function (s) {
    return s.email === email;
  });
  if (!exists) {
    subscribers.push({
      id: uid(),
      name: String(name || "Member"),
      email: email,
      addedAt: new Date().toISOString(),
    });
    await fsPromises
      .writeFile(
        SUBSCRIBERS_FILE,
        JSON.stringify(subscribers, null, 2),
        "utf8"
      )
      .catch(function (err) {
        log("ERR saving subscribers", err);
      });
    log("Subscribed:", email);
  }

  res.json({ ok: true });
}

// POST /subscribe
app.post("/subscribe", handleSubscribe);
// mirror endpoints the frontend might try
app.post("/api/subscribe", handleSubscribe);
app.post("/email/subscribe", handleSubscribe);

// ---------- go live ----------
app.listen(PORT, function () {
  log(
    "TCPP backend listening on",
    PORT,
    "(" + NODE_ENV + ")",
    "ideas=" + ideas.length
  );
});
