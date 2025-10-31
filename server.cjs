// scripts/fix-author-names.cjs
'use strict';
const fs = require('fs');
const path = require('path');

const DATA_DIR  = process.env.DATA_DIR || '/data';
const DATA_FILE = path.join(DATA_DIR, 'ideas.json');
const RESERVED  = new Set(['api','system','backend','service','member','(user)','trader']);

function sanitizeName(s=''){
  return String(s).replace(/[^\p{Letter}\p{Number}\s._-]/gu,'').replace(/\s+/g,' ').trim().slice(0,60);
}
function emailLocal(e=''){ const m=String(e).toLowerCase().match(/^([^@]+)/); return m?m[1]:''; }

const db = JSON.parse(fs.readFileSync(DATA_FILE,'utf8'));
let changed = 0;

for (const it of db.ideas || []) {
  const nm = sanitizeName(it.authorName||'');
  const em = String(it.authorEmail||'').trim().toLowerCase();
  if (!nm || RESERVED.has(nm.toLowerCase())) {
    const fix = sanitizeName(emailLocal(em)) || 'Member';
    if (fix !== nm) { it.authorName = fix; changed++; }
  }
  if (em !== (it.authorEmail||'')) it.authorEmail = em;
  if (Array.isArray(it.comments?.items)) {
    for (const c of it.comments.items) {
      const cn = sanitizeName(c.authorName||'');
      if (!cn || RESERVED.has(cn.toLowerCase())) {
        const fallback = sanitizeName(emailLocal(c.authorId||'')) || 'Member';
        if (fallback !== cn) { c.authorName = fallback; changed++; }
      }
    }
  }
}

fs.writeFileSync(DATA_FILE + '.bak', JSON.stringify(db,null,2));
fs.renameSync(DATA_FILE + '.bak', DATA_FILE);
console.log(`Author name fixes applied: ${changed}`);
