/*
 ╔════════════════════════════════════════════════════════╗
 ║   صقر | SAQR ADMIN — لوحة الويب (بدون أي مكتبات خارجية)    ║
 ╚════════════════════════════════════════════════════════╝
 التشغيل:  node server.js
 المتغيرات (ملف .env أو إعدادات الاستضافة):
   SAQR_KEY      مفتاح سري طويل (نفسه في روبلوكس)        — إلزامي
   PANEL_USERS   حسابات اللوحة:  ahmed:كلمة_سر,sara:كلمة_سر2 — إلزامي
   PORT          المنفذ (افتراضي 3000)
   DEMO=1        يشغل بيانات تجريبية بدون روبلوكس
*/
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');

// ---------- تحميل .env بسيط ----------
try {
  const envFile = path.join(__dirname, '.env');
  if (fs.existsSync(envFile)) {
    for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*)\s*$/);
      if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  }
} catch (e) { /* ignore */ }

const PORT = parseInt(process.env.PORT || '3000', 10);
const DEMO = process.env.DEMO === '1' || process.argv.includes('--demo');
const SAQR_KEY = process.env.SAQR_KEY || (DEMO ? crypto.randomBytes(24).toString('hex') : '');
const TRUST_PROXY = process.env.TRUST_PROXY !== '0';

if (SAQR_KEY.length < 24) {
  console.error('❌ SAQR_KEY لازم يكون 24 حرف أو أكثر. شغّل:  node server.js genkey');
  if (process.argv[2] !== 'genkey') process.exit(1);
}
if (process.argv[2] === 'genkey') {
  console.log('🔑 مفتاحك الجديد:\n' + crypto.randomBytes(32).toString('base64url'));
  process.exit(0);
}

// ---------- الحسابات (كلمات السر تتشفر في الذاكرة بـ scrypt) ----------
const USERS = new Map();
for (const pair of (process.env.PANEL_USERS || (DEMO ? 'admin:admin12345' : '')).split(',')) {
  const i = pair.indexOf(':');
  if (i <= 0) continue;
  const name = pair.slice(0, i).trim().slice(0, 32);
  const pass = pair.slice(i + 1);
  if (pass.length < 8) { console.error(`❌ كلمة سر ${name} قصيرة (أقل شي 8)`); process.exit(1); }
  const salt = crypto.randomBytes(16);
  USERS.set(name.toLowerCase(), { name, salt, hash: crypto.scryptSync(pass, salt, 64) });
}
if (USERS.size === 0) { console.error('❌ حط PANEL_USERS مثل:  ahmed:MyStrongPass123'); process.exit(1); }

// ---------- الحالة ----------
const DATA_FILE = path.join(__dirname, 'data.json');
const state = {
  servers: new Map(),   // jobId -> {...}
  queue: [],            // {id, text, target, by, time, delivered:Set, results:[]}
  logs: [],             // سجل موحد
  audit: [],            // سجل أفعال اللوحة
  catalog: [],          // قائمة الأوامر من روبلوكس
  stats: { commandsToday: 0, day: new Date().toDateString() },
};
try {
  const saved = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  state.logs = Array.isArray(saved.logs) ? saved.logs.slice(-1000) : [];
  state.audit = Array.isArray(saved.audit) ? saved.audit.slice(-500) : [];
  state.catalog = Array.isArray(saved.catalog) ? saved.catalog : [];
} catch (e) { /* أول تشغيل */ }

let saveTimer = null;
function save() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    const data = JSON.stringify({ logs: state.logs.slice(-1000), audit: state.audit.slice(-500), catalog: state.catalog });
    fs.writeFile(DATA_FILE + '.tmp', data, (err) => { if (!err) fs.rename(DATA_FILE + '.tmp', DATA_FILE, () => {}); });
  }, 2000);
}

function pushLog(entry) {
  state.logs.push(entry);
  if (state.logs.length > 1500) state.logs.splice(0, state.logs.length - 1000);
  save();
}

// ---------- أدوات الأمان ----------
const sessions = new Map(); // token -> {user, exp, csrf}
const SESSION_MS = 12 * 60 * 60 * 1000;
const loginAttempts = new Map(); // ip -> {count, until}
const rate = new Map(); // ip -> {tokens, last}

function clientIp(req) {
  if (TRUST_PROXY) {
    const xf = req.headers['x-forwarded-for'];
    if (typeof xf === 'string' && xf.length) return xf.split(',')[0].trim();
  }
  return req.socket.remoteAddress || '?';
}

function allowRate(ip, perSec = 10, burst = 30) {
  const now = Date.now();
  let b = rate.get(ip);
  if (!b) { b = { tokens: burst, last: now }; rate.set(ip, b); }
  b.tokens = Math.min(burst, b.tokens + ((now - b.last) / 1000) * perSec);
  b.last = now;
  if (b.tokens < 1) return false;
  b.tokens -= 1;
  return true;
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) { crypto.timingSafeEqual(ab, ab); return false; }
  return crypto.timingSafeEqual(ab, bb);
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function getSession(req) {
  const tok = parseCookies(req).saqr_s;
  if (!tok || tok.length !== 64) return null;
  const s = sessions.get(tok);
  if (!s) return null;
  if (Date.now() > s.exp) { sessions.delete(tok); return null; }
  s.token = tok;
  return s;
}

function cleanText(t, max) {
  // يشيل رموز التحكم ويقص الطول
  return String(t ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
}

const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://*.rbxcdn.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
};

function send(res, code, body, headers = {}) {
  const isObj = typeof body === 'object' && !Buffer.isBuffer(body);
  const data = isObj ? JSON.stringify(body) : body;
  res.writeHead(code, {
    ...SEC_HEADERS,
    'Content-Type': isObj ? 'application/json; charset=utf-8' : 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    ...headers,
  });
  res.end(data);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new Error('too_large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); }
      catch (e) { reject(new Error('bad_json')); }
    });
    req.on('error', reject);
  });
}

// ---------- صور اللاعبين ----------
const thumbCache = new Map();
function fetchThumbs(ids) {
  const need = ids.filter((id) => !thumbCache.has(id)).slice(0, 100);
  if (!need.length) return;
  need.forEach((id) => thumbCache.set(id, ''));
  const url = `https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${need.join(',')}&size=60x60&format=Png&isCircular=false`;
  https.get(url, { timeout: 5000 }, (r) => {
    let d = '';
    r.on('data', (c) => { d += c; if (d.length > 200000) r.destroy(); });
    r.on('end', () => {
      try {
        for (const it of JSON.parse(d).data || []) {
          if (it && /^https:\/\/[a-z0-9.-]+\.rbxcdn\.com\//.test(it.imageUrl || '')) thumbCache.set(it.targetId, it.imageUrl);
        }
      } catch (e) { /* ignore */ }
    });
  }).on('error', () => { need.forEach((id) => thumbCache.delete(id)); });
}

// ---------- الملفات الثابتة ----------
const PUBLIC = path.join(__dirname, 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.txt': 'text/plain; charset=utf-8' };
function serveStatic(req, res, urlPath) {
  let p = urlPath === '/' ? '/index.html' : urlPath;
  const embedded = globalThis.__SAQR_ASSETS;
  if (embedded) {
    const a = embedded[p];
    if (!a) return send(res, 404, 'not found');
    res.writeHead(200, { ...SEC_HEADERS, 'Content-Type': a.type, 'Cache-Control': 'no-cache' });
    return res.end(a.text != null ? a.text : Buffer.from(a.b64, 'base64'));
  }
  p = path.normalize(decodeURIComponent(p)).replace(/^(\.\.[/\\])+/, '');
  const file = path.join(PUBLIC, p);
  if (!file.startsWith(PUBLIC + path.sep)) return send(res, 403, 'forbidden');
  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, 'not found');
    res.writeHead(200, { ...SEC_HEADERS, 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}

// ---------- منطق الأوامر ----------
function liveServers() {
  const now = Date.now();
  const out = [];
  for (const [id, s] of state.servers) {
    if (now - s.lastSeen > 45000 || s.closing) { if (now - s.lastSeen > 5 * 60000) state.servers.delete(id); continue; }
    out.push(s);
  }
  return out;
}

function enqueue(text, target, by) {
  const day = new Date().toDateString();
  if (state.stats.day !== day) { state.stats.day = day; state.stats.commandsToday = 0; }
  state.stats.commandsToday++;
  const cmd = { id: crypto.randomBytes(9).toString('base64url'), text, target, by, time: Date.now(), delivered: new Set(), results: [] };
  state.queue.push(cmd);
  if (state.queue.length > 300) state.queue.splice(0, state.queue.length - 200);
  state.audit.push({ t: Date.now(), by, text, target });
  if (state.audit.length > 800) state.audit.splice(0, state.audit.length - 500);
  save();
  return cmd;
}

function commandsFor(jobId) {
  const out = [];
  const now = Date.now();
  for (const c of state.queue) {
    if (now - c.time > 2 * 60000) continue; // الأوامر القديمة تنتهي
    if (c.delivered.has(jobId)) continue;
    if (c.target !== 'all' && c.target !== jobId) continue;
    c.delivered.add(jobId);
    out.push({ id: c.id, text: c.text, by: c.by });
    if (out.length >= 10) break;
  }
  return out;
}

// ---------- الراوتر ----------
async function handle(req, res) {
  const ip = clientIp(req);
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  // ===== روبلوكس =====
  if (p === '/api/roblox/sync' && req.method === 'POST') {
    if (!allowRate('rbx:' + ip, 40, 120)) return send(res, 429, { error: 'rate' });
    if (!safeEqual(req.headers['x-saqr-key'] || '', SAQR_KEY)) return send(res, 401, { error: 'key' });
    let body;
    try { body = await readBody(req, 256 * 1024); } catch (e) { return send(res, 413, { error: e.message }); }
    const jobId = cleanText(body.jobId, 64);
    if (!jobId) return send(res, 400, { error: 'jobId' });
    const players = Array.isArray(body.players) ? body.players.slice(0, 200).map((pl) => ({
      id: Number(pl.id) || 0, name: cleanText(pl.name, 32), display: cleanText(pl.display, 40),
      rank: Math.max(0, Math.min(5, Number(pl.rank) || 0)), rankName: cleanText(pl.rankName, 20), team: pl.team ? cleanText(pl.team, 40) : null,
    })) : [];
    const prev = state.servers.get(jobId);
    state.servers.set(jobId, {
      jobId, placeId: Number(body.placeId) || 0, placeVersion: Number(body.placeVersion) || 0,
      players, maxPlayers: Number(body.maxPlayers) || 0, uptime: Number(body.uptime) || 0, fps: Number(body.fps) || 0,
      event: body.event ? cleanText(body.event, 32) : null, locked: Number(body.locked) || 0, studio: !!body.studio,
      lastSeen: Date.now(), firstSeen: prev ? prev.firstSeen : Date.now(), closing: !!body.closing,
    });
    fetchThumbs(players.map((x) => x.id));
    if (Array.isArray(body.logs)) {
      for (const l of body.logs.slice(0, 200)) {
        pushLog({ t: (Number(l.t) || Date.now() / 1000) * 1000, by: cleanText(l.by, 60), text: cleanText(l.text, 300), kind: cleanText(l.kind, 12), server: jobId.slice(0, 8) });
      }
    }
    if (Array.isArray(body.results)) {
      for (const r of body.results.slice(0, 50)) {
        const c = state.queue.find((q) => q.id === r.id);
        if (c && Array.isArray(r.replies)) {
          for (const rep of r.replies.slice(0, 10)) c.results.push({ server: jobId.slice(0, 8), text: cleanText(rep.text, 300), kind: cleanText(rep.kind, 10) });
        }
      }
    }
    if (Array.isArray(body.catalog) && body.catalog.length) {
      state.catalog = body.catalog.slice(0, 300).map((c) => ({
        name: cleanText(c.name, 32), aliases: Array.isArray(c.aliases) ? c.aliases.slice(0, 8).map((a) => cleanText(a, 32)) : [],
        rank: Number(c.rank) || 0, cat: cleanText(c.cat, 32), desc: cleanText(c.desc, 160), args: Array.isArray(c.args) ? c.args.slice(0, 6).map((a) => cleanText(a, 16)) : [], icon: cleanText(c.icon, 8), title: c.title ? cleanText(c.title, 40) : undefined,
      }));
      save();
    }
    return send(res, 200, { ok: true, commands: commandsFor(jobId) });
  }

  // ===== تسجيل الدخول =====
  if (p === '/api/login' && req.method === 'POST') {
    const a = loginAttempts.get(ip) || { count: 0, until: 0 };
    if (Date.now() < a.until) return send(res, 429, { error: 'محاولات كثيرة، انتظر شوي' });
    let body;
    try { body = await readBody(req, 4096); } catch (e) { return send(res, 400, { error: 'bad' }); }
    const u = USERS.get(String(body.user || '').toLowerCase().trim());
    const pass = String(body.pass || '');
    // نحسب الهاش حتى لو المستخدم غير موجود عشان الوقت يكون نفسه
    const salt = u ? u.salt : Buffer.alloc(16);
    const h = crypto.scryptSync(pass, salt, 64);
    const ok = u && crypto.timingSafeEqual(h, u.hash);
    if (!ok) {
      a.count++;
      if (a.count >= 5) { a.until = Date.now() + 60000 * Math.min(30, a.count - 4); }
      loginAttempts.set(ip, a);
      state.audit.push({ t: Date.now(), by: 'النظام', text: `محاولة دخول فاشلة (${cleanText(body.user, 32)}) من ${ip}` });
      return send(res, 401, { error: 'اسم المستخدم أو كلمة السر غلط' });
    }
    loginAttempts.delete(ip);
    const token = crypto.randomBytes(32).toString('hex');
    const csrf = crypto.randomBytes(18).toString('base64url');
    sessions.set(token, { user: u.name, exp: Date.now() + SESSION_MS, csrf });
    const secure = req.headers['x-forwarded-proto'] === 'https' || req.socket.encrypted ? '; Secure' : '';
    return send(res, 200, { ok: true, user: u.name, csrf }, { 'Set-Cookie': `saqr_s=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}${secure}` });
  }

  if (p.startsWith('/api/')) {
    if (!allowRate('web:' + ip, 15, 40)) return send(res, 429, { error: 'rate' });
    const s = getSession(req);
    if (!s) return send(res, 401, { error: 'login' });

    if (req.method === 'POST') {
      // حماية CSRF: توكن في الهيدر + نفس المصدر
      if (!safeEqual(req.headers['x-csrf'] || '', s.csrf)) return send(res, 403, { error: 'csrf' });
      const origin = req.headers.origin;
      if (origin && new URL(origin).host !== req.headers.host) return send(res, 403, { error: 'origin' });
    }

    if (p === '/api/me' && req.method === 'GET') return send(res, 200, { ok: true, user: s.user, csrf: s.csrf, demo: DEMO });

    if (p === '/api/logout' && req.method === 'POST') {
      sessions.delete(s.token);
      return send(res, 200, { ok: true }, { 'Set-Cookie': 'saqr_s=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
    }

    if (p === '/api/state' && req.method === 'GET') {
      const servers = liveServers().map((x) => ({ ...x, players: x.players.map((pl) => ({ ...pl, thumb: thumbCache.get(pl.id) || '' })) }));
      const since = Number(url.searchParams.get('since')) || 0;
      return send(res, 200, {
        ok: true,
        now: Date.now(),
        servers,
        totals: { servers: servers.length, players: servers.reduce((n, x) => n + x.players.length, 0), commandsToday: state.stats.commandsToday, events: servers.filter((x) => x.event).length },
        logs: state.logs.filter((l) => l.t > since).slice(-200),
        results: state.queue.slice(-30).map((c) => ({ id: c.id, text: c.text, by: c.by, target: c.target, time: c.time, delivered: c.delivered.size, results: c.results })),
        catalog: state.catalog,
        demo: DEMO,
      });
    }

    if (p === '/api/command' && req.method === 'POST') {
      let body;
      try { body = await readBody(req, 4096); } catch (e) { return send(res, 400, { error: 'bad' }); }
      const text = cleanText(body.text, 400);
      const target = body.target === 'all' ? 'all' : cleanText(body.target, 64);
      if (!text) return send(res, 400, { error: 'اكتب أمر' });
      if (target !== 'all' && !state.servers.has(target)) return send(res, 404, { error: 'السيرفر غير متصل' });
      const cmd = enqueue(text, target, s.user);
      if (DEMO) demoExecute(cmd);
      return send(res, 200, { ok: true, id: cmd.id });
    }

    if (p === '/api/audit' && req.method === 'GET') return send(res, 200, { ok: true, list: state.audit.slice(-200) });

    return send(res, 404, { error: 'not found' });
  }

  if (req.method === 'GET') return serveStatic(req, res, p);
  return send(res, 405, 'method');
}

// تنظيف دوري
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of sessions) if (now > v.exp) sessions.delete(k);
  for (const [k, v] of loginAttempts) if (now > v.until && v.count < 5) loginAttempts.delete(k);
  if (rate.size > 5000) rate.clear();
  liveServers();
}, 60000).unref();

// ---------- وضع التجربة ----------
function demoExecute(cmd) {
  setTimeout(() => {
    for (const s of liveServers()) {
      if (cmd.target !== 'all' && cmd.target !== s.jobId) continue;
      cmd.delivered.add(s.jobId);
      cmd.results.push({ server: s.jobId.slice(0, 8), text: '✅ (تجريبي) تم تنفيذ: ' + cmd.text, kind: 'success' });
      pushLog({ t: Date.now(), by: '🌐 ' + cmd.by, text: cmd.text, kind: 'cmd', server: s.jobId.slice(0, 8) });
      const ev = cmd.text.replace(/^[;:]/, '').split(/\s+/)[0];
      if (state.catalog.find((c) => c.name === ev && c.cat === 'سينمائي')) { s.event = ev; setTimeout(() => { s.event = null; }, 15000); }
    }
  }, 600);
}

if (DEMO) {
  const names = ['Abu_Fahad', 'Noura_77', 'xX_Saqr_Xx', 'Hamad_Q8', 'Lulu_KSA', 'Faisal.dev', 'Mshari', 'ReemPlays', 'ZiadPro', 'Sultan_99', 'Jood_x', 'Khalid', 'Yara_AE', 'Turki', 'Dana', 'Omar_Builder'];
  const mk = (n) => Array.from({ length: n }, (_, i) => {
    const nm = names[(i * 7 + n) % names.length];
    return { id: 1000 + ((i * 7 + n) % names.length), name: nm, display: nm.replace(/[_.]/g, ' '), rank: i === 0 ? 5 : i === 1 ? 3 : i === 2 ? 2 : i % 5 === 0 ? 1 : 0, rankName: ['لاعب', 'VIP', 'مشرف', 'أدمن', 'مدير عام', 'المالك'][i === 0 ? 5 : i === 1 ? 3 : i === 2 ? 2 : i % 5 === 0 ? 1 : 0], team: null };
  });
  const demoServers = [['a1f3c9d2-7b10-4e', 14, 'meteor'], ['b8e2d417-33ac-41', 9, null], ['c47aa0f1-9e21-4d', 16, null], ['d93b5c88-5f02-4a', 5, 'storm']];
  const tick = () => {
    for (const [id, n, ev] of demoServers) {
      const old = state.servers.get(id);
      state.servers.set(id, { jobId: id, placeId: 123456789, placeVersion: 42, players: mk(n), maxPlayers: 20, uptime: old ? old.uptime + 3 : 3600 + n * 211, fps: 58 + (n % 3), event: old ? old.event : ev, locked: 0, studio: false, lastSeen: Date.now(), firstSeen: old ? old.firstSeen : Date.now() - 3600000, closing: false });
    }
  };
  tick();
  setInterval(tick, 3000).unref();
  if (!state.catalog.length) {
    state.catalog = require('./demo-catalog.json');
  }
  if (state.catalog.some((c) => !c.name)) {
    state.catalog = require('./demo-catalog.json');
  }
  const demoLogs = [['Abu_Fahad', ';meteor'], ['النظام', 'Lulu_KSA دخل السيرفر', 'join'], ['xX_Saqr_Xx', ';kick Spammer123 سبام'], ['Hamad_Q8', ';announce الفعالية تبدأ بعد 5 دقايق 🔥'], ['الحماية', 'طلب مشبوه من Hacker01 (action غير صالح) [1]', 'security'], ['Abu_Fahad', ';storm'], ['Noura_77', ';fly me'], ['النظام', 'ZiadPro طلع من السيرفر', 'leave']];
  if (!state.logs.length) demoLogs.forEach(([by, text, kind], i) => pushLog({ t: Date.now() - (demoLogs.length - i) * 47000, by, text, kind: kind || 'cmd', server: 'a1f3c9d2' }));
}

const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => { console.error(e); try { send(res, 500, { error: 'server' }); } catch (x) { /* ignore */ } });
});
server.headersTimeout = 15000;
server.requestTimeout = 20000;
server.listen(PORT, () => {
  console.log(`🦅 صقر | لوحة الويب شغالة على http://localhost:${PORT}${DEMO ? '  (وضع تجريبي — المستخدم admin / admin12345)' : ''}`);
});
