/* صقر | SAQR ADMIN — واجهة لوحة الويب */
'use strict';
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];

  // يبني عناصر بدون innerHTML (حماية من XSS)
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    if (attrs) for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'style') n.setAttribute('style', v);
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else if (k === 'dataset') Object.assign(n.dataset, v);
      else n.setAttribute(k, v === true ? '' : v);
    }
    for (const c of kids.flat()) if (c != null && c !== false) n.append(c.nodeType ? c : document.createTextNode(String(c)));
    return n;
  }

  let csrf = null;
  let me = null;
  let S = { servers: [], totals: {}, catalog: [], results: [] };
  let logs = [];
  let lastLogT = 0;
  let view = 'dash';
  let target = 'all';
  const myCmds = new Map(); // id -> {text, shown:Set}

  async function api(path, body) {
    const opts = { method: body ? 'POST' : 'GET', headers: {}, credentials: 'same-origin' };
    if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    if (csrf && body) opts.headers['X-CSRF'] = csrf;
    const r = await fetch(path, opts);
    let data = {};
    try { data = await r.json(); } catch (e) { /* ignore */ }
    if (r.status === 401 && path !== '/api/login') { showLogin(); throw new Error('login'); }
    if (!r.ok) throw new Error(data.error || ('HTTP ' + r.status));
    return data;
  }

  function toast(text, bad) {
    const t = el('div', { class: 'toast' + (bad ? ' bad' : '') }, text);
    $('#toasts').append(t);
    setTimeout(() => { t.style.transition = 'opacity .4s, transform .4s'; t.style.opacity = '0'; t.style.transform = 'translateY(10px)'; setTimeout(() => t.remove(), 450); }, 3800);
  }

  function ask(title, placeholder) {
    return new Promise((resolve) => {
      const m = $('#modal');
      $('#mTitle').textContent = title;
      const inp = $('#mInput');
      inp.value = ''; inp.placeholder = placeholder || '';
      m.classList.remove('hidden');
      setTimeout(() => inp.focus(), 30);
      const done = (v) => { m.classList.add('hidden'); $('#mOk').onclick = $('#mCancel').onclick = inp.onkeydown = null; resolve(v); };
      $('#mOk').onclick = () => done(inp.value.trim());
      $('#mCancel').onclick = () => done(null);
      inp.onkeydown = (e) => { if (e.key === 'Enter') done(inp.value.trim()); if (e.key === 'Escape') done(null); };
    });
  }

  async function run(text, tgt) {
    text = String(text || '').trim();
    if (!text) return;
    if (!/^[;:]/.test(text)) text = ';' + text;
    const t = tgt || target;
    try {
      const r = await api('/api/command', { text, target: t });
      myCmds.set(r.id, { text, shown: new Set() });
      termLine('cmd', `⟵ ${text}   → ${t === 'all' ? 'كل السيرفرات' : t.slice(0, 8)}`);
      toast('⚡ انرسل: ' + text);
    } catch (e) {
      if (e.message !== 'login') { toast('⛔ ' + e.message, true); termLine('bad', '⛔ ' + e.message); }
    }
  }

  // ---------------- الدخول ----------------
  function showLogin() {
    $('#app').classList.add('hidden');
    $('#login').classList.remove('hidden');
    stopPoll();
  }
  async function showApp() {
    $('#login').classList.add('hidden');
    $('#app').classList.remove('hidden');
    $('#who').replaceChildren(el('div', null, '👑 ' + me, el('small', null, 'مدير اللوحة')));
    startPoll();
  }
  $('#loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('#loginErr').textContent = '';
    try {
      const r = await api('/api/login', { user: $('#lu').value, pass: $('#lp').value });
      csrf = r.csrf; me = r.user;
      $('#lp').value = '';
      showApp();
    } catch (err) { $('#loginErr').textContent = err.message; }
  });
  $('#logout').addEventListener('click', async () => { try { await api('/api/logout', {}); } catch (e) { /* ignore */ } csrf = null; showLogin(); });

  // ---------------- التنقل ----------------
  const TITLES = {
    dash: ['لوحة القيادة', 'نظرة عامة على كل سيرفرات لعبتك مباشرة'],
    servers: ['السيرفرات', 'كل السيرفرات الشغالة الحين وحالتها'],
    players: ['اللاعبين', 'كل اللاعبين في كل السيرفرات — تحكم فيهم من هنا'],
    cinema: ['الأحداث السينمائية', 'اضغط على أي حدث يشتغل فوراً على السيرفر المختار'],
    console: ['الكونسول', 'نفّذ أي أمر من أوامر صقر عن بعد'],
    logs: ['السجل', 'كل الأوامر ودخول وخروج اللاعبين وتنبيهات الحماية'],
    commands: ['كل الأوامر', 'دليل الأوامر — اضغط على أي أمر عشان تكتبه في الكونسول'],
  };
  function go(v) {
    view = v;
    $$('#nav button').forEach((b) => b.classList.toggle('on', b.dataset.view === v));
    $$('.view').forEach((s) => s.classList.toggle('hidden', s.id !== 'v-' + v));
    $('#viewTitle').textContent = TITLES[v][0];
    $('#viewSub').textContent = TITLES[v][1];
    render();
    if (v === 'console') setTimeout(() => $('#cmdInput').focus(), 50);
  }
  $('#nav').addEventListener('click', (e) => { const b = e.target.closest('button'); if (b) go(b.dataset.view); });
  document.addEventListener('click', (e) => { const g = e.target.closest('[data-goto]'); if (g) go(g.dataset.goto); });
  $('#target').addEventListener('change', (e) => { target = e.target.value; render(); });

  // ---------------- الاستطلاع ----------------
  let pollTimer = null;
  let failCount = 0;
  function startPoll() { stopPoll(); poll(); pollTimer = setInterval(poll, 2500); }
  function stopPoll() { if (pollTimer) clearInterval(pollTimer); pollTimer = null; }
  async function poll() {
    try {
      const d = await api('/api/state?since=' + lastLogT);
      failCount = 0;
      $('#live').textContent = '● متصل'; $('#live').classList.remove('off');
      S = d;
      $('#demoBadge').classList.toggle('hidden', !d.demo);
      for (const l of d.logs) { logs.push(l); lastLogT = Math.max(lastLogT, l.t); }
      if (logs.length > 1200) logs = logs.slice(-1000);
      for (const r of d.results) {
        const mine = myCmds.get(r.id);
        if (!mine) continue;
        r.results.forEach((x, i) => {
          const key = i + ':' + x.server;
          if (mine.shown.has(key)) return;
          mine.shown.add(key);
          termLine(x.kind === 'error' ? 'bad' : 'ok', `[${x.server}] ${x.text}`);
        });
      }
      Space.setServers(S.servers.map((s) => s.jobId));
      render();
    } catch (e) {
      if (e.message === 'login') return;
      failCount++;
      if (failCount > 1) { $('#live').textContent = '● غير متصل'; $('#live').classList.add('off'); }
    }
  }

  // ---------------- العرض ----------------
  const fmtUp = (s) => { s = Number(s) || 0; const h = Math.floor(s / 3600), m = Math.floor(s % 3600 / 60); return h ? `${h}س ${m}د` : `${m}د`; };
  const fmtTime = (t) => new Date(t).toLocaleTimeString('en-GB', { hour12: false });
  const short = (id) => String(id).slice(0, 8);

  function renderTargets() {
    const sel = $('#target');
    const opts = [el('option', { value: 'all' }, `🌐 كل السيرفرات (${S.servers.length})`)];
    for (const s of S.servers) opts.push(el('option', { value: s.jobId }, `🖥️ ${short(s.jobId)} — ${s.players.length} لاعب${s.studio ? ' (Studio)' : ''}`));
    if (target !== 'all' && !S.servers.find((s) => s.jobId === target)) target = 'all';
    const sig = opts.map((o) => o.value + o.textContent).join('|');
    if (sel.dataset.sig !== sig) { sel.replaceChildren(...opts); sel.dataset.sig = sig; }
    sel.value = target;
  }

  function logItem(l) {
    return el('li', { class: l.kind || 'cmd' }, el('span', { class: 'dot' }),
      el('span', null, el('b', null, l.by), ' ', el('bdi', null, l.text), l.server ? el('span', { class: 'srvtag' }, '#' + l.server) : null),
      el('time', null, fmtTime(l.t)));
  }

  const QUICK = [
    ['⏹️', 'إيقاف الأحداث', 'stopevents'], ['🧼', 'تنظيف', 'clean'], ['🔒', 'قفل', 'slock 2'], ['🔓', 'فتح', 'unslock'],
    ['🌙', 'ليل', 'time 0'], ['☀️', 'نهار', 'time 14'], ['⏱️', 'عد 10', 'countdown 10'], ['🎆', 'احتفال', 'fireworks'],
  ];
  function renderDash() {
    const t = S.totals || {};
    $('#sServers').textContent = t.servers ?? 0;
    $('#sPlayers').textContent = t.players ?? 0;
    $('#sCmds').textContent = t.commandsToday ?? 0;
    $('#sEvents').textContent = t.events ?? 0;
    if (!$('#quick').childElementCount) {
      $('#quick').append(...QUICK.map(([i, n, c]) => el('button', { type: 'button', onclick: () => run(c) }, el('span', null, i), n)));
    }
    $('#miniLogs').replaceChildren(...logs.slice(-12).reverse().map(logItem));
    const strip = S.servers.map((s) => el('div', { class: 'srv-mini' + (target === s.jobId ? ' sel' : ''), onclick: () => { target = target === s.jobId ? 'all' : s.jobId; render(); } },
      el('div', { class: 'id' }, '#' + short(s.jobId)),
      el('div', null, `👥 ${s.players.length}/${s.maxPlayers} • ⚙️ ${s.fps} FPS`),
      el('div', { class: 'bar' }, el('i', { style: `width:${Math.min(100, s.players.length / Math.max(1, s.maxPlayers) * 100)}%` })),
      s.event ? el('small', { style: 'color:var(--gold)' }, '🎬 ' + s.event) : el('small', { class: 'muted' }, 'بدون حدث')));
    $('#srvStrip').replaceChildren(...(strip.length ? strip : [el('div', { class: 'empty' }, 'ما فيه سيرفرات متصلة — تأكد إن Web.Enabled = true في Config وإن HTTP مفعّل')]));
  }

  function renderServers() {
    const cards = S.servers.map((s) => el('div', { class: 'srv tilt' },
      el('h4', null, el('span', null, (s.studio ? '🛠️ ' : '🖥️ ') + 'سيرفر'), el('code', null, '#' + short(s.jobId))),
      el('div', { class: 'kv' },
        el('div', null, el('small', null, 'اللاعبين'), el('b', null, `${s.players.length}/${s.maxPlayers}`)),
        el('div', null, el('small', null, 'التشغيل'), el('b', null, fmtUp(s.uptime))),
        el('div', null, el('small', null, 'الأداء'), el('b', null, s.fps + ' FPS'))),
      el('div', { class: 'avatars' }, s.players.slice(0, 24).map((p) => el('div', { class: 'av' + (p.rank >= 2 ? ' admin' : ''), title: p.name, style: p.thumb ? `background-image:url("${encodeURI(p.thumb)}")` : null }, p.thumb ? '' : p.name.slice(0, 1).toUpperCase()))),
      el('div', { class: 'row' },
        el('button', { class: 'btn small', onclick: () => { target = s.jobId; go('console'); } }, '⌨️ كونسول'),
        el('button', { class: 'btn small', onclick: async () => { const m = await ask('📢 إعلان لهذا السيرفر'); if (m) run('announce ' + m, s.jobId); } }, '📢 إعلان'),
        el('button', { class: 'btn small', onclick: () => run(s.locked ? 'unslock' : 'slock 2', s.jobId) }, s.locked ? '🔓 فتح' : '🔒 قفل'),
        el('button', { class: 'btn small red', onclick: async () => { const m = await ask('🛑 سبب إغلاق السيرفر؟ (يتقفل بعد 10 ثواني)', 'تحديث'); if (m !== null) run('shutdown ' + m, s.jobId); } }, '🛑 إغلاق'))));
    $('#srvCards').replaceChildren(...(cards.length ? cards : [el('div', { class: 'empty' }, 'ما فيه سيرفرات متصلة حالياً')]));
    bindTilt();
  }

  function renderPlayers() {
    const q = $('#pSearch').value.trim().toLowerCase();
    const rows = [];
    for (const s of S.servers) for (const p of s.players) {
      if (q && !(p.name.toLowerCase().includes(q) || p.display.toLowerCase().includes(q))) continue;
      const act = (label, cmd, danger) => el('button', { class: danger ? 'danger' : null, onclick: cmd }, label);
      rows.push(el('tr', null,
        el('td', null, el('div', { class: 'pcell' }, el('div', { class: 'av' + (p.rank >= 2 ? ' admin' : ''), style: p.thumb ? `background-image:url("${encodeURI(p.thumb)}")` : null }, p.thumb ? '' : p.name.slice(0, 1)), el('div', null, p.display, el('small', null, '@' + p.name)))),
        el('td', null, el('span', { class: 'rank r' + p.rank }, p.rankName || p.rank)),
        el('td', null, el('code', { style: 'color:var(--cyan);direction:ltr' }, '#' + short(s.jobId))),
        el('td', null, el('div', { class: 'acts' },
          act('🧊 تجميد', () => run('freeze ' + p.name, s.jobId)),
          act('⛓️ سجن', () => run('jail ' + p.name, s.jobId)),
          act('🔇 كتم', () => run('mute ' + p.name, s.jobId)),
          act('⚠️ تحذير', async () => { const m = await ask('⚠️ نص التحذير لـ ' + p.name); if (m) run(`warn ${p.name} ${m}`, s.jobId); }),
          act('✉️ خاص', async () => { const m = await ask('✉️ رسالة خاصة لـ ' + p.name); if (m) run(`pm ${p.name} ${m}`, s.jobId); }),
          act('👢 طرد', async () => { const m = await ask('👢 سبب طرد ' + p.name); if (m !== null) run(`kick ${p.name} ${m}`, s.jobId); }, true),
          act('🔨 باند', async () => { const m = await ask('🔨 سبب باند ' + p.name + ' (نهائي)'); if (m !== null) run(`ban ${p.name} ${m}`, s.jobId); }, true)))));
    }
    $('#pTable tbody').replaceChildren(...(rows.length ? rows : [el('tr', null, el('td', { colspan: '4', class: 'muted', style: 'text-align:center;padding:30px' }, 'ما فيه لاعبين'))]));
  }

  let eventsSig = '';
  function renderCinema() {
    const evs = S.catalog.filter((c) => c.cat === 'سينمائي');
    const sig = evs.map((e) => e.name).join(',');
    if (sig === eventsSig) return;
    eventsSig = sig;
    $('#events').replaceChildren(...evs.map((c) => {
      const targeted = c.args[0] === 'players';
      const b = el('button', { class: 'event tilt' + (targeted ? ' targeted' : ''), type: 'button' },
        el('div', { class: 'ico' }, c.icon || '🎬'),
        el('b', null, c.name === 'stopevents' ? 'إيقاف كل الأحداث' : (c.title || c.aliases[0] || c.name)),
        el('code', null, ';' + c.name + (c.args.length ? ' ' + c.args.join(' ') : '')),
        el('p', null, c.desc));
      b.addEventListener('click', () => {
        b.classList.remove('fire'); void b.offsetWidth; b.classList.add('fire');
        if (targeted) {
          const t = $('#cTarget').value.trim();
          if (!t) { toast('🎯 اكتب اسم الهدف فوق أول', true); $('#cTarget').focus(); return; }
          run(c.name + ' ' + t);
        } else run(c.name);
      });
      b.addEventListener('mousemove', (e) => { const r = b.getBoundingClientRect(); b.style.setProperty('--mx', (e.clientX - r.left) + 'px'); b.style.setProperty('--my', (e.clientY - r.top) + 'px'); });
      return b;
    }));
    if (!evs.length) $('#events').append(el('div', { class: 'empty' }, 'قائمة الأحداث توصل أول ما يتصل سيرفر'));
    bindTilt();
  }

  let logKind = '';
  function renderLogs() {
    const q = $('#lSearch').value.trim().toLowerCase();
    const list = logs.filter((l) => (!logKind || l.kind === logKind) && (!q || (l.by + ' ' + l.text).toLowerCase().includes(q))).slice(-400).reverse();
    $('#logs').replaceChildren(...(list.length ? list.map(logItem) : [el('li', { class: 'muted' }, 'ما فيه سجلات')]));
  }
  $('#lKinds').addEventListener('click', (e) => { const b = e.target.closest('button'); if (!b) return; logKind = b.dataset.k; $$('#lKinds button').forEach((x) => x.classList.toggle('on', x === b)); renderLogs(); });

  let cmdSig = '';
  function renderCommands() {
    const q = $('#kSearch').value.trim().toLowerCase();
    const sig = q + '|' + S.catalog.length;
    if (sig === cmdSig) return;
    cmdSig = sig;
    const groups = new Map();
    for (const c of S.catalog) {
      const hay = (c.name + ' ' + c.aliases.join(' ') + ' ' + c.desc + ' ' + c.cat).toLowerCase();
      if (q && !hay.includes(q)) continue;
      if (!groups.has(c.cat)) groups.set(c.cat, []);
      groups.get(c.cat).push(c);
    }
    const out = [];
    for (const [cat, list] of groups) {
      out.push(el('div', { class: 'cmdcat' }, el('h4', null, '◆ ' + cat + ` (${list.length})`), el('div', { class: 'cmdgrid' }, list.map((c) =>
        el('div', { class: 'cmd', onclick: () => { go('console'); $('#cmdInput').value = c.name + ' '; $('#cmdInput').focus(); } },
          el('code', null, `${c.icon || ''} ;${c.name} `, el('em', null, c.args.join(' '))),
          el('small', null, c.aliases.join('، ')),
          c.desc ? el('p', null, c.desc) : null)))));
    }
    $('#cmdList').replaceChildren(...(out.length ? out : [el('div', { class: 'empty' }, 'ما لقيت أوامر')]));
  }
  $('#kSearch').addEventListener('input', renderCommands);
  $('#pSearch').addEventListener('input', renderPlayers);
  $('#lSearch').addEventListener('input', renderLogs);

  function render() {
    renderTargets();
    if (view === 'dash') renderDash();
    else if (view === 'servers') renderServers();
    else if (view === 'players') renderPlayers();
    else if (view === 'cinema') renderCinema();
    else if (view === 'logs') renderLogs();
    else if (view === 'commands') renderCommands();
  }

  // ---------------- الكونسول ----------------
  function termLine(kind, text) {
    const term = $('#term');
    const stick = term.scrollTop + term.clientHeight >= term.scrollHeight - 20;
    term.append(el('div', { class: 'ln ' + kind }, `${fmtTime(Date.now())}  ${text}`));
    while (term.childElementCount > 400) term.firstChild.remove();
    if (stick) term.scrollTop = term.scrollHeight;
  }
  termLine('info', '🦅 صقر | الكونسول جاهز — اكتب أي أمر بدون ; أو معه. اضغط ↑ للأوامر السابقة.');

  const hist = []; let hi = 0; let sIdx = -1;
  const inp = $('#cmdInput');
  function suggestions() {
    const v = inp.value.replace(/^[;:]/, '');
    const w = v.match(/^(\S+)$/);
    const box = $('#suggest');
    if (!w) { box.classList.add('hidden'); return []; }
    const q = w[1].toLowerCase();
    const list = S.catalog.filter((c) => c.name.startsWith(q) || c.aliases.some((a) => a.toLowerCase().startsWith(q))).slice(0, 7);
    box.replaceChildren(...list.map((c, i) => el('li', { class: i === sIdx ? 'on' : null, onmousedown: (e) => { e.preventDefault(); pick(c); } },
      el('span', null, (c.icon || '') + ' ', el('code', null, ';' + c.name), ' ', el('small', null, c.args.join(' '))), el('small', null, c.desc))));
    box.classList.toggle('hidden', !list.length);
    return list;
  }
  function pick(c) { inp.value = c.name + ' '; $('#suggest').classList.add('hidden'); sIdx = -1; inp.focus(); }
  inp.addEventListener('input', () => { sIdx = -1; suggestions(); });
  inp.addEventListener('blur', () => setTimeout(() => $('#suggest').classList.add('hidden'), 100));
  inp.addEventListener('keydown', (e) => {
    const box = $('#suggest');
    const open = !box.classList.contains('hidden');
    if (open && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      e.preventDefault();
      const n = box.childElementCount;
      sIdx = (sIdx + (e.key === 'ArrowDown' ? 1 : -1) + n) % n;
      suggestions();
      return;
    }
    if (open && (e.key === 'Tab' || (e.key === 'Enter' && sIdx >= 0))) {
      e.preventDefault();
      const list = suggestions();
      if (list[Math.max(0, sIdx)]) pick(list[Math.max(0, sIdx)]);
      return;
    }
    if (!open && e.key === 'ArrowUp' && hist.length) { e.preventDefault(); hi = Math.max(0, hi - 1); inp.value = hist[hi]; }
    if (!open && e.key === 'ArrowDown' && hist.length) { e.preventDefault(); hi = Math.min(hist.length, hi + 1); inp.value = hist[hi] || ''; }
  });
  $('#cmdForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const v = inp.value.trim();
    if (!v) return;
    hist.push(v); hi = hist.length;
    run(v);
    inp.value = '';
    $('#suggest').classList.add('hidden');
  });
  $('#annForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const v = $('#annText').value.trim();
    if (!v) return;
    run('announce ' + v);
    $('#annText').value = '';
  });

  // ---------------- ميلان 3D للبطاقات ----------------
  function bindTilt() {
    for (const n of $$('.tilt')) {
      if (n.dataset.tilt) continue;
      n.dataset.tilt = '1';
      n.addEventListener('mousemove', (e) => {
        const r = n.getBoundingClientRect();
        const x = (e.clientX - r.left) / r.width - 0.5;
        const y = (e.clientY - r.top) / r.height - 0.5;
        const k = Math.min(1, 320 / Math.max(r.width, 1));
        n.style.transform = `rotateX(${(-y * 10 * k).toFixed(2)}deg) rotateY(${(x * 12 * k).toFixed(2)}deg) translateZ(6px)`;
      });
      n.addEventListener('mouseleave', () => { n.style.transform = ''; });
    }
  }

  // ---------------- الفضاء 3D (كرة السيرفرات) ----------------
  const Space = (() => {
    const cv = $('#space');
    const ctx = cv.getContext('2d');
    let W = 0, H = 0, DPR = 1;
    let mx = 0, my = 0, tmx = 0, tmy = 0;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const stars = Array.from({ length: 420 }, () => ({ x: (Math.random() - 0.5) * 2400, y: (Math.random() - 0.5) * 1600, z: Math.random() * 1600 + 200, s: Math.random() * 1.4 + 0.3 }));
    const N = 1100;
    const pts = [];
    const ga = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < N; i++) {
      const y = 1 - (i / (N - 1)) * 2;
      const r = Math.sqrt(1 - y * y);
      const t = ga * i;
      pts.push([Math.cos(t) * r, y, Math.sin(t) * r]);
    }
    let nodes = [];
    const hash = (s) => { let h = 2166136261; for (const c of s) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; };
    function setServers(ids) {
      nodes = ids.map((id) => {
        const h = hash(id);
        const lat = ((h % 1000) / 1000 - 0.5) * 2.2;
        const lon = ((h >>> 10) % 1000) / 1000 * Math.PI * 2;
        return [Math.cos(lat) * Math.cos(lon), Math.sin(lat), Math.cos(lat) * Math.sin(lon)];
      });
    }
    function resize() {
      DPR = Math.min(2, window.devicePixelRatio || 1);
      W = cv.clientWidth; H = cv.clientHeight;
      cv.width = W * DPR; cv.height = H * DPR;
      ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    }
    window.addEventListener('resize', resize);
    window.addEventListener('mousemove', (e) => { tmx = e.clientX / W - 0.5; tmy = e.clientY / H - 0.5; });
    resize();

    function rot([x, y, z], ay, ax) {
      const cy = Math.cos(ay), sy = Math.sin(ay);
      let X = x * cy - z * sy, Z = x * sy + z * cy;
      const cx = Math.cos(ax), sx = Math.sin(ax);
      const Y = y * cx - Z * sx; Z = y * sx + Z * cx;
      return [X, Y, Z];
    }

    let t0 = performance.now();
    function frame(now) {
      const t = (now - t0) / 1000;
      mx += (tmx - mx) * 0.04; my += (tmy - my) * 0.04;
      ctx.clearRect(0, 0, W, H);
      // النجوم
      for (const s of stars) {
        s.z -= reduce ? 0 : 0.6;
        if (s.z < 50) s.z = 1800;
        const k = 600 / s.z;
        const x = W / 2 + (s.x - mx * 300) * k, y = H / 2 + (s.y - my * 200) * k;
        if (x < 0 || x > W || y < 0 || y > H) continue;
        ctx.globalAlpha = Math.min(1, (1800 - s.z) / 1200) * 0.8;
        ctx.fillStyle = '#cfd8ff';
        ctx.fillRect(x, y, s.s * k * 1.6, s.s * k * 1.6);
      }
      // الكرة
      const R = Math.min(W, H) * (W < 760 ? 0.36 : 0.34);
      const cx = W < 760 ? W / 2 : W * 0.36, cy = H * 0.55;
      const ay = t * 0.12 + mx * 0.8, ax = -0.35 + my * 0.5;
      const halo = ctx.createRadialGradient(cx, cy, R * 0.6, cx, cy, R * 1.5);
      halo.addColorStop(0, 'rgba(255,170,60,.10)'); halo.addColorStop(1, 'rgba(255,170,60,0)');
      ctx.globalAlpha = 1; ctx.fillStyle = halo; ctx.beginPath(); ctx.arc(cx, cy, R * 1.5, 0, Math.PI * 2); ctx.fill();
      for (const p of pts) {
        const [x, y, z] = rot(p, ay, ax);
        const depth = (z + 1) / 2;
        ctx.globalAlpha = 0.08 + depth * 0.5;
        ctx.fillStyle = depth > 0.5 ? '#46d2ff' : '#3b4a80';
        const sz = 0.6 + depth * 1.5;
        ctx.fillRect(cx + x * R, cy + y * R, sz, sz);
      }
      // حلقة مدارية
      ctx.globalAlpha = 0.35; ctx.strokeStyle = '#ffc446'; ctx.lineWidth = 1;
      ctx.beginPath();
      for (let i = 0; i <= 120; i++) {
        const a = (i / 120) * Math.PI * 2;
        const [x, y] = rot([Math.cos(a) * 1.35, 0.05 * Math.sin(a * 3 + t), Math.sin(a) * 1.35], ay * 0.6, ax + 0.5);
        if (i === 0) ctx.moveTo(cx + x * R, cy + y * R); else ctx.lineTo(cx + x * R, cy + y * R);
      }
      ctx.stroke();
      // الأقمار على الحلقة
      for (let i = 0; i < 3; i++) {
        const a = t * 0.5 + i * 2.1;
        const [x, y, z] = rot([Math.cos(a) * 1.35, 0, Math.sin(a) * 1.35], ay * 0.6, ax + 0.5);
        ctx.globalAlpha = 0.5 + (z + 1) * 0.25; ctx.fillStyle = '#ffe08a';
        ctx.beginPath(); ctx.arc(cx + x * R, cy + y * R, 2.5 + (z + 1), 0, Math.PI * 2); ctx.fill();
      }
      // السيرفرات + الأقواس
      const proj = nodes.map((n) => rot(n, ay, ax));
      for (let i = 0; i < proj.length; i++) {
        const a = proj[i], b = proj[(i + 1) % proj.length];
        if (proj.length > 1) {
          ctx.globalAlpha = 0.45; ctx.strokeStyle = '#ffc446'; ctx.lineWidth = 1.2;
          ctx.beginPath();
          for (let k = 0; k <= 30; k++) {
            const f = k / 30;
            let x = a[0] + (b[0] - a[0]) * f, y = a[1] + (b[1] - a[1]) * f, z = a[2] + (b[2] - a[2]) * f;
            const len = Math.hypot(x, y, z) || 1;
            const lift = 1 + Math.sin(f * Math.PI) * 0.25;
            x = x / len * lift; y = y / len * lift; z = z / len * lift;
            if (k === 0) ctx.moveTo(cx + x * R, cy + y * R); else ctx.lineTo(cx + x * R, cy + y * R);
          }
          ctx.stroke();
          // نبضة تتحرك
          const f = (t * 0.35 + i * 0.2) % 1;
          let x = a[0] + (b[0] - a[0]) * f, y = a[1] + (b[1] - a[1]) * f, z = a[2] + (b[2] - a[2]) * f;
          const len = Math.hypot(x, y, z) || 1; const lift = 1 + Math.sin(f * Math.PI) * 0.25;
          ctx.globalAlpha = 0.9; ctx.fillStyle = '#fff3c4';
          ctx.beginPath(); ctx.arc(cx + x / len * lift * R, cy + y / len * lift * R, 2.4, 0, Math.PI * 2); ctx.fill();
        }
        const front = a[2] > -0.15;
        const pulse = 1 + Math.sin(t * 3 + i) * 0.35;
        const g = ctx.createRadialGradient(cx + a[0] * R, cy + a[1] * R, 0, cx + a[0] * R, cy + a[1] * R, 18 * pulse);
        g.addColorStop(0, 'rgba(255,210,100,.95)'); g.addColorStop(1, 'rgba(255,150,50,0)');
        ctx.globalAlpha = front ? 1 : 0.35; ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(cx + a[0] * R, cy + a[1] * R, 18 * pulse, 0, Math.PI * 2); ctx.fill();
        ctx.fillStyle = '#fff'; ctx.beginPath(); ctx.arc(cx + a[0] * R, cy + a[1] * R, 2.6, 0, Math.PI * 2); ctx.fill();
      }
      ctx.globalAlpha = 1;
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
    return { setServers };
  })();

  bindTilt();

  // ---------------- البداية ----------------
  (async () => {
    try {
      const r = await fetch('/api/me', { credentials: 'same-origin' });
      if (r.ok) { const d = await r.json(); csrf = d.csrf; me = d.user; showApp(); }
      else showLogin();
    } catch (e) { showLogin(); }
  })();
})();
