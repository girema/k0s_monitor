// k0s-monitor UI script: live updates over SSE, notifications, and small
// helpers. Pages work without it; it only adds convenience.
(function () {
  'use strict';

  const meta = (name) => {
    const m = document.querySelector('meta[name="' + name + '"]');
    return m ? m.getAttribute('content') : '';
  };
  const csrf = meta('csrf');
  const mode = document.documentElement.getAttribute('data-mode') || 'basic';
  const baseTitle = document.title;
  let unread = parseInt(meta('unread') || '0', 10) || 0;

  function store(key, value) {
    try {
      if (value === undefined) return window.localStorage.getItem(key);
      window.localStorage.setItem(key, value);
    } catch (e) { /* storage may be blocked */ }
    return null;
  }

  function request(method, url, body) {
    const opts = { method: method, headers: { 'X-CSRF-Token': csrf }, credentials: 'same-origin' };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    return fetch(url, opts);
  }

  // ---------------------------------------------------------------- unread

  function setUnread(n) {
    unread = n;
    const c = document.getElementById('bellCount');
    if (c) {
      c.textContent = String(n);
      c.classList.toggle('hidden', n === 0);
    }
    const btn = document.getElementById('bellBtn');
    if (btn) btn.setAttribute('aria-label', 'Notifications, ' + n + ' new');
    document.title = (n > 0 ? '(' + n + ') ' : '') + baseTitle;
  }
  setUnread(unread);

  // ---------------------------------------------------------------- theme and menu

  // Each browser remembers its colors and whether the menu on the left is
  // hidden. The server reads the cookies too, so every page starts that
  // way, without a flash.
  function setCookie(name, value) {
    const secure = window.location.protocol === 'https:' ? '; Secure' : '';
    document.cookie = name + '=' + value + '; Path=/; SameSite=Strict' + secure + (value ? '; Max-Age=31536000' : '; Max-Age=0');
  }

  // setTheme applies "light", "dark" or "system" (the computer's setting).
  function setTheme(t) {
    const root = document.documentElement;
    const fixed = t === 'light' || t === 'dark';
    if (fixed) root.setAttribute('data-theme', t);
    else root.removeAttribute('data-theme');
    setCookie('theme', fixed ? t : '');
    document.querySelectorAll('[data-theme-set]').forEach((a) => {
      const on = a.getAttribute('data-theme-set') === (fixed ? t : 'system');
      a.classList.toggle('on', on);
      if (on) a.setAttribute('aria-current', 'true');
      else a.removeAttribute('aria-current');
    });
    document.dispatchEvent(new CustomEvent('k0s:theme'));
  }

  function toggleNav() {
    const root = document.documentElement;
    const hide = root.getAttribute('data-nav') !== 'hidden';
    if (hide) root.setAttribute('data-nav', 'hidden');
    else root.removeAttribute('data-nav');
    setCookie('nav', hide ? 'hidden' : '');
    const b = document.getElementById('navToggle');
    if (b) b.setAttribute('aria-expanded', hide ? 'false' : 'true');
    // Charts fit their width.
    window.dispatchEvent(new Event('resize'));
  }

  // ---------------------------------------------------------------- clicks

  document.addEventListener('click', function (ev) {
    const t = ev.target;
    if (!(t instanceof Element)) return;

    const theme = t.closest('[data-theme-set]');
    if (theme) {
      ev.preventDefault();
      setTheme(theme.getAttribute('data-theme-set'));
      const menu = theme.closest('details');
      if (menu) menu.open = false;
      return;
    }
    if (t.closest('[data-nav-toggle]')) {
      toggleNav();
      return;
    }

    const copy = t.closest('[data-copy]');
    if (copy) {
      const text = copy.getAttribute('data-copy');
      const done = () => { copy.textContent = 'Copied'; setTimeout(() => { copy.textContent = 'Copy'; }, 1500); };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
      } else {
        fallbackCopy(text, done);
      }
      return;
    }

    const post = t.closest('[data-post]');
    if (post) {
      post.setAttribute('disabled', '');
      request('POST', post.getAttribute('data-post')).then(() => {
        setTimeout(() => refresh(true), 800);
      }).finally(() => post.removeAttribute('disabled'));
      return;
    }

    const del = t.closest('[data-delete]');
    if (del) {
      const q = del.getAttribute('data-confirm');
      if (q && !window.confirm(q)) return;
      del.setAttribute('disabled', '');
      request('DELETE', del.getAttribute('data-delete')).then((r) => {
        if (r.ok) {
          window.location.href = del.getAttribute('data-then') || '/';
        } else {
          r.json().then((j) => window.alert(j.error || 'Failed'), () => window.alert('Failed'));
          del.removeAttribute('disabled');
        }
      });
      return;
    }

    const caret = t.closest('[data-toggle-body]');
    if (caret) {
      const body = caret.closest('tbody');
      if (body) body.classList.toggle('collapsed');
      return;
    }

    const bellBtn = t.closest('#bellBtn');
    if (bellBtn) {
      toggleBell();
      return;
    }
    if (t.closest('#markRead')) {
      request('POST', '/api/v1/notifications/read', { upTo: 0 }).then((r) => r.json()).then((j) => {
        setUnread(j.unread || 0);
        loadBell();
      });
      return;
    }
    const panel = document.getElementById('bellPanel');
    if (panel && panel.classList.contains('on') && !t.closest('#bellPanel')) {
      closeBell();
    }
    // Close open menus when clicking elsewhere.
    document.querySelectorAll('details.menu[open]').forEach((d) => {
      if (!d.contains(t)) d.removeAttribute('open');
    });
  });

  function fallbackCopy(text, done) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.className = 'hidden';
    document.body.appendChild(ta);
    ta.classList.remove('hidden');
    ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { /* ignore */ }
    ta.remove();
  }

  // A form with data-confirm-submit asks before it is sent; one with
  // data-busy says it is working, and can't be sent twice.
  document.addEventListener('submit', function (ev) {
    const f = ev.target;
    if (!(f instanceof HTMLFormElement)) return;
    if (f.hasAttribute('data-confirm-submit') && !window.confirm(f.getAttribute('data-confirm-submit'))) {
      ev.preventDefault();
      return;
    }
    if (f.hasAttribute('data-busy')) {
      if (f.dataset.sent) {
        ev.preventDefault();
        return;
      }
      f.dataset.sent = '1';
      const b = f.querySelector('button[type=submit]');
      if (b) {
        b.disabled = true;
        b.textContent = f.getAttribute('data-busy');
      }
    }
  });

  document.addEventListener('change', function (ev) {
    const t = ev.target;
    if ((t instanceof HTMLSelectElement || t instanceof HTMLInputElement) && t.hasAttribute('data-autosubmit') && t.form) {
      t.form.submit();
    }
    if (t instanceof HTMLInputElement && t.id === 'desktopToggle') {
      if (t.checked && 'Notification' in window) {
        Notification.requestPermission().then((p) => {
          t.checked = p === 'granted';
          store('desktop', t.checked ? '1' : '0');
        });
      } else {
        store('desktop', '0');
      }
    }
  });

  document.addEventListener('keydown', function (ev) {
    if (ev.key === 'Escape') closeBell();
    // "/" jumps to the search box; pages without one open the Apps page.
    if (ev.key === '/' && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
      const a = document.activeElement;
      if (a && (a.tagName === 'INPUT' || a.tagName === 'TEXTAREA' || a.tagName === 'SELECT' || a.isContentEditable)) return;
      const box = document.querySelector('input[data-filter]');
      if (box) {
        ev.preventDefault();
        box.focus();
        box.select();
      } else if (pageCluster) {
        ev.preventDefault();
        window.location.href = '/c/' + encodeURIComponent(pageCluster) + '/apps#search';
      }
    }
  });

  // ---------------------------------------------------------------- search

  // An input with data-filter hides the rows (data-search) of its target
  // that don't contain every word typed. The page's address follows, so a
  // live refresh or a copied link keeps the search.
  function applyFilter(input) {
    const target = document.querySelector(input.getAttribute('data-filter'));
    if (!target) return;
    const words = input.value.toLowerCase().split(/\s+/).filter(Boolean);
    let shown = 0;
    target.querySelectorAll('[data-search]').forEach((el) => {
      const text = el.getAttribute('data-search') || '';
      const ok = words.every((w) => text.indexOf(w) >= 0);
      el.classList.toggle('hidden', !ok);
      if (ok) shown++;
    });
    const count = document.querySelector('[data-filter-count]');
    if (count) count.textContent = String(shown);
    const empty = target.querySelector('[data-filter-empty]');
    if (empty) empty.classList.toggle('hidden', shown > 0);
    try {
      const u = new URL(window.location.href);
      if (input.value.trim()) u.searchParams.set('q', input.value.trim()); else u.searchParams.delete('q');
      window.history.replaceState(null, '', u.pathname + u.search + u.hash);
    } catch (e) { /* ignore */ }
  }

  document.addEventListener('input', function (ev) {
    const t = ev.target;
    if (t instanceof HTMLInputElement && t.hasAttribute('data-filter')) applyFilter(t);
  });

  // Links to an app (#app-...) open its rows; #search focuses the box.
  function openTarget() {
    const h = window.location.hash;
    if (h === '#search') {
      const box = document.querySelector('input[data-filter]');
      if (box) box.focus();
      return;
    }
    if (h.indexOf('#app-') !== 0) return;
    const el = document.getElementById(decodeURIComponent(h.slice(1)));
    if (el && el.tagName === 'TBODY') {
      el.classList.remove('collapsed', 'hidden');
      el.scrollIntoView({ block: 'center' });
    }
  }
  openTarget();
  window.addEventListener('hashchange', openTarget);

  // ---------------------------------------------------------------- bell

  function toggleBell() {
    const panel = document.getElementById('bellPanel');
    if (!panel) return;
    if (panel.classList.contains('on')) {
      closeBell();
    } else {
      panel.classList.add('on');
      document.getElementById('bellBtn').setAttribute('aria-expanded', 'true');
      const dt = document.getElementById('desktopToggle');
      if (dt) dt.checked = store('desktop') === '1' && 'Notification' in window && Notification.permission === 'granted';
      loadBell();
    }
  }

  function closeBell() {
    const panel = document.getElementById('bellPanel');
    if (panel && panel.classList.contains('on')) {
      panel.classList.remove('on');
      document.getElementById('bellBtn').setAttribute('aria-expanded', 'false');
    }
  }

  const urg = { P1: ['now', 'Fix now'], P2: ['today', 'Fix today'], P3: ['plan', 'Plan ahead'], P4: ['sugg', 'Suggestion'] };

  function notificationLink(n) {
    if (n.findingId) return '/c/' + encodeURIComponent(n.cluster) + '/problems/' + encodeURIComponent(n.findingId);
    return '/c/' + encodeURIComponent(n.cluster);
  }

  function renderItem(n) {
    const a = document.createElement('a');
    a.className = 'bp-i' + (n.read ? '' : ' new');
    a.href = notificationLink(n);
    const chip = document.createElement('span');
    if (n.kind === 'resolved') {
      chip.className = 'urg ok';
      chip.textContent = mode === 'basic' ? 'Fixed' : 'Resolved';
    } else {
      const u = urg[n.priority] || urg.P4;
      chip.className = 'urg ' + u[0];
      chip.textContent = mode === 'basic' ? u[1] : n.priority;
    }
    const body = document.createElement('div');
    const title = document.createElement('div');
    title.className = 'bt';
    title.textContent = mode === 'basic' ? (n.plainTitle || n.title) : n.title;
    const when = document.createElement('div');
    when.className = 'small muted';
    when.textContent = timeAgo(n.created) + (n.kind === 'worse' ? ' · got worse' : '') + (n.read ? '' : ' · new');
    body.appendChild(title);
    body.appendChild(when);
    a.appendChild(chip);
    a.appendChild(body);
    return a;
  }

  function loadBell() {
    const list = document.getElementById('bellList');
    if (!list) return;
    fetch('/api/v1/notifications?limit=30', { credentials: 'same-origin' }).then((r) => r.json()).then((j) => {
      list.textContent = '';
      const ns = j.notifications || [];
      if (ns.length === 0) {
        const e = document.createElement('div');
        e.className = 'bp-empty';
        e.textContent = 'No notifications yet.';
        list.appendChild(e);
      }
      ns.forEach((n) => list.appendChild(renderItem(n)));
      setUnread(j.unread || 0);
    }).catch(() => { list.textContent = 'Notifications could not be loaded.'; });
  }

  function timeAgo(iso) {
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + ' min ago';
    if (s < 172800) return Math.floor(s / 3600) + ' h ago';
    return Math.floor(s / 86400) + ' d ago';
  }

  function desktopNotify(n) {
    if (store('desktop') !== '1' || !('Notification' in window) || Notification.permission !== 'granted') return;
    if (n.priority !== 'P1' || n.kind === 'resolved') return;
    try {
      const note = new Notification('k0s-monitor', { body: mode === 'basic' ? (n.plainTitle || n.title) : n.title, tag: 'k0sm-' + n.seq });
      note.onclick = function () { window.focus(); window.location.href = notificationLink(n); };
    } catch (e) { /* ignore */ }
  }

  // ---------------------------------------------------------------- live refresh

  const pageCluster = meta('cluster');
  let refreshTimer = null;
  let lastRefresh = 0;

  function busy() {
    if (document.querySelector('[data-no-refresh]')) return true;
    if (document.querySelector('details.menu[open]')) return true;
    const a = document.activeElement;
    if (a && (a.tagName === 'INPUT' || a.tagName === 'TEXTAREA' || a.tagName === 'SELECT')) return true;
    const sel = window.getSelection && window.getSelection();
    return !!(sel && String(sel).length > 0);
  }

  function scheduleRefresh() {
    if (refreshTimer) return;
    const wait = Math.max(800, 3000 - (Date.now() - lastRefresh));
    refreshTimer = setTimeout(() => { refreshTimer = null; refresh(false); }, wait);
  }

  function refresh(force) {
    if (!force && busy()) {
      scheduleRefresh();
      return;
    }
    lastRefresh = Date.now();
    fetch(window.location.href, { credentials: 'same-origin', headers: { 'X-Refresh': '1' } }).then((r) => {
      if (r.redirected || !r.ok) return null;
      return r.text();
    }).then((html) => {
      if (!html) return;
      const doc = new DOMParser().parseFromString(html, 'text/html');
      swap(doc, '#content');
      swap(doc, '.sidebar');
      const m = doc.querySelector('meta[name="unread"]');
      if (m) setUnread(parseInt(m.getAttribute('content'), 10) || 0);
    }).catch(() => {});
  }

  // swap replaces an element's content, keeping which sections are open
  // or collapsed.
  function swap(doc, sel) {
    const cur = document.querySelector(sel);
    const next = doc.querySelector(sel);
    if (!cur || !next) return;
    const open = Array.from(cur.querySelectorAll('details')).map((d) => d.open);
    const collapsed = Array.from(cur.querySelectorAll('tbody')).map((b) => b.classList.contains('collapsed'));
    const y = window.scrollY;
    cur.innerHTML = next.innerHTML;
    cur.querySelectorAll('details').forEach((d, i) => { if (i < open.length && !d.classList.contains('menu')) d.open = open[i]; });
    cur.querySelectorAll('tbody').forEach((b, i) => { if (i < collapsed.length) b.classList.toggle('collapsed', collapsed[i]); });
    window.scrollTo(0, y);
    document.dispatchEvent(new CustomEvent('k0s:swapped', { detail: sel }));
  }

  function relevant(cluster) {
    // The All clusters page and the settings page follow every cluster.
    return !pageCluster || cluster === pageCluster;
  }

  function connect() {
    if (!window.EventSource) return;
    const live = document.getElementById('live');
    const es = new EventSource('/api/v1/stream');
    es.onopen = function () {
      if (live) { live.textContent = 'Live'; live.classList.remove('off'); }
    };
    es.onerror = function () {
      if (live) { live.textContent = 'Reconnecting…'; live.classList.add('off'); }
    };
    es.addEventListener('state', function (e) {
      try {
        const d = JSON.parse(e.data);
        if (relevant(d.cluster)) scheduleRefresh();
      } catch (err) { /* ignore */ }
    });
    es.addEventListener('notification', function (e) {
      try {
        const n = JSON.parse(e.data);
        setUnread(unread + 1);
        const panel = document.getElementById('bellPanel');
        if (panel && panel.classList.contains('on')) loadBell();
        desktopNotify(n);
      } catch (err) { /* ignore */ }
    });
    es.addEventListener('unread', function (e) {
      try { setUnread(JSON.parse(e.data).unread || 0); } catch (err) { /* ignore */ }
    });
  }

  // ---------------------------------------------------------------- explain with AI

  // md shows the simple Markdown models write (headings, lists, code,
  // bold) with DOM nodes: the answer is never inserted as HTML.
  function md(el, text) {
    el.textContent = '';
    el.classList.remove('raw');
    let list = null;
    let para = null;
    let code = null;
    const close = () => { list = null; para = null; };
    text.replace(/\r/g, '').split('\n').forEach((line) => {
      if (code) {
        if (/^\s*```/.test(line)) { code = null; return; }
        code.textContent += (code.textContent ? '\n' : '') + line;
        return;
      }
      if (/^\s*```/.test(line)) {
        close();
        const pre = document.createElement('pre');
        code = document.createElement('code');
        pre.appendChild(code);
        el.appendChild(pre);
        return;
      }
      const h = line.match(/^\s*#{1,6}\s+(.*)$/);
      const ul = line.match(/^\s*[-*•]\s+(.*)$/);
      const ol = line.match(/^\s*\d+[.)]\s+(.*)$/);
      if (h) {
        close();
        const e = document.createElement('h4');
        inline(e, h[1].replace(/\*\*/g, ''));
        el.appendChild(e);
        return;
      }
      if (ul || ol) {
        const tag = ul ? 'UL' : 'OL';
        if (!list || list.tagName !== tag) {
          para = null;
          list = document.createElement(tag.toLowerCase());
          el.appendChild(list);
        }
        const li = document.createElement('li');
        inline(li, (ul || ol)[1]);
        list.appendChild(li);
        return;
      }
      if (!line.trim()) { close(); return; }
      if (list && /^\s{2,}/.test(line) && list.lastElementChild) {
        list.lastElementChild.appendChild(document.createTextNode(' '));
        inline(list.lastElementChild, line.trim());
        return;
      }
      if (!para) {
        list = null;
        para = document.createElement('p');
        el.appendChild(para);
      } else {
        para.appendChild(document.createTextNode(' '));
      }
      inline(para, line.trim());
    });
  }

  function inline(el, text) {
    const re = /(`[^`]+`|\*\*[^*]+\*\*)/g;
    let last = 0;
    let m;
    while ((m = re.exec(text))) {
      if (m.index > last) el.appendChild(document.createTextNode(text.slice(last, m.index)));
      const tok = m[0];
      const e = document.createElement(tok[0] === '`' ? 'code' : 'b');
      e.textContent = tok[0] === '`' ? tok.slice(1, -1) : tok.slice(2, -2);
      el.appendChild(e);
      last = m.index + tok.length;
    }
    if (last < text.length) el.appendChild(document.createTextNode(text.slice(last)));
  }

  function setupAI() {
    const box = document.querySelector('[data-ai]');
    if (!box) return;
    const answer = box.querySelector('[data-ai-answer]');
    if (answer && !answer.hidden && answer.classList.contains('raw') && answer.textContent.trim()) md(answer, answer.textContent);
    const ask = box.querySelector('[data-ai-ask]');
    if (ask && !ask.dataset.bound) {
      ask.dataset.bound = '1';
      ask.addEventListener('click', () => explain(box));
    }
  }

  // explain asks for the answer and shows it as it arrives. The page
  // doesn't refresh meanwhile; the server keeps the answer afterwards.
  function explain(box) {
    const answer = box.querySelector('[data-ai-answer]');
    const status = box.querySelector('[data-ai-status]');
    const note = box.querySelector('[data-ai-meta]');
    const ask = box.querySelector('[data-ai-ask]');
    const stop = box.querySelector('[data-ai-stop]');
    const ctl = new AbortController();
    let text = '';
    box.setAttribute('data-no-refresh', '');
    ask.disabled = true;
    stop.hidden = false;
    stop.onclick = () => ctl.abort();
    answer.hidden = false;
    answer.classList.add('raw');
    answer.textContent = '';
    status.hidden = false;
    status.classList.remove('bad');
    status.textContent = 'Asking the model… local models can take a while.';
    const finish = (msg, bad) => {
      box.removeAttribute('data-no-refresh');
      ask.disabled = false;
      stop.hidden = true;
      ask.textContent = 'Ask again';
      status.hidden = !msg;
      status.textContent = msg || '';
      status.classList.toggle('bad', !!bad);
      if (text) md(answer, text);
      else answer.hidden = true;
    };
    fetch(box.dataset.url, {
      method: 'POST', credentials: 'same-origin', signal: ctl.signal,
      headers: { 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: box.dataset.mode }),
    }).then(async (r) => {
      if (!r.ok) {
        let msg = 'The request failed (HTTP ' + r.status + ').';
        try { const j = await r.json(); if (j.error) msg = j.error; } catch (e) { /* not JSON */ }
        finish(msg, true);
        return;
      }
      const reader = r.body.getReader();
      const dec = new TextDecoder();
      let buf = '';
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        buf += dec.decode(chunk.value, { stream: true });
        let i;
        while ((i = buf.indexOf('\n\n')) >= 0) {
          const raw = buf.slice(0, i);
          buf = buf.slice(i + 2);
          let ev = 'message';
          let data = '';
          raw.split('\n').forEach((l) => {
            if (l.startsWith('event:')) ev = l.slice(6).trim();
            else if (l.startsWith('data:')) data += l.slice(5).trim();
          });
          let v;
          try { v = JSON.parse(data); } catch (e) { continue; }
          if (ev === 'thinking') {
            status.textContent = 'The model is thinking…';
          } else if (ev === 'text') {
            text += v;
            answer.textContent = text;
            status.textContent = 'Writing…';
          } else if (ev === 'error') {
            finish(v.message, true);
            return;
          } else if (ev === 'done') {
            if (note) note.textContent = 'Written by ' + v.model + ' just now. It can be wrong: check before you act.';
            finish('');
            return;
          }
        }
      }
      finish(text ? 'The answer stopped early.' : 'No answer came.', true);
    }).catch((e) => {
      finish(e.name === 'AbortError' ? 'Stopped.' : 'The request failed: ' + e.message, e.name !== 'AbortError');
    });
  }

  setupAI();
  document.addEventListener('k0s:swapped', setupAI);

  // The provider fills in its address, unless one was typed.
  const provider = document.querySelector('[data-ai-provider]');
  if (provider) {
    const url = document.querySelector('[data-ai-url]');
    const note = document.querySelector('[data-ai-note]');
    let prev = provider.selectedOptions[0] ? provider.selectedOptions[0].dataset.url : '';
    provider.addEventListener('change', () => {
      const o = provider.selectedOptions[0];
      if (url && (!url.value || url.value === prev)) url.value = o.dataset.url || '';
      prev = o.dataset.url || '';
      if (note) note.textContent = o.dataset.note || '';
    });
  }

  if (csrf) connect();
})();
