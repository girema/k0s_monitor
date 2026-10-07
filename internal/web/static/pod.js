// Pod page (Full mode): tabs with describe, events, logs and YAML, loaded
// when first opened. Logs can be followed live and filtered.
(function () {
  'use strict';
  const root = document.getElementById('podPage');
  if (!root || !document.getElementById('describeOut')) return;
  const base = root.getAttribute('data-base');
  const $ = (id) => document.getElementById(id);
  const loaded = {};
  let follow = null; // EventSource while following
  let lines = []; // current log lines
  const MAX_LINES = 20000;

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function fetchText(url) {
    return fetch(url, { credentials: 'same-origin' }).then((r) => {
      if (r.ok) return r.text();
      return r.json().then((j) => { throw new Error(j.error || r.statusText); }, () => { throw new Error(r.statusText); });
    });
  }

  // ------------------------------------------------------------ tabs

  function show(tab) {
    document.querySelectorAll('#podPage .tabs button').forEach((b) => {
      const on = b.getAttribute('data-tab') === tab;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('#podPage .tabpane').forEach((p) => p.classList.toggle('on', p.id === 'tab-' + tab));
    if (!loaded[tab]) {
      loaded[tab] = true;
      load(tab);
    }
  }

  function load(tab) {
    if (tab === 'describe') {
      fetchText(base + '/describe').then((t) => { $('describeOut').textContent = t; },
        (e) => { $('describeOut').textContent = 'Describe failed: ' + e.message; });
    } else if (tab === 'yaml') {
      fetchText(base + '/yaml').then((t) => { $('yamlOut').textContent = t; },
        (e) => { $('yamlOut').textContent = 'YAML failed: ' + e.message; });
    } else if (tab === 'events') {
      fetch(base + '/events', { credentials: 'same-origin' }).then((r) => r.json()).then(renderEvents,
        () => { $('eventsOut').textContent = 'Events could not be loaded.'; });
    } else if (tab === 'logs') {
      loadLog();
    }
  }

  function renderEvents(evs) {
    const out = $('eventsOut');
    out.textContent = '';
    out.className = '';
    if (!Array.isArray(evs)) { out.textContent = evs.error || 'Events could not be loaded.'; return; }
    if (evs.length === 0) { out.className = 'muted'; out.textContent = 'No events. Kubernetes keeps events for about one hour.'; return; }
    const t = el('table', 't evtable');
    const head = el('tr');
    ['Last seen', 'Type', 'Reason', 'Message', 'Count', 'From'].forEach((h) => head.appendChild(el('th', '', h)));
    const th = el('thead');
    th.appendChild(head);
    t.appendChild(th);
    const tb = el('tbody');
    evs.forEach((e) => {
      const tr = el('tr');
      tr.appendChild(el('td', 'small', new Date(e.last).toISOString().replace('T', ' ').slice(0, 19)));
      const type = el('td');
      const st = el('span', 'st small');
      const ic = el('i', 'ic ' + (e.type === 'Warning' ? 'warn' : 'info'), e.type === 'Warning' ? '▲' : 'i');
      st.appendChild(ic);
      st.appendChild(document.createTextNode(e.type));
      type.appendChild(st);
      tr.appendChild(type);
      tr.appendChild(el('td', 'mono small', e.reason));
      tr.appendChild(el('td', 'small', e.message));
      tr.appendChild(el('td', 'r', String(e.count)));
      tr.appendChild(el('td', 'small muted', e.source || ''));
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    const wrap = el('div', 'tbl-wrap');
    wrap.appendChild(t);
    out.appendChild(wrap);
  }

  // ------------------------------------------------------------ logs

  function logQuery(extra) {
    const p = new URLSearchParams({
      container: $('logContainer').value,
      previous: $('logPrevious').checked ? 'true' : 'false',
      tail: $('logTail').value,
    });
    Object.keys(extra || {}).forEach((k) => p.set(k, extra[k]));
    return base + '/logs?' + p.toString();
  }

  function stopFollow() {
    if (follow) { follow.close(); follow = null; }
    const b = $('logFollow');
    b.setAttribute('aria-pressed', 'false');
    b.textContent = 'Follow';
  }

  function loadLog() {
    stopFollow();
    $('logInfo').textContent = 'Loading…';
    fetchText(logQuery()).then((t) => {
      lines = t.split('\n');
      if (lines.length && lines[lines.length - 1] === '') lines.pop();
      render(true);
      $('logInfo').textContent = lines.length + (lines.length === 1 ? ' line' : ' lines') + ($('logPrevious').checked ? ' from the previous run' : '');
    }, (e) => {
      lines = [];
      render(false);
      $('logInfo').textContent = 'The log could not be loaded: ' + e.message;
    });
  }

  function startFollow() {
    stopFollow();
    $('logPrevious').checked = false;
    lines = [];
    render(false);
    const es = new EventSource(logQuery({ follow: 'true', tail: '200' }));
    follow = es;
    const b = $('logFollow');
    b.setAttribute('aria-pressed', 'true');
    b.textContent = 'Stop following';
    $('logInfo').textContent = 'Following the log live…';
    let pending = [];
    let timer = null;
    es.onmessage = (m) => {
      pending.push(m.data);
      if (!timer) {
        timer = setTimeout(() => {
          timer = null;
          lines = lines.concat(pending);
          pending = [];
          if (lines.length > MAX_LINES) lines = lines.slice(lines.length - MAX_LINES);
          render(true);
        }, 250);
      }
    };
    es.addEventListener('end', () => { $('logInfo').textContent = 'The log stream ended (the container stopped).'; stopFollow(); });
    es.onerror = () => { if (follow === es) $('logInfo').textContent = 'Reconnecting to the log…'; };
  }

  function filterFn() {
    const q = $('logFilter').value.trim();
    if (!q) return null;
    if (q.length > 2 && q[0] === '/' && q[q.length - 1] === '/') {
      try { const re = new RegExp(q.slice(1, -1), 'i'); return (l) => re.test(l); } catch (e) { return null; }
    }
    const lq = q.toLowerCase();
    return (l) => l.toLowerCase().indexOf(lq) >= 0;
  }

  const errRe = /(fatal|panic|error|exception|traceback|failed|refused|denied|no such host|timed? ?out|killed)/i;
  const warnRe = /\b(warn|warning)\b/i;

  function render(scroll) {
    const out = $('logOut');
    const f = filterFn();
    const shown = f ? lines.filter(f) : lines;
    const atBottom = out.scrollTop + out.clientHeight >= out.scrollHeight - 30;
    out.textContent = '';
    const frag = document.createDocumentFragment();
    shown.forEach((l) => {
      let cls = '';
      if (errRe.test(l)) cls = 'ln-err';
      else if (warnRe.test(l)) cls = 'ln-warn';
      if (cls) {
        frag.appendChild(el('span', cls, l));
      } else {
        frag.appendChild(document.createTextNode(l + '\n'));
      }
    });
    out.appendChild(frag);
    if (f) $('logInfo').textContent = shown.length + ' of ' + lines.length + ' lines match';
    if (scroll && (atBottom || !follow)) out.scrollTop = out.scrollHeight;
  }

  // ------------------------------------------------------------ events

  root.addEventListener('click', (e) => {
    const t = e.target;
    if (!(t instanceof Element)) return;
    const tab = t.closest('[data-tab]');
    if (tab) { show(tab.getAttribute('data-tab')); return; }
    if (t.id === 'logLoad') loadLog();
    if (t.id === 'logFollow') { if (follow) stopFollow(); else startFollow(); }
  });
  ['logContainer', 'logPrevious', 'logTail'].forEach((id) => $(id).addEventListener('change', loadLog));
  let ft = null;
  $('logFilter').addEventListener('input', () => { clearTimeout(ft); ft = setTimeout(() => render(false), 150); });
  window.addEventListener('beforeunload', stopFollow);

  // Open the Logs tab directly with #logs.
  show(window.location.hash === '#logs' ? 'logs' : 'describe');
})();
