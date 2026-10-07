// Add cluster page: read files or pasted text, show what was found, run
// the connection test, and save.
(function () {
  'use strict';
  const root = document.getElementById('addCluster');
  if (!root) return;
  const basic = root.getAttribute('data-basic') === 'true';
  const csrf = document.querySelector('meta[name="csrf"]').getAttribute('content');
  const $ = (id) => document.getElementById(id);
  const MAX_FILES = 5, MAX_SIZE = 1 << 20;

  let draft = null; // {id, result}
  let contextServer = '';

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function icon(status) {
    const map = { pass: ['good', '✓'], warn: ['warn', '▲'], fail: ['crit', '✕'], skip: ['info', '–'],
      error: ['crit', '✕'], warning: ['warn', '▲'], info: ['info', 'i'] };
    const m = map[status] || map.info;
    const i = el('i', 'ic ' + m[0], m[1]);
    i.setAttribute('aria-hidden', 'true');
    return i;
  }

  function post(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify(body),
    }).then((r) => r.json().then((j) => ({ ok: r.ok, status: r.status, body: j }), () => ({ ok: r.ok, status: r.status, body: {} })));
  }

  // ------------------------------------------------------------ reading files

  function readFiles(list) {
    const files = Array.from(list).slice(0, MAX_FILES);
    if (list.length > MAX_FILES) showImportError('At most ' + MAX_FILES + ' files at once.');
    const reads = files.map((f) => new Promise((resolve) => {
      if (f.size > MAX_SIZE) { resolve({ name: f.name, content: '', tooBig: true }); return; }
      const fr = new FileReader();
      fr.onload = () => resolve({ name: f.name, content: String(fr.result) });
      fr.onerror = () => resolve({ name: f.name, content: '' });
      fr.readAsText(f);
    }));
    Promise.all(reads).then((inputs) => {
      const big = inputs.filter((i) => i.tooBig).map((i) => i.name);
      if (big.length) showImportError(big.join(', ') + ': larger than 1 MiB.');
      importInputs(inputs.filter((i) => !i.tooBig));
    });
  }

  function importInputs(inputs) {
    if (!inputs.length) return;
    $('files').textContent = '';
    $('files').appendChild(el('div', 'muted small', 'Reading…'));
    post('/api/v1/clusters/import', { files: inputs.map((i) => ({ name: i.name, content: i.content })) }).then((r) => {
      if (!r.ok) { showImportError(r.body.error || 'The files could not be read.'); return; }
      showImport(r.body);
    }, () => showImportError('The files could not be sent.'));
  }

  function showImportError(msg) {
    const f = $('files');
    f.textContent = '';
    const n = el('div', 'notice bad');
    n.appendChild(icon('error'));
    n.appendChild(el('span', '', msg));
    f.appendChild(n);
  }

  const typeNames = { kubeconfig: 'Kubeconfig', k0sctl: 'k0sctl cluster file', 'k0s-config': 'k0s configuration', unknown: 'Not recognized' };

  function showImport(resp) {
    const res = resp.result;
    const box = $('files');
    box.textContent = '';
    res.files.forEach((f) => {
      const card = el('div', 'file');
      const h = el('div', 'fh');
      h.appendChild(el('span', 'mono', f.name));
      h.appendChild(el('span', 'tag', typeNames[f.type] || f.type));
      const st = el('span', 'st small right-a');
      st.appendChild(icon(f.error ? 'error' : 'pass'));
      st.appendChild(document.createTextNode(f.error ? 'can\'t be used' : (f.type === 'kubeconfig' ? 'gives access' : 'gives the layout')));
      h.appendChild(st);
      card.appendChild(h);
      card.appendChild(el('div', 'fd', f.error || f.summary));
      box.appendChild(card);
    });
    (res.notes || []).forEach((n) => {
      const line = el('div', 'notice ' + (n.level === 'error' ? 'bad' : n.level === 'warning' ? 'warn' : ''));
      line.appendChild(icon(n.level));
      const t = el('div');
      t.appendChild(el('b', '', n.plain));
      if (n.hint) { t.appendChild(document.createTextNode(' ')); t.appendChild(el('span', 'sec', n.hint)); }
      line.appendChild(t);
      box.appendChild(line);
    });
    if (!resp.draftId) {
      $('afterImport').classList.add('hidden');
      draft = null;
      return;
    }
    draft = { id: resp.draftId, result: res };
    const sel = $('ctxSel');
    sel.textContent = '';
    (res.contexts || []).forEach((c) => {
      const o = el('option', '', c.name + (c.server ? ' — ' + c.server : ''));
      o.value = c.name;
      if (c.name === res.current) o.selected = true;
      sel.appendChild(o);
    });
    $('ctxField').classList.toggle('hidden', (res.contexts || []).length < 2);
    $('cname').value = res.name || '';
    setServer(resp.server || '');
    $('afterImport').classList.remove('hidden');
    $('addError').classList.add('hidden');
    const blocking = (res.notes || []).some((n) => n.level === 'error');
    $('addBtn').disabled = blocking;
    $('testBtn').disabled = blocking;
    if (!blocking) runTest();
  }

  function currentContext() {
    const res = draft.result;
    const name = $('ctxSel').value || res.current;
    return (res.contexts || []).find((c) => c.name === name) || {};
  }

  function setServer(suggested) {
    const c = currentContext();
    contextServer = c.server || '';
    const input = $('server');
    const help = $('serverHelp');
    if (c.loopback) {
      input.value = suggested || '';
      input.placeholder = 'https://<controller or load balancer>:6443';
      help.textContent = 'The kubeconfig says ' + contextServer + ', which only works on the controller itself.' +
        (suggested ? ' This address comes from the uploaded files.' : ' Enter an address this machine can reach.');
    } else {
      input.value = contextServer;
      input.placeholder = contextServer;
      help.textContent = basic ? 'Taken from the file. Change it only if this machine reaches the cluster by another address.' :
        'From the kubeconfig. Change it to reach the cluster through another address, for example a load balancer.';
    }
  }

  function settings() {
    const server = $('server').value.trim();
    return {
      draftId: draft.id,
      context: $('ctxSel').value || draft.result.current,
      server: server === contextServer ? '' : server,
      proxy: $('proxy') ? $('proxy').value.trim() : '',
    };
  }

  // ------------------------------------------------------------ test

  function runTest() {
    if (!draft) return;
    const out = $('testResult');
    out.textContent = '';
    const wait = el('div', 'row');
    wait.appendChild(el('span', 'spinner'));
    wait.appendChild(el('span', 'muted', 'Testing the connection…'));
    out.appendChild(wait);
    $('testSummary').textContent = '';
    $('testBtn').disabled = true;
    post('/api/v1/clusters/test', settings()).then((r) => {
      $('testBtn').disabled = false;
      if (!r.ok) { out.textContent = r.body.error || 'The test could not run.'; return; }
      showTest(r.body);
    }, () => { $('testBtn').disabled = false; out.textContent = 'The test could not run.'; });
  }

  function showTest(rep) {
    const out = $('testResult');
    out.textContent = '';
    const sum = $('testSummary');
    sum.textContent = '';
    const s = el('span', 'st small');
    const warn = rep.steps.some((x) => x.status === 'warn');
    s.appendChild(icon(rep.ok ? (warn ? 'warn' : 'pass') : 'fail'));
    s.appendChild(document.createTextNode(rep.ok ? (warn ? 'Connected, with warnings' : 'Connected') : 'Not connected'));
    sum.appendChild(s);
    if (basic) {
      const n = el('div', rep.ok ? 'notice good' : 'notice bad');
      n.appendChild(icon(rep.ok ? 'pass' : 'fail'));
      n.appendChild(el('span', '', rep.ok ? 'k0s-monitor can reach the cluster and sign in. Save it to start the checks.' :
        'k0s-monitor can\'t use this cluster yet. The failed step below says how to fix it.'));
      out.appendChild(n);
    }
    const ul = el('ul', 'checks');
    rep.steps.forEach((st) => {
      const li = el('li');
      li.appendChild(icon(st.status));
      const span = el('span');
      span.appendChild(el('b', '', st.name + ': '));
      span.appendChild(document.createTextNode(st.detail || st.status));
      li.appendChild(span);
      ul.appendChild(li);
      if (st.hint && st.status !== 'pass') {
        const h = el('div', 'fixhint', 'Fix: ' + st.hint);
        ul.appendChild(h);
      }
    });
    out.appendChild(ul);
    // The account options depend on what the credentials may do.
    const ro = $('radioRO'), up = $('radioUp'), note = $('accountNote');
    if (rep.ok && !rep.canCreateAccount) {
      ro.classList.add('disabled');
      ro.querySelector('input').disabled = true;
      up.classList.remove('hidden');
      up.querySelector('input').checked = true;
      note.textContent = 'These credentials can\'t create an account (they are limited already), so they are used as they are.';
      note.classList.remove('hidden');
    } else {
      ro.classList.remove('disabled');
      ro.querySelector('input').disabled = false;
      note.classList.add('hidden');
    }
    markRadios();
  }

  function markRadios() {
    document.querySelectorAll('#addCluster .radio').forEach((r) => {
      r.classList.toggle('on', r.querySelector('input').checked);
    });
  }

  // ------------------------------------------------------------ save

  function save() {
    if (!draft) return;
    const body = settings();
    body.name = $('cname').value.trim();
    body.criticality = $('crit') ? $('crit').value : '';
    const acc = document.querySelector('#addCluster input[name="account"]:checked');
    body.account = acc ? acc.value : 'readonly';
    const tls = $('tlsSecrets');
    body.tlsSecrets = tls ? tls.checked : true;
    const btn = $('addBtn');
    btn.disabled = true;
    btn.textContent = body.account === 'readonly' ? 'Creating the read-only account…' : 'Saving…';
    const err = $('addError');
    err.classList.add('hidden');
    post('/api/v1/clusters', body).then((r) => {
      if (r.ok) { window.location.href = r.body.url; return; }
      btn.disabled = false;
      btn.textContent = 'Save and connect';
      err.textContent = (r.body.error || 'The cluster could not be added.') + (r.body.hint ? ' ' + r.body.hint : '');
      err.classList.remove('hidden');
    }, () => {
      btn.disabled = false;
      btn.textContent = 'Save and connect';
      err.textContent = 'The request failed.';
      err.classList.remove('hidden');
    });
  }

  // ------------------------------------------------------------ events

  const drop = $('drop');
  ['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove('over'); }));
  drop.addEventListener('drop', (e) => { if (e.dataTransfer && e.dataTransfer.files.length) readFiles(e.dataTransfer.files); });
  $('fileInput').addEventListener('change', (e) => { if (e.target.files.length) readFiles(e.target.files); });
  $('pasteBtn').addEventListener('click', () => {
    const text = $('pasteText').value;
    if (text.trim()) importInputs([{ name: '', content: text }]);
  });
  $('ctxSel').addEventListener('change', () => { setServer(''); runTest(); });
  $('testBtn').addEventListener('click', runTest);
  $('addBtn').addEventListener('click', save);
  root.addEventListener('change', (e) => { if (e.target.name === 'account') markRadios(); });
})();
