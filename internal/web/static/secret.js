// Secret page: shows values on request, one key or all of them. The server
// records each value shown. Values live only in the page while shown;
// leaving the page hides them. The page opts out of live refresh, and the
// handlers look up what they act on when clicked, so nothing depends on
// the elements the page first had.
(function () {
  'use strict';
  const csrfMeta = document.querySelector('meta[name="csrf"]');
  const csrf = csrfMeta ? csrfMeta.getAttribute('content') : '';

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function button(text, attr) {
    const b = el('button', 'btn sm', text);
    b.type = 'button';
    b.setAttribute(attr, '');
    return b;
  }

  // mask puts a cell back to its hidden state, with a message if given.
  function mask(td, msg) {
    td.textContent = '';
    td.appendChild(el('span', 'masked', '••••••••'));
    td.appendChild(document.createTextNode(' '));
    td.appendChild(button('Show', 'data-show'));
    if (msg) td.appendChild(el('div', 'err-text mt8', msg));
  }

  function show(td, v) {
    td.textContent = '';
    td.appendChild(el('pre', 'term wrap', v.value));
    const bar = el('div', 'row');
    bar.appendChild(button('Copy', 'data-copy-value'));
    bar.appendChild(button('Hide', 'data-hide'));
    if (v.base64) bar.appendChild(el('span', 'small muted', 'binary, shown as base64'));
    td.appendChild(bar);
  }

  function reveal(td) {
    const page = document.getElementById('secretPage');
    if (!page || td.querySelector('pre')) return;
    const b = td.querySelector('[data-show]');
    if (b) {
      b.disabled = true;
      b.textContent = 'Loading…';
    }
    fetch(page.getAttribute('data-reveal'), {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({ key: td.getAttribute('data-key') }),
    }).then((r) => r.json().then((j) => ({ ok: r.ok, body: j }), () => ({ ok: false, body: { error: r.statusText || 'error ' + r.status } })))
      .then((a) => {
        if (a.ok) { show(td, a.body); return; }
        mask(td, (a.body.error || 'The value could not be shown.') + (a.body.hint ? ' ' + a.body.hint : ''));
      }, () => mask(td, 'k0s-monitor could not be reached.'));
  }

  function copy(td, b) {
    const pre = td.querySelector('pre');
    if (!pre) return;
    const done = () => { b.textContent = 'Copied'; setTimeout(() => { b.textContent = 'Copy'; }, 1500); };
    const select = () => {
      const range = document.createRange();
      range.selectNodeContents(pre);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(pre.textContent).then(done, select);
    } else {
      select();
    }
  }

  document.addEventListener('click', (ev) => {
    const t = ev.target;
    if (!(t instanceof Element)) return;
    const page = t.closest('#secretPage');
    if (!page) return;
    const td = t.closest('td[data-key]');
    if (td && t.closest('[data-show]')) reveal(td);
    else if (td && t.closest('[data-hide]')) mask(td);
    else if (td && t.closest('[data-copy-value]')) copy(td, t.closest('[data-copy-value]'));
    else if (t.closest('[data-show-all]')) page.querySelectorAll('td[data-key]').forEach(reveal);
  });

  // Leaving the page hides the values, so going back doesn't show them.
  window.addEventListener('pagehide', () => {
    document.querySelectorAll('#secretPage td[data-key]').forEach((td) => { if (td.querySelector('pre')) mask(td); });
  });
})();
