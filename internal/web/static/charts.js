// Line charts and sparklines for the Servers and Storage pages. The data
// comes from data-chart (JSON) and data-spark attributes; every chart also
// has a table view rendered by the server.
(function () {
  'use strict';

  const NS = 'http://www.w3.org/2000/svg';
  function el(tag, attrs, parent) {
    const e = document.createElementNS(NS, tag);
    for (const k in attrs) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function txt(attrs, text, parent) {
    const e = el('text', attrs, parent);
    e.textContent = text;
    return e;
  }
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  let tip = null;
  function showTip(evt, value, label) {
    if (!tip) {
      tip = document.createElement('div');
      tip.className = 'tip';
      tip.setAttribute('role', 'status');
      document.body.appendChild(tip);
    }
    tip.replaceChildren();
    const b = document.createElement('b');
    b.textContent = value;
    tip.appendChild(b);
    if (label) {
      const s = document.createElement('span');
      s.textContent = label;
      tip.appendChild(s);
    }
    const box = evt.target.getBoundingClientRect();
    const x = evt.clientX || box.left + 10;
    const y = evt.clientY || box.top;
    tip.style.left = Math.max(8, Math.min(x + 14, window.innerWidth - 220)) + 'px';
    tip.style.top = Math.max(8, y - 48) + 'px';
    tip.classList.add('on');
  }
  function hideTip() {
    if (tip) tip.classList.remove('on');
  }

  const hhmm = (t) => new Date(t * 1000).toISOString().slice(11, 16);
  const pct = (v) => (Math.round(v * 10) / 10) + '%';

  function lineChart(host) {
    let d;
    try { d = JSON.parse(host.getAttribute('data-chart')); } catch (e) { return; }
    if (!d.series || d.series.length < 2) return;
    host.replaceChildren();
    const W = Math.max(host.clientWidth, 280), H = 220, L = 38, T = 14, B = 26;
    const R = d.projection ? 96 : 44;
    const pw = W - L - R, ph = H - T - B;
    const X = (t) => L + ((t - d.start) / (d.end - d.start)) * pw;
    const Y = (v) => T + ph - (Math.max(0, Math.min(v, 100)) / 100) * ph;
    const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, 'aria-hidden': 'true' }, host);
    [0, 25, 50, 75, 100].forEach((v) => {
      el('line', { x1: L, x2: L + pw, y1: Y(v), y2: Y(v), class: v ? 'grid-l' : 'base-l' }, svg);
      txt({ x: L - 8, y: Y(v) + 4, 'text-anchor': 'end', class: 'ax' }, v + '%', svg);
    });
    (d.thresholds || []).forEach((t) => {
      el('line', { x1: L, x2: L + pw, y1: Y(t.v), y2: Y(t.v), stroke: t.kind === 'crit' ? css('--critical') : css('--muted'), 'stroke-width': 1 }, svg);
      txt({ x: L + 4, y: t.below ? Y(t.v) + 13 : Y(t.v) - 4, class: 'lbl2' }, t.label, svg);
    });
    const s = d.series;
    const accent = css('--accent');
    const last = s.length - 1;
    const line = s.map((p, i) => `${i ? 'L' : 'M'}${X(p[0]).toFixed(1)},${Y(p[1]).toFixed(1)}`).join(' ');
    el('path', { d: `${line} L${X(s[last][0]).toFixed(1)},${Y(0)} L${X(s[0][0]).toFixed(1)},${Y(0)} Z`, fill: accent, 'fill-opacity': 0.1 }, svg);
    el('path', { d: line, fill: 'none', stroke: accent, 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }, svg);
    const lx = X(s[last][0]), ly = Y(s[last][1]);
    if (d.projection) {
      const p = d.projection;
      el('path', { d: `M${lx},${ly} L${X(p.t)},${Y(p.v)}`, fill: 'none', stroke: accent, 'stroke-width': 2, 'stroke-dasharray': '5 4', 'stroke-linecap': 'round' }, svg);
      el('circle', { cx: X(p.t), cy: Y(p.v), r: 4, fill: css('--surface'), stroke: accent, 'stroke-width': 2 }, svg);
      txt({ x: X(p.t) + 8, y: Y(p.v) + 4, class: 'lbl' }, p.label, svg);
      txt({ x: lx - 10, y: ly - 8, 'text-anchor': 'end', class: 'lbl' }, pct(s[last][1]), svg);
    } else {
      txt({ x: lx + 10, y: ly + 4, class: 'lbl' }, pct(s[last][1]), svg);
    }
    el('circle', { cx: lx, cy: ly, r: 6, fill: css('--surface') }, svg);
    el('circle', { cx: lx, cy: ly, r: 4, fill: accent }, svg);

    // Hours relative to now on the time axis.
    const ticks = [];
    for (let h = -24; h <= 0; h += 6) ticks.push(h);
    const ahead = (d.end - d.now) / 3600;
    if (ahead >= 1) ticks.push(Math.round(ahead));
    ticks.forEach((h, i) => {
      const t = d.now + h * 3600;
      if (t < d.start - 60 || t > d.end + 60) return;
      const anchor = i === 0 ? 'start' : (i === ticks.length - 1 && h >= 0) ? 'end' : 'middle';
      const label = h === 0 ? 'now' : (h > 0 ? '+' : '−') + Math.abs(h) + 'h';
      txt({ x: X(t), y: H - 6, 'text-anchor': anchor, class: 'ax' }, label, svg);
    });

    // Crosshair and tooltip for the nearest sample.
    const xh = el('line', { x1: 0, x2: 0, y1: T, y2: T + ph, class: 'xhair', visibility: 'hidden' }, svg);
    const hit = el('rect', { x: L, y: T, width: Math.max(1, lx - L), height: ph, fill: 'transparent', tabindex: 0 }, svg);
    const nearest = (sx) => {
      const t = d.start + ((sx - L) / pw) * (d.end - d.start);
      let best = 0;
      for (let i = 1; i < s.length; i++) if (Math.abs(s[i][0] - t) < Math.abs(s[best][0] - t)) best = i;
      return best;
    };
    const show = (e, i) => {
      xh.setAttribute('x1', X(s[i][0]));
      xh.setAttribute('x2', X(s[i][0]));
      xh.setAttribute('visibility', 'visible');
      showTip(e, pct(s[i][1]) + ' used', hhmm(s[i][0]) + ' UTC');
    };
    hit.addEventListener('pointermove', (e) => {
      const box = svg.getBoundingClientRect();
      show(e, nearest((e.clientX - box.left) * (W / box.width)));
    });
    hit.addEventListener('focus', (e) => show(e, last));
    const hide = () => { xh.setAttribute('visibility', 'hidden'); hideTip(); };
    hit.addEventListener('pointerleave', hide);
    hit.addEventListener('blur', hide);
  }

  function sparkline(s) {
    const d = (s.getAttribute('data-spark') || '').split(',').map(Number).filter((v) => !isNaN(v));
    if (d.length < 2) return;
    s.replaceChildren();
    const W = 110, H = 28;
    const lo = Math.min(...d) - 2, hi = Math.max(...d) + 2;
    s.setAttribute('viewBox', `0 0 ${W} ${H}`);
    const X = (i) => 3 + (i / (d.length - 1)) * (W - 10);
    const Y = (v) => H - 4 - ((v - lo) / (hi - lo)) * (H - 8);
    el('path', { d: d.map((v, i) => `${i ? 'L' : 'M'}${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(' '), fill: 'none', stroke: css('--muted'), 'stroke-width': 1.5, 'stroke-linejoin': 'round' }, s);
    const l = d.length - 1;
    el('circle', { cx: X(l), cy: Y(d[l]), r: 5, fill: css('--surface') }, s);
    el('circle', { cx: X(l), cy: Y(d[l]), r: 3.5, fill: css('--accent') }, s);
    s.setAttribute('tabindex', '0');
    const show = (e) => showTip(e, `${pct(d[0])} → ${pct(d[l])}`, 'last 24 h');
    s.onpointermove = show;
    s.onfocus = show;
    s.onpointerleave = hideTip;
    s.onblur = hideTip;
  }

  function render() {
    hideTip();
    document.querySelectorAll('[data-chart]').forEach(lineChart);
    document.querySelectorAll('svg[data-spark]').forEach(sparkline);
  }

  let timer = null;
  function later() {
    clearTimeout(timer);
    timer = setTimeout(render, 150);
  }
  document.addEventListener('k0s:swapped', render);
  document.addEventListener('k0s:theme', render);
  window.addEventListener('resize', later);
  if (window.matchMedia) {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    if (mq.addEventListener) mq.addEventListener('change', render);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', render);
  else render();
})();
