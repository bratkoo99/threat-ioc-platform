/* ==========================================================================
   TIOX core — shared services for every view.

   One module, no framework. Each view file exports a mount() function and is
   loaded independently; core.js owns the things that must behave identically
   everywhere:

     - the authenticated API client (cookie-based, 401 -> login gate)
     - the global time window, which every panel reads
     - formatting helpers
     - pivot navigation, so clicking a hash anywhere lands on the same page
     - toasts and DOM helpers
   ========================================================================== */

const TIOX = (() => {
  'use strict';

  // ---------------------------------------------------------------- state

  const state = {
    window: '24h',      // '15m' | '1h' | '24h' | '7d' | '30d' | 'all' | 'custom'
    customFrom: null,
    customTo: null,
    sse: null,
    views: new Map(),   // name -> { mount, unmount }
    current: null,
  };

  // ---------------------------------------------------------------- api

  /**
   * Authenticated fetch. Attaches the session cookie, and surfaces a 401 by
   * showing the login gate rather than letting each caller handle it.
   *
   * The cookie exists because EventSource cannot set headers, so a header-based
   * token would leave the live stream unauthenticated.
   */
  async function api(path, options = {}) {
    const opts = Object.assign({ credentials: 'same-origin' }, options);
    const res = await fetch(path, opts);
    if (res.status === 401) {
      showLoginGate('Session expired. Sign in again.');
      throw new AuthError();
    }
    if (res.status === 204) return null;
    const text = await res.text();
    let body = null;
    if (text) {
      try { body = JSON.parse(text); } catch { body = text; }
    }
    if (!res.ok) {
      const msg = (body && body.error) || `HTTP ${res.status}`;
      throw new ApiError(msg, res.status, body);
    }
    return body;
  }

  class AuthError extends Error {}
  class ApiError extends Error {
    constructor(message, status, body) {
      super(message);
      this.status = status;
      this.body = body;
    }
  }

  /** Serialize an object into a query string, dropping empty values. */
  function qs(params) {
    const parts = [];
    for (const [k, v] of Object.entries(params || {})) {
      if (v === undefined || v === null || v === '') continue;
      parts.push(`${encodeURIComponent(k)}=${encodeURIComponent(v)}`);
    }
    return parts.length ? '?' + parts.join('&') : '';
  }

  // ---------------------------------------------------------------- time window

  /**
   * The window every panel honours. The server resolves the shorthand, so the
   * client only has to agree on the vocabulary.
   */
  function windowParam(override) {
    return override || state.window;
  }

  function setWindow(w, customFrom, customTo) {
    state.window = w;
    if (w === 'custom') {
      state.customFrom = customFrom || state.customFrom;
      state.customTo = customTo || state.customTo;
    }
    document.querySelectorAll('.time-picker button').forEach(b => {
      b.classList.toggle('active', b.dataset.window === w);
    });
    const picker = document.querySelector('.time-picker');
    if (picker) picker.classList.toggle('custom', w === 'custom');
    // Every mounted view re-renders, so all panels stay on one scope.
    refreshCurrent();
  }

  function windowLabel() {
    if (state.window === 'all') return 'all time';
    if (state.window === 'custom') {
      if (state.customFrom) return `from ${state.customFrom.replace('T', ' ')}`;
      return 'custom range';
    }
    return `last ${state.window}`;
  }

  function initTimePicker() {
    const picker = document.getElementById('time-picker');
    if (!picker) return;
    picker.querySelectorAll('button[data-window]').forEach(btn => {
      btn.addEventListener('click', () => {
        if (btn.dataset.window === 'custom') {
          const from = document.getElementById('time-from');
          const to = document.getElementById('time-to');
          if (!from.value && !to.value) {
            toast('Pick a start or end time first.', 'error');
            return;
          }
          setWindow('custom', from.value, to.value);
          return;
        }
        setWindow(btn.dataset.window);
      });
    });
    const apply = document.getElementById('time-apply');
    if (apply) {
      apply.addEventListener('click', () => {
        const from = document.getElementById('time-from');
        const to = document.getElementById('time-to');
        if (!from.value && !to.value) {
          toast('Pick a start or end time first.', 'error');
          return;
        }
        setWindow('custom', from.value, to.value);
      });
    }
  }

  // ---------------------------------------------------------------- formatting

  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

  function esc(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function num(n) {
    if (n === null || n === undefined || isNaN(n)) return '—';
    return Number(n).toLocaleString();
  }

  function bytes(n) {
    if (!n && n !== 0) return '—';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0, v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
  }

  /** Human duration. A scan of 90s is more useful than "90000 ms". */
  function ms(n) {
    if (n == null) return '—';
    const v = Number(n);
    if (!isFinite(v) || v < 0) return '—';
    if (v < 1000) return `${Math.round(v)}ms`;
    if (v < 60000) return `${(v / 1000).toFixed(1)}s`;
    const m = Math.floor(v / 60000);
    const s = Math.round((v % 60000) / 1000);
    if (m < 60) return `${m}m ${s}s`;
    return `${Math.floor(m / 60)}h ${m % 60}m`;
  }

  function ago(ts) {
    if (!ts) return '—';
    const then = new Date(ts).getTime();
    if (isNaN(then)) return '—';
    const secs = Math.floor((Date.now() - then) / 1000);
    if (secs < 0) return 'just now';
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    if (secs < 2592000) return `${Math.floor(secs / 86400)}d ago`;
    return new Date(ts).toISOString().slice(0, 10);
  }

  function dt(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    if (isNaN(d.getTime())) return '—';
    return d.toISOString().replace('T', ' ').slice(0, 19) + 'Z';
  }

  function shortHash(h) {
    if (!h) return '—';
    if (h.length <= 16) return h;
    return `${h.slice(0, 8)}…${h.slice(-6)}`;
  }

  function sevBadge(sev) {
    const s = (sev || 'info').toLowerCase();
    return `<span class="sev ${esc(s)}">${esc(s)}</span>`;
  }

  function sevRank(sev) {
    const i = SEV_ORDER.indexOf((sev || 'info').toLowerCase());
    return i < 0 ? SEV_ORDER.length : i;
  }

  function techTags(ids) {
    if (!ids || !ids.length) return '';
    return ids.map(id => {
      const t = TIOX.catalog && TIOX.catalog[id];
      const title = t ? `${t.id} — ${t.name} (${t.tactic})` : id;
      return `<span class="tag technique" data-technique="${esc(id)}" title="${esc(title)}">${esc(id)}</span>`;
    }).join(' ');
  }

  // ---------------------------------------------------------------- DOM

  function el(html) {
    const t = document.createElement('template');
    t.innerHTML = html.trim();
    return t.content.firstElementChild;
  }

  function $(sel, root = document) { return root.querySelector(sel); }
  function $$(sel, root = document) { return Array.from(root.querySelectorAll(sel)); }

  function toast(msg, kind = '') {
    const host = document.getElementById('toast');
    if (!host) return;
    const t = el(`<div class="toast ${esc(kind)}">${esc(msg)}</div>`);
    host.appendChild(t);
    setTimeout(() => {
      t.style.transition = 'opacity 0.2s';
      t.style.opacity = '0';
      setTimeout(() => t.remove(), 220);
    }, 3200);
  }

  function empty(msg, icon = '○') {
    return `<div class="empty"><span class="empty-icon">${icon}</span>${esc(msg)}</div>`;
  }

  /**
   * A stat tile that navigates when clicked.
   *
   * Rendered as a real <button> rather than a clickable div so it is reachable
   * by keyboard and announced as a control. The destination is a view plus
   * params, which goto() turns into a hash -- so every drill-down is linkable
   * and the back button works.
   */
  function statTile({ label, value, meta, tone, href, params, cta }) {
    const view = Array.isArray(href) ? href[0] : href;
    const ps = Array.isArray(href) ? (href[1] || {}) : (params || {});
    const inner = `
      <div class="stat-label">${esc(label)}</div>
      <div class="stat-value">${esc(String(value))}</div>
      ${meta ? `<div class="stat-meta">${esc(meta)}</div>` : ''}
      ${cta ? `<div class="stat-cta">${esc(cta)} <span aria-hidden="true">→</span></div>` : ''}`;
    if (!view) {
      return `<div class="stat ${tone || ''}">${inner}</div>`;
    }
    return `<button type="button" class="stat clickable ${tone || ''}"
      data-goto="${esc(view)}" data-params="${esc(JSON.stringify(ps))}"
      title="Show ${esc(String(label).toLowerCase())}">${inner}</button>`;
  }

  function loading(msg = 'Loading…') {
    return `<div class="loading">${esc(msg)}</div>`;
  }

  function errorBox(msg, hint) {
    return `<div class="banner danger">${esc(msg)}${hint ? `<br><span class="faint">${esc(hint)}</span>` : ''}</div>`;
  }

  /**
   * True when this render is still the current one. Views check it after every
   * await, before touching the DOM, so a slow response cannot overwrite a newer
   * view. Cheap, and it removes a class of bug that is invisible in a fast test
   * and maddening for a user clicking quickly.
   */
  function isCurrent(token) {
    // A view calling mount() directly (tests, tooling) passes no token. Treat
    // that as "always current" rather than blocking it, but never let a *stale
    // in-flight* render win: route() bumps renderToken, so a mount with an old
    // token is correctly rejected.
    return token === undefined || token === renderToken;
  }

  // A route() already in flight. The periodic refresh must not start a second
  // one: it clears the container, awaits, and writes -- so an overlapping
  // refresh leaves a half-rendered view.
  let routing = false;
  let pendingRoute = false;

  function routeQueued() {
    if (routing) { pendingRoute = true; return; }
    route();
  }

  // ---------------------------------------------------------------- pivot

  /**
   * Navigate to the entity page. Every pivotable value in the UI routes through
   * here, so a hash means the same thing on every page.
   */
  function pivot(etype, value) {
    if (!etype || !value) return;
    location.hash = `#/entity/${encodeURIComponent(etype)}/${encodeURIComponent(value)}`;
  }

  function goto(page, params) {
    // qs() already returns a leading '?' when there is anything to serialise,
    // so appending one here produced "#/scans??scan=..." -- the second '?' ended
    // up inside the query string, and parseHash silently dropped the params.
    location.hash = `#/${page}${qs(params)}`;
  }

  /**
   * Every clickable value in the UI routes through one delegated listener.
   *
   * Wiring this per-view means a drill-down works on the page that declared it
   * and nowhere else, so a stat tile on the dashboard silently does nothing.
   * Delegating once at the document makes navigation uniform.
   */
  function initPivotDelegation() {
    document.addEventListener('click', ev => {
      // data-params carries a JSON object of filter arguments. A tile needs
      // more than a page name to be useful: "Registered" opens the inventory,
      // but "Stale" opens the inventory filtered to stale.
      const go = ev.target.closest('[data-goto]');
      if (go) {
        ev.preventDefault();
        let params = {};
        const raw = go.dataset.params;
        if (raw) {
          try {
            params = JSON.parse(raw);
          } catch (e) {
            // Malformed params must not break navigation; the page is still
            // worth opening without them.
            params = {};
          }
        }
        goto(go.dataset.goto, params);
        return;
      }
      const link = ev.target.closest('[data-pivot]');
      if (link) {
        ev.preventDefault();
        pivot(link.dataset.pivot, link.dataset.value);
        return;
      }
      const tech = ev.target.closest('[data-technique]');
      if (tech) {
        ev.preventDefault();
        goto('attack', { technique: tech.dataset.technique });
      }
    });
  }

  // ---------------------------------------------------------------- routing

  function registerView(name, mod) {
    state.views.set(name, mod);
  }

  function parseHash() {
    const raw = location.hash.replace(/^#\/?/, '');
    if (!raw) return { page: 'dashboard', params: {} };
    const [path, query] = raw.split('?');
    const parts = path.split('/').filter(Boolean);
    const params = {};
    new URLSearchParams(query || '').forEach((v, k) => { params[k] = v; });
    if (parts[0] === 'entity' && parts[1] && parts[2]) {
      return {
        page: 'entity',
        params: { type: decodeURIComponent(parts[1]), value: decodeURIComponent(parts[2]) },
      };
    }
    return { page: parts[0] || 'dashboard', params };
  }

  let currentRoute = null;
  // Render token. Views await several API calls, so switching pages quickly
  // leaves an earlier mount() in flight; without a token its late innerHTML
  // write lands on top of the newer view and the page shows the wrong content.
  // Each mount captures the token and bails if a newer render started.
  let renderToken = 0;

  async function route() {
    if (routing) { pendingRoute = true; return; }
    routing = true;
    try { await doRoute(); } finally {
      routing = false;
      if (pendingRoute) { pendingRoute = false; route(); }
    }
  }

  async function doRoute() {
    const r = parseHash();
    const mod = state.views.get(r.page) || state.views.get('dashboard');
    if (!mod) return;

    // Tear down the outgoing view so timers and listeners do not leak.
    if (state.current && state.current !== mod && state.views.get(state.current)?.unmount) {
      try { state.views.get(state.current).unmount(); } catch (e) { console.error(e); }
    }
    const prev = currentRoute && currentRoute.page;
    currentRoute = r;

    $$('.view').forEach(v => v.classList.remove('active'));
    // Map, not object: `page in state.views` is always false, so the entity view
    // was being mounted into the dashboard's container and appeared blank.
    const known = state.views.has(r.page);
    const host = document.getElementById('view-' + (known ? r.page : 'dashboard'));
    if (host) host.classList.add('active');

    $$('.nav-item').forEach(n => n.classList.toggle('active', n.dataset.page === r.page));
    const titleEl = document.getElementById('page-title');
    if (titleEl) titleEl.textContent = (mod.title || r.page);
    const subEl = document.getElementById('page-subtitle');
    if (subEl) subEl.textContent = mod.subtitle ? mod.subtitle(r.params) : windowLabel();

    state.current = r.page;
    const myToken = ++renderToken;
    try {
      await mod.mount(host, r.params, myToken);
    } catch (e) {
      if (e instanceof AuthError) return;
      console.error(e);
      if (host && myToken === renderToken) {
        host.innerHTML = errorBox('Failed to load this view.', String(e.message || e));
      }
    }

    if (prev !== r.page) host && host.scrollTo && host.scrollTo(0, 0);
  }

  function refreshCurrent() {
    const subEl = document.getElementById('page-subtitle');
    if (subEl) {
      const mod = state.views.get(state.current);
      subEl.textContent = mod && mod.subtitle ? mod.subtitle((currentRoute || {}).params || {}) : windowLabel();
    }
    route();
  }

  // ---------------------------------------------------------------- login

  function showLoginGate(message) {
    const gate = document.getElementById('login-gate');
    const app = document.getElementById('app');
    if (gate) gate.style.display = 'flex';
    if (app) app.style.display = 'none';
    const err = document.getElementById('login-error');
    if (err && message) err.textContent = message;
  }

  function hideLoginGate() {
    const gate = document.getElementById('login-gate');
    const app = document.getElementById('app');
    if (gate) gate.style.display = 'none';
    if (app) app.style.display = '';
  }

  async function login(key) {
    const res = await fetch('/api/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key }),
    });
    if (!res.ok) throw new Error('Invalid session key');
    return true;
  }

  function initLogin() {
    const form = document.getElementById('login-form');
    if (!form) return;
    form.addEventListener('submit', async ev => {
      ev.preventDefault();
      const input = document.getElementById('login-key');
      const err = document.getElementById('login-error');
      try {
        await login(input.value.trim());
        err.textContent = '';
        input.value = '';
        hideLoginGate();
        start();
      } catch (e) {
        err.textContent = e.message;
      }
    });
  }

  // ---------------------------------------------------------------- lifecycle

  let started = false;

  async function start() {
    if (started) return;
    started = true;
    initTimePicker();
    initPivotDelegation();
    window.addEventListener('hashchange', route);
    // Periodic refresh of the current view keeps "last seen" honest without
    // the analyst having to reload.
    setInterval(() => {
      if (document.getElementById('app').style.display === 'none') return;
      const mod = state.views.get(state.current);
      if (mod && mod.live) routeQueued();
    }, 15000);
    await route();
  }

  async function boot() {
    initLogin();
    // The session cookie is HttpOnly, so JS cannot read it to check for a
    // session. Probe one cheap endpoint instead and show the gate on 401.
    try {
      const res = await fetch('/api/status', { credentials: 'same-origin' });
      if (res.status === 401) { showLoginGate(); return; }
      hideLoginGate();
      await start();
    } catch {
      showLoginGate('Cannot reach the platform server.');
    }
  }

  // ---------------------------------------------------------------- exports

  return {
    state, api, qs, AuthError, ApiError,
    setWindow, windowParam, windowLabel,
    esc, num, bytes, ago, dt, ms, shortHash, sevBadge, sevRank, techTags,
    el, $, $$, toast, empty, loading, errorBox, statTile,
    pivot, goto, registerView, route, refreshCurrent, isCurrent,
    showLoginGate, hideLoginGate, boot, start,
    SEV_ORDER,
  };
})();

window.TIOX = TIOX;
document.addEventListener('DOMContentLoaded', TIOX.boot);
