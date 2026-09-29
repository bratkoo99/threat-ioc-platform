/* Scanner: run a scan and watch it live.
   The SSE stream is the reason the session is cookie-based: EventSource cannot
   set request headers, so a bearer token would leave the one long-lived
   connection unauthenticated. */

/* Own scope: helpers here must not collide with another view's. */
(function () {
  TIOX.registerView('scanner', {
    title: 'Scanner',
    live: true,
    _cleanup: null,

    async mount(host, params, token) {
      const root = window.TIOX;
      host.innerHTML = `
        <div class="grid split">
          <div>
            <div class="card">
              <div class="card-head"><h2 class="card-title">Run a scan</h2></div>
              <div class="card-body">
                <div class="stack">
                  <label class="stack" style="gap:4px">
                    <span class="faint" style="font-size:11px;text-transform:uppercase;letter-spacing:.05em">Path</span>
                    <input class="field" id="s-path" value="/home" style="width:100%">
                  </label>
                  <label class="row" style="font-size:13px">
                    <input type="checkbox" id="s-quick"> Quick mode
                    <span class="faint" style="font-size:12px">— only hash files whose name matches a pattern</span>
                  </label>
                  <div class="row">
                    <button class="btn primary" id="s-start">Start scan</button>
                    <button class="btn danger" id="s-stop" disabled>Stop</button>
                    <button class="btn" id="s-reset">Reset</button>
                  </div>
                </div>
              </div>
            </div>

            <div class="card">
              <div class="card-head"><h2 class="card-title">Progress</h2>
                <span class="card-hint" id="s-state">idle</span></div>
              <div class="card-body">
                <div class="meter-track" style="height:6px"><div class="meter-fill" id="s-bar" style="width:0%"></div></div>
                <div class="grid cols-4 mt-3" style="gap:12px">
                  <div><div class="stat-label">Files</div><div class="mono" id="s-files" style="font-size:18px">0</div></div>
                  <div><div class="stat-label">Dirs</div><div class="mono" id="s-dirs" style="font-size:18px">0</div></div>
                  <div><div class="stat-label">Threats</div><div class="mono" id="s-threats" style="font-size:18px;color:var(--sev-high)">0</div></div>
                  <div><div class="stat-label">Errors</div><div class="mono" id="s-errors" style="font-size:18px">0</div></div>
                </div>
                <p class="faint mt-3 mb-3" style="font-size:12px;margin-bottom:0;font-family:var(--mono)"
                   id="s-current">&nbsp;</p>
              </div>
            </div>
          </div>

          <div class="card">
            <div class="card-head"><h2 class="card-title">Findings</h2>
              <span class="card-hint" id="s-count">0</span></div>
            <div class="card-body flush" id="s-findings"></div>
          </div>
        </div>`;

      const $ = sel => host.querySelector(sel);

      $('#s-start').addEventListener('click', async () => {
        try {
          await TIOX.api('/api/scan/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              path: $('#s-path').value.trim() || '/home',
              quick: $('#s-quick').checked,
            }),
          });
          TIOX.toast('Scan started', 'ok');
        } catch (e) {
          TIOX.toast(e.message, 'error');
        }
      });

      $('#s-stop').addEventListener('click', async () => {
        try {
          await TIOX.api('/api/scan/stop', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
          });
          TIOX.toast('Stop requested', 'ok');
        } catch (e) { TIOX.toast(e.message, 'error'); }
      });

      $('#s-reset').addEventListener('click', async () => {
        try {
          await TIOX.api('/api/scan/reset', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
          });
          TIOX.toast('State reset', 'ok');
          TIOX.route();
        } catch (e) { TIOX.toast(e.message, 'error'); }
      });

      // Initial state, then subscribe. The stream is created once per mount and
      // torn down on unmount so switching views does not leak a connection.
      try {
        const st = await TIOX.api('/api/status');
        if (TIOX.isCurrent(token)) apply(st);
      } catch { /* status is public-ish; ignore if it fails */ }

      if (this._cleanup) this._cleanup();
      const es = new EventSource('/api/events');
      this._cleanup = () => es.close();

      const onState = ev => { try { apply(JSON.parse(ev.data)); } catch {} };
      es.addEventListener('connected', onState);
      es.addEventListener('scan_start', onState);
      es.addEventListener('progress', onState);
      es.addEventListener('scan_complete', ev => {
        try {
          const d = JSON.parse(ev.data);
          apply(d);
          TIOX.toast(`Scan ${d.status}: ${d.threats_found || 0} threat(s)`, d.status === 'error' ? 'error' : 'ok');
        } catch {}
      });
      es.onerror = () => {
        const s = host.querySelector('#s-state');
        if (s) s.textContent = 'stream disconnected — retrying';
      };

      function apply(d) {
        const q = sel => host.querySelector(sel);
        if (!q) return;
        q('#s-state').textContent = d.status || 'idle';
        q('#s-files').textContent = TIOX.num(d.files_scanned || 0);
        q('#s-dirs').textContent = TIOX.num(d.dirs_scanned || 0);
        q('#s-threats').textContent = TIOX.num(d.threats_found || 0);
        q('#s-errors').textContent = TIOX.num(d.errors || 0);
        const pct = Math.max(0, Math.min(100, d.progress || 0));
        q('#s-bar').style.width = pct + '%';
        const cur = q('#s-current');
        if (cur) cur.textContent = (d.current_file || '').slice(-90) || ' ';

        const running = !!d.running;
        q('#s-start').disabled = running;
        q('#s-stop').disabled = !running;

        const threats = d.threats || [];
        q('#s-count').textContent = threats.length;
        const box = q('#s-findings');
        if (!threats.length) {
          box.innerHTML = TIOX.empty('No findings yet.', '◇');
          return;
        }
        box.innerHTML = `<div class="table-wrap"><table class="data">
          <thead><tr><th>Type</th><th>File</th><th>Family</th></tr></thead>
          <tbody>${threats.map(t => `<tr>
            <td class="nowrap"><span class="sev ${t.type === 'Known malicious hash' ? 'critical' : 'high'}">${TIOX.esc(t.type || '—')}</span></td>
            <td class="mono truncate" style="max-width:200px" title="${TIOX.esc(t.file)}">${TIOX.esc((t.file || '').split('/').pop() || '—')}</td>
            <td class="nowrap faint">${TIOX.esc(t.family || '—')}</td>
          </tr>`).join('')}</tbody></table></div>`;
      }
    },

    unmount() {
      if (this._cleanup) { this._cleanup(); this._cleanup = null; }
    },
  });
})();
