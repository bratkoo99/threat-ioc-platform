/* Agent setup: enroll an endpoint, and show the credential split.
   The two-key model is easy to get wrong, so the page states plainly which key
   goes where and why. Revealing the agent key requires the session key, and the
   page says so rather than failing silently. */

/* Own scope: helpers here must not collide with another view's. */
(function () {
  TIOX.registerView('agents', {
    title: 'Agent Setup',

    async mount(host, params, token) {
      host.innerHTML = `
        <div class="grid split">
          <div class="card">
            <div class="card-head"><h2 class="card-title">Download the agent</h2></div>
            <div class="card-body">
              <p class="dim" style="margin-top:0;font-size:13px">
                The agent registers, heartbeats, and reports scan results. It
                authenticates with the <strong>agent key</strong>, which is scoped
                to <code>/api/agent/*</code> only.
              </p>
              <div class="row">
                <a class="btn primary" id="a-dl" href="/api/agent/script">Download script</a>
                <button class="btn" id="a-copy">Copy to clipboard</button>
              </div>
              <div class="banner info mt-4" style="margin-bottom:0">
                <strong>Install on the target host:</strong>
                <pre style="margin:8px 0 0;font-size:12px;overflow-x:auto">curl -sk https://&lt;platform&gt;:8443/api/agent/script -o /usr/local/bin/ioc_agent
  chmod +x /usr/local/bin/ioc_agent
  # edit AGENT_KEY and SERVER_URL at the top of the script
  /usr/local/bin/ioc_agent register</pre>
              </div>
            </div>
          </div>

          <div>
            <div class="card">
              <div class="card-head"><h2 class="card-title">Agent key</h2></div>
              <div class="card-body" id="a-key">
                <p class="faint" style="margin:0;font-size:13px">
                  Reveals the key that lets a host register and report. Treat it as
                  a credential for your infrastructure.
                </p>
                <button class="btn mt-3" id="a-reveal">Reveal agent key</button>
              </div>
            </div>

            <div class="card">
              <div class="card-head"><h2 class="card-title">Credential model</h2></div>
              <div class="card-body">
                <dl class="kv">
                  <dt>Session key</dt>
                  <dd>Everything except <code>/api/agent/*</code>. Printed at startup, not persisted. This is what you are logged in with.</dd>
                  <dt>Agent key</dt>
                  <dd>Only registration, heartbeat, and scan requests. A compromised endpoint cannot read the dashboard or change incidents.</dd>
                  <dt>Comparison</dt>
                  <dd>Constant-time, so the key cannot be recovered by timing.</dd>
                </dl>
                <div class="banner info mt-4" style="margin-bottom:0;font-size:12px">
                  Both are compared per request, so rotating either takes effect
                  without restarting the server. Set <code>TIOX_AGENT_KEY</code> or
                  <code>TIOX_SESSION_KEY</code> to pin them.
                </div>
              </div>
            </div>
          </div>
        </div>`;

      host.querySelector('#a-copy').addEventListener('click', async () => {
        // Not TIOX.api(): this needs the raw text, not parsed JSON. Still goes
        // through a status check so a stale session reports itself instead of
        // copying an error page to the clipboard.
        const res = await fetch('/api/agent/script', { credentials: 'same-origin' });
        if (res.status === 401) { TIOX.showLoginGate('Session expired.'); return; }
        if (!res.ok) { TIOX.toast(`Could not fetch the agent script (HTTP ${res.status})`, 'error'); return; }
        const text = await res.text();
        try {
          await navigator.clipboard.writeText(text);
          TIOX.toast('Agent script copied', 'ok');
        } catch {
          TIOX.toast('Clipboard blocked — use the download button.', 'error');
        }
      });

      host.querySelector('#a-reveal').addEventListener('click', async () => {
        const box = host.querySelector('#a-key');
        try {
          const d = await TIOX.api('/api/agent/key');
          // The user may have navigated away while this was in flight; `box` then
          // belongs to a page that is no longer on screen.
          if (!TIOX.isCurrent(token) || !document.body.contains(box)) return;
          box.innerHTML = `
            <p class="faint" style="margin:0 0 8px;font-size:12px">
              Also stored in <code>.agent_key</code> (mode 0600) on the server.
            </p>
            <pre style="background:var(--surface-2);border:1px solid var(--border);border-radius:5px;
                        padding:10px;font-size:12px;overflow-x:auto;margin:0">${TIOX.esc(d.key)}</pre>`;
        } catch (e) {
          box.innerHTML = TIOX.errorBox('Could not reveal the agent key.', e.message);
        }
      });
    },
  });
})();
