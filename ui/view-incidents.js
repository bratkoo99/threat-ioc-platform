/* Incidents: the analyst's queue. Triage actions are audited, and an update
   against a bad id reports failure rather than pretending to succeed. */

/* Own scope: helpers here must not collide with another view's. */
(function () {
  TIOX.registerView('incidents', {
    title: 'Incidents',
    live: true,

    async mount(host, params, token) {
      const filter = params.status || 'open';
      host.innerHTML = `
        <div class="card">
          <div class="filters">
            ${['open', 'closed', 'all'].map(s => `
              <button class="btn sm ${filter === s ? 'primary' : ''}" data-status="${s}">${s}</button>`).join('')}
            <span style="flex:1"></span>
            <input class="field" id="i-new" placeholder="New incident title…" style="flex:1;min-width:200px">
            <select class="field" id="i-sev">
              ${['low', 'medium', 'high', 'critical'].map(s => `<option value="${s}">${s}</option>`).join('')}
            </select>
            <button class="btn sm primary" id="i-create">Create</button>
          </div>
          <div class="card-body flush" id="rows"></div>
        </div>`;

      host.querySelectorAll('[data-status]').forEach(b => {
        b.addEventListener('click', () => TIOX.goto('incidents', { status: b.dataset.status }));
      });

      const input = host.querySelector('#i-new');
      const sev = host.querySelector('#i-sev');
      const create = async () => {
        const title = input.value.trim();
        if (!title) { input.focus(); return; }
        try {
          await TIOX.api('/api/incidents/create', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title, severity: sev.value }),
          });
          input.value = '';
          TIOX.toast('Incident created', 'ok');
          TIOX.route();
        } catch (e) {
          TIOX.toast(e.message, 'error');
        }
      };
      host.querySelector('#i-create').addEventListener('click', create);
      input.addEventListener('keydown', e => { if (e.key === 'Enter') create(); });

      const box = host.querySelector('#rows');
      box.innerHTML = TIOX.loading();
      const data = await TIOX.api(`/api/incidents${filter === 'all' ? '' : `?status=${filter}`}`);
      if (!TIOX.isCurrent(token)) return;
      render(box, data, filter);
    },
  });

  function render(box, data, filter) {
    const rows = (data && data.incidents) || [];
    if (!rows.length) {
      box.innerHTML = TIOX.empty(`No ${filter === 'all' ? '' : filter + ' '}incidents.`, '◇');
      return;
    }
    const counts = data;
    box.innerHTML = `
      <div class="spark-axis" style="padding-top:12px">
        <span>${TIOX.num(counts.total)} total · ${TIOX.num(counts.open)} open · ${TIOX.num(counts.critical)} critical</span>
      </div>
      <div class="table-wrap"><table class="data">
        <thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Source</th>
          <th>Status</th><th>Notes</th><th>Created</th><th></th></tr></thead>
        <tbody>${rows.map(inc => `<tr data-inc="${TIOX.esc(inc.id)}">
          <td class="mono nowrap">${TIOX.esc(inc.id)}</td>
          <td>${TIOX.sevBadge(inc.severity)}</td>
          <td class="truncate" title="${TIOX.esc(inc.description || inc.title)}">${TIOX.esc(inc.title)}</td>
          <td class="nowrap faint">${TIOX.esc(inc.source || '—')}</td>
          <td><span class="tag">${TIOX.esc(inc.status)}</span></td>
          <td class="num faint">${(inc.notes || []).length || '—'}</td>
          <td class="nowrap faint">${TIOX.ago(inc.created)}</td>
          <td class="nowrap">
            ${inc.status === 'open'
              ? `<button class="btn sm" data-close="${TIOX.esc(inc.id)}">Close</button>`
              : `<button class="btn sm" data-reopen="${TIOX.esc(inc.id)}">Reopen</button>`}
          </td>
        </tr>`).join('')}</tbody></table></div>`;

    box.querySelectorAll('[data-close]').forEach(b => {
      b.addEventListener('click', async () => {
        try {
          await TIOX.api('/api/incidents/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: b.dataset.close, status: 'closed', note: 'Closed from dashboard' }),
          });
          TIOX.toast('Incident closed', 'ok');
          TIOX.route();
        } catch (e) {
          TIOX.toast(e.message, 'error');
        }
      });
    });
    box.querySelectorAll('[data-reopen]').forEach(b => {
      b.addEventListener('click', async () => {
        try {
          await TIOX.api('/api/incidents/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: b.dataset.reopen, status: 'open' }),
          });
          TIOX.toast('Incident reopened', 'ok');
          TIOX.route();
        } catch (e) {
          TIOX.toast(e.message, 'error');
        }
      });
    });
  }
})();
