/* Endpoints: the estate, and what it has been doing.

   Combines the control-plane inventory (which hosts report in) with the lake
   (what each host has produced) and the scan history (what was actually run),
   because an inventory page that only lists hostnames tells an analyst nothing
   they did not already know.

   The stat tiles are the navigation. "3 registered" is a question, and clicking
   it should answer it. */

(function () {
  TIOX.registerView('endpoints', {
    title: 'Endpoints',
    live: true,

    async mount(host, params, token) {
      const w = TIOX.windowParam();
      const [inv, summary, stale, scans] = await Promise.all([
        TIOX.api('/api/inventory'),
        TIOX.api(`/api/investigations/hosts${TIOX.qs({ window: w })}`),
        TIOX.api('/api/investigations/stale?days=7'),
        TIOX.api('/api/scans?limit=25'),
      ]);
      if (!TIOX.isCurrent(token)) return;

      const eps = inv.endpoints || [];
      const byHost = new Map();
      (summary.hosts || []).forEach((h) => byHost.set(h.host, h));
      const staleIds = new Set((stale.endpoints || []).map((e) => e.id));
      const scanList = scans.scans || [];
      const scanStats = scans.stats || {};
      const totalScans = scanStats.total || 0;
      const totalThreats = scanStats.threats || 0;

      // A filter in the URL wins over "show everything", so a drill-down from a
      // tile stays filtered across a refresh and can be linked to.
      const statusFilter = params.status || '';

      host.innerHTML = `
        ${(stale.endpoints || []).length ? `<div class="banner warn">
          <strong>${TIOX.num(stale.endpoints.length)} endpoint(s) have not reported in 7+ days.</strong>
          That is a blind spot, not necessarily a compromise — but you cannot detect
          what you cannot see.
          <span class="pivot-link" data-goto="endpoints" data-params='{"status":"stale"}'>Review them →</span>
        </div>` : ''}

        <div class="grid cols-4">
          ${TIOX.statTile({
            label: 'Registered',
            value: TIOX.num(eps.length),
            meta: `${TIOX.num(eps.filter((e) => e.status === 'online').length)} online`,
            cta: 'View inventory',
            href: ['endpoints', {}],
          })}
          ${TIOX.statTile({
            label: 'Scans',
            value: TIOX.num(totalScans),
            meta: `${TIOX.num(totalThreats)} threat hit(s)`,
            tone: totalThreats ? 'high' : '',
            cta: 'Scan history',
            href: ['scans', {}],
          })}
          ${TIOX.statTile({
            label: 'Stale',
            value: TIOX.num(stale.endpoints.length),
            meta: '7+ days silent',
            tone: stale.endpoints.length ? 'high' : 'ok',
            cta: 'Show only stale',
            href: ['endpoints', { status: 'stale' }],
          })}
          ${TIOX.statTile({
            label: 'Active hosts',
            value: TIOX.num((summary.hosts || []).length),
            meta: `in ${TIOX.windowLabel()}`,
            cta: 'Their events',
            href: ['events', {}],
          })}
        </div>

        <div class="card mt-4">
          <div class="card-head">
            <h2 class="card-title">Inventory</h2>
            <span class="card-hint">click a host to pivot</span>
          </div>
          <div class="card-body flush" id="rows"></div>
        </div>

        <div class="card mt-4">
          <div class="card-head">
            <h2 class="card-title">Recent scans</h2>
            <span class="card-hint">each run has its own id; click to see what it found</span>
          </div>
          <div class="card-body flush" id="scan-rows"></div>
        </div>`;

      renderInventory(host, eps, byHost, staleIds, statusFilter);
      renderScans(host, scanList);
    },
  });

  function renderInventory(host, eps, byHost, staleIds, statusFilter) {
    const box = host.querySelector('#rows');
    if (!eps.length) {
      box.innerHTML = TIOX.empty('No endpoints registered. Run the agent setup to enroll one.', '▤');
      return;
    }

    // Filtered views must be able to say they are filtered, or an empty table
    // reads as "no endpoints" rather than "none matching your filter".
    const match = (e) => {
      const isStale = staleIds.has(e.id);
      if (statusFilter === 'stale') return isStale;
      if (statusFilter === 'online') return e.status === 'online';
      if (statusFilter === 'offline') return e.status !== 'online';
      return true;
    };
    const rows = eps.filter(match);

    const header = statusFilter
      ? `<div class="filters">
           <span class="faint" style="font-size:12px">Filtered: ${TIOX.esc(statusFilter)}</span>
           <button class="btn sm" data-goto="endpoints" data-params="{}">Clear filter</button>
         </div>`
      : '';

    if (!rows.length) {
      box.innerHTML = header + TIOX.empty(
        `No endpoints match "${statusFilter}".`, '▤');
      return;
    }

    box.innerHTML = header + `<div class="table-wrap"><table class="data">
      <thead><tr><th>Host</th><th>IP</th><th>OS</th><th>Status</th>
        <th class="num">Scans</th><th class="num">Events</th><th>Techniques</th><th>Last seen</th></tr></thead>
      <tbody>${rows.map((e) => {
        const s = byHost.get(e.hostname);
        const isStale = staleIds.has(e.id);
        const dot = e.status === 'online' ? (isStale ? 'stale' : 'online') : 'offline';
        return `<tr class="pivotable" data-pivot="host" data-value="${TIOX.esc(e.hostname)}">
          <td class="mono"><span class="dot ${dot}"></span><span class="pivot-link">${TIOX.esc(e.hostname)}</span></td>
          <td class="mono faint">${TIOX.esc(e.ip || '—')}</td>
          <td class="faint truncate" style="max-width:150px">${TIOX.esc(e.os || '—')}</td>
          <td class="nowrap">${isStale ? '<span class="sev medium">stale</span>'
            : `<span class="tag">${TIOX.esc(e.status || 'unknown')}</span>`}</td>
          <td class="num">${TIOX.num(e.scan_count || 0)}</td>
          <td class="num faint">${s ? TIOX.num(s.events) : '—'}</td>
          <td class="nowrap">${s && s.techniques && s.techniques.length
            ? TIOX.techTags(s.techniques)
            : '<span class="faint">—</span>'}</td>
          <td class="nowrap faint">${TIOX.ago(e.last_seen)}</td>
        </tr>`;
      }).join('')}</tbody></table></div>`;
  }

  function renderScans(host, scans) {
    const box = host.querySelector('#scan-rows');
    if (!scans.length) {
      box.innerHTML = TIOX.empty(
        'No scans recorded yet. Start one from the Scanner view.', '⌕');
      return;
    }
    box.innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th>Scan</th><th>Host</th><th>Path</th><th>Status</th>
        <th class="num">Files</th><th class="num">Hits</th><th>Started</th><th>Duration</th></tr></thead>
      <tbody>${scans.map((s) => `<tr class="pivotable" data-goto="scans" data-params='${TIOX.esc(JSON.stringify({ scan: s.scan_id }))}'>
        <td class="mono nowrap"><span class="pivot-link">${TIOX.esc(s.label)}</span></td>
        <td class="mono faint">${TIOX.esc(s.host || '—')}</td>
        <td class="mono faint truncate" style="max-width:220px" title="${TIOX.esc(s.scan_path || '')}">${TIOX.esc(s.scan_path || '—')}</td>
        <td class="nowrap">${statusTag(s.status)}</td>
        <td class="num">${TIOX.num(s.files_scanned)}</td>
        <td class="num ${s.threats_found ? 'sev-critical' : 'faint'}">${TIOX.num(s.threats_found)}</td>
        <td class="nowrap faint">${TIOX.ago(s.started_ts)}</td>
        <td class="nowrap faint">${s.duration_ms != null ? TIOX.ms(s.duration_ms) : '—'}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  function statusTag(status) {
    if (status === 'completed') return '<span class="tag ok">completed</span>';
    if (status === 'error') return '<span class="tag crit">error</span>';
    return '<span class="tag">running</span>';
  }
})();
