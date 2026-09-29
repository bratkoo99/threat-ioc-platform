/* Events: the raw lake, filterable and paged.
   Every value in the table that is a pivot target is clickable, which is the
   whole point of the canonical entity model. */

/* Own scope: helpers here must not collide with another view's. */
(function () {
  TIOX.registerView('events', {
    title: 'Events',
    live: true,

    async mount(host, params, token) {
      const filters = {
        type: params.type || '',
        severity: params.severity || '',
        host: params.host || '',
        source: params.source || '',
        limit: params.limit || '100',
      };

      host.innerHTML = `
        <div class="card">
          <div class="filters">
            <select class="field" id="f-type">
              <option value="">All types</option>
              ${['threat_hit', 'file', 'process', 'network_conn', 'dns', 'auth',
                 'alert', 'incident', 'agent_status'].map(t =>
                `<option value="${t}"${filters.type === t ? ' selected' : ''}>${t}</option>`).join('')}
            </select>
            <select class="field" id="f-sev">
              <option value="">Any severity</option>
              ${['critical', 'high', 'medium', 'low', 'info'].map(s =>
                `<option value="${s}"${filters.severity === s ? ' selected' : ''}>${s}</option>`).join('')}
            </select>
            <input class="field" id="f-host" placeholder="host" value="${TIOX.esc(filters.host)}" style="width:130px">
            <select class="field" id="f-source">
              <option value="">All sources</option>
              ${['agent', 'system'].map(s =>
                `<option value="${s}"${filters.source === s ? ' selected' : ''}>${s}</option>`).join('')}
            </select>
            <select class="field" id="f-limit">
              ${[50, 100, 250, 500, 1000].map(n =>
                `<option value="${n}"${String(n) === filters.limit ? ' selected' : ''}>${n} rows</option>`).join('')}
            </select>
            <button class="btn sm" id="f-apply">Apply</button>
            <button class="btn sm" id="f-clear">Clear</button>
          </div>
          <div class="card-body flush" id="rows"></div>
        </div>
      `;

      const apply = () => {
        TIOX.goto('events', {
          type: host.querySelector('#f-type').value,
          severity: host.querySelector('#f-sev').value,
          host: host.querySelector('#f-host').value,
          source: host.querySelector('#f-source').value,
          limit: host.querySelector('#f-limit').value,
        });
      };
      host.querySelector('#f-apply').addEventListener('click', apply);
      host.querySelector('#f-host').addEventListener('keydown', e => { if (e.key === 'Enter') apply(); });
      host.querySelector('#f-clear').addEventListener('click', () => TIOX.goto('events'));

      const box = host.querySelector('#rows');
      box.innerHTML = TIOX.loading('Querying lake…');

      const q = TIOX.qs({
        type: filters.type, severity: filters.severity,
        host: filters.host, source: filters.source,
        window: TIOX.windowParam(), limit: filters.limit,
      });
      const data = await TIOX.api(`/api/lake${q}`);
      if (!TIOX.isCurrent(token)) return;
      render(box, data);
    },
  });

  function render(box, data) {
    const rows = (data && data.events) || [];
    if (!rows.length) {
      box.innerHTML = TIOX.empty('No events match these filters. Try widening the time range.', '◌');
      return;
    }
    const body = rows.map(ev => {
      const ents = ev.techniques || [];
      const e = ev.entities || {};
      // Show the most specific identifier the event carries, so the row is
      // pivotable on something more useful than "a thing happened".
      const pivots = [];
      if (e.file_hash && e.file_hash.length) {
        pivots.push(`<span class="pivot-link" data-pivot="file_hash" data-value="${TIOX.esc(e.file_hash[0])}" title="${TIOX.esc(e.file_hash[0])}">${TIOX.esc(TIOX.shortHash(e.file_hash[0]))}</span>`);
      } else if (e.domain && e.domain.length) {
        pivots.push(`<span class="pivot-link" data-pivot="domain" data-value="${TIOX.esc(e.domain[0])}">${TIOX.esc(e.domain[0])}</span>`);
      } else if (e.ip && e.ip.length) {
        pivots.push(`<span class="pivot-link" data-pivot="ip" data-value="${TIOX.esc(e.ip[0])}">${TIOX.esc(e.ip[0])}</span>`);
      }
      if (ev.host) {
        pivots.push(`<span class="pivot-link" data-pivot="host" data-value="${TIOX.esc(ev.host)}">${TIOX.esc(ev.host)}</span>`);
      }
      return `<tr>
        <td class="nowrap faint mono" title="${TIOX.esc(ev.ts)}">${TIOX.ago(ev.ts)}</td>
        <td>${TIOX.sevBadge(ev.severity)}</td>
        <td class="nowrap"><span class="tag">${TIOX.esc(ev.type)}</span></td>
        <td class="truncate" title="${TIOX.esc(ev.title)}">${TIOX.esc(ev.title)}</td>
        <td class="nowrap mono">${pivots[0] || '<span class="faint">—</span>'}</td>
        <td class="nowrap">${pivots[1] || '<span class="faint">—</span>'}</td>
        <td class="nowrap">${TIOX.techTags(ents) || '<span class="faint">—</span>'}</td>
        <td class="nowrap mono faint" title="${TIOX.esc(ev.rule_id || '')}">${TIOX.esc(ev.rule_id || '—')}</td>
        <td class="nowrap faint">${TIOX.esc(ev.source)}</td>
      </tr>`;
    }).join('');

    box.innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr>
        <th>Time</th><th>Severity</th><th>Type</th><th>Event</th>
        <th>Indicator</th><th>Host</th><th>Technique</th><th>Rule</th><th>Source</th>
      </tr></thead>
      <tbody>${body}</tbody></table></div>
      <div class="spark-axis"><span>${rows.length} row(s)</span>
        <span class="faint">${TIOX.esc(TIOX.windowLabel())}</span></div>`;
  }
})();
