/* Entity page: everything ever seen for one value.
   This is the view the canonical schema was designed to make possible. Click a
   hash, an IP, a host, anywhere in the product, and you land here: full history
   across all sources, how far it spread, and which related entities it appeared
   with. */

/* Own scope: helpers here must not collide with another view's. */
(function () {
  TIOX.registerView('entity', {
    title: 'Entity',
    subtitle: (p) => p.value ? `${p.type}: ${String(p.value).slice(0, 48)}` : '',

    async mount(host, params, token) {
      const { type, value } = params;
      if (!type || !value) {
        host.innerHTML = TIOX.errorBox('No entity specified.', 'Use the Events or Hosts view to pick one.');
        return;
      }
      host.innerHTML = TIOX.loading('Pivoting…');

      const w = TIOX.windowParam();
      const [pivot, spread] = await Promise.all([
        TIOX.api(`/api/entity${TIOX.qs({ type, value, limit: 200, window: w })}`),
        TIOX.api(`/api/entity/spread${TIOX.qs({ type, value, window: w })}`),
      ]);
      if (!TIOX.isCurrent(token)) return;

      const related = collectRelated(pivot.events || []);

      host.innerHTML = `
        <div class="grid cols-4">
          <div class="stat ${spread.host_count > 1 ? 'critical' : 'muted'}">
            <div class="stat-label">Hosts affected</div>
            <div class="stat-value">${TIOX.num(spread.host_count)}</div>
            <div class="stat-meta">${spread.host_count > 1 ? 'spreading — investigate' : 'contained'}</div>
          </div>
          <div class="stat muted">
            <div class="stat-label">Events</div>
            <div class="stat-value">${TIOX.num(spread.events)}</div>
            <div class="stat-meta">${TIOX.esc(TIOX.windowLabel())}</div>
          </div>
          <div class="stat muted">
            <div class="stat-label">First seen</div>
            <div class="stat-value" style="font-size:15px">${TIOX.esc(TIOX.dt(spread.first_seen))}</div>
          </div>
          <div class="stat muted">
            <div class="stat-label">Last seen</div>
            <div class="stat-value" style="font-size:15px">${TIOX.esc(TIOX.dt(spread.last_seen))}</div>
          </div>
        </div>

        ${spread.families && spread.families.length ? `
        <div class="banner info">
          Associated malware families: ${spread.families.map(f =>
            `<span class="tag">${TIOX.esc(f)}</span>`).join(' ')}
        </div>` : ''}

        <div class="grid split mt-4">
          <div class="card">
            <div class="card-head">
              <h2 class="card-title">History</h2>
              <span class="card-hint">${pivot.total} event(s) total, showing ${pivot.returned}</span>
            </div>
            <div class="card-body flush" id="hist"></div>
          </div>
          <div>
            <div class="card">
              <div class="card-head"><h2 class="card-title">Hosts</h2></div>
              <div class="card-body flush" id="hosts"></div>
            </div>
            <div class="card">
              <div class="card-head">
                <h2 class="card-title">Related entities</h2>
                <span class="card-hint">co-observed</span>
              </div>
              <div class="card-body" id="related"></div>
            </div>
          </div>
        </div>
      `;

      renderHistory(host.querySelector('#hist'), pivot);
      renderHosts(host.querySelector('#hosts'), spread);
      renderRelated(host.querySelector('#related'), related);
    },
  });

  function renderHistory(box, pivot) {
    const rows = pivot.events || [];
    if (!rows.length) {
      box.innerHTML = TIOX.empty('No events recorded for this value.', '◌');
      return;
    }
    box.innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Event</th>
        <th>Host</th><th>Technique</th><th>Rule</th></tr></thead>
      <tbody>${rows.map(ev => `<tr>
        <td class="nowrap faint mono" title="${TIOX.esc(ev.ts)}">${TIOX.ago(ev.ts)}</td>
        <td>${TIOX.sevBadge(ev.severity)}</td>
        <td class="nowrap"><span class="tag">${TIOX.esc(ev.type)}</span></td>
        <td class="truncate" title="${TIOX.esc(ev.title)}">${TIOX.esc(ev.title)}</td>
        <td class="nowrap mono">${ev.host ?
          `<span class="pivot-link" data-pivot="host" data-value="${TIOX.esc(ev.host)}">${TIOX.esc(ev.host)}</span>`
          : '<span class="faint">—</span>'}</td>
        <td class="nowrap">${TIOX.techTags(ev.techniques) || '<span class="faint">—</span>'}</td>
        <td class="nowrap mono faint">${TIOX.esc(ev.rule_id || '—')}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  function renderHosts(box, spread) {
    const rows = spread.hosts || [];
    if (!rows.length) {
      box.innerHTML = TIOX.empty('No hosts.', '▤');
      return;
    }
    box.innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th>Host</th><th class="num">Events</th><th>Last seen</th></tr></thead>
      <tbody>${rows.map(h => `<tr class="pivotable" data-pivot="host" data-value="${TIOX.esc(h.host)}">
        <td class="mono"><span class="pivot-link">${TIOX.esc(h.host)}</span></td>
        <td class="num">${TIOX.num(h.events)}</td>
        <td class="nowrap faint">${TIOX.ago(h.last_seen)}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  /**
   * Entities that appear alongside this one. The pivot between two indicators is
   * often the actual finding: same hash and same C2 on two hosts is a campaign,
   * where each alone is noise.
   */
  function collectRelated(events) {
    const counts = new Map();
    for (const ev of events) {
      const e = ev.entities || {};
      for (const [etype, values] of Object.entries(e)) {
        if (etype === 'host' || etype === 'file_name') continue;
        for (const v of values) {
          const key = `${etype}|${v}`;
          if (!counts.has(key)) counts.set(key, { type: etype, value: v, count: 0 });
          counts.get(key).count++;
        }
      }
    }
    return Array.from(counts.values())
      .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value))
      .slice(0, 20);
  }

  function renderRelated(box, related) {
    if (!related.length) {
      box.innerHTML = `<p class="faint" style="margin:0;font-size:13px">No co-occurring entities yet.</p>`;
      return;
    }
    box.innerHTML = `<div class="stack">${related.map(r => `
      <div class="row between">
        <span class="mono pivot-link" data-pivot="${TIOX.esc(r.type)}" data-value="${TIOX.esc(r.value)}"
              title="${TIOX.esc(r.value)}">${TIOX.esc(TIOX.shortHash(r.value))}</span>
        <span class="faint nowrap" style="font-size:11px">${TIOX.esc(r.type)} ×${r.count}</span>
      </div>`).join('')}</div>`;
  }
})();
