/* ATT&CK view: what this environment has actually shown.
   Deliberately reads from the catalog, not from a static copy of ATT&CK. The
   useful question is not "what is in the framework" but "which techniques have
   we observed here, on how many hosts, and where do I go next". A coverage gap
   is surfaced rather than hidden, so an unmapped rule is visible. */

/* Own scope: helpers here must not collide with another view's. */
(function () {
  TIOX.registerView('attack', {
    title: 'ATT&CK Coverage',
    subtitle: () => TIOX.windowLabel(),

    async mount(host, params, token) {
      const w = TIOX.windowParam();
      const [observed, catalog] = await Promise.all([
        TIOX.api(`/api/attack/techniques${TIOX.qs({ window: w })}`),
        TIOX.api('/api/attack/catalog'),
      ]);
      if (!TIOX.isCurrent(token)) return;

      // Cache for hover text on technique tags elsewhere in the UI.
      TIOX.catalog = {};
      (catalog.techniques || []).forEach(t => { TIOX.catalog[t.id] = t; });

      const byTactic = new Map();
      for (const t of observed.techniques || []) {
        if (!byTactic.has(t.tactic)) byTactic.set(t.tactic, []);
        byTactic.get(t.tactic).push(t);
      }

      const unmapped = catalog.unmapped_rules || [];
      host.innerHTML = `
        ${unmapped.length ? `<div class="banner warn">
          <strong>${unmapped.length} detection rule(s) have no ATT&amp;CK mapping.</strong>
          These still fire and are still in the lake; they are simply not counted in
          technique reporting. <code>${TIOX.esc(unmapped.join(', '))}</code>
        </div>` : ''}

        ${(observed.techniques || []).length === 0 ? TIOX.empty(
          'No adversary techniques observed in this window. Agent heartbeats and operator notes are intentionally not tagged — an ATT&CK report full of operational noise is worse than none.',
          '◈') : ''}

        ${Array.from(byTactic.entries()).map(([tactic, list]) => `
          <div class="card mb-4">
            <div class="card-head">
              <h2 class="card-title">${TIOX.esc(tactic)}</h2>
              <span class="card-hint">${list.length} technique(s) observed</span>
            </div>
            <div class="card-body flush">
              <div class="table-wrap"><table class="data">
                <thead><tr><th>Technique</th><th>Name</th><th class="num">Hosts</th>
                  <th class="num">Events</th><th>Severity</th><th>Last seen</th></tr></thead>
                <tbody>${list.map(t => `<tr>
                  <td class="nowrap"><span class="tag technique" data-technique="${TIOX.esc(t.technique)}">${TIOX.esc(t.technique)}</span></td>
                  <td>${t.url ? `<a href="${TIOX.esc(t.url)}" target="_blank" rel="noopener">${TIOX.esc(t.name)}</a>` : TIOX.esc(t.name)}</td>
                  <td class="num">${TIOX.num(t.hosts)}</td>
                  <td class="num faint">${TIOX.num(t.events)}</td>
                  <td>${TIOX.sevBadge(t.worst_severity)}</td>
                  <td class="nowrap faint">${TIOX.ago(t.last_seen)}</td>
                </tr>`).join('')}</tbody>
              </table></div>
            </div>
          </div>`).join('')}

        <div class="card">
          <div class="card-head">
            <h2 class="card-title">Catalogued techniques</h2>
            <span class="card-hint">${(catalog.techniques || []).length} techniques this platform can tag · not an ATT&amp;CK mirror</span>
          </div>
          <div class="card-body"><div class="row wrap">
            ${(catalog.techniques || []).map(t => `
              <span class="tag technique ${(observed.techniques || []).some(o => o.technique === t.id) ? '' : 'faint'}"
                    data-technique="${TIOX.esc(t.id)}"
                    title="${TIOX.esc(t.name)} (${TIOX.esc(t.tactic)})${(observed.techniques || []).some(o => o.technique === t.id) ? '' : ' — not observed'}">
                ${TIOX.esc(t.id)}</span>`).join('')}
          </div></div>
        </div>
      `;

      // A catalogued-but-unobserved technique is still worth showing: it tells the
      // analyst what they could hunt for but have not seen.
      if (params && params.technique) {
        const tid = params.technique.toUpperCase();
        const card = el();
        try {
          const detail = await TIOX.api(`/api/attack/technique${TIOX.qs({ id: tid, window: w })}`);
          if (!TIOX.isCurrent(token)) return;
          card.innerHTML = detailCard(detail, tid);
          host.prepend(card);
        } catch (e) {
          host.prepend(el(TIOX.errorBox(`Could not load ${tid}.`, e.message)));
        }
      }
    },
  });

  function el() { return document.createElement('div'); }

  function detailCard(detail, tid) {
    const t = detail.technique;
    const hosts = detail.hosts || [];
    return `<div class="card mb-4" id="tech-detail">
      <div class="card-head">
        <span class="tag technique">${TIOX.esc(t.id)}</span>
        <h2 class="card-title">${TIOX.esc(t.name)}</h2>
        <span class="tag tactic">${TIOX.esc(t.tactic)}</span>
        <span class="card-hint">${TIOX.num(detail.host_count)} host(s) in window</span>
        <span style="flex:1"></span>
        <a class="btn sm" href="${TIOX.esc(t.url)}" target="_blank" rel="noopener">ATT&amp;CK ↗</a>
        <button class="btn sm" onclick="location.hash='#/attack'">Clear</button>
      </div>
      <div class="card-body flush">
        ${hosts.length ? `<div class="table-wrap"><table class="data">
          <thead><tr><th>Host</th><th class="num">Events</th><th>Severity</th><th>First seen</th><th>Last seen</th></tr></thead>
          <tbody>${hosts.map(h => `<tr class="pivotable" data-pivot="host" data-value="${TIOX.esc(h.host)}">
            <td class="mono"><span class="pivot-link">${TIOX.esc(h.host)}</span></td>
            <td class="num">${TIOX.num(h.events)}</td>
            <td>${TIOX.sevBadge(h.worst_severity)}</td>
            <td class="nowrap faint">${TIOX.dt(h.first_seen)}</td>
            <td class="nowrap faint">${TIOX.dt(h.last_seen)}</td>
          </tr>`).join('')}</tbody></table></div>`
          : `<div class="empty">No host activity for ${TIOX.esc(t.id)} in this window.</div>`}
      </div>
    </div>`;
  }
})();
