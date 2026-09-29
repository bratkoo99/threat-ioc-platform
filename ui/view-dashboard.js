/* Dashboard: the "what changed" view.
   Lake figures, not endpoint-counter sums, so the numbers reflect the event
   store rather than a per-endpoint tally that drifts. */

/* Own scope: helpers here must not collide with another view's. */
(function () {
  TIOX.registerView('dashboard', {
    title: 'Dashboard',
    live: true,

    async mount(host, params, token) {
      const w = TIOX.windowParam();
      host.innerHTML = TIOX.loading();

      const [stats, timeline, top, attack, hosts] = await Promise.all([
        TIOX.api('/api/stats'),
        TIOX.api(`/api/investigations/timeline${TIOX.qs({ bucket: 'hour', window: w })}`),
        TIOX.api(`/api/investigations/top${TIOX.qs({ type: 'file_hash', window: w, limit: 8 })}`),
        TIOX.api(`/api/attack/techniques${TIOX.qs({ window: w })}`),
        TIOX.api(`/api/investigations/hosts${TIOX.qs({ window: w })}`),
      ]);
      if (!TIOX.isCurrent(token)) return;

      const highCrit = (stats.events_high_severity || 0);
      const openCrit = stats.incidents_critical || 0;

      host.innerHTML = `
        <div class="grid cols-6">
          <div class="stat">
            <div class="stat-label">Events</div>
            <div class="stat-value">${TIOX.num(stats.events_total)}</div>
            <div class="stat-meta">${TIOX.num(stats.event_hosts)} host(s)</div>
          </div>
          <div class="stat ${highCrit ? 'critical' : 'muted'}">
            <div class="stat-label">High/Critical</div>
            <div class="stat-value">${TIOX.num(highCrit)}</div>
            <div class="stat-meta">${TIOX.windowLabel()}</div>
          </div>
          <div class="stat ${openCrit ? 'critical' : 'muted'}">
            <div class="stat-label">Open Critical</div>
            <div class="stat-value">${TIOX.num(openCrit)}</div>
            <div class="stat-meta">${TIOX.num(stats.incidents_open)} open total</div>
          </div>
          <div class="stat ${stats.endpoints_online ? 'ok' : 'muted'}">
            <div class="stat-label">Endpoints</div>
            <div class="stat-value">${TIOX.num(stats.endpoints_online)}<span class="faint" style="font-size:15px">/${TIOX.num(stats.endpoints)}</span></div>
            <div class="stat-meta">online</div>
          </div>
          <div class="stat muted">
            <div class="stat-label">Scans</div>
            <div class="stat-value">${TIOX.num(stats.scans_total)}</div>
            <div class="stat-meta">${TIOX.num(stats.threats_total)} threat hit(s)</div>
          </div>
          <div class="stat muted">
            <div class="stat-label">Sources</div>
            <div class="stat-value">${TIOX.num(stats.event_sources)}</div>
            <div class="stat-meta">${TIOX.num(stats.reports)} report(s)</div>
          </div>
        </div>

        <div class="card">
          <div class="card-head">
            <h2 class="card-title">Event volume</h2>
            <span class="card-hint">${TIOX.esc(TIOX.windowLabel())} · hourly · click a bar to filter</span>
          </div>
          <div class="card-body flush" id="spark"></div>
        </div>

        <div class="grid split mt-4">
          <div class="card">
            <div class="card-head">
              <h2 class="card-title">Top indicators by host spread</h2>
              <span class="card-hint">one host seen often is one problem; many hosts is an incident</span>
            </div>
            <div class="card-body flush" id="top"></div>
          </div>
          <div class="card">
            <div class="card-head">
              <h2 class="card-title">ATT&amp;CK techniques observed</h2>
            </div>
            <div class="card-body flush" id="attack"></div>
          </div>
        </div>

        <div class="card mt-4">
          <div class="card-head">
            <h2 class="card-title">Hosts</h2>
            <span class="card-hint">ranked by high-severity events</span>
          </div>
          <div class="card-body flush" id="hosts"></div>
        </div>
      `;

      // Pass the child elements directly. Re-querying by id inside each renderer
      // is what put the last render on the container: `#hosts` resolved to the
      // view host rather than the card body, so the final table replaced the
      // whole page. Capturing the nodes once, right after the template is set,
      // removes the ambiguity entirely.
      const q = (sel) => {
        const el = host.querySelector(sel);
        if (!el) throw new Error('dashboard: missing container ' + sel);
        return el;
      };
      renderSparkline(q('#spark'), timeline);
      renderTop(q('#top'), top);
      renderAttack(q('#attack'), attack);
      renderHosts(q('#hosts'), hosts);
    },
  });

  function renderSparkline(box, timeline) {
    const buckets = (timeline && timeline.buckets) || [];
    if (!buckets.length) {
      box.innerHTML = TIOX.empty('No events in this window. Widen the time range or start a scan.', '◔');
      return;
    }
    const max = Math.max(...buckets.map(b => b.events), 1);
    const bars = buckets.slice(-72).map(b => {
      const h = Math.max(3, Math.round((b.events / max) * 100));
      const cls = b.high > 0 ? 'spark-bar has-high' : 'spark-bar';
      const title = `${b.bucket} — ${b.events} event(s)${b.high ? `, ${b.high} high` : ''}`;
      return `<div class="${cls}" style="height:${h}%" title="${TIOX.esc(title)}"></div>`;
    }).join('');

    const first = buckets[0].bucket, last = buckets[buckets.length - 1].bucket;
    box.innerHTML = `
      <div class="sparkline">${bars}</div>
      <div class="spark-axis">
        <span>${TIOX.esc(first || '')}</span>
        <span class="faint">peak ${TIOX.num(max)}/h</span>
        <span>${TIOX.esc(last || '')}</span>
      </div>`;
  }

  function renderTop(box, top) {
    const rows = (top && top.entities) || [];
    if (!rows.length) {
      box.innerHTML = TIOX.empty('No indicators in this window.', '◇');
      return;
    }
    const maxHosts = Math.max(...rows.map(r => r.hosts || 0), 1);
    box.innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th>Indicator</th><th class="num">Hosts</th><th class="num">Events</th><th>Last seen</th></tr></thead>
      <tbody>${rows.map(r => {
        const pct = Math.round(((r.hosts || 0) / maxHosts) * 100);
        return `<tr class="pivotable" data-pivot="file_hash" data-value="${TIOX.esc(r.value)}">
          <td class="mono"><span class="pivot-link">${TIOX.esc(TIOX.shortHash(r.value))}</span></td>
          <td class="num">
            <div class="meter" style="justify-content:flex-end">
              <div class="meter-track" style="max-width:56px"><div class="meter-fill ${pct > 66 ? 'crit' : ''}" style="width:${pct}%"></div></div>
              <span class="meter-val">${TIOX.num(r.hosts)}</span>
            </div>
          </td>
          <td class="num faint">${TIOX.num(r.events)}</td>
          <td class="nowrap faint">${TIOX.ago(r.last_seen)}</td>
        </tr>`;
      }).join('')}</tbody></table></div>`;
  }

  function renderAttack(box, attack) {
    const rows = (attack && attack.techniques) || [];
    if (!rows.length) {
      box.innerHTML = TIOX.empty('No adversary techniques observed. Operational events are deliberately not tagged.', '◈');
      return;
    }
    box.innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th>Technique</th><th>Tactic</th><th class="num">Hosts</th></tr></thead>
      <tbody>${rows.slice(0, 10).map(t => `<tr>
        <td><span class="tag technique" data-technique="${TIOX.esc(t.technique)}" title="${TIOX.esc(t.name)}">${TIOX.esc(t.technique)}</span>
            <span class="faint" style="margin-left:6px">${TIOX.esc(t.name)}</span></td>
        <td><span class="tag tactic">${TIOX.esc(t.tactic)}</span></td>
        <td class="num">${TIOX.num(t.hosts)}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  function renderHosts(box, hosts) {
    const rows = (hosts && hosts.hosts) || [];
    if (!rows.length) {
      box.innerHTML = TIOX.empty('No host activity in this window.', '▤');
      return;
    }
    box.innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th>Host</th><th class="num">Events</th><th class="num">High/Crit</th><th>Techniques</th><th>Last seen</th></tr></thead>
      <tbody>${rows.map(h => `<tr class="pivotable" data-pivot="host" data-value="${TIOX.esc(h.host)}">
        <td class="mono"><span class="pivot-link">${TIOX.esc(h.host)}</span></td>
        <td class="num">${TIOX.num(h.events)}</td>
        <td class="num ${h.high ? 'sev-critical' : 'faint'}" style="${h.high ? 'color:var(--sev-critical)' : ''}">${TIOX.num(h.high)}</td>
        <td>${TIOX.techTags(h.techniques) || '<span class="faint">—</span>'}</td>
        <td class="nowrap faint">${TIOX.ago(h.last_seen)}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }
})();
