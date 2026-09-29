/* Scans: every run, and what each one found.

   Every scan carries a durable id, so a finding can be traced to the run that
   produced it, and a run can be compared with another. That traceability is the
   reason this page exists rather than a line in the scanner's live output --
   live output answers "is it running", this answers "what have we ever run". */

(function () {
  TIOX.registerView('scans', {
    title: 'Scans',
    live: true,

    async mount(host, params, token) {
      const data = await TIOX.api('/api/scans?limit=200');
      if (!TIOX.isCurrent(token)) return;

      const scans = data.scans || [];
      const stats = data.stats || {};
      const openId = params.scan || '';

      host.innerHTML = `
        <div class="grid cols-4">
          ${TIOX.statTile({
            label: 'Total runs', value: TIOX.num(stats.total || 0),
            meta: `${TIOX.num(stats.hosts || 0)} host(s)`,
            cta: 'New scan', href: ['scanner', {}],
          })}
          ${TIOX.statTile({
            label: 'Threat hits', value: TIOX.num(stats.threats || 0),
            meta: 'across all runs',
            tone: stats.threats ? 'high' : 'ok',
            cta: 'See the events', href: ['events', { type: 'threat_hit' }],
          })}
          ${TIOX.statTile({
            label: 'Files scanned', value: TIOX.num(stats.files || 0),
            meta: 'cumulative',
            cta: 'Scan now', href: ['scanner', {}],
          })}
          ${TIOX.statTile({
            label: 'Avg duration', value: TIOX.ms(stats.avg_duration_ms),
            meta: 'per run',
          })}
        </div>

        <div class="grid split mt-4">
          <div class="card">
            <div class="card-head">
              <h2 class="card-title">Scan history</h2>
              <span class="card-hint">click a run for its findings</span>
            </div>
            <div class="card-body flush" id="list"></div>
          </div>
          <div class="card">
            <div class="card-head">
              <h2 class="card-title">Findings</h2>
              <span class="card-hint" id="detail-hint">select a scan</span>
            </div>
            <div class="card-body flush" id="detail"></div>
          </div>
        </div>`;

      renderList(host, scans, openId);
      if (openId) {
        loadDetail(host, openId, token);
      } else {
        host.querySelector('#detail').innerHTML =
          TIOX.empty('Select a scan to see what it found.', '⌕');
      }
    },
  });

  function renderList(host, scans, openId) {
    const box = host.querySelector('#list');
    if (!scans.length) {
      box.innerHTML = TIOX.empty(
        'No scans yet. Start one from the Scanner view.', '⌕');
      return;
    }
    box.innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th>Scan</th><th>Host</th><th>Status</th>
        <th class="num">Files</th><th class="num">Hits</th><th>Started</th></tr></thead>
      <tbody>${scans.map((s) => `<tr class="pivotable ${s.scan_id === openId ? 'selected' : ''}"
          data-goto="scans" data-params='${TIOX.esc(JSON.stringify({ scan: s.scan_id }))}'>
        <td class="mono nowrap"><span class="pivot-link">${TIOX.esc(s.label)}</span></td>
        <td class="mono faint truncate" style="max-width:120px">${TIOX.esc(s.host || '—')}</td>
        <td class="nowrap">${statusTag(s.status)}</td>
        <td class="num faint">${TIOX.num(s.files_scanned)}</td>
        <td class="num ${s.threats_found ? 'sev-critical' : 'faint'}">${TIOX.num(s.threats_found)}</td>
        <td class="nowrap faint">${TIOX.ago(s.started_ts)}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  async function loadDetail(host, scanId, token) {
    const box = host.querySelector('#detail');
    const hint = host.querySelector('#detail-hint');
    box.innerHTML = TIOX.loading('Loading findings…');
    let data;
    try {
      data = await TIOX.api(`/api/scan${TIOX.qs({ id: scanId })}`);
    } catch (e) {
      if (!TIOX.isCurrent(token)) return;
      box.innerHTML = TIOX.errorBox('Could not load that scan.', e.message);
      return;
    }
    if (!TIOX.isCurrent(token)) return;

    const s = data.scan || {};
    const findings = data.findings || [];
    hint.textContent = `${s.label || 'scan'} · ${findings.length} finding(s)`;

    if (s.error) {
      box.innerHTML = `<div class="card-body"><div class="banner crit">
        <strong>This run failed.</strong> ${TIOX.esc(s.error)}
        <div class="faint" style="margin-top:6px;font-size:12px">
          A failed scan is not a clean scan — it means nothing was checked.
        </div>
      </div>${renderFindings(findings)}</div>`;
      return;
    }

    box.innerHTML = `<div class="card-body">
        <div class="builder-actions" style="margin:0 0 12px">
          <button class="btn sm primary" id="d-report">Report this scan</button>
          <button class="btn sm" id="d-report-xlsx">Report as Excel</button>
        </div>
        <dl class="kv">
          <dt>Scan id</dt><dd class="mono">${TIOX.esc(s.scan_id || '')}</dd>
          <dt>Path</dt><dd class="mono truncate">${TIOX.esc(s.scan_path || '—')}</dd>
          <dt>Host</dt><dd class="mono">${TIOX.esc(s.host || '—')}</dd>
          <dt>Started by</dt><dd class="mono">${TIOX.esc(s.initiated_by || '—')}</dd>
          <dt>Duration</dt><dd>${TIOX.ms(s.duration_ms)}</dd>
          <dt>Counted</dt><dd>${TIOX.num(s.files_scanned)} files, ${TIOX.num(s.dirs_scanned)} dirs, ${TIOX.num(s.errors)} error(s)</dd>
        </dl>
      </div>${renderFindings(findings)}`;

    // Report straight from a past run. The format choice stays the user's, so
    // these are shortcuts to the Reports page with the scan pre-selected
    // rather than generating here behind their back. Wired after the innerHTML
    // assignment because the buttons do not exist until it happens.
    const rp = (fmt) => TIOX.goto('reports', {
      kind: 'scan', scan_id: s.scan_id, window: 'all', format: fmt,
    });
    const b1 = box.querySelector('#d-report');
    const b2 = box.querySelector('#d-report-xlsx');
    if (b1) b1.addEventListener('click', () => rp('txt'));
    if (b2) b2.addEventListener('click', () => rp('xlsx'));
  }

  function renderFindings(findings) {
    if (!findings.length) {
      return TIOX.empty('This run found nothing.', '✓');
    }
    return `<div class="table-wrap"><table class="data">
      <thead><tr><th>File</th><th>Hash</th><th>Family</th><th>Technique</th></tr></thead>
      <tbody>${findings.map((f) => `<tr>
        <td class="mono truncate" style="max-width:220px" title="${TIOX.esc(f.file_path || '')}">
          ${f.file_hash
            ? `<span class="pivot-link" data-pivot="file_hash" data-value="${TIOX.esc(f.file_hash)}">${TIOX.esc(TIOX.shortHash(f.file_hash))}</span>`
            : `<span class="faint">${TIOX.esc(f.file_path || '—')}</span>`}
        </td>
        <td class="mono faint truncate" style="max-width:130px" title="${TIOX.esc(f.file_path || '')}">
          ${TIOX.esc(f.file_path || '—')}</td>
        <td>${f.family ? `<span class="tag crit">${TIOX.esc(f.family)}</span>` : '<span class="faint">—</span>'}</td>
        <td class="nowrap">${TIOX.techTags(f.techniques || []) || '<span class="faint">—</span>'}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  function statusTag(status) {
    if (status === 'completed') return '<span class="tag ok">completed</span>';
    if (status === 'error') return '<span class="tag crit">error</span>';
    return '<span class="tag">running</span>';
  }
})();
