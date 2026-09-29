/* Reports: build one, in the format that suits where it is going.

   The format choice is the analyst's, not the system's. JSON feeds another
   tool, XLSX gets filtered in a spreadsheet, plain text goes into a ticket or a
   chat channel. So the choice is presented up front, with a note on what each
   one is for, rather than buried in a download menu.

   Reports can also be produced from any past scan, which is why this page and
   the Scans page both link here. */

(function () {
  TIOX.registerView('reports', {
    title: 'Reports',
    live: true,

    async mount(host, params, token) {
      const [meta, existing] = await Promise.all([
        TIOX.api('/api/reports/kinds'),
        TIOX.api('/api/reports'),
      ]);
      if (!TIOX.isCurrent(token)) return;

      const kinds = meta.kinds || [];
      const formats = meta.formats || [];
      // A kind may be pre-selected from the URL: a scan page links here with
      // ?kind=scan&scan_id=..., so "report this scan" is one click, not a form.
      const kind = params.kind || 'summary';
      const scanId = params.scan_id || '';
      const needsScan = kind === 'scan';

      let scans = [];
      if (needsScan) {
        try {
          scans = (await TIOX.api('/api/scans?limit=50')).scans || [];
        } catch (e) { /* the select degrades to "type an id" */ }
        if (!TIOX.isCurrent(token)) return;
      }

      host.innerHTML = `
        <div class="grid split">
          <div class="card">
            <div class="card-head">
              <h2 class="card-title">Generate a report</h2>
              <span class="card-hint">pick what you want to know, and where it goes</span>
            </div>
            <div class="card-body">
              <div class="field-row">
                <label class="field-label" for="rp-kind">What to report</label>
                <select class="field" id="rp-kind">
                  ${kinds.map((k) => `<option value="${TIOX.esc(k.id)}"${k.id === kind ? ' selected' : ''}>
                    ${TIOX.esc(k.id)} — ${TIOX.esc(k.description)}</option>`).join('')}
                </select>
              </div>

              <div id="scan-picker" ${needsScan ? '' : 'hidden'}>
                <div class="field-row">
                  <label class="field-label" for="rp-scan">Scan</label>
                  <select class="field" id="rp-scan">
                    ${scanId ? `<option value="${TIOX.esc(scanId)}" selected>${TIOX.esc(scanId.slice(0, 8))}…</option>` : ''}
                    ${scans.map((s) => `<option value="${TIOX.esc(s.scan_id)}"${s.scan_id === scanId ? ' selected' : ''}>
                      ${TIOX.esc(s.label)} — ${TIOX.esc(s.host || 'local')} — ${TIOX.ago(s.started_ts)}
                      ${s.threats_found ? `— ${TIOX.num(s.threats_found)} hit(s)` : ''}</option>`).join('')}
                    ${!scans.length ? '<option value="">no scans recorded yet</option>' : ''}
                  </select>
                </div>
              </div>

              <div class="field-row">
                <label class="field-label" for="rp-window">Time window</label>
                <select class="field" id="rp-window">
                  ${['1h', '6h', '24h', '7d', '30d', '90d', 'all'].map((w) =>
                    `<option value="${w}"${w === (params.window || '7d') ? ' selected' : ''}>
                      ${w === 'all' ? 'everything, ever' : 'last ' + w}</option>`).join('')}
                </select>
              </div>

              <div class="field-row">
                <label class="field-label" for="rp-title">Title</label>
                <input class="field" id="rp-title" placeholder="optional — defaults to a sensible name">
              </div>

              <h3 class="builder-h">Format</h3>
              <div class="fmt-grid" id="rp-formats">
                ${formats.map((f, i) => `
                  <label class="fmt-option">
                    <input type="radio" name="rp-format" value="${TIOX.esc(f.id)}"
                           ${(f.id === (params.format || formats[0].id)) ? 'checked' : ''}>
                    <span class="fmt-label">${TIOX.esc(f.label)}</span>
                    <span class="fmt-note">${TIOX.esc(f.note)}</span>
                    <span class="fmt-ext mono">.${TIOX.esc(f.id)}</span>
                  </label>`).join('')}
              </div>

              <div class="builder-actions mt-4">
                <button class="btn primary" id="rp-go">Generate report</button>
              </div>
              <div id="rp-result"></div>
            </div>
          </div>

          <div class="card">
            <div class="card-head">
              <h2 class="card-title">Saved reports</h2>
              <span class="card-hint">${existing.length} on disk</span>
            </div>
            <div class="card-body flush" id="rp-list"></div>
          </div>
        </div>`;

      const kindSel = host.querySelector('#rp-kind');
      host.querySelector('#rp-kind').addEventListener('change', () => {
        // A scan report needs a scan, so reveal the picker only then. Choosing a
        // different kind must not silently keep the old scan selected.
        const need = kindSel.value === 'scan';
        host.querySelector('#scan-picker').hidden = !need;
        if (need && !host.querySelector('#rp-scan').value) {
          TIOX.refreshCurrent();
        }
      });

      host.querySelector('#rp-go').addEventListener('click', () => generate(host, token));
      renderList(host, existing);
    },
  });

  async function generate(host, token) {
    const out = host.querySelector('#rp-result');
    const fmt = host.querySelector('input[name="rp-format"]:checked');
    const scanSel = host.querySelector('#rp-scan');

    const params = {
      kind: host.querySelector('#rp-kind').value,
      format: fmt ? fmt.value : 'json',
      window: host.querySelector('#rp-window').value,
    };
    const title = host.querySelector('#rp-title').value.trim();
    if (title) params.title = title;
    // Only send scan_id when the picker is actually being used: sending an
    // empty one would build a summary report labelled as a scan report.
    if (!host.querySelector('#scan-picker').hidden && scanSel && scanSel.value) {
      params.scan_id = scanSel.value;
    }

    out.innerHTML = '<div class="loading">Building report…</div>';
    let res;
    try {
      res = await TIOX.api(`/api/reports/generate${TIOX.qs(params)}`, { method: 'POST' });
    } catch (e) {
      if (!TIOX.isCurrent(token)) return;
      out.innerHTML = TIOX.errorBox('Could not generate the report.', e.message);
      return;
    }
    if (!TIOX.isCurrent(token)) return;

    const r = res.report || {};
    const dl = TIOX.qs({ name: r.name });
    out.innerHTML = `
      <div class="banner ok mt-3">
        <strong>Report generated.</strong>
        <div class="faint" style="margin-top:6px;font-size:12px">
          ${TIOX.num(r.size)} bytes · sections: ${TIOX.esc((r.sections || []).join(', '))}
        </div>
      </div>
      <div class="builder-actions">
        <a class="btn primary" href="/api/reports/download${TIOX.esc(dl)}" download>Download ${TIOX.esc(r.name)}</a>
        <button class="btn" id="rp-again">Generate another</button>
      </div>`;
    const again = out.querySelector('#rp-again');
    if (again) again.addEventListener('click', () => { out.innerHTML = ''; });

    // Refresh the saved list so the new report appears without a reload.
    try {
      const list = await TIOX.api('/api/reports');
      if (TIOX.isCurrent(token)) renderList(host, list);
    } catch (e) { /* the list refresh is a convenience, not the result */ }
  }

  function renderList(host, reports) {
    const box = host.querySelector('#rp-list');
    if (!reports || !reports.length) {
      box.innerHTML = TIOX.empty(
        'No reports yet. Generate one on the left.', '▧');
      return;
    }
    box.innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th>Report</th><th>Format</th><th class="num">Size</th><th>Created</th><th></th></tr></thead>
      <tbody>${reports.map((r) => {
        const dl = TIOX.qs({ name: r.name });
        return `<tr>
          <td class="truncate" title="${TIOX.esc(r.name)}">
            ${TIOX.esc(r.name)}
            ${r.kind ? `<div class="faint" style="font-size:11px">${TIOX.esc(r.kind)}${r.window ? ' · ' + TIOX.esc(r.window) : ''}</div>` : ''}
          </td>
          <td><span class="tag">${TIOX.esc(r.format)}</span></td>
          <td class="num faint">${TIOX.bytes(r.size)}</td>
          <td class="nowrap faint">${TIOX.ago(r.modified)}</td>
          <td class="nowrap">
            <a class="btn xs" href="/api/reports/download${TIOX.esc(dl)}" download>Download</a>
          </td>
        </tr>`;
      }).join('')}</tbody></table></div>`;
  }
})();
