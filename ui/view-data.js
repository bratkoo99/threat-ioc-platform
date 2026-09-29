/* Databases and reports: file management for local IOC data.
   Kept as two small views rather than one, since they operate on unrelated
   things. */

/* Own scope: helpers here must not collide with another view's. */
(function () {
  TIOX.registerView('databases', {
    title: 'IOC Databases',

    async mount(host, params, token) {
      host.innerHTML = `<div class="card">
        <div class="card-head">
          <h2 class="card-title">Local IOC files</h2>
          <span class="card-hint">loaded at scan time with <code>-H</code> / <code>-P</code>, not by the web server</span>
        </div>
        <div class="card-body flush" id="rows"></div>
      </div>`;

      const box = host.querySelector('#rows');
      let dbs = [];
      try { dbs = await TIOX.api('/api/databases'); } catch (e) {
        if (!TIOX.isCurrent(token)) return;
        box.innerHTML = TIOX.errorBox('Could not list databases.', e.message);
        return;
      }
      if (!TIOX.isCurrent(token)) return;
      if (!dbs.length) {
        box.innerHTML = TIOX.empty(
          'No IOC files. Create one with: make ioc', '▤');
        return;
      }
      box.innerHTML = `<div class="table-wrap"><table class="data">
        <thead><tr><th>File</th><th class="num">Size</th><th class="num">Entries</th></tr></thead>
        <tbody>${dbs.map(d => `<tr>
          <td class="mono">${TIOX.esc(d.name)}</td>
          <td class="num faint">${TIOX.bytes(d.size)}</td>
          <td class="num">${TIOX.num(d.entries)}</td>
        </tr>`).join('')}</tbody></table></div>`;
    },
  });

})();
