/* Shell wiring: nav clicks, sidebar badges, and a keyboard shortcut for the
   time picker. Loaded last, after every view has registered itself. */

(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', init);

  function init() {
    // Nav: hash routing means no click handler per item, and the browser's
    // back button works through the workbench.
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', () => {
        location.hash = '#/' + item.dataset.page;
      });
    });

    // Sidebar counts. Cheap, and an analyst should never have to open a view to
    // learn there is something in it.
    refreshBadges();
    setInterval(refreshBadges, 30000);

    // Keyboard: "/" focuses the path field on the scanner, "t" cycles the time
    // window. Both are conveniences, not requirements.
    document.addEventListener('keydown', ev => {
      const tag = (ev.target.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
      if (ev.key === '/') {
        const p = document.getElementById('s-path');
        if (p) { ev.preventDefault(); p.focus(); p.select(); }
      } else if (ev.key === 't' || ev.key === 'T') {
        cycleWindow();
      }
    });
  }

  async function refreshBadges() {
    if (document.getElementById('app').style.display === 'none') return;
    try {
      const stats = await TIOX.api('/api/stats');
      set('badge-events', stats.events_total);
      set('badge-endpoints', stats.endpoints_online);
      const inc = document.getElementById('badge-incidents');
      if (inc) {
        inc.textContent = stats.incidents_open;
        inc.classList.toggle('alert', stats.incidents_critical > 0);
        inc.title = stats.incidents_critical > 0
          ? `${stats.incidents_critical} critical open`
          : 'open incidents';
      }
    } catch { /* an occasional failed poll is not worth surfacing */ }
  }

  function set(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = TIOX.num(value || 0);
  }

  const WINDOWS = ['15m', '1h', '24h', '7d', '30d', 'all'];
  function cycleWindow() {
    const cur = TIOX.state.window;
    const i = WINDOWS.indexOf(cur);
    TIOX.setWindow(WINDOWS[(i + 1) % WINDOWS.length]);
  }
})();
