/* Tuning: which rules are earning their keep.

   Phase 2's purpose is not more detections, it is fewer useless ones. This page
   is the feedback loop that makes that possible: per-rule hits, incidents, and
   analyst rejections, ranked so the worst offender is first.

   Nothing here disables anything automatically. A rule that quietly stops firing
   is the failure mode this whole phase exists to prevent, so every action is an
   explicit, reversible, time-boxed choice by the analyst. */

(function () {
  TIOX.registerView('tuning', {
    title: 'Tuning',
    live: true,

    async mount(host, params, token) {
      const window = params.window || '7d';
      const data = await TIOX.api(
        `/api/rules/effectiveness${TIOX.qs({ window })}`);
      if (!TIOX.isCurrent(token)) return;

      const rules = data.rules || [];
      const suppressed = new Set(
        (data.suppressions || []).map((s) => s.rule_id));

      host.innerHTML = `
        <div class="grid cols-4">
          ${TIOX.statTile({
            label: 'Rules', value: TIOX.num(rules.length),
            meta: `${TIOX.num(rules.filter((r) => r.enabled).length)} enabled`,
          })}
          ${TIOX.statTile({
            label: 'Productive', value: TIOX.num(rules.filter((r) => r.grade === 'productive').length),
            meta: 'opened incidents',
            tone: 'ok',
          })}
          ${TIOX.statTile({
            label: 'Needs tuning',
            value: TIOX.num(rules.filter((r) => ['noisy', 'marginal'].includes(r.grade)).length),
            meta: 'noisy or marginal',
            tone: rules.some((r) => r.grade === 'noisy') ? 'high' : '',
          })}
          ${TIOX.statTile({
            label: 'Suppressed',
            value: TIOX.num(suppressed.size),
            meta: 'muted, time-boxed',
            tone: suppressed.size ? 'medium' : '',
          })}
        </div>

        <div class="banner info mt-4">
          <strong>Nothing is disabled automatically.</strong>
          The grades below are advice, not action. A detection that disappears
          without explanation is worse than a noisy one, because nobody notices.
          Mute a rule when you have evidence it is noise; it comes back on its own.
        </div>

        <div class="card mt-4">
          <div class="card-head">
            <h2 class="card-title">Rule effectiveness</h2>
            <span class="card-hint">ranked worst-first · last ${TIOX.esc(window)}</span>
          </div>
          <div class="card-body flush" id="rows"></div>
        </div>

        ${suppressed.size ? `<div class="card mt-4">
          <div class="card-head">
            <h2 class="card-title">Suppressed rules</h2>
            <span class="card-hint">these open no incidents until the timer ends</span>
          </div>
          <div class="card-body flush" id="supp"></div>
        </div>` : ''}`;

      renderRows(host, rules, suppressed);
      if (suppressed.size) renderSuppressed(host, data.suppressions || [], token);
      wireActions(host, token);
    },
  });

  function renderRows(host, rules, suppressed) {
    const box = host.querySelector('#rows');
    if (!rules.length) {
      box.innerHTML = TIOX.empty(
        'No rules yet. Author one in the Rules view.', '⚙');
      return;
    }
    box.innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th>Rule</th><th>Mode</th><th class="num">Hits</th>
        <th class="num">Incidents</th><th class="num">Rejected</th>
        <th>Yield</th><th>Assessment</th><th></th></tr></thead>
      <tbody>${rules.map((r) => `<tr>
        <td>
          <span class="pivot-link" data-goto="rules"
                data-params='${TIOX.esc(JSON.stringify({ rule: r.rule_id }))}'>
            ${TIOX.esc(r.name)}</span>
          <div class="faint" style="font-size:11px">${TIOX.sevBadge(r.severity)}</div>
        </td>
        <td class="nowrap">
          <span class="tag ${r.mode === 'alert' ? 'crit' : ''}">${TIOX.esc(r.mode)}</span>
          ${suppressed.has(r.rule_id) ? '<span class="tag">muted</span>' : ''}
        </td>
        <td class="num">${TIOX.num(r.hits)}</td>
        <td class="num ${r.incidents ? '' : 'faint'}">${TIOX.num(r.incidents)}</td>
        <td class="num ${r.false_positives ? 'sev-critical' : 'faint'}">${TIOX.num(r.false_positives)}</td>
        <td class="nowrap faint">${r.precision == null ? '—' : (r.precision * 100).toFixed(0) + '%'}</td>
        <td class="nowrap">${gradeTag(r.grade)}</td>
        <td class="nowrap">${actionsFor(r, suppressed)}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  function gradeTag(grade) {
    const map = {
      productive: ['ok', 'productive'],
      marginal: ['medium', 'marginal'],
      noisy: ['crit', 'noisy'],
      quiet: ['', 'quiet'],
      untested: ['', 'untested'],
    };
    const [cls, label] = map[grade] || ['', grade];
    const title = {
      productive: 'opened incidents often enough to be worth keeping',
      marginal: 'opened some incidents, but most hits were noise',
      noisy: 'produced more rejected work than useful incidents',
      quiet: 'fires, but has never opened an incident',
      untested: 'has never fired, so there is no evidence either way',
    }[grade] || '';
    return `<span class="tag ${cls}" title="${TIOX.esc(title)}">${TIOX.esc(label)}</span>`;
  }

  function actionsFor(r, suppressed) {
    if (suppressed.has(r.rule_id)) {
      return `<button class="btn xs" data-unmute="${TIOX.esc(r.rule_id)}">Unmute</button>`;
    }
    return `<button class="btn xs" data-mute="${TIOX.esc(r.rule_id)}"
      data-fp="${r.grade === 'noisy' ? '1' : '0'}">Mute 24h</button>`;
  }

  function renderSuppressed(host, suppressions, token) {
    const box = host.querySelector('#supp');
    if (!box) return;
    box.innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th>Rule</th><th>Muted until</th><th>Reason</th><th></th></tr></thead>
      <tbody>${suppressions.map((s) => `<tr>
        <td class="mono">${TIOX.esc(s.rule_id.slice(0, 8))}…</td>
        <td class="nowrap">${TIOX.ago(s.suppressed_until)}
          <span class="faint">(${TIOX.dt(s.suppressed_until)})</span></td>
        <td class="faint">${TIOX.esc(s.reason || '—')}</td>
        <td><button class="btn xs" data-unmute="${TIOX.esc(s.rule_id)}">Unmute now</button></td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  // Mute and unmute are delegated on the view, so the list re-renders in place
  // rather than needing a full page navigation.
  function wireActions(host, token) {
    const onClick = async (ev) => {
      const mute = ev.target.closest('[data-mute]');
      const unmute = ev.target.closest('[data-unmute]');
      if (!mute && !unmute) return;
      ev.preventDefault();
      const ruleId = (mute || unmute).dataset.mute || unmute.dataset.unmute;
      const isMute = Boolean(mute);
      const body = isMute
        ? {
          rule_id: ruleId,
          minutes: 1440,
          false_positive: mute.dataset.fp === '1',
          reason: mute.dataset.fp === '1' ? 'marked noisy in tuning' : 'muted in tuning',
        }
        : { rule_id: ruleId, action: 'unsuppress' };
      try {
        await TIOX.api('/api/rules/suppress', {
          method: 'POST', body: JSON.stringify(body),
        });
        TIOX.toast(isMute ? 'Rule muted for 24h' : 'Rule unmuted', 'ok');
        TIOX.refreshCurrent();
      } catch (e) {
        TIOX.toast(`Could not change the rule: ${e.message}`, 'error');
      }
    };
    if (!host.dataset.tuningWired) {
      host.dataset.tuningWired = '1';
      host.addEventListener('click', onClick);
    }
  }
})();
