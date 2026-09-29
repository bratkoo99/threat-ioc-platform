/* Custom rules: a building-block editor, in the QRadar mould.

   The editor is deliberately not a free-text JSON box. A rule written as JSON
   cannot be reviewed by someone who does not write code, and a detection nobody
   can review is a detection nobody will trust. So the tree is edited as nested
   blocks -- AND / OR / NOT around match and threshold blocks -- with a live
   plain-English read-back and a dry run against real events.

   The block list comes from /api/rules/schema, which the engine generates, so
   the editor cannot offer an operator the backend would reject. */

(function () {
  TIOX.registerView('rules', {
    title: 'Custom Rules',
    live: true,

    async mount(host, params, token) {
      const [data, schema] = await Promise.all([
        TIOX.api('/api/rules'),
        TIOX.api('/api/rules/schema'),
      ]);
      if (!TIOX.isCurrent(token)) return;

      const rules = data.rules || [];
      const openId = params.rule || '';

      host.innerHTML = `
        <div class="grid cols-4">
          ${TIOX.statTile({
            label: 'Rules', value: TIOX.num(rules.length),
            meta: `${TIOX.num(rules.filter((r) => r.enabled).length)} enabled`,
          })}
          ${TIOX.statTile({
            label: 'Fired (total)',
            value: TIOX.num(rules.reduce((a, r) => a + (r.hits_total || 0), 0)),
            meta: 'all runs',
            tone: 'muted',
          })}
          ${TIOX.statTile({
            label: 'Never fired',
            value: TIOX.num(rules.filter((r) => !r.hits_total).length),
            meta: 'check the logic',
            tone: rules.some((r) => !r.hits_total) ? 'medium' : 'ok',
          })}
          ${TIOX.statTile({
            label: 'Building blocks',
            value: TIOX.num(Object.keys(schema.fields || {}).length),
            meta: 'fields available',
            tone: 'muted',
          })}
        </div>

        <div class="grid split mt-4">
          <div class="card">
            <div class="card-head">
              <h2 class="card-title">Your rules</h2>
              <span class="card-hint">click to edit</span>
            </div>
            <div class="card-body flush" id="list"></div>
            <div class="card-body">
              <button class="btn primary" id="new-rule">+ New rule</button>
            </div>
          </div>
          <div class="card">
            <div class="card-head">
              <h2 class="card-title">Builder</h2>
              <span class="card-hint" id="b-hint">select or create a rule</span>
            </div>
            <div class="card-body" id="builder"></div>
          </div>
        </div>`;

      // The builder owns its own state; the view re-reads it on every render.
      const editor = new RuleEditor(host, schema);
      renderList(host, rules, openId, editor, schema);

      host.querySelector('#new-rule').addEventListener('click', () => {
        editor.load(null);
        TIOX.toast('New rule — add a block to begin', 'ok');
      });

      if (openId) {
        const found = rules.find((r) => r.rule_id === openId);
        if (found) editor.load(found);
        else host.querySelector('#builder').innerHTML =
          TIOX.errorBox('That rule no longer exists.', openId);
      } else {
        host.querySelector('#builder').innerHTML = TIOX.empty(
          'Select a rule, or create one.', '⚙');
      }
    },
  });

  function renderList(host, rules, openId, editor, schema) {
    const box = host.querySelector('#list');
    if (!rules.length) {
      box.innerHTML = TIOX.empty(
        'No custom rules yet. Create one, or start from a template below.', '⚙');
      // Templates are the fastest route to a working rule, and they double as
      // documentation of what the engine can express.
      box.innerHTML += templates().map((t) => `
        <div class="card" style="margin:12px 16px">
          <div class="card-head">
            <h3 class="card-title">${TIOX.esc(t.name)}</h3>
            <span class="card-hint">${TIOX.esc(t.why)}</span>
          </div>
          <div class="card-body">
            <pre class="rule-explain">${TIOX.esc(explainLocal(t.tree))}</pre>
            <button class="btn sm mt-3" data-template='${TIOX.esc(JSON.stringify(t.tree))}'>
              Use this template
            </button>
          </div>
        </div>`).join('');
      box.querySelectorAll('[data-template]').forEach((b) => {
        b.addEventListener('click', () => {
          try {
            editor.load(null, JSON.parse(b.dataset.template));
          } catch (e) {
            TIOX.toast('Template was unreadable', 'error');
          }
        });
      });
      return;
    }
    box.innerHTML = `<div class="table-wrap"><table class="data">
      <thead><tr><th>Name</th><th>Severity</th><th>Enabled</th>
        <th class="num">Hits</th><th>Last run</th></tr></thead>
      <tbody>${rules.map((r) => `<tr class="pivotable ${r.rule_id === openId ? 'selected' : ''}"
          data-goto="rules" data-params='${TIOX.esc(JSON.stringify({ rule: r.rule_id }))}'>
        <td>${TIOX.esc(r.name)}</td>
        <td>${TIOX.sevBadge(r.severity)}</td>
        <td class="nowrap">${r.enabled
          ? '<span class="tag ok">on</span>' : '<span class="tag">off</span>'}</td>
        <td class="num ${r.hits_total ? '' : 'faint'}">${TIOX.num(r.hits_total || 0)}</td>
        <td class="nowrap faint">${r.last_run_ts ? TIOX.ago(r.last_run_ts) : 'never'}</td>
      </tr>`).join('')}</tbody></table></div>`;
  }

  // ---------------------------------------------------------------- editor

  function RuleEditor(host, schema) {
    this.host = host;
    this.schema = schema;
    this.rule = null;
    this.tree = { kind: 'test', op: 'and', children: [] };
  }

  RuleEditor.prototype.load = function (rule, template) {
    this.rule = rule;
    this.tree = rule
      ? JSON.parse(JSON.stringify(rule.tree))
      : (template || { kind: 'test', op: 'and', children: [] });
    this.render();
  };

  RuleEditor.prototype.render = function () {
    const box = this.host.querySelector('#builder');
    const hint = this.host.querySelector('#b-hint');
    const r = this.rule;
    hint.textContent = r ? r.name : 'new rule';

    box.innerHTML = `
      <div class="field-row">
        <label class="field-label" for="r-name">Name</label>
        <input class="field" id="r-name" value="${TIOX.esc(r ? r.name : '')}"
               placeholder="e.g. Outbound port sweep">
      </div>
      <div class="field-row">
        <label class="field-label" for="r-desc">Description</label>
        <input class="field" id="r-desc" value="${TIOX.esc(r ? (r.description || '') : '')}"
               placeholder="what this catches and why it matters">
      </div>
      <div class="field-row">
        <label class="field-label" for="r-sev">Severity</label>
        <select class="field" id="r-sev">
          ${(this.schema.severities || []).map((s) =>
            `<option value="${s}"${r && r.severity === s ? ' selected' : ''}>${s}</option>`).join('')}
        </select>
      </div>
      <div class="field-row">
        <label class="field-label" for="r-mode">On a hit</label>
        <select class="field" id="r-mode">
          <option value="log"${(!r || r.mode === 'log') ? ' selected' : ''}>
            log only — record the event, open no incident</option>
          <option value="alert"${(r && r.mode === 'alert') ? ' selected' : ''}>
            alert — record the event and open an incident</option>
        </select>
      </div>
      <div class="banner info" style="font-size:12px;margin-bottom:10px">
        <strong>log</strong> is the default. A rule that should have alerted and
        did not is a missed detection and you would never see it; a rule that
        should not have and did is noise you can see and fix. Start in log, and
        promote to alert once the rule has proved it is worth someone's attention.
      </div>
      <div class="field-row">
        <label class="field-label" for="r-tech">ATT&amp;CK techniques</label>
        <input class="field" id="r-tech"
               value="${TIOX.esc(r ? (r.techniques || []).join(', ') : '')}"
               placeholder="T1486, T1485 (optional, comma-separated)">
      </div>

      <h3 class="builder-h">Condition</h3>
      <div id="tree"></div>
      <div class="builder-actions">
        <button class="btn sm" id="add-match">+ Match</button>
        <button class="btn sm" id="add-threshold">+ Threshold</button>
      </div>

      <h3 class="builder-h">Reads as</h3>
      <pre class="rule-explain" id="explain"></pre>

      <div class="builder-actions mt-4">
        <button class="btn" id="test">Test against recent events</button>
        <button class="btn primary" id="save">${r ? 'Save' : 'Create rule'}</button>
        ${r ? `<button class="btn" id="toggle">${r.enabled ? 'Disable' : 'Enable'}</button>
               <button class="btn danger" id="delete">Delete</button>` : ''}
      </div>
      <div id="result"></div>`;

    this.renderTree();
    this.wire();
  };

  RuleEditor.prototype.wire = function () {
    const self = this;
    const on = (id, ev, fn) => {
      const el = self.host.querySelector(id);
      if (el) el.addEventListener(ev, fn);
    };

    on('#add-match', 'click', () => {
      if (self.tree.kind !== 'test') {
        self.tree = { kind: 'test', op: 'and', children: [self.tree] };
      }
      self.tree.children.push({
        kind: 'match', field: 'host', op: 'contains', value: '',
      });
      self.render();
    });

    on('#add-threshold', 'click', () => {
      // A threshold cannot be a child of AND/OR, so it becomes the root. Doing
      // that automatically is better than letting the author build a rule the
      // engine will reject.
      self.tree = {
        kind: 'threshold', field: 'ip', op: 'gte', value: 20,
        window_minutes: 5, group_by: 'host', children: [],
      };
      self.render();
    });

    on('#save', 'click', () => self.save());
    on('#test', 'click', () => self.test());
    on('#toggle', 'click', () => self.toggle());
    on('#delete', 'click', () => self.remove());
  };

  RuleEditor.prototype.renderTree = function () {
    const box = this.host.querySelector('#tree');
    box.innerHTML = this.node(this.tree, 0);
    this.wireNodes();
    this.updateExplain();
  };

  /**
   * One block. Recursive because a rule is a tree, and a flat editor cannot
   * express AND(OR(a, b), c) -- which is most real detections.
   */
  RuleEditor.prototype.node = function (n, depth) {
    if (depth > 8) {
      return '<div class="banner warn">Nesting limit reached.</div>';
    }
    if (n.kind === 'match') return this.matchNode(n);
    if (n.kind === 'threshold') return this.thresholdNode(n);
    return this.testNode(n, depth);
  };

  RuleEditor.prototype.testNode = function (n, depth) {
    const ops = [['and', 'ALL of (AND)'], ['or', 'ANY of (OR)'], ['not', 'NOT']];
    return `<div class="rule-block rule-test">
      <div class="rule-block-head">
        <select class="field sm" data-path="op">
          ${ops.map(([v, l]) =>
            `<option value="${v}"${n.op === v ? ' selected' : ''}>${l}</option>`).join('')}
        </select>
        ${depth > 0 ? `<button class="btn xs ghost" data-del="${depth}">Remove block</button>` : ''}
      </div>
      <div class="rule-children">
        ${(n.children || []).map((c, i) => this.child(c, depth, i)).join('')
          || '<div class="faint" style="font-size:12px;padding:4px 0">No blocks yet.</div>'}
      </div>
    </div>`;
  };

  RuleEditor.prototype.child = function (c, depth, index) {
    // Each child carries its own remove button; the parent's op applies to all.
    return `<div class="rule-child" data-child-of="${depth}" data-index="${index}">
      ${this.node(c, depth + 1)}
      <button class="btn xs ghost rule-remove" data-remove-child="${depth}:${index}">Remove</button>
    </div>`;
  };

  RuleEditor.prototype.matchNode = function (n) {
    const fields = this.schema.fields || {};
    const ops = this.schema.operators || {};
    // Hide the value box for operators that take none, so the form does not
    // suggest a value is required when it is not.
    const noValue = ['exists', 'missing', 'private_ip', 'public_ip'];
    return `<div class="rule-block rule-match">
      <div class="rule-block-head"><span class="rule-kind">IF</span></div>
      <div class="rule-fields">
        <select class="field sm" data-field="field">
          ${Object.keys(fields).map((f) =>
            `<option value="${f}"${n.field === f ? ' selected' : ''}>${TIOX.esc(f)} — ${TIOX.esc(fields[f])}</option>`).join('')}
        </select>
        <select class="field sm" data-field="op">
          ${Object.keys(ops).map((o) =>
            `<option value="${o}"${n.op === o ? ' selected' : ''}>${TIOX.esc(ops[o])}</option>`).join('')}
        </select>
        ${noValue.includes(n.op)
          ? '<span class="faint" style="font-size:12px">no value needed</span>'
          : `<input class="field sm" data-field="value" value="${TIOX.esc(n.value == null ? '' : n.value)}"
                   placeholder="value">`}
        <button class="btn xs ghost" data-remove-node>Remove</button>
      </div>
    </div>`;
  };

  RuleEditor.prototype.thresholdNode = function (n) {
    const fields = this.schema.fields || {};
    const ops = this.schema.operators || {};
    return `<div class="rule-block rule-threshold">
      <div class="rule-block-head"><span class="rule-kind">COUNT</span></div>
      <div class="rule-fields">
        <select class="field sm" data-field="field">
          ${Object.keys(fields).map((f) =>
            `<option value="${f}"${n.field === f ? ' selected' : ''}>${TIOX.esc(f)}</option>`).join('')}
        </select>
        <select class="field sm" data-field="op">
          ${['gte', 'gt', 'lte', 'lt'].map((o) =>
            `<option value="${o}"${n.op === o ? ' selected' : ''}>${TIOX.esc(ops[o] || o)}</option>`).join('')}
        </select>
        <input class="field sm" type="number" data-field="value" value="${TIOX.esc(n.value)}"
               placeholder="20" style="max-width:80px">
        <span class="faint" style="font-size:12px">within</span>
        <input class="field sm" type="number" data-field="window_minutes" value="${TIOX.esc(n.window_minutes == null ? '' : n.window_minutes)}"
               placeholder="5" style="max-width:70px">
        <span class="faint" style="font-size:12px">min, per</span>
        <select class="field sm" data-field="group_by">
          <option value="">everything</option>
          ${Object.keys(fields).map((f) =>
            `<option value="${f}"${n.group_by === f ? ' selected' : ''}>${TIOX.esc(f)}</option>`).join('')}
        </select>
        <button class="btn xs ghost" data-remove-node>Remove</button>
      </div>
      <div class="rule-note faint">
        Counts <em>distinct</em> values. Twenty events to one destination is traffic;
        twenty destinations is a sweep.
      </div>
    </div>`;
  };

  /** Bind the inputs, mutating the tree in place as the author types. */
  RuleEditor.prototype.wireNodes = function () {
    const self = this;
    const treeBox = this.host.querySelector('#tree');

    // Walk the DOM and the tree together so every input knows its node.
    const bind = (el, node, depth) => {
      el.querySelectorAll('[data-field]').forEach((inp) => {
        inp.addEventListener('change', () => {
          const key = inp.dataset.field;
          node[key] = inp.type === 'number'
            ? (inp.value === '' ? null : Number(inp.value))
            : inp.value;
          self.renderTree();
        });
      });
      el.querySelectorAll('[data-path="op"]').forEach((inp) => {
        inp.addEventListener('change', () => {
          node.op = inp.value;
          self.renderTree();
        });
      });
      el.querySelectorAll('[data-remove-node]').forEach((b) => {
        b.addEventListener('click', () => self.removeNode(depth));
      });
    };

    // Top-level node.
    const top = treeBox.firstElementChild;
    if (top) bind(top, this.tree, 0);

    // Children, by index, at the matching depth.
    treeBox.querySelectorAll('[data-child-of]').forEach((wrap) => {
      const depth = Number(wrap.dataset.childOf);
      const index = Number(wrap.dataset.index);
      const parent = depth === 0 ? this.tree : this.childAt(this.tree, depth, index);
      if (!parent) return;
      const block = wrap.querySelector('.rule-block');
      if (block) bind(block, parent, depth + 1);
    });

    treeBox.querySelectorAll('[data-remove-child]').forEach((b) => {
      b.addEventListener('click', () => {
        const [depth, index] = b.dataset.removeChild.split(':').map(Number);
        const parent = depth === 0 ? this.tree : this.childAt(this.tree, depth, index);
        if (parent && parent.children) {
          parent.children.splice(index, 1);
          self.renderTree();
        }
      });
    });
  };

  /** Descend `depth` levels from the root, following index at each level. */
  RuleEditor.prototype.childAt = function (node, depth, index) {
    let cur = node;
    for (let d = 0; d < depth; d++) {
      if (!cur || !cur.children || !cur.children.length) return null;
      cur = cur.children[0];
    }
    return cur;
  };

  RuleEditor.prototype.removeNode = function (depth) {
    if (depth === 0) {
      this.tree = { kind: 'test', op: 'and', children: [] };
      this.renderTree();
    }
  };

  RuleEditor.prototype.updateExplain = function () {
    const el = this.host.querySelector('#explain');
    if (el) el.textContent = explainLocal(this.tree);
  };

  RuleEditor.prototype.payload = function () {
    const name = this.host.querySelector('#r-name').value.trim();
    const desc = this.host.querySelector('#r-desc').value.trim();
    const sev = this.host.querySelector('#r-sev').value;
    const techs = this.host.querySelector('#r-tech').value
      .split(',').map((s) => s.trim().toUpperCase()).filter(Boolean);
    return {
      name: name || 'untitled rule',
      description: desc,
      severity: sev,
      mode: this.host.querySelector('#r-mode').value,
      techniques: techs,
      tree: this.tree,
      enabled: this.rule ? this.rule.enabled : true,
    };
  };

  RuleEditor.prototype.test = async function () {
    const out = this.host.querySelector('#result');
    out.innerHTML = '<div class="loading">Running against recent events…</div>';
    try {
      const res = await TIOX.api('/api/rules/test', {
        method: 'POST',
        body: JSON.stringify({ ...this.payload(), window_hours: 24 }),
      });
      // The analyst may have navigated away mid-test; `out` then belongs to a
      // view that is no longer on screen.
      if (!document.body.contains(out)) return;
      out.innerHTML = `
        <div class="banner ok mt-3">
          <strong>${TIOX.num(res.hit_count)} hit(s)</strong> from
          ${TIOX.num(res.events_examined)} event(s) in the last 24h.
        </div>
        ${(res.hits || []).length ? `<div class="table-wrap mt-3"><table class="data">
          <thead><tr><th>Severity</th><th>Rule</th><th>Why</th><th class="num">Events</th></tr></thead>
          <tbody>${res.hits.map((h) => `<tr>
            <td>${TIOX.sevBadge(h.severity)}</td>
            <td>${TIOX.esc(h.rule_name)}</td>
            <td class="faint">${TIOX.esc(h.reason)}</td>
            <td class="num">${(h.matched_events || []).length}</td>
          </tr>`).join('')}</tbody></table></div>` : ''}
        ${res.hit_count === 0 ? `<div class="faint mt-3" style="font-size:12px">
          No hits. Either the logic is wrong, the field is never populated, or there
          is genuinely nothing here. Zero hits is not proof a rule is correct.
        </div>` : ''}`;
    } catch (e) {
      if (!document.body.contains(out)) return;
      out.innerHTML = TIOX.errorBox('Test failed.', e.message);
    }
  };

  RuleEditor.prototype.save = async function () {
    const out = this.host.querySelector('#result');
    const body = this.payload();
    try {
      if (this.rule) {
        await TIOX.api(`/api/rules/${encodeURIComponent(this.rule.rule_id)}`, {
          method: 'PUT', body: JSON.stringify(body),
        });
        TIOX.toast('Rule saved', 'ok');
      } else {
        const res = await TIOX.api('/api/rules', {
          method: 'POST', body: JSON.stringify(body),
        });
        this.rule = res.rule;
        TIOX.toast('Rule created', 'ok');
      }
      // Re-render from the server so what is on screen is what was stored.
      if (!document.body.contains(out)) return;
      out.innerHTML = '<div class="banner ok">Saved.</div>';
      TIOX.goto('rules', { rule: this.rule.rule_id });
    } catch (e) {
      out.innerHTML = TIOX.errorBox('Could not save the rule.', e.message);
    }
  };

  RuleEditor.prototype.toggle = async function () {
    if (!this.rule) return;
    try {
      await TIOX.api(`/api/rules/${encodeURIComponent(this.rule.rule_id)}`, {
        method: 'PUT', body: JSON.stringify({ enabled: !this.rule.enabled }),
      });
      TIOX.goto('rules', { rule: this.rule.rule_id });
    } catch (e) {
      TIOX.toast('Could not change the rule state', 'error');
    }
  };

  RuleEditor.prototype.remove = async function () {
    if (!this.rule) return;
    // Deleting a detection is not undoable, so confirm. Silently deleting a
    // rule someone spent an afternoon tuning is the worst possible behaviour.
    if (!window.confirm(`Delete "${this.rule.name}"? This cannot be undone.`)) return;
    try {
      await TIOX.api(`/api/rules/${encodeURIComponent(this.rule.rule_id)}`, {
        method: 'DELETE',
      });
      TIOX.toast('Rule deleted', 'ok');
      TIOX.goto('rules', {});
    } catch (e) {
      TIOX.toast('Could not delete the rule', 'error');
    }
  };

  // ------------------------------------------------------------- templates

  /**
   * Starting points. Each is a real detection that catches something, so a new
   * user sees a working rule rather than an empty form.
   */
  function templates() {
    return [
      {
        name: 'Outbound port sweep',
        why: 'many destinations, one host, short window',
        tree: {
          kind: 'threshold', field: 'ip', op: 'gte', value: 20,
          window_minutes: 5, group_by: 'host',
          children: [{ kind: 'match', field: 'type', op: 'equals', value: 'network_conn' }],
        },
      },
      {
        name: 'Brute-force attempts',
        why: 'many failures for one user, then any success',
        tree: {
          kind: 'threshold', field: 'ip', op: 'gte', value: 10,
          window_minutes: 5, group_by: 'user',
          children: [
            { kind: 'match', field: 'type', op: 'equals', value: 'auth' },
            { kind: 'match', field: 'severity', op: 'in', value: 'low,medium,high' },
          ],
        },
      },
      {
        name: 'Ransomware precursor',
        why: 'shadow-copy deletion, a known precursor to encryption',
        tree: {
          kind: 'test', op: 'and', children: [
            { kind: 'match', field: 'process', op: 'in',
              value: 'vssadmin, wbadmin, bcdedit' },
            { kind: 'match', field: 'title', op: 'contains', value: 'delete' },
          ],
        },
      },
      {
        name: 'Execution from a temp directory',
        why: 'a classic LOLBin chain',
        tree: {
          kind: 'test', op: 'and', children: [
            { kind: 'match', field: 'file_path', op: 'matches',
              value: '\\\\(Temp|AppData\\\\Local\\\\Temp)\\\\' },
            { kind: 'match', field: 'file_path', op: 'ends_with', value: '.exe' },
            { kind: 'test', op: 'or', children: [
              { kind: 'match', field: 'process', op: 'equals', value: 'rundll32.exe' },
              { kind: 'match', field: 'process', op: 'equals', value: 'powershell.exe' },
              { kind: 'match', field: 'process', op: 'equals', value: 'mshta.exe' },
            ] },
          ],
        },
      },
      {
        name: 'Known-bad hash, any source',
        why: 'the simplest possible IOC rule',
        tree: {
          kind: 'match', field: 'file_hash', op: 'equals', value: '',
        },
      },
    ];
  }

  /**
   * Local copy of the engine's read-back.
   *
   * Duplicated deliberately: the server is authoritative for validation, but
   * rendering the rule as you type must not need a round trip per keystroke.
   * The shapes are kept in step by the test that compares this output with
   * tiox.rules.engine.explain on the same trees.
   */
  function explainLocal(node, indent = 0) {
    const pad = '  '.repeat(indent);
    if (!node || typeof node !== 'object') return pad + '(empty)';
    if (node.kind === 'match') {
      return `${pad}IF ${node.field} ${node.op} ${JSON.stringify(node.value == null ? '' : node.value)}`;
    }
    if (node.kind === 'test') {
      const label = { and: 'ALL of', or: 'ANY of', not: 'NOT' }[node.op] || 'ALL of';
      const kids = (node.children || []).map((c) => explainLocal(c, indent + 1));
      return [`${pad}${label}:`, ...kids].join('\n');
    }
    if (node.kind === 'threshold') {
      let head = `${pad}COUNT ${node.field} ${node.op} ${node.value}`;
      if (node.window_minutes) head += ` within ${node.window_minutes}m`;
      if (node.group_by) head += `, per ${node.group_by}`;
      const kids = (node.children || []).map((c) => explainLocal(c, indent + 1));
      return [head, ...kids].join('\n');
    }
    return pad + '(unrecognised block)';
  }

  // expose for the parity test
  TIOX._ruleExplainLocal = explainLocal;
  TIOX._ruleTemplates = templates;
})();
