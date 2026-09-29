"""
Frontend regression tests.

The workbench is plain ES modules loaded by the browser, so most of it can only
be tested in a browser. What *is* testable here is the two things that broke
silently and would break again:

  1. static structure: every view is registered, every nav item resolves to a
     view, every view container exists, every apiFetch path exists server-side
  2. the two logic bugs already found: `in` on a Map (which is always false) and
     XSS from unescaped interpolation

Structural tests are worth more than they look: a renamed function or a deleted
container produces a blank page in production and a red test here.

Run:  python3 -m unittest tests.test_ui -v
"""

import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "ui"
sys.path.insert(0, str(ROOT))


def read(name):
    return (UI / name).read_text()


# Views the sidebar advertises. Kept as a literal so adding a nav item without a
# view (or vice versa) is a test failure, not a dead click.
EXPECTED_VIEWS = {
    "dashboard", "events", "endpoints", "incidents", "attack",
    "rules", "tuning", "scans", "scanner", "agents", "databases", "reports", "entity",
}


class TestStructure(unittest.TestCase):
    def test_all_files_exist(self):
        for f in ["index.html", "app.css", "core.js", "shell.js"]:
            self.assertTrue((UI / f).exists(), f"ui/{f} missing")
        # Several views share a file where they are trivially similar
        # (databases + reports). The set of *registered* views is checked
        # separately, so a view with no file is still caught.
        shared = {"reports", "databases"}
        for v in EXPECTED_VIEWS - shared - {"entity"}:
            self.assertTrue(list(UI.glob(f"view-{v}.js")),
                            f"no view module file for {v}")
        for f in ["view-data.js", "view-entity.js"]:
            self.assertTrue((UI / f).exists(), f"{f} missing")

    def test_every_view_registers_itself(self):
        registered = set()
        for f in UI.glob("view-*.js"):
            for m in re.finditer(r"registerView\(\s*'([^']+)'", f.read_text()):
                registered.add(m.group(1))
        self.assertEqual(registered, EXPECTED_VIEWS,
                         f"registered views differ: missing={EXPECTED_VIEWS - registered} "
                         f"extra={registered - EXPECTED_VIEWS}")

    def test_no_view_is_registered_twice(self):
        """
        registerView() overwrites by name, and plain scripts load in order, so a
        second registration silently wins. That is how a new Reports page was
        shadowed by a leftover stub in another file: the old one loaded last, so
        the new page never ran and the view rendered empty with no error.
        """
        owners: dict[str, list[str]] = {}
        for f in sorted(UI.glob("view-*.js")):
            for m in re.finditer(r"registerView\(\s*'([^']+)'", f.read_text()):
                owners.setdefault(m.group(1), []).append(f.name)
        dupes = {name: files for name, files in owners.items() if len(files) > 1}
        self.assertEqual(
            dupes, {},
            "these view names are registered by more than one file, so the "
            "last one loaded silently replaces the other: "
            + "; ".join(f"{n} in {', '.join(f)}" for n, f in sorted(dupes.items())),
        )

    def test_every_view_script_is_loaded_by_the_page(self):
        """A view file the page never loads registers nothing and shows nothing."""
        # read() resolves inside ui/, so use the path relative to that. A bare
        # "../index.html" picks up the repo-root legacy page instead, which has
        # no /ui/ references at all and fails for the wrong reason.
        html = read("index.html")
        for f in sorted(UI.glob("view-*.js")):
            self.assertIn(f"/ui/{f.name}", html,
                          f"{f.name} exists but is not referenced by index.html")

    def test_every_nav_item_has_a_view(self):
        html = read("index.html")
        nav = set(re.findall(r'data-page="([^"]+)"', html))
        for page in nav:
            self.assertIn(page, EXPECTED_VIEWS, f"nav item {page!r} has no view module")

    def test_every_view_has_a_container(self):
        html = read("index.html")
        containers = set(re.findall(r'id="view-([a-z-]+)"', html))
        for v in EXPECTED_VIEWS:
            self.assertIn(v, containers, f"no #view-{v} container in index.html")

    def test_view_scripts_are_loaded_in_order(self):
        """core.js must load before the views that call registerView."""
        html = read("index.html")
        scripts = re.findall(r'<script src="/ui/([^"]+)"', html)
        self.assertIn("core.js", scripts)
        self.assertIn("shell.js", scripts)
        self.assertLess(scripts.index("core.js"),
                        min(scripts.index(s) for s in scripts if s.startswith("view-")),
                        "core.js must load before the view modules")
        self.assertEqual(scripts[-1], "shell.js", "shell.js wires up after the views")

    def test_every_referenced_ui_file_exists(self):
        html = read("index.html")
        for src in re.findall(r'<script src="/ui/([^"]+)"', html) + \
                   re.findall(r'href="/ui/([^"]+)"', html):
            self.assertTrue((UI / src).exists(), f"index.html references missing {src}")

    def test_no_framework_or_build_step(self):
        """The whole point of separate files is that they load directly."""
        for f in UI.glob("*.js"):
            src = f.read_text()
            for banned in ("import ", "require(", "export default"):
                if banned == "import " and "import(" in src:
                    continue
                self.assertNotIn(banned, src,
                                 f"{f.name} uses {banned!r}; views must be plain scripts")

    def test_css_has_no_external_dependency(self):
        css = read("app.css")
        self.assertNotIn("@import", css, "no external CSS imports")
        self.assertNotIn("url(http", css, "no remote CSS assets")


class TestAuthAndApiPaths(unittest.TestCase):
    """Every path the UI calls must exist as a server route."""

    def server_routes(self):
        src = (ROOT / "web_ui_server.py").read_text()
        return set(re.findall(r'parsed\.path == "(/api/[^"]+)"', src))

    def ui_api_paths(self):
        """Static API paths the UI calls, with any query string stripped so
        '/api/x?days=7' compares equal to the route '/api/x'."""
        paths = set()
        for f in list(UI.glob("*.js")) + [UI / "core.js"]:
            for m in re.finditer(r"TIOX\.api\(\s*[`'\"](/api/[^`'\"]*)", f.read_text()):
                p = m.group(1).split("?")[0].rstrip("/")
                if "${" not in p and "{" not in p:
                    paths.add(p)
        return paths

    def test_every_ui_api_path_exists_on_the_server(self):
        routes = self.server_routes()
        # Paths assembled with template literals; check the static prefix.
        for path in self.ui_api_paths():
            if "${" in path or "{" in path:
                continue
            self.assertIn(path, routes, f"UI calls {path}, server has no such route")

    def test_json_api_calls_go_through_the_wrapper(self):
        """
        JSON API calls must go through TIOX.api, which attaches the cookie and
        surfaces 401. A bare fetch() is a request with no auth handling.

        A plain-text download is allowed to use fetch() directly, but only if it
        checks the status -- otherwise a stale session silently copies an error
        page instead of the file.
        """
        for f in UI.glob("view-*.js"):
            src = f.read_text()
            for m in re.finditer(r"(?<![\w.])fetch\((.{0,120})", src):
                arg = m.group(1)
                is_json_api = "/api/" in arg and "/api/agent/script" not in arg
                if is_json_api:
                    self.fail(f"{f.name} calls fetch() on a JSON endpoint: {arg[:60]}")
                # Allowed case: raw download. Require a status check nearby.
                if "agent/script" in arg:
                    after = src[m.end():m.end() + 400]
                    self.assertRegex(after, r"res\.status|!res\.ok",
                                     f"{f.name} downloads raw text without checking "
                                     f"the status; a 401 would copy an error page")

    def test_agent_key_is_only_revealed_from_the_agents_view(self):
        """
        /api/agent/key needs the session key. Only the Agents page may show it,
        and only on an explicit click -- never rendered on page load, and never
        on a page an operator did not choose to visit.
        """
        for f in UI.glob("view-*.js"):
            if f.name == "view-agents.js":
                continue
            self.assertNotIn("/api/agent/key", f.read_text(),
                             f"{f.name} should not reveal the agent key")
        agents = (UI / "view-agents.js").read_text()
        self.assertIn("a-reveal", agents, "reveal must be an explicit click")
        # The call has to live inside the click handler, not in the markup or
        # an unconditional statement in mount(). Check that the fetch appears
        # after the binding that introduces the handler.
        binding = agents.index("#a-reveal")
        fetch_at = agents.index("/api/agent/key")
        self.assertGreater(fetch_at, binding,
                           "the key must only be fetched from the click handler, "
                           "never while rendering the page")
        # And nothing fetches it before that click.
        self.assertNotIn("/api/agent/key", agents[:binding],
                         "the key must not be fetched on page load")

    def test_login_and_status_are_the_only_public_calls(self):
        core = read("core.js")
        self.assertIn("'/api/login'", core)
        self.assertIn("'/api/status'", core)


class TestViewScoping(unittest.TestCase):
    """
    Plain <script> tags share one global scope. Two views defining a helper with
    the same name silently break each other -- the later file wins.

    This is not hypothetical: view-events.js and view-incidents.js both declared
    render(), so the events table rendered incident rows, matched none, and the
    view showed an empty state while the API was returning 26 events.
    """

    def _top_level_helpers(self, src: str) -> set[str]:
        """Function names declared at the top level of the file body."""
        return set(re.findall(r"^function (\w+)", src, re.M))

    def test_view_helpers_do_not_collide(self):
        seen: dict[str, str] = {}
        clashes = []
        for f in sorted(UI.glob("view-*.js")):
            for name in self._top_level_helpers(f.read_text()):
                if name in seen:
                    clashes.append(f"{name}: {seen[name]} and {f.name}")
                else:
                    seen[name] = f.name
        self.assertEqual(
            clashes, [],
            "view files declare colliding global helpers; wrap each view in an "
            "IIFE (scripts/isolate_view_scopes.py) so scopes stay separate: "
            + "; ".join(clashes),
        )

    def test_every_view_is_wrapped_in_its_own_scope(self):
        for f in sorted(UI.glob("view-*.js")):
            src = f.read_text()
            self.assertIn("(function ()", src,
                          f"{f.name} is not wrapped in an IIFE, so its helpers "
                          f"leak into the shared global scope")
            self.assertTrue(src.rstrip().endswith("})();"),
                            f"{f.name} does not close its IIFE wrapper")

    def test_events_table_cells_match_headers(self):
        """
        The events table rendered 8 cells under 9 headers: the Indicator and
        Host columns were merged into one cell, so every column after Event was
        mislabelled. Count the <td> and <th> in the same row builder.
        """
        src = read("view-events.js")
        head = src[src.index("function render("):]
        thead = head[head.index("<thead>"):head.index("</thead>")]
        # <th\\b[^>]*> and not <thead>: a bare <th[^>]*> also matches "<thead>".
        headers = re.findall(r"<th(?:\s[^>]*)?>", thead)
        # the first body <tr> block, up to its closing </tr>
        start = head.index("return `<tr>")
        first_row = head[start:head.index("</tr>", start)]
        cells = re.findall(r"<td(?:\s[^>]*)?>", first_row)
        self.assertEqual(
            len(cells), len(headers),
            f"events table has {len(headers)} headers but {len(cells)} cells "
            f"per row, so columns are mislabelled",
        )


class TestRouting(unittest.TestCase):
    def test_qs_adds_exactly_one_question_mark(self):
        """
        qs() prefixes '?' itself. A caller that also added one produced
        "#/scans??scan=...", and parseHash -- which splits on the first '?' --
        read the second '?' as part of the query, silently dropping every param.
        That made every parameterised drill-down land on an unfiltered page.
        """
        core = read("core.js")
        goto = core[core.index("function goto("):core.index("function parseHash(")]
        self.assertNotIn("'?' +", goto,
                         "goto() adds its own '?' on top of the one qs() returns")
        self.assertIn("qs(params)", goto)

    def test_qs_skips_empty_values(self):
        core = read("core.js")
        qs = core[core.index("function qs("):core.index("function routeUrl(")
                  if "function routeUrl(" in core else core.index("function goto(")]
        for guard in ("undefined", "null", "''"):
            self.assertIn(guard, qs,
                          f"qs() must skip {guard} values, or a cleared filter "
                          f"still filters the page")

    def test_parse_hash_tolerates_a_stray_question_mark(self):
        """Defensive: a hand-edited or legacy hash should not silently lose params."""
        core = read("core.js")
        self.assertIn("split('?')", core)


class TestExports(unittest.TestCase):
    """
    Every TIOX.* member a view calls must be in core.js's export list.

    A helper defined but not exported is undefined at runtime, and the failure
    is a TypeError thrown mid-render -- the view silently ends up empty while the
    API is returning data. This exact bug shipped once: statTile() existed, three
    views used it, and none of them rendered.
    """

    def _exported(self) -> set[str]:
        """
        Names in core.js's export list.

        Anchored to the "exports" banner: an unanchored search for "return {"
        finds parseHash's `return { page: ... }` first and reads the wrong block,
        which makes the test report nonsense.
        """
        core = read("core.js")
        marker = core.index("// ---------------------------------------------------------------- exports")
        start = core.index("return {", marker)
        body = core[start:core.index("};", start)]
        return set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", body))

    def test_every_helper_a_view_uses_is_exported(self):
        exported = self._exported()
        used: dict[str, str] = {}
        for f in sorted(UI.glob("view-*.js")):
            for m in re.finditer(r"\bTIOX\.([A-Za-z_][A-Za-z0-9_]*)", f.read_text()):
                used.setdefault(m.group(1), f.name)
        # Not core helpers: state is the shared object, api is exported anyway,
        # _rule* are attached by view-rules.js for the parity test, and
        # `catalog` is a cache that view-attack.js assigns itself after
        # fetching /api/attack/catalog. A view is allowed to hang its own data
        # off the namespace.
        assigned_by_views = {"_ruleExplainLocal", "_ruleTemplates", "catalog"}
        allowed = {"state", "api"} | assigned_by_views
        missing = {
            name: f for name, f in used.items()
            if name not in exported and name not in allowed
        }
        self.assertEqual(
            missing, {},
            "views call TIOX.* members that core.js does not export, so the "
            "view throws on render and appears empty: "
            + ", ".join(f"{n} (in {f})" for n, f in sorted(missing.items())),
        )

    def test_core_exports_match_its_own_definitions(self):
        """A function defined in core.js but absent from the exports is dead code
        at best, and a runtime TypeError at worst."""
        core = read("core.js")
        defined = set(re.findall(r"^  function ([A-Za-z_][A-Za-z0-9_]*)", core, re.M))
        exported = self._exported()
        # Lifecycle and internal helpers are reachable through the API surface
        # without being exported; only assert on the ones a view could want.
        view_facing = {n for n in defined if n[0].islower()} - {
            "initLogin", "initTimePicker", "initPivotDelegation", "login",
            "doRoute", "routeQueued", "isCurrent", "parseHash",
        }
        orphaned = {n for n in view_facing if n not in exported}
        self.assertEqual(
            orphaned, set(),
            "these helpers are defined in core.js but never exported: "
            + ", ".join(sorted(orphaned)),
        )


class TestRenderRaces(unittest.TestCase):
    def test_views_awaiting_api_calls_guard_their_render(self):
        """
        A view that awaits before writing innerHTML can be overtaken: switch
        pages while a slow request is in flight and the earlier response lands on
        top of the newer view. Every such view must check isCurrent() after its
        awaits, or the user sees the wrong page.

        This actually happened -- the dashboard showed only the hosts table
        because a stale mount overwrote it.
        """
        for f in sorted(UI.glob("view-*.js")):
            src = f.read_text()
            if "await TIOX.api(" not in src:
                continue  # no awaits, no race
            self.assertIn("isCurrent", src,
                          f"{f.name} awaits an API call but never checks "
                          f"isCurrent() -- a late response can overwrite a "
                          f"newer view")
            # The guard must come after the first await, not just be imported.
            # Two forms are acceptable: isCurrent(token) for a mount, and
            # document.body.contains(node) for an event handler that writes to
            # an element it captured before the await.
            first_await = src.index("await TIOX.api(")
            after = src[first_await:]
            self.assertTrue(
                "isCurrent" in after or "document.body.contains" in after,
                f"{f.name} has an await with no post-await render guard: a late "
                f"response can write into a view that is no longer on screen",
            )

    def test_core_exposes_the_token(self):
        core = read("core.js")
        self.assertIn("function isCurrent(", core)
        self.assertIn("renderToken", core)
        self.assertIn("myToken", core)


class TestLogicBugs(unittest.TestCase):
    def test_map_is_not_probed_with_in_operator(self):
        """`x in map` is always false; use .has(). This silently blanked the
        entity view while every other view worked."""
        core = read("core.js")
        # Strip comments first: the fix explains the bug in a comment, and the
        # comment legitimately mentions the broken pattern.
        code = re.sub(r"/\*.*?\*/", "", core, flags=re.S)
        code = re.sub(r"//.*", "", code)
        self.assertNotRegex(code, r"\bin\s+state\.views",
                            "use state.views.has() -- `in` does not work on a Map")
        self.assertIn("state.views.has(", code)

    def test_interpolation_is_escaped(self):
        """Any server value dropped into innerHTML must go through esc().

        Checked by requiring that template interpolations touching known
        server-controlled keys are escaped, rather than trying to prove every
        case is safe.
        """
        risky_keys = ("ev.title", "ev.rule_id", "ev.source", "r.value", "h.host",
                      "inc.title", "inc.id", "inc.source", "t.name", "t.tactic",
                      "d.name", "e.hostname", "r.hostname", "d.key")
        for f in UI.glob("view-*.js"):
            src = f.read_text()
            for key in risky_keys:
                for m in re.finditer(r"\$\{([^}]*" + re.escape(key) + r"[^}]*)\}", src):
                    expr = m.group(1)
                    if "TIOX.esc(" in expr:
                        continue
                    # numeric/short keys are fine unescaped
                    if key in ("inc.id",):
                        self.assertIn("TIOX.esc(", expr,
                                      f"{f.name}: ${{{expr}}} should be escaped")
                        continue
                    self.fail(f"{f.name}: unescaped interpolation ${{{expr}}}")

    def test_time_window_is_centralised(self):
        """One control governs scope. A view that hardcodes a range would
        silently disagree with the picker."""
        core = read("core.js")
        self.assertIn("windowParam", core)
        for f in UI.glob("view-*.js"):
            src = f.read_text()
            self.assertNotRegex(src, r"window=\d+[hdw]",
                                f"{f.name} hardcodes a time window; use TIOX.windowParam()")

    def test_pivot_goes_through_one_helper(self):
        """Every pivotable value must route the same way, or the same hash means
        different things on different pages."""
        core = read("core.js")
        self.assertIn("function pivot(", core)
        self.assertIn("data-pivot", core)
        total = sum(len(re.findall(r"data-pivot=", f.read_text()))
                    for f in UI.glob("view-*.js"))
        self.assertGreater(total, 5, "expected several pivotable values across views")

    def test_login_gate_is_outside_the_app(self):
        html = read("index.html")
        gate = html.index('id="login-gate"')
        app = html.index('id="app"')
        self.assertLess(gate, app,
                        "the gate must come before #app so #app can be hidden")

    def test_time_picker_buttons_declare_their_window(self):
        html = read("index.html")
        picker = html[html.index('id="time-picker"'):]
        picker = picker[:picker.index("</div>")]
        for w in ("15m", "1h", "24h", "7d", "30d", "all"):
            self.assertIn(f'data-window="{w}"', picker, f"missing window {w}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
