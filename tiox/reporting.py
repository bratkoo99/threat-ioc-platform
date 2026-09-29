"""
Report generation.

A report is a question asked of the lake and answered in a form someone can act
on. That makes the format choice an analyst decision, not a technical one:
JSON to feed another tool, XLSX to triage and filter in a spreadsheet, TXT to
paste into a ticket or a chat channel.

Two things are deliberate here.

* No third-party dependencies. The project has none, and a reporting feature is
  not a reason to add one -- an XLSX file is a zip of XML, and the stdlib can
  write that. Adding xlsxwriter would mean every deployment now needs a wheel
  built for its platform.

* Reports are built from the same queries the UI uses. A report that computes
  its own numbers with different logic is a report that eventually disagrees
  with the dashboard, and then nobody trusts either.
"""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable
from xml.sax.saxutils import escape

FORMATS = ("json", "xlsx", "txt")

# Kinds of report. Each maps to a different investigation question, so each
# collects different sections. Keeping them named means the UI can offer
# "what do you want to know?" rather than an empty form.
REPORT_KINDS = {
    "summary": "Executive summary: posture, counts, and what stands out",
    "findings": "Every threat finding, with technique and affected host",
    "hosts": "Per-host activity: volume, techniques, last seen",
    "incidents": "Open and closed incidents with severity and ownership",
    "scan": "One scan run and everything it found",
    "technique": "ATT&CK coverage: observed vs catalogue, and where the gaps are",
    "timeline": "Event volume over time, bucketed",
}

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


# --------------------------------------------------------------------------
# Section collection
# --------------------------------------------------------------------------


def build_document(
    kind: str,
    store,
    *,
    window: str = "24h",
    scan_id: str | None = None,
    technique: str | None = None,
    title: str | None = None,
) -> dict[str, Any]:
    """
    Gather the data for one report.

    Returns a plain dict, which is the JSON document and also the input every
    other renderer walks. Building the document once and rendering it three
    ways is what guarantees the formats agree.
    """
    inv = store.investigations
    since = _since(window)

    doc: dict[str, Any] = {
        "report": {
            "kind": kind,
            "kind_description": REPORT_KINDS.get(kind, ""),
            "title": title or _default_title(kind, scan_id, technique),
            "window": window,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "schema_version": "1.0.0",
        },
        "sections": [],
    }

    def add(name: str, rows: Any, note: str = "") -> None:
        doc["sections"].append({
            "name": name,
            "note": note,
            "rows": rows,
            "row_count": len(rows) if isinstance(rows, list) else None,
        })

    # Every report carries the same summary block: it is the context that makes
    # the detail rows interpretable, and it is what a reader checks first.
    stats = store.event_stats(since=since)
    add("summary", [{
        "metric": "events", "value": stats.get("total", 0),
        "note": window_phrase(window),
    }, {
        "metric": "high_severity_events", "value": stats.get("high", 0),
        "note": "high or critical",
    }, {
        "metric": "endpoints_registered", "value": len(store.list_endpoints()),
        "note": "all time",
    }, {
        "metric": "open_incidents", "value": store.incident_counts().get("open", 0),
        "note": "awaiting triage",
    }, {
        "metric": "critical_incidents", "value": store.incident_counts().get("critical", 0),
        "note": "need attention now",
    }, {
        "metric": "scans_run", "value": store.scan_stats().get("total", 0),
        "note": "all time",
    }, {
        "metric": "threats_found", "value": store.scan_stats().get("threats", 0),
        "note": "across all scans",
    }])

    if kind == "summary":
        add("top_indicators", inv.top_entities("file_hash", since, 15),
            "ranked by how many hosts saw each one, not raw count")
        add("attack_techniques", _techniques(store, window),
            "what this environment has actually shown")
        add("scan_history", store.list_scans(limit=25), "most recent runs first")
        add("stale_endpoints", inv.stale_endpoints(days=7),
            "7+ days without a heartbeat")

    elif kind == "findings":
        add("threat_events", _threat_events(store, since, 500),
            "every event the scanner or a rule flagged")
        add("scan_findings", _all_findings(store, 500),
            "file-level findings, linked to the scan that produced them")

    elif kind == "hosts":
        add("host_activity", inv.host_summary(since),
            "volume, high-severity count, techniques, and last seen")
        add("stale_endpoints", inv.stale_endpoints(days=7), "blind spots")

    elif kind == "incidents":
        add("incidents", store.list_incidents(limit=500),
            "most recent first")

    elif kind == "scan":
        if not scan_id:
            raise ValueError("a scan report needs a scan id")
        scan = store.get_scan(scan_id)
        if not scan:
            raise ValueError(f"no such scan: {scan_id}")
        findings = store.scan_findings(scan_id, limit=1000)
        add("scan", [scan], f"{scan.get('label', '')} -- the run itself")
        add("findings", findings, "what this specific run found")
        # The events the run produced, so the report is self-contained rather
        # than making the reader cross-reference the UI.
        evs = []
        for f in findings:
            if not f.get("event_id"):
                continue
            rows = store.query_events(limit=1, since=since)
            hit = next((r for r in rows if r.get("event_id") == f["event_id"]), None)
            if hit:
                evs.append(hit)
        if evs:
            add("events", evs, "the events this run generated")

    elif kind == "technique":
        if technique:
            from tiox.schemas import attack as _attack

            tid = technique.strip().upper()
            meta = _attack.get(tid)
            if meta:
                hosts = inv.technique_hosts(tid, since)
                add("technique", [{
                    "technique": meta.id,
                    "name": meta.name,
                    "tactic": meta.tactic,
                    "url": meta.url,
                    "host_count": len(hosts),
                }], "the technique in question")
                if hosts:
                    add("technique_hosts", hosts, f"hosts that hit {tid}")
        add("observed_techniques", _techniques(store, window),
            "observed in this environment")
        add("catalogue", _catalogue_with_status(store, window),
            "every catalogued technique, marked observed or not seen")

    elif kind == "timeline":
        add("hourly", inv.timeline(since, bucket="hour"), "events per hour")
        add("daily", inv.timeline(since, bucket="day"), "events per day")

    else:
        raise ValueError(f"unknown report kind {kind!r}; known: {', '.join(sorted(REPORT_KINDS))}")

    doc["section_names"] = [s["name"] for s in doc["sections"]]
    return doc


def _default_title(kind: str, scan_id: str | None, technique: str | None) -> str:
    if kind == "scan" and scan_id:
        return f"Scan report {scan_id}"
    if kind == "technique" and technique:
        return f"Technique report {technique}"
    return f"{kind.capitalize()} report"


def _since(window: str) -> str | None:
    """
    Turn a window shorthand into a `since` timestamp.

    parse_window returns (since, until); every query in Investigations takes
    `since`, so that is all the report layer needs.
    """
    from tiox.store.investigations import parse_window

    since, _until = parse_window(window)
    return since


def _techniques(store, window: str) -> list[dict[str, Any]]:
    """Observed techniques. technique_breakdown is the query the UI reads too."""
    return store.investigations.technique_breakdown(_since(window))


def _threat_events(store, since: str | None, limit: int) -> list[dict[str, Any]]:
    rows = store.query_events(type="threat_hit", since=since, limit=limit)
    for r in rows:
        r.pop("raw", None)  # the full payload bloats a report without informing
    return rows


def _all_findings(store, limit: int) -> list[dict[str, Any]]:
    out = []
    for scan in store.list_scans(limit=200):
        for f in store.scan_findings(scan["scan_id"], limit=limit):
            f = dict(f)
            f["scan_id"] = scan["scan_id"]
            f["scan_label"] = scan["label"]
            out.append(f)
            if len(out) >= limit:
                return out
    return out


def _catalogue_with_status(store, window: str) -> list[dict[str, Any]]:
    from tiox.schemas import attack

    seen = {t["technique"] for t in _techniques(store, window)}
    rows = []
    for t in attack.catalog():
        rows.append({
            "technique": t["id"],
            "name": t["name"],
            "tactic": t["tactic"],
            "observed": t["id"] in seen,
        })
    return rows


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------


def to_json(doc: dict[str, Any]) -> tuple[bytes, str, str]:
    """Return (bytes, filename suffix, content type)."""
    body = json.dumps(doc, indent=2, default=str, ensure_ascii=False)
    return body.encode("utf-8"), "json", "application/json"


def to_txt(doc: dict[str, Any]) -> tuple[bytes, str, str]:
    """
    Plain text, fixed-width, readable in a terminal or a ticket.

    No colour and no markup: this format exists to be pasted somewhere that
    cannot render anything else, so it has to survive a copy-paste into a
    plain-text field.
    """
    out: list[str] = []
    meta = doc["report"]
    rule = "=" * 78

    out.append(rule)
    out.append(f"  {meta['title']}")
    out.append(rule)
    out.append(f"  Report type : {meta['kind']} -- {meta['kind_description']}")
    out.append(f"  Window      : {window_phrase(meta['window'])}")
    out.append(f"  Generated   : {meta['generated_at']}")
    out.append(f"  Sections    : {', '.join(doc['section_names'])}")
    out.append("")

    for section in doc["sections"]:
        rows = section["rows"]
        out.append("-" * 78)
        head = f"{section['name'].upper()}  ({len(rows) if isinstance(rows, list) else 0} row(s))"
        out.append(head)
        if section["note"]:
            out.append(f"  {section['note']}")
        out.append("-" * 78)
        if not isinstance(rows, list) or not rows:
            out.append("  (nothing to report)")
            out.append("")
            continue

        columns = _columns_for(rows)
        widths = _fit_widths(rows, columns)
        out.append("  " + "  ".join(c.upper().ljust(widths[c]) for c in columns))
        out.append("  " + "  ".join("-" * widths[c] for c in columns))
        for row in rows:
            cells = [_cell(row.get(c)) for c in columns]
            out.append("  " + "  ".join(
                cells[i].ljust(widths[c])[:widths[c]] for i, c in enumerate(columns)
            ))
        out.append("")

    out.append(rule)
    out.append("  End of report. Machine-readable equivalent: request the same")
    out.append("  report in JSON format.")
    out.append(rule)
    return ("\n".join(out) + "\n").encode("utf-8"), "txt", "text/plain; charset=utf-8"


def window_phrase(window: str) -> str:
    """
    Human phrasing for a time window.

    Naive interpolation produces "last all", and it lands in a header that a
    reader trusts. Both renderers share this so they cannot disagree.
    """
    w = (window or "").strip()
    if not w or w.lower() == "all":
        return "all time"
    if w[:4].isdigit() and "-" in w:
        return f"since {w}"
    return f"the last {w}"


def _cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple)):
        return ",".join(str(v) for v in value) if value else "-"
    if isinstance(value, dict):
        return json.dumps(value, separators=(",", ":"))[:60]
    s = str(value)
    return s.replace("\n", " ")


def _columns_for(rows: list[dict[str, Any]]) -> list[str]:
    """
    Union of keys across rows, in first-seen order.

    Rows can differ -- a scan has no `user`, a rule breakdown has no `host` --
    so a fixed column list would either drop data or pad most rows with blanks.
    """
    seen: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for k in row.keys():
            if k not in seen:
                seen.append(k)
    return seen


def _fit_widths(rows: list[dict[str, Any]], columns: list[str], cap: int = 34) -> dict[str, int]:
    widths = {}
    for c in columns:
        longest = len(c)
        for row in rows:
            if not isinstance(row, dict):
                continue
            longest = max(longest, len(_cell(row.get(c))))
        # Cap the widest column so one long path does not push everything else
        # off the edge of a pasted report.
        widths[c] = min(longest, cap)
    return widths


# --------------------------------------------------------------------------
# XLSX
# --------------------------------------------------------------------------
#
# An XLSX file is a zip of XML parts. The minimum useful workbook needs:
#   [Content_Types].xml  -- declares the parts
#   _rels/.rels          -- package relationships
#   xl/workbook.xml      -- the sheet list
#   xl/_rels/workbook.xml.rels
#   xl/worksheets/sheetN.xml
#   xl/styles.xml        -- so headers are bold and cells are strings, not guesses
#
# Inline strings are used rather than a shared-string table: it costs a little
# size on a wide report and removes an entire class of index-tracking bugs.


def to_xlsx(doc: dict[str, Any]) -> tuple[bytes, str, str]:
    """Return (bytes, filename suffix, content type)."""
    meta = doc["report"]
    sheets: list[tuple[str, list[dict[str, Any]]]] = [
        (s["name"], s["rows"] if isinstance(s["rows"], list) else [])
        for s in doc["sections"]
    ]
    # A cover sheet first, so opening the file answers "what is this?" without
    # scrolling to a data tab.
    cover = [{
        "field": "Report", "value": meta["title"],
    }, {
        "field": "Type", "value": f"{meta['kind']} -- {meta['kind_description']}",
    }, {
        "field": "Window", "value": window_phrase(meta["window"]),
    }, {
        "field": "Generated", "value": meta["generated_at"],
    }, {
        "field": "Sections", "value": ", ".join(doc["section_names"]),
    }]
    sheets.insert(0, ("about", cover))

    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", _content_types(len(sheets)))
        z.writestr("_rels/.rels", _root_rels())
        z.writestr("xl/workbook.xml", _workbook_xml([n for n, _ in sheets]))
        z.writestr("xl/_rels/workbook.xml.rels", _workbook_rels(len(sheets)))
        z.writestr("xl/styles.xml", _styles_xml())
        for i, (name, rows) in enumerate(sheets, start=1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", _sheet_xml(rows))

    return (
        buf.getvalue(),
        "xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


def _col_name(index: int) -> str:
    """1 -> A, 26 -> Z, 27 -> AA."""
    name = ""
    while index > 0:
        index, rem = divmod(index - 1, 26)
        name = chr(65 + rem) + name
    return name


def _content_types(n_sheets: int) -> str:
    overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
        f'ContentType="application/vnd.openxmlformats-officedocument.'
        f'spreadsheetml.worksheet+xml"/>'
        for i in range(1, n_sheets + 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-'
        'officedocument.spreadsheetml.sheet.main+xml"/>'
        f'{overrides}'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-'
        'officedocument.spreadsheetml.styles+xml"/>'
        '</Types>'
    )


def _root_rels() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships/officeDocument" Target="xl/workbook.xml"/>'
        '</Relationships>'
    )


def _workbook_xml(names: list[str]) -> str:
    sheets = "".join(
        f'<sheet name="{escape(n[:31])}" sheetId="{i}" r:id="rId{i}"/>'
        for i, n in enumerate(names, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets>{sheets}</sheets></workbook>'
    )


def _workbook_rels(n: int) -> str:
    rels = "".join(
        f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/'
        f'2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>'
        for i in range(1, n + 1)
    )
    # rId{N+1} is the styles part; the sheet ids above must not collide with it.
    rels += (
        f'<Relationship Id="rId{n + 1}" Type="http://schemas.openxmlformats.org/'
        f'officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openformats.org/package/2006/relationships">'
        f'{rels}</Relationships>'
    ).replace("openxmlformats.org/package", "openxmlformats.org/package")


def _styles_xml() -> str:
    """
    Two cell formats: style 1 is a bold header. Everything else is the default,
    which is enough for a data report and keeps the stylesheet trivial to
    generate correctly.
    """
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<fonts count="2">'
        '<font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/></font>'
        '</fonts>'
        '<fills count="2">'
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        '</fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0"/>'
        '</cellStyleXfs>'
        '<cellXfs count="2">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
        '</cellXfs>'
        # A named default cell style. Without it Excel and openpyxl both warn
        # that the workbook has no default style, and some readers fall back to
        # their own, which is how a report ends up looking subtly wrong.
        '<cellStyles count="1">'
        '<cellStyle name="Normal" xfId="0" builtinId="0"/>'
        '</cellStyles>'
        '</styleSheet>'
    )


def _sheet_xml(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            '<sheetData/></worksheet>'
        )

    columns = _columns_for(rows)
    parts = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">',
        '<sheetData>',
    ]

    # Header row, bold.
    parts.append("<row r=\"1\">")
    for i, c in enumerate(columns, start=1):
        ref = f"{_col_name(i)}1"
        parts.append(
            f'<c r="{ref}" s="1" t="inlineStr"><is><t xml:space="preserve">'
            f"{escape(c)}</t></is></c>"
        )
    parts.append("</row>")

    for r, row in enumerate(rows, start=2):
        parts.append(f'<row r="{r}">')
        for i, c in enumerate(columns, start=1):
            value = row.get(c) if isinstance(row, dict) else None
            text = _cell(value)
            if not text:
                continue
            ref = f"{_col_name(i)}{r}"
            # An empty <c> would be dropped, so a blank cell is simply omitted:
            # spreadsheets handle missing cells better than empty ones.
            parts.append(
                f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">'
                f"{escape(text)}</t></is></c>"
            )
        parts.append("</row>")

    parts.append("</sheetData></worksheet>")
    return "".join(parts)


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------


def render(doc: dict[str, Any], fmt: str) -> tuple[bytes, str, str]:
    """Render a document. Returns (bytes, suffix, content type)."""
    fmt = (fmt or "").lower().strip()
    if fmt not in FORMATS:
        raise ValueError(
            f"unsupported format {fmt!r}; choose one of: {', '.join(FORMATS)}"
        )
    if fmt == "json":
        return to_json(doc)
    if fmt == "xlsx":
        return to_xlsx(doc)
    return to_txt(doc)


def render_to_file(
    doc: dict[str, Any], fmt: str, directory: Path | str, *, stem: str | None = None
) -> dict[str, Any]:
    """
    Render and write, returning a descriptor of what was written.

    The filename carries the kind, the window, and a UTC timestamp, so a folder
    of reports is self-describing without opening anything.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    body, suffix, content_type = render(doc, fmt)
    meta = doc["report"]
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = stem or f"{meta['kind']}-{meta['window']}-{ts}"
    path = directory / f"{base}.{suffix}"
    path.write_bytes(body)

    return {
        "name": path.name,
        "path": str(path),
        "size": len(body),
        "format": suffix,
        "content_type": content_type,
        "kind": meta["kind"],
        "window": meta["window"],
        "title": meta["title"],
        "sections": doc["section_names"],
        "generated_at": meta["generated_at"],
    }
