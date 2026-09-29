"""Wrap each view module in an IIFE so its helpers cannot leak into the global scope.

Plain <script> tags share one global scope, so two views that both define a
helper called render() silently break each other: the later file wins. That is
exactly what happened -- view-events.js and view-incidents.js both defined
render(), so the events table rendered incident rows and found zero events.

The fix is not "rename carefully". It is to give every view its own scope so the
collision cannot be written in the first place.
"""

import re
import sys
from pathlib import Path

UI = Path("/home/filip/Desktop/codeBase_AV/threat-ioc-platform/ui")

WRAP_OPEN = "/* Own scope: helpers here must not collide with another view's. */\n(function () {\n"
WRAP_CLOSE = "})();\n"


def leading_comment(src: str) -> str:
    """
    Return the file's leading comment block, so it stays outside the IIFE.

    Consume until the block actually closes. A line-based "starts with *" test
    truncates a comment whose description lines do not all begin with a star,
    which orphans the rest of the comment inside the wrapper and breaks the
    parse -- the exact failure this script is meant to prevent.
    """
    lines = src.split("\n")
    i = 0
    while i < len(lines) and lines[i].strip() == "":
        i += 1
    if i >= len(lines) or not lines[i].strip().startswith("/*"):
        return ""
    start = i
    closed = False
    while i < len(lines):
        if "*/" in lines[i]:
            closed = True
            i += 1
            break
        i += 1
    if not closed:
        raise SystemExit(f"unterminated comment at line {start + 1}")
    return "\n".join(lines[:i]).rstrip()


def wrap(path: Path) -> bool:
    src = path.read_text()
    if "(function ()" in src.split("\n\n")[0] or src.lstrip().startswith("(function"):
        return False
    head = leading_comment(src)
    body = src[len(head):].strip("\n")
    if not body:
        return False
    indented = "\n".join(("  " + l if l.strip() else "") for l in body.split("\n"))
    out = f"{head}\n\n{WRAP_OPEN}{indented}\n{WRAP_CLOSE}"
    path.write_text(out)
    return True


def main() -> int:
    changed = []
    for p in sorted(UI.glob("view-*.js")):
        if wrap(p):
            changed.append(p.name)
    print("wrapped:", ", ".join(changed) if changed else "(none)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
