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

# Relative to the repository, not an absolute path: the hardcoded version only
# worked on the machine it was written on.
REPO = Path(__file__).resolve().parents[1]
UI = REPO / "ui"

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


def already_wrapped(src: str) -> bool:
    """
    Whether this file is already inside an IIFE.

    The previous check was `"<marker>" in src.split("\n\n")[0] or
    src.lstrip().startswith("(function")`. It missed the files whose comment
    block is followed by a blank line and the wrapper further down, so a re-run
    wrapped them a second time: nine files ended up with nested IIFEs and the
    helper names were shadowed again -- reintroducing the exact bug the script
    exists to prevent, while appearing to succeed.

    A file is considered wrapped if it contains the marker this script writes, or
    any top-level `(function` opening. Matching our own marker is what makes a
    re-run safe; matching the pattern at all covers files scoped by hand.
    """
    if WRAP_OPEN.strip()[:30] in src:
        return True
    return bool(re.search(r"^\(function", src, re.M))


def wrap(path: Path) -> bool:
    src = path.read_text()
    if already_wrapped(src):
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
