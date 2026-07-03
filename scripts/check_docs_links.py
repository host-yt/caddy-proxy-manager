#!/usr/bin/env python3
"""Fail if any Markdown file links to a local file that does not exist.

Catches doc rot like a SECURITY.md pointing at a deleted audit report.
Only checks relative local links; skips http(s), mailto and #anchors.
"""
import os
import re
import sys

LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

dead = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    # skip vendored / build / worktree noise
    dirnames[:] = [d for d in dirnames if d not in
                   (".git", "node_modules", "vendor", ".claude", "bin", "dist")]
    for name in filenames:
        if not name.endswith(".md"):
            continue
        path = os.path.join(dirpath, name)
        with open(path, encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                for target in LINK.findall(line):
                    target = target.split()[0].strip()  # drop optional "title"
                    if target.startswith(("http://", "https://", "mailto:", "#", "tel:")):
                        continue
                    target = target.split("#", 1)[0]  # strip anchor
                    if not target:
                        continue
                    resolved = os.path.normpath(os.path.join(dirpath, target))
                    if not os.path.exists(resolved):
                        rel = os.path.relpath(path, ROOT)
                        dead.append(f"{rel}:{lineno} -> {target}")

if dead:
    print("Dead local doc links:")
    for d in dead:
        print(f"  {d}")
    sys.exit(1)
print("All local doc links resolve.")
