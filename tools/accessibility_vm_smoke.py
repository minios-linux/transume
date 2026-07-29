#!/usr/bin/env python3
"""Inspect the production GTK accessibility tree and real keyboard focus."""
from __future__ import annotations

import subprocess
import time

import pyatspi


def descendants(node):
    yield node
    for index in range(node.childCount):
        yield from descendants(node.getChildAtIndex(index))


def focused_name(app) -> str | None:
    for node in descendants(app):
        try:
            if node.getState().contains(pyatspi.STATE_FOCUSED):
                return node.name or f"{node.getRoleName()}:{node.getIndexInParent()}"
        except (LookupError, RuntimeError):
            continue
    return None


def main() -> int:
    desktop = pyatspi.Registry.getDesktop(0)
    app = next((child for child in descendants(desktop)
                if child.getRole() == pyatspi.ROLE_APPLICATION
                and (child.name or "").casefold() == "transume"), None)
    if app is None:
        raise RuntimeError("Transume accessibility application was not found")
    names = {node.name for node in descendants(app) if node.name}
    required = {"About", "Backup", "Restore", "Clone", "Images", "Activity"}
    missing = required - names
    if missing:
        raise RuntimeError(f"missing accessible controls: {sorted(missing)}")
    window = subprocess.run(
        ["/usr/bin/xdotool", "search", "--onlyvisible", "--name", "Transume"],
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()[-1]
    subprocess.run(["/usr/bin/xdotool", "windowactivate", "--sync", window], check=True)
    seen = set()
    for _ in range(14):
        subprocess.run(["/usr/bin/xdotool", "key", "Tab"], check=True)
        time.sleep(.05)
        name = focused_name(app)
        if name:
            seen.add(name)
    if len(seen) < 5:
        raise RuntimeError(f"keyboard focus reached too few controls: {sorted(seen)}")
    subprocess.run(["/usr/bin/xdotool", "key", "shift+Tab", "Return"], check=True)
    print(f"AT-SPI names and keyboard traversal passed ({len(seen)} focus targets)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
