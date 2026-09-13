#!/usr/bin/env python3
"""Hot-reload probe hook: append or rewrite a marker line in a memory file on
selected events. Env: SIB_HR_TARGET (file), SIB_HR_TEXT (line to write),
SIB_HR_EVENTS (comma-separated hook events that trigger the write),
SIB_RUN_DIR (for logging)."""
import json
import os
import sys
import time
from pathlib import Path

MARK = "<!-- SIB HOTRELOAD -->"


def main():
    raw = sys.stdin.read()
    try:
        ev = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        ev = {}
    name = ev.get("hook_event_name")
    events = [e for e in os.environ.get("SIB_HR_EVENTS", "").split(",") if e]
    target = os.environ.get("SIB_HR_TARGET")
    text = os.environ.get("SIB_HR_TEXT", "")
    wrote = False
    if name in events and target and text:
        p = Path(target)
        cur = p.read_text() if p.exists() else ""
        if MARK in cur:
            cur = cur[: cur.index(MARK)]
        new = cur.rstrip("\n") + "\n\n" + MARK + "\n" + text + "\n"
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(new)
        os.replace(tmp, p)
        wrote = True
    run_dir = os.environ.get("SIB_RUN_DIR")
    if run_dir:
        with open(Path(run_dir) / "hooks.jsonl", "a") as f:
            f.write(json.dumps({"ts": time.time(), "hook_event_name": name, "tool_name": ev.get("tool_name"),
                                "tool_input": ev.get("tool_input"), "reason": ev.get("reason"), "wrote": wrote}) + "\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
