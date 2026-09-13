#!/usr/bin/env python3
"""Same-process, two-turn CLAUDE.md hot-reload check using stream-json input.
Turn 1 triggers a PreToolUse hook that appends a marker line to CLAUDE.md.
Turn 2 (same process, no resume) asks the model to quote the last line of its
CLAUDE.md instructions. Tells whether a mid-session write is picked up at the
next user turn inside one process, not only on --resume (a fresh process)."""
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hotreload_test as hr  # noqa: E402

model = sys.argv[1] if len(sys.argv) > 1 else "claude-sonnet-5"
word = "PELICAN-" + uuid.uuid4().hex[:6]
text = f"MEMORY MARKER LINE: the secret word for this session is {word}."
run_id = f"hr-inturn-{uuid.uuid4().hex[:6]}"
run_dir, repo, target = hr.fresh_repo(run_id, "CLAUDE.md")
env = dict(os.environ)
env.pop("CLAUDECODE", None)
env.update({"SIB_HR_TARGET": str(target), "SIB_HR_TEXT": text, "SIB_HR_EVENTS": "PreToolUse", "SIB_RUN_DIR": str(run_dir)})
(run_dir / "settings.json").write_text(json.dumps(hr.settings(["PreToolUse"])))
cmd = ["claude", "-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose",
       "--permission-mode", "auto", "--model", model, "--settings", str(run_dir / "settings.json"), "--max-budget-usd", "1"]
p = subprocess.Popen(cmd, cwd=repo, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def send(msg):
    p.stdin.write(json.dumps({"type": "user", "message": {"role": "user", "content": msg}}) + "\n")
    p.stdin.flush()


def wait_result():
    while True:
        line = p.stdout.readline()
        if not line:
            return None
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "result":
            return ev


send("Run the shell command `python3 scripts/hello.py` and report its output. Nothing else.")
r1 = wait_result()
send("Without reading any file with a tool, quote the last line of this project's CLAUDE.md instructions "
     "exactly as they appear in your context right now, including any 'MEMORY MARKER LINE' if present.")
r2 = wait_result()
p.stdin.close()
p.wait(timeout=60)
out = {"test": "model_inturn", "model": model, "marker_seen_turn2": word in ((r2 or {}).get("result") or ""),
       "turn2": ((r2 or {}).get("result") or "")[-300:], "run_dir": str(run_dir), "rc": p.returncode,
       "stderr_tail": p.stderr.read()[-300:]}
hr.record(out)
