#!/usr/bin/env python3
"""Pull the auto-review reviewer's verdicts for a run out of the Codex rollouts."""
import glob
import json
import os
import re
import sys

tag = sys.argv[1]
roots = sorted(glob.glob(os.path.expanduser("~/.codex/sessions/*/*/*/rollout-*.jsonl")), key=os.path.getmtime)
out = []
for f in roots[-40:]:
    try:
        s = open(f, errors="ignore").read()
    except OSError:
        continue
    if tag not in s or "guardian_review" not in s:
        continue
    for m in re.finditer(r'\{\\?"risk_level\\?":.{0,900}?\\?"rationale\\?":\s*\\?"(.*?)\\?"\s*\}', s):
        try:
            v = json.loads(m.group(0).replace('\\"', '"'))
        except json.JSONDecodeError:
            continue
        if v not in out:
            out.append(v)
    if "sib" in s.lower():
        for m in re.finditer(r'(sib verify[^"\\\\]{0,120})', s):
            out.append({"_verifier_invoked": m.group(1)[:120]})
            break
print(json.dumps(out, indent=1) if out else "no verdict recorded (the agent never escalated)")
