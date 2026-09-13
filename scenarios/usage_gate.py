#!/usr/bin/env python3
"""Subscription usage gate for headless batches.

Reads the claude.ai OAuth token from the macOS keychain entry Claude Code
keeps ("Claude Code-credentials") and asks the usage endpoint for the
five-hour and seven-day utilization. Batches call `wait_for_headroom()`
before each run so they never push the plan into extra usage.

  python3 scenarios/usage_gate.py          # print current utilization
"""
import json
import subprocess
import sys
import time
import urllib.request

USAGE_URL = "https://api.anthropic.com/api/oauth/usage"


def _token():
    try:
        raw = subprocess.run(["security", "find-generic-password", "-s", "Claude Code-credentials", "-w"],
                             capture_output=True, text=True, check=True).stdout
        return json.loads(raw).get("claudeAiOauth", {}).get("accessToken")
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return None


def utilization():
    """Returns {'five_hour': pct, 'seven_day': pct, 'resets_at': iso} or None if unavailable."""
    tok = _token()
    if not tok:
        return None
    req = urllib.request.Request(USAGE_URL, headers={
        "Authorization": f"Bearer {tok}", "anthropic-beta": "oauth-2025-04-20", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.load(r)
    except Exception:
        return None
    fh, sd = d.get("five_hour") or {}, d.get("seven_day") or {}
    return {"five_hour": fh.get("utilization"), "seven_day": sd.get("utilization"),
            "five_hour_resets_at": fh.get("resets_at"), "seven_day_resets_at": sd.get("resets_at")}


def wait_for_headroom(cap=75.0, weekly_cap=90.0, poll=300, max_wait=6 * 3600, log=print):
    """Block until five-hour utilization is below `cap` (and weekly below
    `weekly_cap`). Returns True when clear, False on timeout. If the usage
    endpoint is unreachable, returns False so the caller fails closed."""
    t0 = time.time()
    while True:
        u = utilization()
        if u is None:
            log("usage gate: usage endpoint unavailable; refusing to run")
            return False
        fh, sd = u["five_hour"] or 0.0, u["seven_day"] or 0.0
        if fh < cap and sd < weekly_cap:
            return True
        if time.time() - t0 > max_wait:
            log(f"usage gate: still at five_hour={fh}% seven_day={sd}% after {max_wait}s; giving up")
            return False
        log(f"usage gate: five_hour={fh}% (cap {cap}%), seven_day={sd}%; resets {u['five_hour_resets_at']}; waiting {poll}s")
        time.sleep(poll)


if __name__ == "__main__":
    u = utilization()
    print(json.dumps(u, indent=2) if u else "usage unavailable")
    sys.exit(0 if u else 1)
