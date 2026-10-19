"""Assert that a Codex run is isolated, reading `codex doctor --json` on stdin.

    codex doctor --json | preflight.py <expected CODEX_HOME> <expected model>

`-c` overrides layer on top of the operator's own ~/.codex/config.toml, so a
run inherits their model, mcp_servers and plugins unless CODEX_HOME moves the
whole home. A user-scope file leaking into a measurement is what invalidated
forty Claude Code runs, so the runner checks rather than assumes. Exits
non-zero with the mismatch named.
"""
import json
import sys


def main() -> int:
    want_home, want_model = sys.argv[1], sys.argv[2]
    try:
        details = json.load(sys.stdin)["checks"]["config.load"]["details"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"preflight: cannot read `codex doctor --json` ({e})", file=sys.stderr)
        return 1
    bad = []
    if details.get("CODEX_HOME") != want_home:
        bad.append(f"CODEX_HOME is {details.get('CODEX_HOME')!r}, wanted {want_home!r}")
    if details.get("model") != want_model:
        bad.append(f"model is {details.get('model')!r}, wanted {want_model!r}")
    if details.get("config.toml") != want_home + "/config.toml":
        bad.append(f"config.toml is {details.get('config.toml')!r}, not the one we wrote")
    if details.get("mcp servers") not in (None, "", "none", "0"):
        bad.append(f"mcp servers configured ({details['mcp servers']}); the operator's own are loaded")
    if bad:
        print("preflight: the run would not be isolated:", *bad, sep="\n  ", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
