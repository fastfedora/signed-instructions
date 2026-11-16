"""CLI identifier defaults: either the signer or the kid is enough."""
import datetime as dt
import json
import subprocess
import sys

import pytest

from sib.cli import main
from sib.registry import Registry


def run(argv, monkeypatch=None, stdin=""):
    """Run the CLI in-process; return (rc, stdout, stderr)."""
    import io
    from contextlib import redirect_stdout, redirect_stderr
    out, err = io.StringIO(), io.StringIO()
    old_stdin = sys.stdin
    sys.stdin = io.StringIO(stdin)
    try:
        with redirect_stdout(out), redirect_stderr(err):
            try:
                main(argv)
                rc = 0
            except SystemExit as e:
                if isinstance(e.code, str):   # SystemExit("message") prints at exit; capture it here
                    err.write(e.code)
                rc = e.code if isinstance(e.code, int) else 1
    finally:
        sys.stdin = old_stdin
    return rc, out.getvalue(), err.getvalue()


def test_keygen_derives_kid_from_signer(sib_home):
    rc, out, err = run(["keygen", "--signer", "alice@example.com", "--enroll"])
    assert rc == 0
    month = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m")
    assert f"alice@example.com#dev-{month}" in out
    assert Registry().lookup(f"alice@example.com#dev-{month}")[0] == "alice@example.com"


def test_keygen_needs_one_identifier(sib_home):
    rc, out, err = run(["keygen"])
    assert rc != 0


def test_sign_with_signer_only(sib_home):
    run(["keygen", "--signer", "alice@example.com", "--enroll"])
    rc, out, err = run(["sign", "--signer", "alice@example.com", "--file", "-"], stdin="Deploy to staging.")
    assert rc == 0 and "BEGIN SIB SIGNED INSTRUCTION" in out and "kid=alice@example.com#dev-" in err


def test_sign_with_kid_only_derives_signer(sib_home):
    run(["keygen", "--signer", "alice@example.com", "--kid", "alice@example.com#laptop", "--enroll"])
    rc, out, err = run(["sign", "--kid", "alice@example.com#laptop", "--file", "-"], stdin="Deploy to staging.")
    assert rc == 0 and "Signer: alice@example.com" in out


def test_sign_refuses_ambiguous_signer_and_mismatch(sib_home):
    run(["keygen", "--signer", "alice@example.com", "--kid", "alice@example.com#a", "--enroll"])
    run(["keygen", "--signer", "alice@example.com", "--kid", "alice@example.com#b", "--enroll"])
    rc, out, err = run(["sign", "--signer", "alice@example.com", "--file", "-"], stdin="x")
    assert rc != 0 and "several keys" in err
    rc, out, err = run(["sign", "--signer", "bob@example.com", "--kid", "alice@example.com#a", "--file", "-"], stdin="x")
    assert rc != 0 and "not 'bob@example.com'" in err
    rc, out, err = run(["sign", "--file", "-"], stdin="x")
    assert rc != 0 and "give --kid or --signer" in err


def test_sign_text_flag(sib_home):
    run(["keygen", "--signer", "alice@example.com", "--enroll"])
    rc, out, err = run(["sign", "--signer", "alice@example.com", "--text", "Deploy to staging."])
    assert rc == 0 and "\nDeploy to staging.\n-----BEGIN SIB SIGNATURE-----" in out
    rc, out, err = run(["sign", "--signer", "alice@example.com", "--text", "x", "--file", "-"], stdin="y")
    assert rc != 0 and "not both" in err


def test_install_writes_one_settings_file(sib_home, tmp_path):
    out = tmp_path / "sib-settings.json"
    rc, so, se = run(["install", "claude-code", "--settings-json", str(out)])
    assert rc == 0
    d = json.loads(out.read_text())
    assert sorted(d["hooks"]) == ["PostToolUse", "UserPromptSubmit"]
    # the autoMode rule must be inert where no provenance note is delivered
    assert "does not apply at all" in d["autoMode"]["soft_deny"][1]


def test_install_into_a_project(sib_home, tmp_path):
    repo = tmp_path / "repo"; repo.mkdir()
    rc, so, se = run(["install", "claude-code", "--project", str(repo)])
    assert rc == 0
    d = json.loads((repo / ".claude" / "settings.json").read_text())
    assert "PostToolUse" in d["hooks"] and "autoMode" not in d   # project settings never carry autoMode
    assert "~/.claude/settings.json" in so


def test_install_layers_and_no_target(sib_home, tmp_path):
    out = tmp_path / "s.json"
    rc, so, se = run(["install", "claude-code", "--settings-json", str(out), "--layers", "post", "--no-prose"])
    assert rc == 0
    d = json.loads(out.read_text())
    assert sorted(d["hooks"]) == ["PostToolUse"] and "autoMode" not in d
    rc, so, se = run(["install", "claude-code"])
    assert rc != 0 and "nothing to do" in se


def test_module_entry_point_still_works(tmp_path):
    out = tmp_path / "m.json"
    p = subprocess.run([sys.executable, "-m", "sib.hooks.claude_code.install", "--settings-json", str(out)],
                       capture_output=True, text=True)
    assert p.returncode == 0 and json.loads(out.read_text())["hooks"]
