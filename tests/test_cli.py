"""CLI identifier defaults: either the signer or the kid is enough."""
import datetime as dt
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
