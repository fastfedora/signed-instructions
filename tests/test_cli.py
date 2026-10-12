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


# ---- passkeys (Phase 2): the browser flows are answered by the fake authenticator ----

from sib import keys_dev, keys_webauthn
from tests.fake_authenticator import FakeAuthenticator, enroll_fake, ORIGIN


def _fake_sign_in_browser(auth):
    def fake(header, ctext, key, allowed, timeout=180, open_browser=True, browser=None):
        from dataclasses import replace
        a = auth.get(keys_webauthn.challenge(header.encode(), ctext))
        full = replace(header, credentialId=a["rawId"], authenticatorData=a["response"]["authenticatorData"],
                       clientDataJSON=a["response"]["clientDataJSON"])
        failure = keys_webauthn.check_assertion(full, ctext, a["response"]["signature"], key, allowed)
        return {"header": full, "signature": a["response"]["signature"],
                "status": failure[0] if failure else "verified", "error": failure[1] if failure else None, "uvm": None}
    return fake


def test_enroll_manual_public_key_path(sib_home):
    rc, out, err = run(["enroll", "--signer", "bob@example.com", "--kid", "bob@example.com#k", "--public-key", "AAAA", "--dev"])
    assert rc == 0 and Registry().lookup("bob@example.com#k")[1]["mode"] == "dev"
    rc, out, err = run(["enroll", "--signer", "bob@example.com", "--public-key", "AAAA"])
    assert rc != 0 and "--kid is required" in err


def test_enroll_passkey_in_browser(sib_home, monkeypatch):
    auth = FakeAuthenticator()
    chal = b"\x05" * 32

    def fake_enroll(signer, existing, allowed, timeout=180, open_browser=True, browser=None):
        assert signer == "alice@example.com" and existing == []
        return keys_webauthn.verify_enrollment(auth.register(chal), chal, ORIGIN, roots={})
    import sib.webauthn_app
    monkeypatch.setattr(sib.webauthn_app, "enroll_in_browser", fake_enroll)
    rc, out, err = run(["enroll", "--signer", "alice@example.com"])
    assert rc == 0, err
    kid = f"alice@example.com#passkey-{auth.credential_id[:2].hex()}"
    assert f"enrolled {kid}" in out and "attestation none not verified" in out
    assert "not on the biometric-capable allowlist" in err and "attestation_verified=false" in err
    k = Registry().lookup(kid)[1]
    assert k["alg"] == "ES256-webauthn" and k["mode"] == "enforced" and k["credential_id"] == auth.credential_id_b64u
    assert k["aaguid"] == auth.aaguid and k["origins"] == [ORIGIN] and k["attestation_verified"] is False


def test_sign_prefers_passkey_and_dev_flag_picks_the_dev_key(sib_home, monkeypatch):
    auth = FakeAuthenticator()
    run(["keygen", "--signer", "alice@example.com", "--enroll"])
    reg = Registry()
    enroll_fake(reg, auth, "alice@example.com", "alice@example.com#passkey-1")
    reg.save()
    import sib.webauthn_app
    monkeypatch.setattr(sib.webauthn_app, "sign_in_browser", _fake_sign_in_browser(auth))
    # the passkey wins without --dev, and needs an audience
    rc, out, err = run(["sign", "--signer", "alice@example.com", "--text", "Deploy to staging."])
    assert rc != 0 and "--audience is required" in err
    rc, out, err = run(["sign", "--signer", "alice@example.com", "--audience", "acme/dev-agent", "--text", "Deploy to staging."])
    assert rc == 0, err
    assert "mode=enforced" in err and "signed with alice@example.com#passkey-1" in err and "DEV MODE" not in err
    assert "BEGIN SIB SIGNED INSTRUCTION" in out
    # the default verify mode is now enforced, and the block verifies in it
    (sib_home / "block.txt").write_text(out)
    rc, vout, verr = run(["verify", str(sib_home / "block.txt"), "--audience", "acme/dev-agent"])
    assert rc == 0 and "VERIFIED alice@example.com" in vout and "mode enforced" in vout and "DEV MODE" not in verr
    # --dev signs with the dev key, which the default (enforced) verify refuses and --dev accepts
    keys_dev._warned = False      # the warning prints once per process; keygen above already printed it
    rc, out, err = run(["sign", "--signer", "alice@example.com", "--dev", "--text", "Deploy to staging."])
    assert rc == 0 and "mode=dev" in err and "DEV MODE" in err
    (sib_home / "dev.txt").write_text(out)
    rc, vout, verr = run(["verify", str(sib_home / "dev.txt")])
    assert rc == 1 and "DEV_KEY_IN_ENFORCED_MODE" in vout
    keys_dev._warned = False
    rc, vout, verr = run(["verify", str(sib_home / "dev.txt"), "--dev"])
    assert rc == 0 and "DEV MODE" in verr
    # --dev with a passkey kid is refused
    rc, out, err = run(["sign", "--kid", "alice@example.com#passkey-1", "--dev", "--text", "x"])
    assert rc != 0 and "--dev signs with a dev key" in err


def test_sign_refuses_an_assertion_that_does_not_verify(sib_home, monkeypatch):
    auth = FakeAuthenticator(aaguid="11111111-2222-3333-4444-555555555555")
    reg = Registry()
    enroll_fake(reg, auth, "alice@example.com", "alice@example.com#passkey-1", allow=False)
    reg.save()
    import sib.webauthn_app
    monkeypatch.setattr(sib.webauthn_app, "sign_in_browser", _fake_sign_in_browser(auth))
    rc, out, err = run(["sign", "--signer", "alice@example.com", "--audience", "a", "--text", "x"])
    assert rc != 0 and "authenticator_not_allowed" in err and "no block written" in err and out == ""


def test_install_writes_one_settings_file(sib_home, tmp_path):
    out = tmp_path / "sib-settings.json"
    rc, so, se = run(["install", "claude-code", "--settings-json", str(out)])
    assert rc == 0
    d = json.loads(out.read_text())
    assert sorted(d["hooks"]) == ["PostToolUse", "PreToolUse", "UserPromptSubmit"]
    # the autoMode rule must be inert where no provenance note is delivered
    assert "does not apply at all" in d["autoMode"]["soft_deny"][1]


def test_install_into_a_project(sib_home, tmp_path):
    repo = tmp_path / "repo"; repo.mkdir()
    rc, so, se = run(["install", "claude-code", "--project", str(repo)])
    assert rc == 0
    d = json.loads((repo / ".claude" / "settings.json").read_text())
    assert "PreToolUse" in d["hooks"] and "autoMode" not in d   # project settings never carry autoMode
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
