"""CLI identifier defaults: either the signer or the kid is enough."""
import datetime as dt
import subprocess
import sys
import tomllib
from pathlib import Path

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


def test_install_codex_prints_a_usable_fragment(sib_home, tmp_path):
    rc, so, se = run(["install", "codex", "--audience", "acme/dev-agent",
                      "--home", str(tmp_path / "sib"), "--sib-path", "/usr/bin/true", "--print"])
    assert rc == 0
    assert "[auto_review]" in so and "experimental_policy_template" in so and "extra_policy" in so
    # the reviewer runs the command literally, so the machine's own values must be baked in
    assert f"SIB_HOME={tmp_path / 'sib'}" in so and "--audience acme/dev-agent" in so
    # --print writes nothing and does not offer to
    assert "appended to" not in so


def test_install_codex_writes_and_merges(sib_home, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("model = \"gpt-6\"\n")
    args = ["install", "codex", "--audience", "a/b", "--config", str(cfg),
            "--home", str(tmp_path / "sib"), "--sib-path", "/usr/bin/true", "--yes"]
    rc, so, se = run(args)
    assert rc == 0 and "wrote" in so
    text = cfg.read_text()
    assert text.startswith("model = ") and "[auto_review]" in text
    assert 'approvals_reviewer = "auto_review"' in text       # the default answer is yes
    # a second run replaces our keys rather than refusing, and the result is still one valid file
    rc, so, se = run(args)
    assert rc == 0 and "wrote" in so
    d = tomllib.loads(cfg.read_text())
    assert d["model"] == "gpt-6" and d["approvals_reviewer"] == "auto_review"
    assert cfg.read_text().count("extra_policy =") == 1
    assert (tmp_path / "config.toml.sib-bak").exists()        # the previous file is kept


def test_install_codex_leaves_other_settings_alone(sib_home, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("model = \"gpt-6\"\n\n[auto_review]\nignore_rules = true\n\n"
                   "[mcp_servers.fs]\ncommand = \"npx\"\n")
    rc, so, se = run(["install", "codex", "--audience", "a/b", "--config", str(cfg),
                      "--home", str(tmp_path / "sib"), "--sib-path", "/usr/bin/true", "--yes"])
    assert rc == 0
    d = tomllib.loads(cfg.read_text())
    assert d["auto_review"]["ignore_rules"] is True           # a neighbouring key in our own table
    assert "extra_policy" in d["auto_review"]
    assert d["mcp_servers"]["fs"]["command"] == "npx"         # a later table is not swallowed


def test_install_codex_keeps_another_reviewer_by_default(sib_home, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("approvals_reviewer = \"none\"\n")
    rc, so, se = run(["install", "codex", "--audience", "a/b", "--config", str(cfg),
                      "--home", str(tmp_path / "sib"), "--sib-path", "/usr/bin/true"])
    assert rc == 0
    d = tomllib.loads(cfg.read_text())
    assert d["approvals_reviewer"] == "none"                  # declining leaves the user's choice
    assert "extra_policy" in d["auto_review"]                 # the policy still lands
    assert "--approve-for-me" in se                           # and says how to enable it per run


def test_install_codex_asks_before_replacing_our_own_keys(sib_home, tmp_path):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[auto_review]\nextra_policy = \"mine\"\n")
    rc, so, se = run(["install", "codex", "--audience", "a/b", "--config", str(cfg),
                      "--home", str(tmp_path / "sib"), "--sib-path", "/usr/bin/true"])
    assert rc != 0 and "left unchanged" in se
    assert cfg.read_text() == "[auto_review]\nextra_policy = \"mine\"\n"

def test_install_codex_needs_an_audience(sib_home, monkeypatch):
    monkeypatch.delenv("SIB_AUDIENCE", raising=False)
    rc, so, se = run(["install", "codex", "--print"])
    assert rc != 0 and "--audience" in se


def test_install_codex_warns_about_a_registry_inside_the_repo(sib_home, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    rc, so, se = run(["install", "codex", "--audience", "a/b", "--home", str(tmp_path / "inside"),
                      "--sib-path", "/usr/bin/true", "--print"])
    assert rc == 0 and "inside the working directory" in se


def test_install_codex_follows_codex_home(sib_home, tmp_path, monkeypatch):
    """CODEX_HOME relocates the whole Codex home, so the default must follow it."""
    from sib.codex.install import default_config
    monkeypatch.delenv("CODEX_HOME", raising=False)
    assert default_config() == Path.home() / ".codex" / "config.toml"
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "ch"))
    assert default_config() == tmp_path / "ch" / "config.toml"
    # and an install with no --config writes there
    rc, so, se = run(["install", "codex", "--audience", "a/b", "--home", str(tmp_path / "sib"),
                      "--sib-path", "/usr/bin/true", "--yes"])
    assert rc == 0 and (tmp_path / "ch" / "config.toml").exists()


def test_audience_resolution_order(sib_home, monkeypatch):
    """A flag wins, then SIB_AUDIENCE, then the registry's recorded default."""
    from sib.registry import resolve_audience
    monkeypatch.delenv("SIB_AUDIENCE", raising=False)
    assert resolve_audience() == (None, "unset")
    rc, so, se = run(["audience"])
    assert rc != 0 and "names this deployment, not the vendor" in se

    rc, so, se = run(["audience", "my-company/trevor-dev"])
    assert rc == 0 and "recorded in" in so
    assert Registry().default_audience == "my-company/trevor-dev"
    assert resolve_audience()[0] == "my-company/trevor-dev"
    rc, so, se = run(["audience"])
    assert "my-company/trevor-dev" in so and "default_audience in" in so

    monkeypatch.setenv("SIB_AUDIENCE", "my-company/ci")
    assert resolve_audience() == ("my-company/ci", "SIB_AUDIENCE")
    assert resolve_audience("my-company/other") == ("my-company/other", "--audience")


def test_sign_and_verify_use_the_recorded_audience(sib_home, tmp_path, monkeypatch):
    monkeypatch.delenv("SIB_AUDIENCE", raising=False)
    run(["keygen", "--signer", "alice@example.com", "--enroll", "--audience", "my-company/trevor-dev"])
    assert Registry().default_audience == "my-company/trevor-dev"
    out = tmp_path / "b.txt"
    rc, so, se = run(["sign", "--signer", "alice@example.com", "--text", "You may deploy to staging.",
                      "--out", str(out)])
    assert rc == 0 and "my-company/trevor-dev" in se       # named, with its source, before signing
    # the block carries it, and a verifier with no flag accepts it
    rc, so, se = run(["verify", str(out)])
    assert rc == 0 and "my-company/trevor-dev" in so
    # matching is exact: a sibling deployment is not a prefix match
    rc, so, se = run(["verify", str(out), "--audience", "my-company"])
    assert rc != 0 and "audience_mismatch" in so
