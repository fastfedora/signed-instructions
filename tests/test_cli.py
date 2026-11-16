"""CLI identifier defaults: either the signer or the kid is enough."""
import datetime as dt
import io
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
    rc, out, err = run(["sign", "--signer", "alice@example.com", "--out", "-", "--file", "-"],
                       stdin="Deploy to staging.")
    assert rc == 0 and "BEGIN SIB SIGNED INSTRUCTION" in out and "kid=alice@example.com#dev-" in err


def test_sign_with_kid_only_derives_signer(sib_home):
    run(["keygen", "--signer", "alice@example.com", "--kid", "alice@example.com#laptop", "--enroll"])
    rc, out, err = run(["sign", "--kid", "alice@example.com#laptop", "--out", "-", "--file", "-"],
                       stdin="Deploy to staging.")
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
    rc, out, err = run(["sign", "--signer", "alice@example.com", "--out", "-", "--text", "Deploy to staging."])
    assert rc == 0 and "\nDeploy to staging.\n-----BEGIN SIB SIGNATURE-----" in out
    rc, out, err = run(["sign", "--signer", "alice@example.com", "--text", "x", "--file", "-"], stdin="y")
    assert rc != 0 and "give the instruction once" in err


# ---- passkeys (Phase 2): the browser flows are answered by the fake authenticator ----

from sib import keys_dev, keys_webauthn
from tests.fake_authenticator import FakeAuthenticator, enroll_fake, ORIGIN


def _fake_sign_in_browser(auth, seen=None):
    def fake(header, ctext, key, allowed, timeout=180, open_browser=True, browser=None, action="",
             code_in_terminal=True):
        if seen is not None:
            seen.update(action=action, code_in_terminal=code_in_terminal, ctext=ctext)
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
    rc, so, se = run(["install", "codex", "--audience", "acme/dev-agent", "--config", str(tmp_path / "config.toml"),
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
                      "--config", str(tmp_path / "config.toml"),
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
    assert rc != 0 and "authorization context, not the vendor" in se

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


def test_allow_authenticator_widens_the_allowlist(sib_home):
    """1Password's AAGUID, the real case: off the list, then deliberately added."""
    from sib.keys_webauthn import aaguid_allowed
    one_password = "bada5566-a7aa-401f-bd96-45619a55120d"
    assert aaguid_allowed({"aaguid": one_password}, Registry().allowed_aaguids()) == (False, one_password)
    rc, so, se = run(["allow-authenticator", one_password, "1Password"])
    assert rc == 0 and "allowed" in so and "not bound to one device" in se
    assert aaguid_allowed({"aaguid": one_password}, Registry().allowed_aaguids()) == (True, "1Password")
    # a model already on the default list is a no-op, not a duplicate entry
    rc, so, se = run(["allow-authenticator", "ADCE0002-35BC-C60A-648B-0B25F1F05503", "mine"])
    assert rc == 0 and "already allowed" in so and "Chrome on Mac" in so
    assert "adce0002-35bc-c60a-648b-0b25f1f05503" not in Registry().extra_aaguids


def test_the_allowlist_matches_the_published_names(sib_home):
    """Guards the audit: these are the names the published lists give, not our glosses."""
    from sib.keys_webauthn import DEFAULT_ALLOWED_AAGUIDS as A
    assert A["fbfc3007-154e-4ecc-8c0b-6e020557d7bd"] == "Apple Passwords"
    assert A["dd4ec289-e01d-41c9-bb89-70fa845d4bf2"] == "iCloud Keychain (Managed)"
    assert A["7409272d-1ff9-4e10-9fc9-ac0019c124fd"] == "YubiKey Bio Series - FIDO Edition"
    assert "bada5566-a7aa-401f-bd96-45619a55120d" not in A        # a software vault stays off


def test_a_keyless_aaguid_cannot_be_allowlisted(sib_home):
    """The hole this closes: `enroll --public-key` records no AAGUID, so allowing
    the empty or all-zero value would accept an agent's own software key."""
    from sib.keys_webauthn import aaguid_allowed, ZERO_AAGUID
    for bad in ("", "   ", "not-a-uuid", ZERO_AAGUID):
        rc, so, se = run(["allow-authenticator", bad, "mine"])
        assert rc != 0 and "not a model AAGUID" in se, bad
        assert Registry().extra_aaguids == {}
    # and the check refuses a keyless entry even if the file is edited by hand
    reg = Registry()
    reg.extra_aaguids[""] = "smuggled"
    reg.save()
    assert Registry().extra_aaguids == {}                     # dropped on load
    assert aaguid_allowed({}, {"": "smuggled"}) == (False, "(none recorded)")
    assert aaguid_allowed({"aaguid": ""}, {"": "smuggled"}) == (False, "(none recorded)")


def test_enroll_with_a_raw_public_key_says_it_cannot_verify(sib_home):
    rc, so, se = run(["enroll", "--signer", "evil@agent", "--kid", "evil@agent#k1",
                      "--public-key", "AAAA", "--alg", "ES256-webauthn"])
    assert rc == 0 and "records no AAGUID" in se and "authenticator_not_allowed" in se


class _Tty(io.StringIO):
    """Stands in for a terminal, so the setup questions are asked at all."""
    def isatty(self):
        return True


def test_install_codex_offers_a_deployment_name(sib_home, tmp_path, monkeypatch):
    """The audience is the one thing an install cannot derive. It is a question
    with a suggestion, not a prerequisite found out by being refused."""
    from sib.first_run import suggest_audience
    monkeypatch.delenv("SIB_AUDIENCE", raising=False)
    cfg = tmp_path / "config.toml"
    rc, so, se = run(["install", "codex", "--config", str(cfg), "--sib-path", "/usr/bin/true", "--yes"])
    assert rc == 0
    assert Registry().default_audience == suggest_audience()        # recorded, not just used
    assert f"--audience {suggest_audience()}" in cfg.read_text()    # and baked into the command
    assert "No signing key enrolled" in se                          # the other half of the setup


def test_install_codex_refuses_to_invent_a_name_unasked(sib_home, tmp_path, monkeypatch):
    """Without a terminal and without --yes, nobody would see the name chosen,
    and a wrong audience fails silently: it verifies nothing."""
    monkeypatch.delenv("SIB_AUDIENCE", raising=False)
    cfg = tmp_path / "config.toml"
    rc, so, se = run(["install", "codex", "--config", str(cfg), "--sib-path", "/usr/bin/true"])
    assert rc != 0 and "nobody to ask" in se
    assert not cfg.exists() and Registry().default_audience is None


def test_the_suggested_audience_names_the_machine_not_the_vendor(monkeypatch):
    import socket
    from sib.first_run import suggest_audience
    monkeypatch.setattr(socket, "gethostname", lambda: "M4-Watchtower.local")
    name = suggest_audience()
    assert name.startswith("m4-watchtower/")
    # a vendor name would be byte-identical in everyone's install, so one laptop's
    # signature would verify in CI and in anyone else's copy of the same tool
    for vendor in ("openai", "codex", "anthropic", "claude"):
        assert vendor not in name


def test_install_offers_a_key_and_prefers_a_passkey(sib_home, monkeypatch):
    """A config with no key verifies every block as unknown_signer: correct, and
    inert. The install offers the key too, so one command is enough."""
    from sib import first_run
    from sib.cli import default_kid
    monkeypatch.setattr(sys, "stdin", _Tty())
    asked = []

    def yes_no(question, default):
        asked.append(question)
        return default if "Enroll" in question else False   # yes to enrolling, no to the passkey
    monkeypatch.setattr(first_run, "ask_yes_no", yes_no)
    monkeypatch.setattr(first_run, "ask_text", lambda question, default=None: "carol@example.com")
    first_run.ensure_key(Registry(), sib_home)
    assert "Enroll a signing key now?" in asked[0]
    assert "passkey" in asked[1] and "fingerprint" in asked[1]      # asked first, and by name
    fresh = Registry()
    assert fresh.has_signer("carol@example.com")
    assert fresh.lookup(default_kid("carol@example.com"))[1]["mode"] == "dev"


def test_install_takes_no_for_an_answer_on_the_key(sib_home, monkeypatch, capsys):
    from sib import first_run
    monkeypatch.setattr(sys, "stdin", _Tty())
    monkeypatch.setattr(first_run, "ask_yes_no", lambda question, default: False)
    first_run.ensure_key(Registry(), sib_home)
    assert Registry().signers == {}
    assert "sib enroll --signer" in capsys.readouterr().err         # and says how, later


def test_install_offers_a_passkey_when_only_dev_keys_exist(sib_home, monkeypatch, registry):
    """A software key is not a reason to stop asking: it leaves the install in dev
    mode, where a block confers nothing once any passkey exists."""
    from sib import first_run
    monkeypatch.setattr(sys, "stdin", _Tty())
    asked, enrolled = [], {}
    monkeypatch.setattr(first_run, "ask_yes_no", lambda question, default: asked.append(question) or True)
    monkeypatch.setattr(first_run, "ask_text",
                        lambda question, default=None: asked.append(f"{question} [{default}]") or default)
    monkeypatch.setattr(first_run, "_enroll",
                        lambda signer, passkey, home: enrolled.update(signer=signer, passkey=passkey))
    first_run.ensure_key(Registry(), sib_home)
    assert asked[0] == "Enroll a passkey now?"                  # a passkey by name, not "a key"
    assert "[alice@example.com]" in asked[1]                    # the signer already in the registry
    assert enrolled == {"signer": "alice@example.com", "passkey": True}
    assert len(asked) == 2                                      # and no dev-key fallback offered


def test_install_says_nothing_when_a_passkey_is_enrolled(sib_home, monkeypatch, capsys):
    from sib import first_run
    from tests.fake_authenticator import FakeAuthenticator, enroll_fake
    monkeypatch.setattr(sys, "stdin", _Tty())
    monkeypatch.setattr(first_run, "ask_yes_no", lambda question, default: pytest.fail("asked anyway"))
    reg = Registry()
    enroll_fake(reg, FakeAuthenticator(), "alice@example.com", "alice@example.com#passkey-1")
    first_run.ensure_key(reg, sib_home)
    assert capsys.readouterr().err == ""


def test_sign_falls_back_to_the_git_identity(sib_home, registry, monkeypatch):
    """With neither --signer nor --kid, sign as whoever this machine commits as —
    but only when a key is enrolled for them."""
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "alice@example.com")
    rc, so, se = run(["sign", "--out", "-", "--text", "You may deploy to staging."])
    assert rc == 0 and "BEGIN SIB SIGNED INSTRUCTION" in so
    assert "signing as alice@example.com (git config user.email)" in se


def test_sign_says_when_the_git_identity_has_no_key(sib_home, registry, monkeypatch):
    """Guessing a signer with no key would surface as unknown_signer at verify
    time, a long way from the missing flag that caused it."""
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "nobody@example.com")
    rc, so, se = run(["sign", "--text", "x"])
    assert rc != 0 and "nothing is enrolled for 'nobody@example.com'" in se and "git identity" in se
    monkeypatch.setattr(cli, "git_signer", lambda: None)
    rc, so, se = run(["sign", "--text", "x"])
    assert rc != 0 and "give --kid or --signer" in se


def test_sign_has_no_expiry_by_default(sib_home, registry, monkeypatch):
    """A standing instruction should last until it is deleted from the file, so
    the absence of --expires means the absence of the claim."""
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "alice@example.com")
    rc, so, se = run(["sign", "--out", "-", "--text", "You may deploy to staging."])
    assert rc == 0 and "expires=never, valid until removed" in se
    assert "Expires:" not in so                       # no clear line either
    rc, so, se = run(["sign", "--out", "-", "--text", "x", "--expires", "2h"])
    assert rc == 0 and "Expires:" in so               # and one appears when asked for


# ---- where the instruction comes from, and where the block goes ----

def test_the_instruction_can_be_an_argument(sib_home, registry, monkeypatch):
    """`sib sign "..."` with nothing else is the whole command, so the text has
    to be sayable without a flag."""
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "alice@example.com")
    rc, so, se = run(["sign", "--out", "-", "You may deploy to staging."])
    assert rc == 0 and "\nYou may deploy to staging.\n-----BEGIN SIB SIGNATURE-----" in so


def test_the_instruction_can_come_from_stdin_with_no_flag(sib_home, registry, monkeypatch):
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "alice@example.com")
    rc, so, se = run(["sign", "--out", "-"], stdin="You may deploy to staging.\n")
    assert rc == 0 and "\nYou may deploy to staging.\n-----BEGIN SIB SIGNATURE-----" in so


def test_two_sources_for_one_instruction_is_refused(sib_home, registry):
    rc, so, se = run(["sign", "--signer", "alice@example.com", "--out", "-", "first", "--text", "second"])
    assert rc != 0 and "give the instruction once" in se


def test_sign_with_nothing_at_a_terminal_says_what_to_type(sib_home, registry, monkeypatch):
    """Reading a terminal would hang with no prompt, which looks like a wedged
    command rather than a missing argument."""
    from contextlib import redirect_stderr, redirect_stdout
    monkeypatch.setattr(sys, "stdin", _Tty())
    err = io.StringIO()
    with pytest.raises(SystemExit) as e, redirect_stderr(err), redirect_stdout(io.StringIO()):
        main(["sign", "--out", "-"])
    assert "nothing to sign" in str(e.value) and "sib sign" in str(e.value)


def test_the_block_lands_in_the_nearest_agents_file(sib_home, registry, monkeypatch, tmp_path):
    """With no --out the block goes where the harness will read it, which is the
    point of signing it: one command, and the instruction is in force."""
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "alice@example.com")
    (tmp_path / ".git").mkdir()
    agents = tmp_path / "AGENTS.md"
    agents.write_text("# Project\n\nBuild with make.\n")
    work = tmp_path / "src" / "deep"
    work.mkdir(parents=True)
    monkeypatch.chdir(work)
    rc, so, se = run(["sign", "You may deploy to staging."])
    assert rc == 0, se
    text = agents.read_text()
    assert text.startswith("# Project\n\nBuild with make.\n")       # nothing overwritten
    assert "\n\n-----BEGIN SIB SIGNED INSTRUCTION-----" in text      # one blank line before it
    assert "You may deploy to staging." in text
    assert f"appended to {agents}" in se and so == ""


def test_a_second_block_joins_the_first(sib_home, registry, monkeypatch, tmp_path):
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "alice@example.com")
    (tmp_path / ".git").mkdir()
    agents = tmp_path / "AGENTS.md"
    agents.write_text("# Project")                      # no trailing newline
    monkeypatch.chdir(tmp_path)
    assert run(["sign", "First."])[0] == 0
    assert run(["sign", "Second."])[0] == 0
    text = agents.read_text()
    assert text.startswith("# Project\n\n-----BEGIN")  # a newline of its own was added
    assert text.count("-----BEGIN SIB SIGNED INSTRUCTION-----") == 2


def test_agents_md_wins_over_claude_md_in_one_directory(sib_home, registry, monkeypatch, tmp_path):
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "alice@example.com")
    (tmp_path / ".git").mkdir()
    (tmp_path / "AGENTS.md").write_text("a\n")
    (tmp_path / "CLAUDE.md").write_text("c\n")
    monkeypatch.chdir(tmp_path)
    assert run(["sign", "x"])[0] == 0
    assert "BEGIN SIB" in (tmp_path / "AGENTS.md").read_text()
    assert "BEGIN SIB" not in (tmp_path / "CLAUDE.md").read_text()


def test_claude_md_is_used_when_there_is_no_agents_md(sib_home, registry, monkeypatch, tmp_path):
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "alice@example.com")
    (tmp_path / ".git").mkdir()
    (tmp_path / "CLAUDE.md").write_text("c\n")
    monkeypatch.chdir(tmp_path)
    assert run(["sign", "x"])[0] == 0
    assert "BEGIN SIB" in (tmp_path / "CLAUDE.md").read_text()


def test_the_search_stops_at_the_repository_root(sib_home, registry, monkeypatch, tmp_path):
    """A block signed in one checkout must not drift up into an instructions
    file that covers every checkout above it."""
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "alice@example.com")
    outer = tmp_path / "AGENTS.md"
    outer.write_text("everything, everywhere\n")
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    monkeypatch.chdir(repo)
    rc, so, se = run(["sign", "x"])
    assert rc == 0 and "BEGIN SIB SIGNED INSTRUCTION" in so    # printed, not appended
    assert "BEGIN SIB" not in outer.read_text()


def test_append_names_the_file_outright(sib_home, registry, monkeypatch, tmp_path):
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "alice@example.com")
    target = tmp_path / "notes.md"
    target.write_text("notes\n")
    rc, so, se = run(["sign", "--append", str(target), "x"])
    assert rc == 0 and target.read_text().startswith("notes\n\n-----BEGIN")
    rc, so, se = run(["sign", "--append", str(target), "--out", "x", "y"])
    assert rc != 0 and "not both" in se


def test_find_instructions_file_is_told_where_to_start(tmp_path):
    from sib.cli import find_instructions_file
    (tmp_path / ".git").mkdir()
    assert find_instructions_file(tmp_path) is None
    (tmp_path / "AGENTS.md").write_text("x\n")
    assert find_instructions_file(tmp_path) == tmp_path / "AGENTS.md"


# ---- what a signature is allowed to rest on ----

def test_a_software_key_is_refused_beside_a_passkey(sib_home, registry, monkeypatch):
    """Anything that can run `sib` can mint a software key for any signer id, so
    the only thing keeping one from reading as this person's signature is
    enforced mode. Not enrolling it is the cheaper half of that defence."""
    from tests.fake_authenticator import FakeAuthenticator, enroll_fake
    reg = Registry()
    enroll_fake(reg, FakeAuthenticator(), "alice@example.com", "alice@example.com#passkey-1")
    reg.save()
    before = len(Registry().signers["alice@example.com"])
    rc, so, se = run(["keygen", "--signer", "alice@example.com", "--enroll"])
    assert rc != 0 and "refusing to enroll a software key" in se
    assert "alice@example.com#passkey-1" in se                  # names what they already hold
    assert len(Registry().signers["alice@example.com"]) == before   # and nothing was added

    # the same refusal on the raw-public-key path, which is the same act
    rc, so, se = run(["enroll", "--signer", "alice@example.com", "--kid", "alice@example.com#x",
                      "--public-key", "AAAA", "--dev"])
    assert rc != 0 and "refusing to enroll a software key" in se

    # a signer with no passkey is unaffected
    rc, so, se = run(["keygen", "--signer", "bob@example.com", "--enroll"])
    assert rc == 0 and Registry().signers["bob@example.com"]


def test_keygen_without_enroll_still_writes_the_key(sib_home, registry):
    """The refusal is about the registry entry, not the file: a key nobody is
    enrolled for confers nothing, so there is no reason to withhold it."""
    from tests.fake_authenticator import FakeAuthenticator, enroll_fake
    reg = Registry()
    enroll_fake(reg, FakeAuthenticator(), "alice@example.com", "alice@example.com#passkey-1")
    reg.save()
    rc, so, se = run(["keygen", "--signer", "alice@example.com"])
    assert rc == 0 and "dev key created" in so


def test_the_terms_are_printed_before_the_ceremony(sib_home, registry, monkeypatch):
    """Everything that carries authority reaches the terminal before anything is
    signed. The terminal does not ask -- approval happens on the sign page, the
    one surface a signer is certain to be looking at -- but a signer who has a
    terminal should be able to read the terms there too."""
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "alice@example.com")
    rc, so, se = run(["sign", "--out", "-", "--audience", "acme/dev-agent", "--expires", "2h",
                      "You may deploy to staging."])
    assert rc == 0, se
    assert "You may deploy to staging." in se
    assert "signer=alice@example.com" in se and "kid=alice@example.com#dev-" in se
    assert "audience=acme/dev-agent" in se and "expires=" in se
    assert "printing the block to stdout" in se


def test_signing_needs_no_terminal(sib_home, registry, monkeypatch, tmp_path):
    """There is nothing left to ask at a terminal, so not having one is not a
    refusal. A signer whose command is run by something that owns the keyboard
    -- an agent harness's shell escape -- has no controlling terminal, and that
    is the ordinary case rather than an unattended one."""
    from sib import cli
    monkeypatch.setattr(cli, "git_signer", lambda: "alice@example.com")
    agents = tmp_path / "AGENTS.md"
    agents.write_text("# Project\n")
    monkeypatch.chdir(tmp_path)
    rc, so, se = run(["sign", "You may deploy to staging."])
    assert rc == 0, se
    assert "BEGIN SIB SIGNED INSTRUCTION" in agents.read_text()
    assert "no terminal" not in se


def test_there_is_no_way_to_skip_a_confirmation_that_no_longer_exists(sib_home, registry):
    """-y is gone. It only ever skipped the terminal question, and the page the
    signer approves on now shows every term that question covered, including
    where the block is going, so there was nothing left for it to skip."""
    rc, so, se = run(["sign", "--out", "-", "-y", "x"])
    assert rc != 0 and "unrecognized arguments: -y" in se


def test_the_confirmation_code_is_printed_for_a_passkey(sib_home, monkeypatch):
    """Dev-mode signing opens no page, so there is nothing to compare a code
    against; a passkey ceremony is where it matters."""
    from tests.fake_authenticator import FakeAuthenticator, enroll_fake
    from sib import cli
    import sib.webauthn_app
    auth = FakeAuthenticator()
    reg = Registry()
    enroll_fake(reg, auth, "alice@example.com", "alice@example.com#passkey-1")
    reg.save()
    monkeypatch.setattr(sib.webauthn_app, "sign_in_browser", _fake_sign_in_browser(auth))
    rc, so, se = run(["sign", "--out", "-", "--signer", "alice@example.com",
                      "--audience", "acme/dev-agent", "You may deploy to staging."])
    assert rc == 0, se
    line = next(l for l in se.splitlines() if "confirmation code" in l)
    code = line.split("confirmation code ")[1].split(",")[0]
    assert len(code) == 6 and code.isdigit() and "the sign page must show" in line


def test_the_page_is_told_where_the_block_will_go(sib_home, monkeypatch):
    """The destination is a term the signer approves, so it has to reach the page
    they approve on. Declining is theirs to do there: close the page, or dismiss
    the authenticator."""
    from tests.fake_authenticator import FakeAuthenticator, enroll_fake
    import sib.webauthn_app
    auth = FakeAuthenticator()
    reg = Registry()
    enroll_fake(reg, auth, "alice@example.com", "alice@example.com#passkey-1")
    reg.save()
    seen = {}
    monkeypatch.setattr(sib.webauthn_app, "sign_in_browser", _fake_sign_in_browser(auth, seen))
    agents = sib_home / "AGENTS.md"
    agents.write_text("# Project\n")
    rc, so, se = run(["sign", "--append", str(agents), "--signer", "alice@example.com",
                      "--audience", "acme/dev-agent", "You may deploy to staging."])
    assert rc == 0, se
    assert seen["action"] == f"appending to {agents}"
    assert "You may deploy to staging." in agents.read_text()


def test_the_destination_shown_to_the_signer_is_the_one_used(sib_home, monkeypatch):
    """One function answers both, so the page cannot promise one file while the
    CLI appends to another."""
    from tests.fake_authenticator import FakeAuthenticator, enroll_fake
    import sib.webauthn_app
    auth = FakeAuthenticator()
    reg = Registry()
    enroll_fake(reg, auth, "alice@example.com", "alice@example.com#passkey-1")
    reg.save()
    seen = {}
    monkeypatch.setattr(sib.webauthn_app, "sign_in_browser", _fake_sign_in_browser(auth, seen))
    rc, so, se = run(["sign", "--out", "-", "--signer", "alice@example.com",
                      "--audience", "acme/dev-agent", "x"])
    assert rc == 0 and seen["action"] == "printing the block to stdout"
    assert "  printing the block to stdout" in se       # and the terminal says the same
    out = sib_home / "block.txt"
    rc, so, se = run(["sign", "--out", str(out), "--signer", "alice@example.com",
                      "--audience", "acme/dev-agent", "x"])
    assert rc == 0 and seen["action"] == f"writing {out}" and f"  writing {out}" in se


def test_a_decline_in_the_browser_leaves_the_destination_alone(sib_home, monkeypatch, tmp_path):
    """Cancelling on the sign page, or closing it, is the signer saying no -- and
    saying no has to leave the file exactly as it was. The destination is
    resolved before the ceremony, so this is the one place a resolved path could
    still be written to after the signer declined."""
    from tests.fake_authenticator import FakeAuthenticator, enroll_fake
    import sib.webauthn_app
    from sib.webauthn_app import BrowserFlowError
    auth = FakeAuthenticator()
    reg = Registry()
    enroll_fake(reg, auth, "alice@example.com", "alice@example.com#passkey-1")
    reg.save()

    def declined(*a, **k):
        raise BrowserFlowError("the browser reported: cancelled on the sign page")
    monkeypatch.setattr(sib.webauthn_app, "sign_in_browser", declined)
    agents = tmp_path / "AGENTS.md"
    agents.write_text("# Project\n")
    monkeypatch.chdir(tmp_path)
    rc, so, se = run(["sign", "--signer", "alice@example.com", "--audience", "acme/dev-agent",
                      "You may deploy to staging."])
    assert rc != 0 and "cancelled on the sign page" in se
    assert agents.read_text() == "# Project\n" and so == ""


def test_the_code_the_terminal_prints_is_the_code_the_page_shows(sib_home, monkeypatch):
    """The whole value of the code is that the two sides agree, so this
    recomputes the page's side from the block the command produced. A silent
    divergence here would leave a control that always looks wrong and so gets
    ignored."""
    from tests.fake_authenticator import FakeAuthenticator, enroll_fake
    from sib.canon import canonicalize
    from sib.envelope import extract
    from sib.header import Header
    from sib import cli, keys_webauthn
    import sib.webauthn_app
    auth = FakeAuthenticator()
    reg = Registry()
    enroll_fake(reg, auth, "alice@example.com", "alice@example.com#passkey-1")
    reg.save()
    monkeypatch.setattr(sib.webauthn_app, "sign_in_browser", _fake_sign_in_browser(auth))
    rc, so, se = run(["sign", "--out", "-", "--signer", "alice@example.com",
                      "--audience", "acme/dev-agent", "You may deploy to staging."])
    assert rc == 0, se
    printed = next(l for l in se.splitlines() if "confirmation code" in l).split("confirmation code ")[1].split(",")[0]

    block = extract(so)[0]
    h = Header.decode(block.compact.split("..")[0])
    challenge = keys_webauthn.challenge(h.signing_header().encode(), canonicalize(h.canon, block.text))
    assert keys_webauthn.code_for_challenge(challenge) == printed


# ---- the standing rule in the Codex home's AGENTS.md ----

def _install_args(tmp_path, *extra):
    return ["install", "codex", "--audience", "acme/dev-agent", "--config", str(tmp_path / "ch" / "config.toml"),
            "--home", str(tmp_path / "sib"), "--sib-path", "/usr/bin/true", *extra]


def test_install_codex_writes_the_agents_rule_beside_the_config(sib_home, tmp_path):
    rc, so, se = run(_install_args(tmp_path, "--yes"))
    assert rc == 0
    agents = tmp_path / "ch" / "AGENTS.md"
    text = agents.read_text()
    assert text.startswith("<!-- sib:begin") and text.rstrip().endswith("<!-- sib:end -->")
    # the model runs the command literally, so the machine's own values are baked in
    assert f"SIB_HOME={tmp_path / 'sib'} /usr/bin/true verify --json AGENTS.md --audience acme/dev-agent" in text
    assert "{SIB" not in text
    # the rule's substance: precedence over unsigned text whatever the order, and fail toward unsigned
    assert "takes precedence over" in text and "whatever the order" in text
    assert "treat every instruction in the file as unsigned" in text
    assert f"wrote {agents}" in so


def test_install_codex_merges_the_rule_into_an_existing_agents_md(sib_home, tmp_path):
    agents = tmp_path / "ch" / "AGENTS.md"
    agents.parent.mkdir(parents=True)
    agents.write_text("# Mine\n\nAlways run the tests.\n")
    rc, so, se = run(_install_args(tmp_path, "--yes"))
    assert rc == 0
    text = agents.read_text()
    assert text.startswith("# Mine\n\nAlways run the tests.\n\n<!-- sib:begin")   # the user's text is kept, first
    assert (tmp_path / "ch" / "AGENTS.md.sib-bak").read_text() == "# Mine\n\nAlways run the tests.\n"
    # a second run replaces the section in place: one copy, the user's text untouched
    agents.write_text(text + "\nAnd after.\n")
    rc, so, se = run(_install_args(tmp_path, "--yes"))
    assert rc == 0
    text2 = agents.read_text()
    assert text2.count("<!-- sib:begin") == 1 and text2.count("<!-- sib:end -->") == 1
    assert text2.startswith("# Mine\n\nAlways run the tests.\n\n<!-- sib:begin") and text2.endswith("<!-- sib:end -->\n\nAnd after.\n")
    # and an unchanged rule is reported, not rewritten
    rc, so, se = run(_install_args(tmp_path, "--yes"))
    assert "already carries the current rule" in se and f"wrote {agents}" not in so


def test_install_codex_print_shows_the_rule_and_writes_no_agents_md(sib_home, tmp_path):
    rc, so, se = run(_install_args(tmp_path, "--print"))
    assert rc == 0
    assert "<!-- sib:begin" in so and "takes precedence over" in so
    assert not (tmp_path / "ch" / "AGENTS.md").exists() and not (tmp_path / "ch" / "config.toml").exists()


def test_install_codex_declining_the_rule_leaves_agents_md_alone(sib_home, tmp_path, monkeypatch):
    import sib.codex.install as inst
    answers = {"auto_review": True, "standing rule": False}
    monkeypatch.setattr(inst, "_ask", lambda q, default: next((v for k, v in answers.items() if k in q), default))
    rc, so, se = run(_install_args(tmp_path))
    assert rc == 0 and (tmp_path / "ch" / "config.toml").exists()
    assert not (tmp_path / "ch" / "AGENTS.md").exists() and "Skipped the rule" in se
