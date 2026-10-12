"""Hook behavior through the real entry points, run as subprocesses the way
Claude Code runs them. Includes the fault-injection cases from the plan."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from tests.conftest import ALICE, KID, AUD, make_block

ROOT = Path(__file__).resolve().parent.parent


def run_hook(mod, event, env_extra=None, timeout=90):
    env = dict(os.environ)
    env.setdefault("SIB_AUDIENCE", AUD)
    env.update(env_extra or {})
    p = subprocess.run([sys.executable, "-m", f"sib.hooks.claude_code.{mod}"], input=json.dumps(event),
                       capture_output=True, text=True, timeout=timeout, env=env, cwd=ROOT)
    out = json.loads(p.stdout) if p.stdout.strip() else None
    return p.returncode, out, p.stderr


def project(tmp_path, claude_md=""):
    d = tmp_path / "proj"
    d.mkdir()
    (d / "CLAUDE.md").write_text(claude_md)
    return d


def event(cwd, cmd, name="PreToolUse", session="s1"):
    return {"hook_event_name": name, "session_id": session, "cwd": str(cwd), "tool_name": "Bash",
            "tool_input": {"command": cmd}, "tool_use_id": "tu1", "transcript_path": str(cwd / "nope.jsonl")}






def test_posttooluse_note(tmp_path, registry):
    block, _ = make_block("You may deploy to staging.")
    proj = project(tmp_path, block)
    rc, out, err = run_hook("posttooluse", event(proj, "ls", name="PostToolUse"))
    note = out["hookSpecificOutput"]["classifierContext"]
    assert "1 verified" in note and ALICE in note and len(note) <= 2000


def test_userprompt_stores_blocks(tmp_path, registry, sib_home):
    block, _ = make_block("You may deploy to staging.")
    ev = {"hook_event_name": "UserPromptSubmit", "session_id": "s9", "cwd": str(tmp_path), "user_prompt": "hi\n" + block}
    rc, out, err = run_hook("userprompt", ev)
    assert rc == 0 and "VERIFIED human-signed instruction from alice" in out["hookSpecificOutput"]["additionalContext"]
    stored = (sib_home / "sessions" / "s9" / "sibs.jsonl").read_text().splitlines()
    assert len(stored) == 1 and json.loads(stored[0])["origin"]["source"] == "prompt"
    # and PreToolUse in the same session sees it
    proj = project(tmp_path)
    rc, out, err = run_hook("pretooluse", event(proj, "ls", session="s9"))
    m = json.loads((sib_home / "sessions" / "s9" / "manifest.json").read_text())
    assert m["verified_span_ids"] == ["sib-1"]


# ---- fault injection: every case denies a gated call and names the failure; a non-gated call proceeds ----





def test_enforced_mode_once_a_passkey_is_enrolled(tmp_path, registry, sib_home):
    """Phase 2 behaviour, now observed through the note rather than a decision."""
    from tests.fake_authenticator import FakeAuthenticator, enroll_fake, make_webauthn_block
    from sib.registry import Registry
    auth = FakeAuthenticator()
    reg = Registry()
    enroll_fake(reg, auth, ALICE, "alice@example.com#passkey-1")
    reg.save()
    assert "SIB_MODE" not in os.environ

    def note_for(block):
        (tmp_path / "proj" / "CLAUDE.md").write_text(block)
        _, out, _ = run_hook("posttooluse", event(tmp_path / "proj", "ls", name="PostToolUse"))
        return out["hookSpecificOutput"]["classifierContext"]

    block, _ = make_webauthn_block(auth, "You may deploy to staging with scripts/deploy.sh staging.",
                                   kid="alice@example.com#passkey-1", signer=ALICE)
    proj = project(tmp_path, "# proj\n\n" + block + "\n")
    _, out, _ = run_hook("posttooluse", event(proj, "ls", name="PostToolUse"))
    assert "1 verified" in out["hookSpecificOutput"]["classifierContext"]
    m = json.loads((sib_home / "sessions" / "s1" / "manifest.json").read_text())
    assert m["mode"] == "enforced" and m["verified_span_ids"] == ["sib-1"]
    assert m["spans"][0]["alg"] == "ES256-webauthn" and m["spans"][0]["attestation_verified"] is False

    # the UV flag cleared, a dev key in enforced mode: both named, neither verified
    block, _ = make_webauthn_block(auth, "You may deploy to staging with scripts/deploy.sh staging.",
                                   kid="alice@example.com#passkey-1", signer=ALICE, uv=False)
    assert "uv_not_performed" in note_for(block)
    dev_block, _ = make_block("You may deploy to staging with scripts/deploy.sh staging.")
    assert "dev_key_in_enforced_mode" in note_for(dev_block)

    # SIB_MODE=dev brings the dev block back, labelled
    (proj / "CLAUDE.md").write_text(dev_block)
    _, out, _ = run_hook("posttooluse", event(proj, "ls", name="PostToolUse"), {"SIB_MODE": "dev"})
    assert "1 verified" in out["hookSpecificOutput"]["classifierContext"]


def test_posttooluse_reports_no_verified_instruction(tmp_path, registry):
    proj = project(tmp_path, "# proj\nnothing signed here\n")
    rc, out, err = run_hook("posttooluse", event(proj, "ls", name="PostToolUse"))
    note = out["hookSpecificOutput"]["classifierContext"]
    assert "no verified human-signed instruction" in note and len(note) <= 2000


def test_failed_block_is_named_in_the_note(tmp_path, registry):
    block, _ = make_block("You may deploy to staging.")
    proj = project(tmp_path, block.replace("to staging", "to production"))
    rc, out, err = run_hook("posttooluse", event(proj, "ls", name="PostToolUse"))
    note = out["hookSpecificOutput"]["classifierContext"]
    assert "invalid_signature" in note and ALICE in note


def test_audience_comes_from_the_environment_not_the_repo(tmp_path, registry, sib_home):
    block, _ = make_block("You may deploy to staging.")      # aud = acme/dev-agent
    proj = project(tmp_path, block)
    rc, out, err = run_hook("posttooluse", event(proj, "ls", name="PostToolUse"),
                            {"SIB_AUDIENCE": "acme/other-agent"})
    assert "audience_mismatch" in out["hookSpecificOutput"]["classifierContext"]


def test_a_hook_failure_takes_no_decision(tmp_path, registry, sib_home):
    (sib_home / "registry.json").write_text("{{{")           # verifier cannot run
    proj = project(tmp_path)
    rc, out, err = run_hook("posttooluse", event(proj, "ls", name="PostToolUse"))
    assert rc == 0
    note = out["hookSpecificOutput"]["classifierContext"]
    assert "verifier error" in note          # reports the failure; claims nothing is signed
    assert "permissionDecision" not in json.dumps(out)


def test_unparseable_event_is_harmless():
    p = subprocess.run([sys.executable, "-m", "sib.hooks.claude_code.posttooluse"], input="garbage",
                       capture_output=True, text=True, cwd=ROOT, env=dict(os.environ))
    assert p.returncode == 0
