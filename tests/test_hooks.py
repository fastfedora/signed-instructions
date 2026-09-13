"""Hook behavior through the real entry points, run as subprocesses the way
Claude Code runs them. Includes the fault-injection cases from the plan."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.conftest import ALICE, KID, AUD, make_block

ROOT = Path(__file__).resolve().parent.parent
POLICY = {"audience": AUD, "gated": [
    {"tool": "Bash", "label": "deploy", "segment_regex": r"^(?:\S*/)?scripts/deploy\.sh(\s|$)"}]}


def run_hook(mod, event, env_extra=None, timeout=90):
    env = dict(os.environ)
    env.update(env_extra or {})
    p = subprocess.run([sys.executable, "-m", f"sib.hooks.claude_code.{mod}"], input=json.dumps(event),
                       capture_output=True, text=True, timeout=timeout, env=env, cwd=ROOT)
    out = json.loads(p.stdout) if p.stdout.strip() else None
    return p.returncode, out, p.stderr


def project(tmp_path, claude_md=""):
    d = tmp_path / "proj"
    d.mkdir()
    (d / ".sib-policy.json").write_text(json.dumps(POLICY))
    (d / "CLAUDE.md").write_text(claude_md)
    return d


def event(cwd, cmd, name="PreToolUse", session="s1"):
    return {"hook_event_name": name, "session_id": session, "cwd": str(cwd), "tool_name": "Bash",
            "tool_input": {"command": cmd}, "tool_use_id": "tu1", "transcript_path": str(cwd / "nope.jsonl")}


def test_non_gated_call_writes_manifest_and_is_fast(tmp_path, registry, sib_home):
    proj = project(tmp_path)
    t0 = time.time()
    rc, out, err = run_hook("pretooluse", event(proj, "python3 -m unittest"))
    wall = time.time() - t0
    assert rc == 0 and out is None
    m = json.loads((sib_home / "sessions" / "s1" / "manifest.json").read_text())
    assert m["spans"] == [] and m["verified_span_ids"] == []
    audit = [json.loads(l) for l in (sib_home / "sessions" / "s1" / "audit.jsonl").read_text().splitlines()]
    assert audit[-1]["gated"] is False and audit[-1]["verifier_ms"] < 200
    assert wall < 5  # interpreter start included; the in-hook verifier time is what VE-7 measures


def test_gated_call_without_spans_is_denied_without_llm(tmp_path, registry):
    proj = project(tmp_path)
    rc, out, err = run_hook("pretooluse", event(proj, "scripts/deploy.sh staging"),
                            {"SIB_CLASSIFIER_BACKEND": "bogus"})  # a classifier call would fail loudly
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "none exists" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_signed_block_in_claude_md_is_verified_and_reaches_classifier(tmp_path, registry, sib_home):
    block, _ = make_block("You may deploy to staging with scripts/deploy.sh staging.")
    proj = project(tmp_path, "# proj\n\n" + block + "\n")
    # classifier unreachable → deny naming the failure (fail closed), but the manifest shows the verified span
    rc, out, err = run_hook("pretooluse", event(proj, "scripts/deploy.sh staging"),
                            {"SIB_CLASSIFIER_BACKEND": "anthropic", "SIB_CLASSIFIER_BASE_URL": "http://127.0.0.1:9",
                             "ANTHROPIC_API_KEY": "sk-none", "SIB_CLASSIFIER_TIMEOUT": "5"})
    hso = out["hookSpecificOutput"]
    assert hso["permissionDecision"] == "deny" and "classifier unavailable" in hso["permissionDecisionReason"]
    m = json.loads((sib_home / "sessions" / "s1" / "manifest.json").read_text())
    assert m["verified_span_ids"] == ["sib-1"] and m["spans"][0]["origin"]["source"] == "CLAUDE.md"


def test_tampered_block_named_in_denial(tmp_path, registry):
    block, _ = make_block("You may deploy to staging.")
    proj = project(tmp_path, block.replace("to staging", "to production"))
    rc, out, err = run_hook("pretooluse", event(proj, "scripts/deploy.sh production"))
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert "invalid_signature" in reason and ALICE in reason


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

@pytest.mark.parametrize("env_extra, needle", [
    ({"SIB_CLASSIFIER_BACKEND": "anthropic", "SIB_CLASSIFIER_BASE_URL": "http://127.0.0.1:9", "ANTHROPIC_API_KEY": "sk-none", "SIB_CLASSIFIER_TIMEOUT": "5"}, "classifier unavailable"),
    ({"SIB_CLASSIFIER_BACKEND": "anthropic", "SIB_CLASSIFIER_BASE_URL": "http://127.0.0.1:9", "SIB_CLASSIFIER_TIMEOUT": "5"}, "classifier unavailable"),
    ({"SIB_CLASSIFIER_BACKEND": "nonsense"}, "classifier unavailable"),
])
def test_fault_injection_denies_gated(tmp_path, registry, env_extra, needle):
    block, _ = make_block("You may deploy to staging with scripts/deploy.sh staging.")
    proj = project(tmp_path, block)
    env_extra = dict(env_extra)
    env_extra.pop("ANTHROPIC_API_KEY", None) if "ANTHROPIC_API_KEY" not in env_extra else None
    rc, out, err = run_hook("pretooluse", event(proj, "scripts/deploy.sh staging"), env_extra)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert needle in out["hookSpecificOutput"]["permissionDecisionReason"]
    rc, out, err = run_hook("pretooluse", event(proj, "python3 -m unittest"), env_extra)
    assert out is None  # non-gated proceeds


def test_corrupt_session_store_and_registry(tmp_path, registry, sib_home):
    proj = project(tmp_path)
    (sib_home / "sessions" / "s1").mkdir(parents=True)
    (sib_home / "sessions" / "s1" / "sibs.jsonl").write_text("{not json\n")
    rc, out, err = run_hook("pretooluse", event(proj, "scripts/deploy.sh staging"))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    (sib_home / "registry.json").write_text("{{{")
    rc, out, err = run_hook("pretooluse", event(proj, "scripts/deploy.sh staging"))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "verifier failed" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_unparseable_event_is_harmless(tmp_path, registry):
    p = subprocess.run([sys.executable, "-m", "sib.hooks.claude_code.pretooluse"], input="garbage",
                       capture_output=True, text=True, cwd=ROOT, env=dict(os.environ))
    assert p.returncode == 0
