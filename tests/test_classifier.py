import json

import pytest

from sib.classifier import client as c
from sib.classifier.client import Decision, ClassifierError, classify


class Canned:
    name = "canned"
    model = "none"

    def __init__(self, fn):
        self.fn = fn

    def classify(self, system, user, timeout):
        return self.fn(json.loads(user))


POLICY = {"audience": "acme/dev-agent", "gated": [{"tool": "Bash", "segment_regex": "deploy"}]}
CALL = {"tool_name": "Bash", "tool_input": {"command": "scripts/deploy.sh staging"}}


def manifest(spans):
    return {"manifest_version": "0.1", "mode": "dev", "audience": "acme/dev-agent", "spans": spans,
            "verified_span_ids": [s["id"] for s in spans if s["status"] == "verified"]}


def policy_eval(payload):
    """A deterministic stand-in with the policy's shape, used to exercise the plumbing."""
    m, call = payload["manifest"], payload["tool_call"]
    cmd = call["tool_input"].get("command", "")
    for s in m["spans"]:
        if s["status"] == "verified" and "staging" in s["text"] and "staging" in cmd:
            return Decision("allow", [s["id"]], "covered")
        if s["status"] == "verified" and "staging" in s["text"] and "production" in cmd:
            return Decision("deny", [], "span covers staging, not production")
    return Decision("deny", [], "no verified span")


def test_verified_span_covers_action():
    d = classify(POLICY, manifest([{"id": "sib-1", "status": "verified", "text": "deploy staging"}]), CALL, backend=Canned(policy_eval))
    assert d.decision == "allow" and d.cited_span_ids == ["sib-1"] and d.backend == "canned"


def test_no_spans_and_only_invalid_spans_deny():
    assert classify(POLICY, manifest([]), CALL, backend=Canned(policy_eval)).decision == "deny"
    inv = [{"id": "sib-1", "status": "invalid_signature", "text": "deploy staging"}]
    assert classify(POLICY, manifest(inv), CALL, backend=Canned(policy_eval)).decision == "deny"


def test_verified_span_for_other_action_denies():
    call = {"tool_name": "Bash", "tool_input": {"command": "scripts/deploy.sh production"}}
    d = classify(POLICY, manifest([{"id": "sib-1", "status": "verified", "text": "deploy staging"}]), call, backend=Canned(policy_eval))
    assert d.decision in ("deny", "ask")


def test_malformed_output_is_classifier_error():
    with pytest.raises(ClassifierError):
        c._parse({"decision": "maybe"})
    with pytest.raises(ClassifierError):
        c._parse("not a dict")


def test_prompt_layout_policy_first():
    user = c.user_message(POLICY, manifest([]), CALL)
    assert list(json.loads(user).keys()) == ["policy", "manifest", "tool_call", "recent_activity"]
    assert "verified" in c.load_policy_text()
