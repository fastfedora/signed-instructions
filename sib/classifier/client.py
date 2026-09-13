"""Reference permission classifier (CI-1). The manifest reaches it as
structured JSON, never as in-context text the agent could have written.

Backends:
  anthropic   Anthropic Python SDK against the Messages API (needs a key or
              `ant auth login`); structured output via output_config.format.
  claude-cli  `claude -p --json-schema` (subscription login); same schema.
SIB_CLASSIFIER_BACKEND selects one; `auto` picks anthropic when
ANTHROPIC_API_KEY is set, else claude-cli."""
from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

POLICY_PATH = Path(__file__).with_name("policy.md")
DEFAULT_MODEL = "claude-opus-5"

SCHEMA = {
    "type": "object",
    "properties": {
        "decision": {"type": "string", "enum": ["allow", "deny", "ask"]},
        "cited_span_ids": {"type": "array", "items": {"type": "string"}},
        "reason": {"type": "string"},
    },
    "required": ["decision", "cited_span_ids", "reason"],
    "additionalProperties": False,
}


class ClassifierError(RuntimeError):
    pass


@dataclass
class Decision:
    decision: str
    cited_span_ids: list[str]
    reason: str
    backend: str = ""
    model: str = ""
    latency_s: float = 0.0

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def load_policy_text() -> str:
    return POLICY_PATH.read_text()


def user_message(policy: dict, manifest: dict, tool_call: dict) -> str:
    return json.dumps({"policy": policy, "manifest": manifest, "tool_call": tool_call}, ensure_ascii=False, indent=1)


def _parse(obj) -> Decision:
    if not isinstance(obj, dict) or obj.get("decision") not in ("allow", "deny", "ask"):
        raise ClassifierError(f"classifier output is not a valid decision: {str(obj)[:200]}")
    return Decision(decision=obj["decision"], cited_span_ids=list(obj.get("cited_span_ids") or []),
                    reason=str(obj.get("reason") or ""))


class ClassifierBackend(Protocol):
    name: str

    def classify(self, system: str, user: str, timeout: float) -> Decision: ...


class AnthropicBackend:
    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL, base_url: str | None = None):
        self.model = model
        self.base_url = base_url

    def classify(self, system: str, user: str, timeout: float) -> Decision:
        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise ClassifierError(f"anthropic SDK not installed: {e}") from None
        kwargs = {"timeout": timeout, "max_retries": 0}
        if self.base_url:
            kwargs["base_url"] = self.base_url
        client = anthropic.Anthropic(**kwargs)
        try:
            resp = client.messages.create(
                model=self.model, max_tokens=1024, system=system,
                messages=[{"role": "user", "content": user}],
                output_config={"format": {"type": "json_schema", "schema": SCHEMA}},
            )
        except Exception as e:  # noqa: BLE001 - every failure is a classifier failure to the caller
            raise ClassifierError(f"{type(e).__name__}: {e}") from None
        if getattr(resp, "stop_reason", None) == "refusal":
            raise ClassifierError("classifier request refused")
        text = next((b.text for b in resp.content if getattr(b, "type", "") == "text"), "")
        try:
            return _parse(json.loads(text))
        except json.JSONDecodeError:
            raise ClassifierError(f"classifier returned non-JSON: {text[:200]}") from None


class ClaudeCliBackend:
    name = "claude-cli"

    def __init__(self, model: str = DEFAULT_MODEL):
        self.model = model

    def classify(self, system: str, user: str, timeout: float) -> Decision:
        env = dict(os.environ)
        env.pop("CLAUDECODE", None)  # we may be running inside a Claude Code hook
        cmd = ["claude", "-p", user, "--system-prompt", system, "--model", self.model,
               "--output-format", "json", "--json-schema", json.dumps(SCHEMA),
               "--tools", "", "--no-session-persistence", "--max-budget-usd", "0.50"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env,
                                  stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise ClassifierError(f"claude -p exceeded {timeout}s") from None
        except FileNotFoundError:
            raise ClassifierError("claude CLI not found") from None
        if proc.returncode != 0:
            raise ClassifierError(f"claude -p failed rc={proc.returncode}: {proc.stderr[-300:]}")
        try:
            res = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise ClassifierError(f"claude -p returned non-JSON: {proc.stdout[:200]}") from None
        if res.get("is_error"):
            raise ClassifierError(f"claude -p error: {str(res.get('result'))[:200]}")
        out = res.get("structured_output")
        if out is None:
            try:
                out = json.loads(res.get("result") or "")
            except json.JSONDecodeError:
                raise ClassifierError("claude -p returned no structured output") from None
        return _parse(out)


def choose_backend() -> ClassifierBackend:
    which = os.environ.get("SIB_CLASSIFIER_BACKEND", "auto")
    model = os.environ.get("SIB_CLASSIFIER_MODEL", DEFAULT_MODEL)
    if which == "auto":
        which = "anthropic" if os.environ.get("ANTHROPIC_API_KEY") else "claude-cli"
    if which == "anthropic":
        return AnthropicBackend(model, os.environ.get("SIB_CLASSIFIER_BASE_URL") or None)
    if which == "claude-cli":
        return ClaudeCliBackend(model)
    raise ClassifierError(f"unknown SIB_CLASSIFIER_BACKEND {which!r}")


def classify(policy: dict, manifest: dict, tool_call: dict, timeout: float = 45.0,
             backend: ClassifierBackend | None = None) -> Decision:
    """Never raises anything but ClassifierError. Callers fail closed on it."""
    backend = backend or choose_backend()
    t0 = time.time()
    d = backend.classify(load_policy_text(), user_message(policy, manifest, tool_call), timeout)
    d.backend, d.model, d.latency_s = backend.name, getattr(backend, "model", ""), round(time.time() - t0, 2)
    return d
