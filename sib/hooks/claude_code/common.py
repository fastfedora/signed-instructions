"""Shared machinery for the Claude Code hooks: event I/O, the per-session SIB
store, transcript scanning, manifest assembly, the gate policy, audit logging,
and the fail-closed wrapper."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import time
import traceback
from pathlib import Path

from ...envelope import extract, Block
from ...keys_dev import sib_home
from ...manifest import build_manifest
from ...nonce_store import NoopNonceStore
from ...registry import Registry
from ...verify import verify_block

POLICY_FILENAME = ".sib-policy.json"
DEFAULT_POLICY = {"audience": None, "gated": [], "description": "no gated actions configured"}
SEGMENT_SPLIT = re.compile(r"\s*(?:;|&&|\|\||\||\n)\s*")


# ---------- event I/O ----------

def read_event() -> dict:
    raw = sys.stdin.read()
    try:
        return json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        return {"hook_event_name": "unparseable", "_raw": raw[:500]}


def emit(obj: dict | None) -> None:
    if obj is not None:
        sys.stdout.write(json.dumps(obj))
        sys.stdout.flush()


def log(msg: str) -> None:
    print(f"sib-hook: {msg}", file=sys.stderr, flush=True)


# ---------- policy ----------

def load_policy(cwd: str | None) -> dict:
    """`.sib-policy.json` from SIB_POLICY, else the project directory. In v1
    the file may live in the repo, which an attacker can edit; Phase 3 moves
    the gated class to user scope. Missing or unreadable → no gated actions,
    which is fail-open for the gate but the classifier note still flows."""
    p = os.environ.get("SIB_POLICY")
    path = Path(p) if p else (Path(cwd or os.getcwd()) / POLICY_FILENAME)
    try:
        d = json.loads(path.read_text())
        d.setdefault("gated", [])
        d.setdefault("audience", None)
        return d
    except (OSError, json.JSONDecodeError):
        return dict(DEFAULT_POLICY)


def command_segments(cmd: str) -> list[str]:
    out = []
    for seg in SEGMENT_SPLIT.split(cmd or ""):
        seg = seg.strip()
        seg = re.sub(r"^(?:cd\s+\S+\s+&&\s*)", "", seg)
        seg = re.sub(r"^(?:[A-Z_]+=\S+\s+)+", "", seg)
        if seg:
            out.append(seg)
    return out


def is_gated(policy: dict, tool_name: str | None, tool_input: dict | None) -> tuple[bool, str | None]:
    """Deterministic pre-filter. A cost control, not a security boundary."""
    for rule in policy.get("gated", []):
        if rule.get("tool") and rule["tool"] != tool_name:
            continue
        rx = rule.get("segment_regex")
        if tool_name == "Bash" and rx:
            for seg in command_segments((tool_input or {}).get("command", "")):
                if re.search(rx, seg):
                    return True, rule.get("label") or rx
        elif rule.get("input_regex"):
            if re.search(rule["input_regex"], json.dumps(tool_input or {})):
                return True, rule.get("label") or rule["input_regex"]
        elif not rx and not rule.get("input_regex") and rule.get("tool") == tool_name:
            return True, rule.get("label") or tool_name
    return False, None


# ---------- session store ----------

def session_dir(session_id: str | None) -> Path:
    d = sib_home() / "sessions" / (session_id or "no-session")
    d.mkdir(parents=True, exist_ok=True)
    return d


def store_prompt_blocks(session_id: str | None, prompt: str, message_index: int | None = None) -> int:
    blocks = extract(prompt or "")
    if not blocks:
        return 0
    path = session_dir(session_id) / "sibs.jsonl"
    with open(path, "a") as f:
        for b in blocks:
            f.write(json.dumps({"text": b.text, "compact": b.compact, "clear": b.clear,
                                "origin": {"role": "user", "source": "prompt", "message_index": message_index}}) + "\n")
    return len(blocks)


def load_session_blocks(session_id: str | None) -> list[tuple[Block, dict]]:
    path = session_dir(session_id) / "sibs.jsonl"
    out = []
    if not path.exists():
        return out
    for line in path.read_text().splitlines():
        try:
            d = json.loads(line)
            out.append((Block(text=d["text"], compact=d["compact"], clear=d.get("clear") or {}), d["origin"]))
        except (json.JSONDecodeError, KeyError):
            continue  # a corrupt line is skipped; it can only lose a block, never add authority
    return out


# ---------- candidates from the project and the transcript ----------

def project_instruction_blocks(cwd: str | None) -> list[tuple[Block, dict]]:
    out = []
    for name in ("CLAUDE.md", "CLAUDE.local.md"):
        p = Path(cwd or os.getcwd()) / name
        try:
            text = p.read_text()
        except OSError:
            continue
        for b in extract(text):
            out.append((b, {"role": "project_instructions", "source": name}))
    return out


def transcript_blocks(transcript_path: str | None, limit_bytes: int = 20_000_000) -> list[tuple[Block, dict]]:
    """Best-effort scan of Claude Code's session JSONL. The format is
    undocumented; anything unreadable is skipped. Only adds candidates."""
    out = []
    if not transcript_path:
        return out
    try:
        p = Path(transcript_path)
        if not p.exists() or p.stat().st_size > limit_bytes:
            return out
        lines = p.read_text().splitlines()
    except OSError:
        return out
    tool_names = {}
    for idx, line in enumerate(lines):
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        typ = d.get("type")
        msg = d.get("message") or {}
        content = msg.get("content")
        if typ not in ("user", "assistant") or not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            bt = block.get("type")
            if bt == "tool_use":
                tool_names[block.get("id")] = (block.get("name"), block.get("input") or {})
            texts = []
            if bt == "text":
                texts.append((block.get("text") or "", {"role": typ, "source": "message", "message_index": idx}))
            elif bt == "tool_result":
                tu = tool_names.get(block.get("tool_use_id"), (None, {}))
                src = tu[1].get("file_path") or tu[1].get("command") or tu[0] or "tool_result"
                c = block.get("content")
                if isinstance(c, str):
                    texts.append((c, {"role": "tool_result", "source": str(src)[:200], "message_index": idx,
                                      "tool": tu[0]}))
                elif isinstance(c, list):
                    for cc in c:
                        if isinstance(cc, dict) and cc.get("type") == "text":
                            texts.append((cc.get("text") or "", {"role": "tool_result", "source": str(src)[:200],
                                                                 "message_index": idx, "tool": tu[0]}))
            for t, origin in texts:
                if "SIB SIGNED INSTRUCTION" in t:
                    for b in extract(t):
                        out.append((b, origin))
    return out


def gather_candidates(event: dict) -> list[tuple[Block, dict]]:
    cwd = event.get("cwd")
    cands = load_session_blocks(event.get("session_id"))
    cands += project_instruction_blocks(cwd)
    cands += transcript_blocks(event.get("transcript_path"))
    # De-duplicate identical blocks (same compact signature), keep first origin.
    seen, out = set(), []
    for b, o in cands:
        if b.compact in seen:
            continue
        seen.add(b.compact)
        out.append((b, o))
    return out


# ---------- manifest ----------

def assemble_manifest(event: dict, policy: dict) -> dict:
    """Verifier error → manifest with zero verified spans and an error field (fail closed on authority)."""
    mode = os.environ.get("SIB_MODE", "dev")
    audience = policy.get("audience")
    session_id, tool_use_id = event.get("session_id"), event.get("tool_use_id")
    try:
        registry = Registry()
        cands = gather_candidates(event)
        now = dt.datetime.now(dt.timezone.utc)
        spans = [(verify_block(b, now, audience, registry, NoopNonceStore(), session_id, mode), o) for b, o in cands]
        return build_manifest(spans, session_id, tool_use_id, audience, mode)
    except Exception as e:  # noqa: BLE001
        log(f"verifier error: {type(e).__name__}: {e}")
        return build_manifest([], session_id, tool_use_id, audience, mode, error=f"{type(e).__name__}: {e}")


def write_manifest(event: dict, manifest: dict) -> None:
    try:
        d = session_dir(event.get("session_id"))
        (d / "manifest.json").write_text(json.dumps(manifest, indent=2))
    except OSError as e:
        log(f"could not write manifest: {e}")


def audit(event: dict, record: dict) -> None:
    try:
        d = session_dir(event.get("session_id"))
        rec = {"ts": time.time(), "hook_event_name": event.get("hook_event_name"), "tool_name": event.get("tool_name"),
               "tool_use_id": event.get("tool_use_id"), **record}
        with open(d / "audit.jsonl", "a") as f:
            f.write(json.dumps(rec) + "\n")
        extra = os.environ.get("SIB_AUDIT_FILE")
        if extra:
            with open(extra, "a") as f:
                f.write(json.dumps(rec) + "\n")
    except OSError as e:
        log(f"could not write audit: {e}")


# ---------- fail-closed wrapper ----------

def run_hook(handler, deny_reason: str = "SIB hook failed; gated actions are denied until it is fixed"):
    """Any uncaught exception denies a gated call and lets a non-gated call
    proceed with a logged warning. Claude Code's own default on hook error is
    to proceed, so the hook must never rely on it."""
    t0 = time.time()
    event = read_event()
    try:
        out = handler(event, t0)
        emit(out)
        sys.exit(0)
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        log("uncaught exception:\n" + traceback.format_exc())
        try:
            policy = load_policy(event.get("cwd"))
            gated, _ = is_gated(policy, event.get("tool_name"), event.get("tool_input"))
        except Exception:  # noqa: BLE001
            gated = True
        if gated and event.get("hook_event_name") == "PreToolUse":
            emit({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                         "permissionDecisionReason": deny_reason}})
        sys.exit(0)
