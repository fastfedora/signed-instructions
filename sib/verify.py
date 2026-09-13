"""Deterministic verifier. No LLM anywhere in this module (VE-5)."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, asdict

from . import keys_dev
from .canon import canonicalize, UnknownCanonicalization
from .envelope import Block
from .header import Header, MalformedHeader, parse_time, signing_input
from .registry import Registry

STATUSES = ("verified", "invalid_signature", "unknown_signer", "unknown_key", "expired", "not_yet_valid",
            "audience_mismatch", "metadata_mismatch", "malformed", "nonce_replayed", "revoked",
            "dev_key_in_enforced_mode")
CLOCK_SKEW = dt.timedelta(seconds=60)


@dataclass
class SpanResult:
    status: str
    text: str | None = None             # canonical text (what was signed)
    text_as_written: str | None = None
    signer: str | None = None
    kid: str | None = None
    mode: str | None = None
    canon: str | None = None
    issued_at: str | None = None
    expires_at: str | None = None
    audience: str | None = None
    jti: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _claims(h: Header) -> dict:
    return dict(signer=h.iss, kid=h.kid, mode=h.mode, canon=h.canon, issued_at=h.iat,
                expires_at=h.exp, audience=h.aud, jti=h.jti)


def verify_block(block: Block, now: dt.datetime, audience: str | None, registry: Registry,
                 nonce_store, session_id: str | None = None, mode: str = "dev") -> SpanResult:
    """Order matters: a tampered text reports invalid_signature before any
    time or audience problem, and every failing status still carries the
    claims the block makes, labelled by the status."""
    parts = block.compact.split(".")
    if len(parts) != 3 or parts[1] != "":
        return SpanResult("malformed", text_as_written=block.text,
                          error="signature is not a detached JWS (header..signature)")
    header_b64, _, sig_b64 = parts
    try:
        h = Header.decode(header_b64)
    except MalformedHeader as e:
        return SpanResult("malformed", text_as_written=block.text, error=str(e))
    try:
        ctext = canonicalize(h.canon, block.text)
    except UnknownCanonicalization:
        return SpanResult("malformed", text_as_written=block.text, error=f"unknown canonicalization {h.canon!r}",
                          **_claims(h))
    base = dict(text=ctext, text_as_written=block.text, **_claims(h))

    found = registry.lookup(h.kid)
    if found is None:
        if registry.has_signer(h.iss):
            return SpanResult("unknown_key", error=f"kid {h.kid!r} not enrolled for {h.iss}", **base)
        return SpanResult("unknown_signer", error=f"signer {h.iss!r} not in registry", **base)
    reg_signer, key = found
    if reg_signer != h.iss:
        return SpanResult("unknown_key", error=f"kid {h.kid!r} belongs to {reg_signer}, not {h.iss}", **base)
    if key.get("alg") != h.alg:
        return SpanResult("unknown_key", error=f"kid {h.kid!r} is a {key.get('alg')} key, header says {h.alg}", **base)
    if mode == "enforced" and (h.mode == "dev" or key.get("mode") == "dev"):
        return SpanResult("dev_key_in_enforced_mode", error="dev-mode block or key in enforced mode", **base)

    if h.alg == "EdDSA":
        ok = keys_dev.verify(key["public_key"], sig_b64, signing_input(header_b64, ctext))
    else:  # pragma: no cover - closed alg list
        ok = False
    if not ok:
        return SpanResult("invalid_signature", error="signature does not verify over the header and canonical text", **base)

    mismatches = _metadata_mismatches(block.clear, h)
    if mismatches:
        return SpanResult("metadata_mismatch", error="; ".join(mismatches), **base)

    iat, exp = parse_time(h.iat), parse_time(h.exp)
    if now + CLOCK_SKEW < iat:
        return SpanResult("not_yet_valid", error=f"issued at {h.iat}, now {h and now.strftime('%Y-%m-%dT%H:%M:%SZ')}", **base)
    if now >= exp:
        return SpanResult("expired", error=f"expired at {h.exp}", **base)
    if h.aud is None:
        if mode == "enforced":
            return SpanResult("audience_mismatch", error="block has no audience; required in enforced mode", **base)
    elif audience is not None and h.aud != audience:
        return SpanResult("audience_mismatch", error=f"block audience {h.aud!r}, this harness is {audience!r}", **base)
    if key.get("revoked"):
        return SpanResult("revoked", error=f"kid {h.kid!r} is revoked", **base)
    if not nonce_store.check(h.aud, h.jti, session_id):
        return SpanResult("nonce_replayed", error=f"jti {h.jti!r} already used by another session", **base)
    return SpanResult("verified", **base)


def _metadata_mismatches(clear: dict, h: Header) -> list[str]:
    expected = {"Signer": h.iss, "Expires": h.exp, "Audience": h.aud}
    out = []
    for k, v in clear.items():
        if k in expected and expected[k] is not None and v != expected[k]:
            out.append(f"clear line {k}: {v!r} does not match signed header {expected[k]!r}")
    return out


def clear_lines(h: Header) -> dict:
    d = {"Signer": h.iss, "Expires": h.exp}
    if h.aud:
        d["Audience"] = h.aud
    return d
