"""The signed header: JOSE/JWT registered names where one exists, SIB names
(`canon`, `mode`) otherwise. Serialized with RFC 8785 rules (sorted keys, no
whitespace, UTF-8) and carried base64url as the first JWS segment."""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field, asdict

from .b64 import b64u_encode, b64u_decode

TYP = "SIB/1"
ALGS = ("EdDSA",)          # closed list; Phase 2 adds ES256-webauthn
MODES = ("dev", "enforced")


class MalformedHeader(ValueError):
    pass


@dataclass
class Header:
    alg: str
    kid: str
    canon: str
    iss: str
    iat: str
    exp: str
    jti: str
    mode: str
    aud: str | None = None
    typ: str = TYP
    b64: bool = False
    crit: list[str] = field(default_factory=lambda: ["b64"])

    def to_dict(self) -> dict:
        d = asdict(self)
        if d["aud"] is None:
            del d["aud"]
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def encode(self) -> str:
        return b64u_encode(self.to_json().encode("utf-8"))

    @classmethod
    def from_dict(cls, d: dict) -> "Header":
        if not isinstance(d, dict):
            raise MalformedHeader("header is not an object")
        required = ("alg", "kid", "canon", "iss", "iat", "exp", "jti", "mode")
        missing = [k for k in required if k not in d]
        if missing:
            raise MalformedHeader(f"missing header fields: {', '.join(missing)}")
        if d.get("typ") != TYP:
            raise MalformedHeader(f"unsupported typ {d.get('typ')!r}")
        if d.get("b64") is not False or "b64" not in (d.get("crit") or []):
            raise MalformedHeader("b64 must be false and listed in crit (RFC 7797)")
        if d["alg"] not in ALGS:
            raise MalformedHeader(f"unsupported alg {d['alg']!r}")
        if d["mode"] not in MODES:
            raise MalformedHeader(f"unsupported mode {d['mode']!r}")
        for k in ("iat", "exp"):
            parse_time(d[k])  # raises MalformedHeader
        known = {"alg", "kid", "canon", "iss", "iat", "exp", "jti", "mode", "aud", "typ", "b64", "crit"}
        extra = {k: v for k, v in d.items() if k not in known}
        h = cls(alg=d["alg"], kid=d["kid"], canon=d["canon"], iss=d["iss"], iat=d["iat"], exp=d["exp"],
                jti=d["jti"], mode=d["mode"], aud=d.get("aud"), typ=d["typ"], b64=False, crit=list(d["crit"]))
        h.extra = extra  # WebAuthn fields in Phase 2 live here
        return h

    @classmethod
    def decode(cls, b64: str) -> "Header":
        try:
            d = json.loads(b64u_decode(b64).decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            raise MalformedHeader(f"header segment is not base64url JSON: {e}") from None
        return cls.from_dict(d)


def parse_time(s: str) -> dt.datetime:
    """RFC 3339 UTC timestamps only ('...Z')."""
    if not isinstance(s, str) or not s.endswith("Z"):
        raise MalformedHeader(f"timestamp must be RFC 3339 UTC with Z: {s!r}")
    try:
        return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        raise MalformedHeader(f"bad timestamp {s!r}") from None


def format_time(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def signing_input(header_b64: str, canonical_text: str) -> bytes:
    """RFC 7797 unencoded detached payload: ASCII(BASE64URL(header)) || '.' || payload."""
    return header_b64.encode("ascii") + b"." + canonical_text.encode("utf-8")
