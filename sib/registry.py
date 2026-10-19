"""Flat-file signer registry: signer id -> enrolled keys, plus the allowlist of
biometric-capable authenticators. An external directory maps signers to
people (PDF, out of scope); this file is v1's stand-in."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path

from .keys_dev import sib_home
from .keys_webauthn import ALG as WEBAUTHN_ALG, DEFAULT_ALLOWED_AAGUIDS, is_model_aaguid


class Registry:
    def __init__(self, path: Path | None = None):
        self.path = path or (sib_home() / "registry.json")
        self.signers: dict[str, list[dict]] = {}
        self.extra_aaguids: dict[str, str] = {}
        self.default_audience: str | None = None
        if self.path.exists():
            data = json.loads(self.path.read_text())
            self.signers = {s["signer"]: s["keys"] for s in data.get("signers", [])}
            # a hand-edited or agent-written entry that names no model is ignored: allowing
            # the empty or all-zero AAGUID would pass every key with the field missing
            self.extra_aaguids = {k.lower(): v for k, v in (data.get("allowed_aaguids") or {}).items()
                                  if is_model_aaguid(k)}
            self.default_audience = data.get("default_audience") or None

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"signers": [{"signer": s, "keys": ks} for s, ks in self.signers.items()]}
        if self.extra_aaguids:
            data["allowed_aaguids"] = self.extra_aaguids
        if self.default_audience:
            data["default_audience"] = self.default_audience
        self.path.write_text(json.dumps(data, indent=2) + "\n")

    def add_key(self, signer: str, kid: str, alg: str, public_key: str, mode: str,
                attestation_verified: bool = False, attestation: dict | None = None, **fields) -> None:
        """`fields` carries the WebAuthn enrollment record: `credential_id`,
        `aaguid`, `origins`, `rp_id`, `sign_count` and whatever else
        `keys_webauthn.verify_enrollment` returned."""
        if self.lookup(kid) is not None:
            raise ValueError(f"kid already enrolled: {kid}")
        self.signers.setdefault(signer, []).append({
            "kid": kid, "alg": alg, "public_key": public_key, "mode": mode,
            "enrolled_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "attestation_verified": attestation_verified, "attestation": attestation or {},
            "revoked": False, **fields,
        })

    def lookup(self, kid: str) -> tuple[str, dict] | None:
        for signer, keys in self.signers.items():
            for k in keys:
                if k["kid"] == kid:
                    return signer, k
        return None

    def has_signer(self, signer: str) -> bool:
        return signer in self.signers

    def has_webauthn_key(self) -> bool:
        return any(k.get("alg") == WEBAUTHN_ALG and not k.get("revoked") for ks in self.signers.values() for k in ks)

    def allowed_aaguids(self) -> dict[str, str]:
        """The built-in biometric-capable list plus the file's `allowed_aaguids`."""
        return {**DEFAULT_ALLOWED_AAGUIDS, **self.extra_aaguids}

    def allow_aaguid(self, aaguid: str, label: str) -> None:
        if not is_model_aaguid(aaguid):
            raise ValueError(f"{aaguid!r} is not a model AAGUID: give the UUID `sib enroll` "
                             f"reported. The empty and all-zero values name no model, and "
                             f"allowing them would accept every key with the field missing.")
        self.extra_aaguids[aaguid.lower()] = label


def default_mode(registry: Registry | None = None) -> str:
    """The verifier's mode when the harness does not set one (NF-4): `SIB_MODE`
    when set; otherwise `enforced` once any WebAuthn key is enrolled and
    `dev` before that."""
    env = os.environ.get("SIB_MODE")
    if env:
        return env
    try:
        reg = registry if registry is not None else Registry()
        return "enforced" if reg.has_webauthn_key() else "dev"
    except (OSError, ValueError, KeyError):
        return "dev"


def resolve_audience(explicit: str | None = None) -> tuple[str | None, str]:
    """The audience to use, and where it came from.

    A flag wins, then SIB_AUDIENCE, then the registry's `default_audience`.
    The name identifies one deployment, not a vendor or product: matching is
    exact, so a block signed for another agent must not verify here. Returning
    the source lets a command say which of the three it used.
    """
    if explicit:
        return explicit, "--audience"
    env = os.environ.get("SIB_AUDIENCE")
    if env:
        return env, "SIB_AUDIENCE"
    reg = Registry()
    if reg.default_audience:
        return reg.default_audience, f"default_audience in {reg.path}"
    return None, "unset"
