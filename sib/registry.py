"""Flat-file signer registry: signer id -> enrolled keys, plus the allowlist of
biometric-capable authenticators. An external directory maps signers to
people (PDF, out of scope); this file is v1's stand-in."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path

from .keys_dev import sib_home
from .keys_webauthn import ALG as WEBAUTHN_ALG, DEFAULT_ALLOWED_AAGUIDS


class Registry:
    def __init__(self, path: Path | None = None):
        self.path = path or (sib_home() / "registry.json")
        self.signers: dict[str, list[dict]] = {}
        self.extra_aaguids: dict[str, str] = {}
        if self.path.exists():
            data = json.loads(self.path.read_text())
            self.signers = {s["signer"]: s["keys"] for s in data.get("signers", [])}
            self.extra_aaguids = {k.lower(): v for k, v in (data.get("allowed_aaguids") or {}).items()}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"signers": [{"signer": s, "keys": ks} for s, ks in self.signers.items()]}
        if self.extra_aaguids:
            data["allowed_aaguids"] = self.extra_aaguids
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
