"""Flat-file signer registry: signer id -> enrolled keys. An external
directory maps signers to people (PDF, out of scope); this file is v1's stand-in."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

from .keys_dev import sib_home


class Registry:
    def __init__(self, path: Path | None = None):
        self.path = path or (sib_home() / "registry.json")
        self.signers: dict[str, list[dict]] = {}
        if self.path.exists():
            data = json.loads(self.path.read_text())
            self.signers = {s["signer"]: s["keys"] for s in data.get("signers", [])}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"signers": [{"signer": s, "keys": ks} for s, ks in self.signers.items()]}
        self.path.write_text(json.dumps(data, indent=2) + "\n")

    def add_key(self, signer: str, kid: str, alg: str, public_key: str, mode: str,
                attestation_verified: bool = False, attestation: dict | None = None) -> None:
        if self.lookup(kid) is not None:
            raise ValueError(f"kid already enrolled: {kid}")
        self.signers.setdefault(signer, []).append({
            "kid": kid, "alg": alg, "public_key": public_key, "mode": mode,
            "enrolled_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "attestation_verified": attestation_verified, "attestation": attestation or {},
            "revoked": False,
        })

    def lookup(self, kid: str) -> tuple[str, dict] | None:
        for signer, keys in self.signers.items():
            for k in keys:
                if k["kid"] == kid:
                    return signer, k
        return None

    def has_signer(self, signer: str) -> bool:
        return signer in self.signers
