"""Dev-mode software keys (Ed25519). Clearly labelled; confer nothing in
enforced mode. Real signing keys arrive with WebAuthn in Phase 2."""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .b64 import b64u_encode, b64u_decode

DEV_WARNING = "SIB DEV MODE: software key in use; this signature proves possession of a file, not a person."
_warned = False


def sib_home() -> Path:
    return Path(os.environ.get("SIB_HOME") or (Path.home() / ".sib"))


def dev_warning() -> None:
    global _warned
    if not _warned:
        print(DEV_WARNING, file=sys.stderr, flush=True)
        _warned = True


def _key_path(kid: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._@#-]", "_", kid)
    return sib_home() / "dev-keys" / f"{safe}.pem"


def generate(kid: str) -> str:
    """Create a dev key under $SIB_HOME/dev-keys and return the public key (base64url raw)."""
    dev_warning()
    p = _key_path(kid)
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        raise FileExistsError(f"dev key already exists: {p}")
    sk = Ed25519PrivateKey.generate()
    p.write_bytes(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    os.chmod(p, 0o600)
    return public_key_b64u(kid)


def _load(kid: str) -> Ed25519PrivateKey:
    p = _key_path(kid)
    if not p.exists():
        raise FileNotFoundError(f"no dev key for {kid}: {p}")
    return serialization.load_pem_private_key(p.read_bytes(), password=None)


def public_key_b64u(kid: str) -> str:
    return b64u_encode(_load(kid).public_key().public_bytes(serialization.Encoding.Raw,
                                                            serialization.PublicFormat.Raw))


def sign(kid: str, data: bytes) -> str:
    dev_warning()
    return b64u_encode(_load(kid).sign(data))


def verify(public_key_b64u_: str, signature_b64u: str, data: bytes) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(b64u_decode(public_key_b64u_))
        pk.verify(b64u_decode(signature_b64u), data)
        return True
    except (InvalidSignature, ValueError):
        return False
