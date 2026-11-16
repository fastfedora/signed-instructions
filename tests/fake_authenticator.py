"""A software authenticator for the tests and the conformance vectors. It
produces real WebAuthn-shaped registration and assertion responses signed
with ES256, with the flags, AAGUID, origin, RP ID and attestation format all
settable, so every status on the verifier's WebAuthn path is reachable
without hardware. It is not a dev-mode key: the verifier treats what it
produces exactly like a passkey, which is the point."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import secrets
import uuid
from dataclasses import replace

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from sib import keys_webauthn
from sib.b64 import b64u_encode
from sib.canon import canonicalize
from sib.envelope import render
from sib.header import Header, format_time
from sib.registry import Registry
from sib.verify import clear_lines

AAGUID = "0bb0a6c1-7d9e-4e0f-9b1a-5a6c7d8e9f00"       # a made-up model; tests allowlist it explicitly
RP_ID = keys_webauthn.RP_ID
ORIGIN = f"http://{RP_ID}:{keys_webauthn.DEFAULT_PORT}"


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


class FakeAuthenticator:
    def __init__(self, aaguid: str = AAGUID, rp_id: str = RP_ID, origin: str = ORIGIN):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(16)
        self.aaguid, self.rp_id, self.origin = aaguid, rp_id, origin
        self.counter = 0

    @property
    def credential_id_b64u(self) -> str:
        return b64u_encode(self.credential_id)

    def cose_public_key(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big")})

    def auth_data(self, *, up=True, uv=True, attested=False, rp_id=None) -> bytes:
        flags = (0x01 if up else 0) | (0x04 if uv else 0) | (0x40 if attested else 0)
        self.counter += 1
        data = _sha256((rp_id or self.rp_id).encode()) + bytes([flags]) + self.counter.to_bytes(4, "big")
        if attested:
            cose = self.cose_public_key()
            data += uuid.UUID(self.aaguid).bytes + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cose
        return data

    def client_data(self, typ: str, challenge: bytes, origin=None) -> bytes:
        return json.dumps({"type": typ, "challenge": b64u_encode(challenge), "origin": origin or self.origin,
                           "crossOrigin": False}).encode()

    def sign(self, auth_data: bytes, cdj: bytes, key=None) -> bytes:
        return (key or self.key).sign(auth_data + _sha256(cdj), ec.ECDSA(hashes.SHA256()))

    def register(self, challenge: bytes, *, uv=True, fmt="none", origin=None, attestation_key=None, x5c=None,
                 uvm=None) -> dict:
        """A registration response as the browser's JSON serialization would carry it."""
        auth_data = self.auth_data(uv=uv, attested=True)
        cdj = self.client_data("webauthn.create", challenge, origin)
        if fmt == "none":
            att_stmt = {}
        elif fmt == "packed":
            att_stmt = {"alg": -7, "sig": self.sign(auth_data, cdj, attestation_key)}
            if x5c:
                att_stmt["x5c"] = x5c
        else:
            raise ValueError(fmt)
        obj = cbor2.dumps({"fmt": fmt, "attStmt": att_stmt, "authData": auth_data})
        ext = {} if uvm is None else {"uvm": uvm}
        return {"id": self.credential_id_b64u, "rawId": self.credential_id_b64u, "type": "public-key",
                "response": {"clientDataJSON": b64u_encode(cdj), "attestationObject": b64u_encode(obj),
                             "transports": ["internal"]},
                "clientExtensionResults": ext, "authenticatorAttachment": "platform"}

    def get(self, challenge: bytes, *, up=True, uv=True, origin=None, typ="webauthn.get", rp_id=None,
            signing_key=None) -> dict:
        """An assertion as the browser's JSON serialization would carry it."""
        auth_data = self.auth_data(up=up, uv=uv, rp_id=rp_id)
        cdj = self.client_data(typ, challenge, origin)
        sig = self.sign(auth_data, cdj, signing_key)
        return {"id": self.credential_id_b64u, "rawId": self.credential_id_b64u, "type": "public-key",
                "response": {"clientDataJSON": b64u_encode(cdj), "authenticatorData": b64u_encode(auth_data),
                             "signature": b64u_encode(sig), "userHandle": None},
                "clientExtensionResults": {}}


def make_attestation_ca() -> tuple[bytes, bytes, ec.EllipticCurvePrivateKey]:
    """A throwaway attestation CA: (root PEM, leaf DER, leaf key). The leaf
    plays the authenticator's attestation certificate."""
    now = dt.datetime.now(dt.timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake Authenticator Root CA")])
    root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
            .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(root_key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                           x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake Authenticator Inc"),
                           x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
                           x509.NameAttribute(NameOID.COMMON_NAME, "Fake Authenticator Attestation")])
    leaf = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(root_name)
            .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(root_key, hashes.SHA256()))
    return (root.public_bytes(serialization.Encoding.PEM), leaf.public_bytes(serialization.Encoding.DER), leaf_key)


def enroll_fake(reg: Registry, auth: FakeAuthenticator, signer: str, kid: str, *, attestation_verified=False,
                allow=True, mode="enforced") -> None:
    """Write the registry entry an enrollment through the app would produce."""
    reg.add_key(signer, kid, keys_webauthn.ALG, b64u_encode(auth.cose_public_key()), mode=mode,
                attestation_verified=attestation_verified, attestation={"format": "none", "x5c_present": False, "roots": None},
                credential_id=auth.credential_id_b64u, aaguid=auth.aaguid, origins=[auth.origin], rp_id=auth.rp_id,
                sign_count=0, transports=["internal"])
    if allow:
        reg.allow_aaguid(auth.aaguid, "fake biometric authenticator (tests)")


def make_webauthn_block(auth: FakeAuthenticator, text: str, *, kid: str, signer: str, aud="acme/dev-agent",
                        canon="text/1", iat=None, exp=None, jti=None, clear=None, up=True, uv=True, origin=None,
                        typ="webauthn.get", rp_id=None, signed_text=None, credential_id=None, signing_key=None,
                        now=None) -> tuple[str, Header]:
    """A block signed by the fake authenticator. `signed_text` lets the
    assertion cover a different text than the block carries (challenge
    mismatch); `credential_id` overrides the header's credentialId."""
    now = now or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    h = Header(alg=keys_webauthn.ALG, kid=kid, canon=canon, iss=signer,
               iat=format_time(iat or now - dt.timedelta(minutes=1)),
               exp=format_time(exp or now + dt.timedelta(hours=2)),
               jti=jti or b64u_encode(secrets.token_bytes(12)), mode="enforced", aud=aud)
    chal = keys_webauthn.challenge(h.encode(), canonicalize(canon, signed_text if signed_text is not None else text))
    a = auth.get(chal, up=up, uv=uv, origin=origin, typ=typ, rp_id=rp_id, signing_key=signing_key)
    full = replace(h, credentialId=credential_id or a["rawId"], authenticatorData=a["response"]["authenticatorData"],
                   clientDataJSON=a["response"]["clientDataJSON"])
    block = render(text, f"{full.encode()}..{a['response']['signature']}", clear if clear is not None else clear_lines(h))
    return block, full
