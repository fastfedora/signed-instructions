"""Enforced-mode keys: WebAuthn passkeys signing with ES256. The private key
never leaves the authenticator; the registry holds the COSE public key, the
credential id, the authenticator's AAGUID and what the enrollment
attestation proved. This module checks an assertion against a block and
verifies an enrollment; the browser-facing app lives in `sib.webauthn_app`.

What an assertion proves, and what it does not, is spelled out in
`docs/guide/components/signing.qmd`: the UV flag covers PIN and password as
well as biometrics, and the AAGUID is self-reported unless the enrollment
carried attestation that chained to a known root."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path

from .b64 import b64u_decode, b64u_encode
from .header import Header, signing_input

ALG = "ES256-webauthn"
RP_ID = "localhost"
RP_NAME = "Signed Instruction Blocks"
DEFAULT_PORT = 7391
ZERO_AAGUID = "00000000-0000-0000-0000-000000000000"

# Authenticator models known to verify the user with a biometric sensor, by
# AAGUID, compiled from the public passkey AAGUID list
# (https://github.com/passkeydeveloper/passkey-authenticator-aaguids). The
# list is policy, not proof: an AAGUID is self-reported unless the enrollment's
# attestation was verified. The zero AAGUID, which Apple's `apple` attestation
# reports, is accepted only on an enrollment with verified attestation.
# Authenticator models known to verify their user biometrically, with the names the
# published lists give them. Audited 19 October 2026 against
# passkeydeveloper/passkey-authenticator-aaguids: aaguid.json for the platform
# providers and combined_aaguid.json (FIDO MDS derived) for every YubiKey Bio model.
# Re-audit before an enforced deployment relies on it; vendors add models and rename
# them. A registry adds its own under `allowed_aaguids`, or `sib allow-authenticator`.
# Deliberately absent: software password-manager vaults such as 1Password
# (bada5566-a7aa-401f-bd96-45619a55120d), whose key is not bound to one device.
DEFAULT_ALLOWED_AAGUIDS = {
    "fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "Apple Passwords",
    "dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain (Managed)",
    "adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
    "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
    "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
    "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
    "9dd8d593-2213-438a-97f8-d6b813d51c27": "YubiKey Bio Fido Edition (Consumer Profile)",
    "add92433-0d69-4026-8166-29b25bce64e9": "YubiKey Bio Fido Edition (Enterprise Profile)",
    "ba0a9266-40d8-4048-9786-d710b5474752": "YubiKey Bio Multi-protocol Edition (Consumer Profile)",
    "9806a2c8-c0da-478e-b4ca-620005d34182": "YubiKey Bio Multi-protocol Edition (Consumer Profile) 1VDJSN-2",
    "dc5e949d-f939-43b3-9877-a85c7186b753": "YubiKey Bio Multi-protocol Edition (Enterprise Profile)",
    "7409272d-1ff9-4e10-9fc9-ac0019c124fd": "YubiKey Bio Series - FIDO Edition",
    "d8522d9f-575b-4866-88a9-ba99fa02f35b": "YubiKey Bio Series - FIDO Edition",
    "dd86a2da-86a0-4cbe-b462-4bd31f57bc6f": "YubiKey Bio Series - FIDO Edition",
    "83c47309-aabb-4108-8470-8be838b573cb": "YubiKey Bio Series - FIDO Edition (Enterprise Profile)",
    "8c39ee86-7f9a-4a95-9ba3-f6b097e5c2ee": "YubiKey Bio Series - FIDO Edition (Enterprise Profile)",
    "ad08c78a-4e41-49b9-86a2-ac15b06899e2": "YubiKey Bio Series - FIDO Edition (Enterprise Profile)",
    "34744913-4f57-4e6e-a527-e9ec3c4b94e6": "YubiKey Bio Series - Multi-protocol Edition",
    "7d1351a6-e097-4852-b8bf-c9ac5c9ce4a3": "YubiKey Bio Series - Multi-protocol Edition",
    "90636e1f-ef82-43bf-bdcf-5255f139d12f": "YubiKey Bio Series - Multi-protocol Edition",
    "6ec5cff2-a0f9-4169-945b-f33b563f7b99": "YubiKey Bio Series - Multi-protocol Edition (Enterprise Profile)",
    "97e6a830-c952-4740-95fc-7c78dc97ce47": "YubiKey Bio Series - Multi-protocol Edition (Enterprise Profile)",
    "58276709-bb4b-4bb3-baf1-60eea99282a7": "YubiKey Bio Series - Multi-protocol Edition 1VDJSN",
    ZERO_AAGUID: "Apple platform authenticator with `apple` attestation (verified attestation required)",
}

FLAG_UP = 0x01
FLAG_UV = 0x04


def port() -> int:
    return int(os.environ.get("SIB_WEBAUTHN_PORT") or DEFAULT_PORT)


def default_origin() -> str:
    return f"http://{RP_ID}:{port()}"


def challenge(signing_header_b64: str, canonical_text: str) -> bytes:
    """What the authenticator signs on the signer's behalf: SHA-256 of the
    signing input over the header without the assertion fields."""
    return hashlib.sha256(signing_input(signing_header_b64, canonical_text)).digest()


def is_model_aaguid(aaguid: str) -> bool:
    """True for a well-formed AAGUID that names a model.

    The all-zero value names no model: many authenticators zero the field under
    attestation `none`, so it is handled by its own rule in the default list and
    is never a legitimate registry entry.
    """
    try:
        parsed = uuid.UUID(str(aaguid))
    except (ValueError, AttributeError, TypeError):
        return False
    return str(parsed) != ZERO_AAGUID


def aaguid_allowed(key: dict, allowed: dict) -> tuple[bool, str]:
    """Policy check on the AAGUID recorded at enrollment. Returns (allowed, label).

    A key with no AAGUID, or a malformed one, is refused whatever the allowlist
    says. Allowing the absence of a model would make every key with the field
    missing pass, which is what `enroll --public-key` produces, so the check
    cannot be delegated to the list's contents.
    """
    raw = key.get("aaguid")
    aaguid = (raw or "").lower()
    if not is_model_aaguid(aaguid) and aaguid != ZERO_AAGUID:
        return False, aaguid or "(none recorded)"
    if aaguid not in allowed:
        return False, aaguid or "(none recorded)"
    if aaguid == ZERO_AAGUID and not key.get("attestation_verified"):
        return False, f"{aaguid} without verified attestation"
    return True, allowed[aaguid]


def check_assertion(h: Header, canonical_text: str, sig_b64: str, key: dict,
                    allowed: dict) -> tuple[str, str] | None:
    """The WebAuthn checks of the verification algorithm, in order. `sig_b64`
    is the block's signature segment. Returns (status, error) at the first
    failing check and None when the assertion verifies. Deterministic; no
    network, no model."""
    try:
        cdj_bytes = b64u_decode(h.clientDataJSON)
        cdj = json.loads(cdj_bytes.decode("utf-8"))
        auth_data = b64u_decode(h.authenticatorData)
    except Exception as e:  # noqa: BLE001
        return "malformed", f"WebAuthn fields do not decode: {e}"
    if not isinstance(cdj, dict) or cdj.get("type") != "webauthn.get":
        return "malformed", f"clientDataJSON.type is {cdj.get('type')!r}, not 'webauthn.get'"
    if len(auth_data) < 37:
        return "malformed", "authenticatorData shorter than 37 bytes"

    expected = b64u_encode(challenge(h.signing_header().encode(), canonical_text))
    got = str(cdj.get("challenge") or "").rstrip("=")
    if got != expected:
        return "invalid_signature", "WebAuthn challenge does not match the header and canonical text"

    origins = key.get("origins") or [default_origin()]
    if cdj.get("origin") not in origins:
        return "origin_not_allowed", f"assertion origin {cdj.get('origin')!r} is not enrolled for this key ({', '.join(origins)})"

    rp_id = key.get("rp_id") or RP_ID
    if auth_data[:32] != hashlib.sha256(rp_id.encode("utf-8")).digest():
        return "rp_id_mismatch", f"authenticatorData rpIdHash is not SHA-256({rp_id!r})"

    flags = auth_data[32]
    if not flags & FLAG_UP:
        return "uv_not_performed", "user presence (UP) flag not set"
    if not flags & FLAG_UV:
        return "uv_not_performed", "user verification (UV) flag not set; the authenticator did not verify the user"

    ok, label = aaguid_allowed(key, allowed)
    if not ok:
        return "authenticator_not_allowed", f"authenticator AAGUID {label} is not on the biometric-capable allowlist"

    if not verify_es256(key["public_key"], sig_b64, auth_data, cdj_bytes):
        return "invalid_signature", "ES256 signature does not verify over authenticatorData and the client data hash"
    return None


def verify_es256(public_key_b64u: str, signature_b64u: str, auth_data: bytes, client_data_json: bytes) -> bool:
    """ES256 over authenticatorData || SHA-256(clientDataJSON) with the enrolled
    COSE public key. The signature is the ASN.1 DER form the authenticator
    returned."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from webauthn.helpers import decode_credential_public_key, decoded_public_key_to_cryptography
    from webauthn.helpers.cose import COSEAlgorithmIdentifier
    try:
        decoded = decode_credential_public_key(b64u_decode(public_key_b64u))
        if decoded.alg != COSEAlgorithmIdentifier.ECDSA_SHA_256:
            return False
        pk = decoded_public_key_to_cryptography(decoded)
        data = auth_data + hashlib.sha256(client_data_json).digest()
        pk.verify(b64u_decode(signature_b64u), data, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, Exception):  # noqa: BLE001 - any decode failure is "does not verify"
        return False


# ---------- enrollment ----------

class EnrollmentRefused(ValueError):
    pass


def attestation_roots() -> dict:
    """Extra root certificates for attestation formats, from the PEM files in
    `SIB_ATTESTATION_ROOTS`. py_webauthn bundles Apple's root; `packed`
    (YubiKey, most security keys), `tpm` and `fido-u2f` chains are verified
    only when a root is supplied here."""
    from webauthn.helpers.structs import AttestationFormat
    d = os.environ.get("SIB_ATTESTATION_ROOTS")
    if not d:
        return {}
    pems = [p.read_bytes() for p in sorted(Path(d).glob("*.pem"))]
    if not pems:
        return {}
    return {AttestationFormat.PACKED: pems, AttestationFormat.TPM: pems, AttestationFormat.FIDO_U2F: pems}


def verify_enrollment(credential: dict, expected_challenge: bytes, origin: str, rp_id: str = RP_ID,
                      roots: dict | None = None, require_attestation: bool | None = None) -> dict:
    """Verify a registration response and return the registry entry fields for
    it. `attestation_verified` is true only when the attestation statement
    carried a certificate chain and a root for its format was available to
    check it against; otherwise the AAGUID is the authenticator's own claim."""
    from webauthn import verify_registration_response
    from webauthn.helpers import parse_attestation_object
    from webauthn.helpers.cose import COSEAlgorithmIdentifier
    from webauthn.helpers.exceptions import InvalidRegistrationResponse
    from webauthn.helpers.structs import AttestationFormat

    roots = attestation_roots() if roots is None else roots
    if require_attestation is None:
        require_attestation = os.environ.get("SIB_REQUIRE_ATTESTATION", "").lower() in ("1", "true", "yes")
    try:
        reg = verify_registration_response(credential=credential, expected_challenge=expected_challenge,
                                           expected_rp_id=rp_id, expected_origin=origin,
                                           require_user_verification=True, pem_root_certs_bytes_by_fmt=roots or None,
                                           supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256])
    except InvalidRegistrationResponse as e:
        raise EnrollmentRefused(f"registration response did not verify: {e}") from None
    att = parse_attestation_object(reg.attestation_object)
    x5c_present = bool(att.att_stmt.x5c)
    fmt = att.fmt.value if hasattr(att.fmt, "value") else str(att.fmt)
    roots_known = att.fmt == AttestationFormat.APPLE or bool((roots or {}).get(att.fmt))
    verified = x5c_present and roots_known
    if require_attestation and not verified:
        raise EnrollmentRefused(f"attestation {fmt!r} could not be verified and SIB_REQUIRE_ATTESTATION is set")
    ext = credential.get("clientExtensionResults") or {}
    entry = {
        "credential_id": b64u_encode(reg.credential_id),
        "public_key": b64u_encode(reg.credential_public_key),
        "aaguid": reg.aaguid,
        "attestation_verified": verified,
        "attestation": {"format": fmt, "x5c_present": x5c_present,
                        "roots": ("bundled" if att.fmt == AttestationFormat.APPLE else "configured" if roots_known else None)},
        "sign_count": reg.sign_count,
        "origins": [origin],
        "rp_id": rp_id,
        "user_verified_at_enrollment": bool(reg.user_verified),
    }
    if ext.get("uvm") is not None:
        entry["uvm"] = ext["uvm"]
    return entry
