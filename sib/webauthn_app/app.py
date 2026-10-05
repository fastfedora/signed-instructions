"""The local signing app: the enroll and sign pages and the JSON endpoints
behind them, on `http://localhost:<port>` (a secure context, so WebAuthn
works without TLS). The CLI starts it for one request and stops it when
the request is answered.

Every request is addressed by a one-time token the CLI minted, so a stray
tab cannot enroll a key or sign a payload the CLI did not ask for. The sign
request's challenge is fixed when the request is created: SHA-256 of the
signing input the CLI showed the signer."""
from __future__ import annotations

import json
import secrets
import threading
from dataclasses import dataclass, field, replace

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse

from .. import keys_webauthn
from ..b64 import b64u_decode
from . import pages


@dataclass
class PendingRequest:
    kind: str                       # "enroll" or "sign"
    payload: dict
    challenge: bytes | None = None
    result: dict | None = None
    error: str | None = None
    consumed: bool = False
    done: threading.Event = field(default_factory=threading.Event)

    def finish(self, result: dict | None = None, error: str | None = None) -> None:
        self.result, self.error, self.consumed = result, error, True
        self.done.set()


class AppState:
    def __init__(self):
        self.pending: dict[str, PendingRequest] = {}

    def add(self, kind: str, payload: dict, challenge: bytes | None = None) -> str:
        token = secrets.token_urlsafe(24)
        self.pending[token] = PendingRequest(kind, payload, challenge)
        return token

    def get(self, token: str, kind: str) -> PendingRequest:
        p = self.pending.get(token)
        if p is None or p.kind != kind or p.consumed:
            raise HTTPException(404, "unknown or already used request token")
        return p


def create_app(state: AppState, origin: str) -> FastAPI:
    from webauthn import generate_registration_options, generate_authentication_options, options_to_json
    from webauthn.helpers.cose import COSEAlgorithmIdentifier
    from webauthn.helpers.structs import (AttestationConveyancePreference, AuthenticatorAttachment,
                                          AuthenticatorSelectionCriteria, AuthenticatorTransport,
                                          PublicKeyCredentialDescriptor, ResidentKeyRequirement,
                                          UserVerificationRequirement)

    def transports(key: dict) -> list | None:
        known = {t.value for t in AuthenticatorTransport}
        out = [AuthenticatorTransport(t) for t in key.get("transports") or [] if t in known]
        return out or None

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.post("/api/{kind}/{token}/abort")
    async def abort(kind: str, token: str, request: Request):
        """The page reports a browser-side failure (the user cancelled, the
        authenticator refused) so the CLI ends now instead of at its timeout."""
        p = state.get(token, kind)
        body = await request.json()
        p.finish(error=f"the browser reported: {str((body or {}).get('error') or 'cancelled')[:300]}")
        return {"ok": True}

    # ---- enroll ----

    @app.get("/enroll/{token}", response_class=HTMLResponse)
    def enroll_page(token: str):
        p = state.get(token, "enroll")
        return pages.enroll_page(token, p.payload["signer"])

    @app.post("/api/enroll/{token}/options")
    def enroll_options(token: str):
        p = state.get(token, "enroll")
        signer = p.payload["signer"]
        exclude = [PublicKeyCredentialDescriptor(id=b64u_decode(c)) for c in p.payload.get("existing_credential_ids", [])]
        opts = generate_registration_options(
            rp_id=keys_webauthn.RP_ID, rp_name=keys_webauthn.RP_NAME, user_name=signer, user_display_name=signer,
            # a fresh user handle per enrollment: a reused handle makes the authenticator replace the
            # earlier passkey for this RP, which would orphan the key enrolled under the earlier kid
            user_id=secrets.token_bytes(32), timeout=120_000,
            attestation=AttestationConveyancePreference.DIRECT,
            # the alg is ES256-webauthn: offer nothing else, or an authenticator may create an Ed25519 key
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.REQUIRED),
            exclude_credentials=exclude or None)
        p.challenge = opts.challenge
        return json.loads(options_to_json(opts))

    @app.post("/api/enroll/{token}/finish")
    async def enroll_finish(token: str, request: Request):
        p = state.get(token, "enroll")
        if p.challenge is None:
            raise HTTPException(409, "options were not requested first")
        cred = await request.json()
        try:
            entry = keys_webauthn.verify_enrollment(cred, p.challenge, origin)
        except keys_webauthn.EnrollmentRefused as e:
            p.finish(error=str(e))
            raise HTTPException(400, str(e))
        entry["transports"] = list((cred.get("response") or {}).get("transports") or [])
        ok, label = keys_webauthn.aaguid_allowed(entry, p.payload.get("allowed_aaguids") or {})
        p.finish(result=entry)
        return {"ok": True, "aaguid": entry["aaguid"], "aaguid_allowed": ok, "aaguid_label": label if ok else None,
                "attestation_format": entry["attestation"]["format"], "attestation_verified": entry["attestation_verified"]}

    # ---- sign ----

    @app.get("/sign/{token}", response_class=HTMLResponse)
    def sign_page(token: str):
        p = state.get(token, "sign")
        h = p.payload["header"]
        return pages.sign_page(token, {"signer": h.iss, "kid": h.kid, "exp": h.exp, "aud": h.aud, "jti": h.jti,
                                       "ctext": p.payload["ctext"]})

    @app.post("/api/sign/{token}/options")
    def sign_options(token: str):
        p = state.get(token, "sign")
        key = p.payload["key"]
        opts = generate_authentication_options(
            rp_id=key.get("rp_id") or keys_webauthn.RP_ID, challenge=p.challenge, timeout=120_000,
            allow_credentials=[PublicKeyCredentialDescriptor(id=b64u_decode(key["credential_id"]),
                                                             transports=transports(key))],
            user_verification=UserVerificationRequirement.REQUIRED)
        return json.loads(options_to_json(opts))

    @app.post("/api/sign/{token}/finish")
    async def sign_finish(token: str, request: Request):
        p = state.get(token, "sign")
        cred = await request.json()
        resp = cred.get("response") or {}
        try:
            full = replace(p.payload["header"], credentialId=cred["rawId"], authenticatorData=resp["authenticatorData"],
                           clientDataJSON=resp["clientDataJSON"])
            sig = resp["signature"]
        except (KeyError, TypeError):
            raise HTTPException(400, "assertion response is missing fields")
        key = p.payload["key"]
        if full.credentialId != key.get("credential_id"):
            failure = ("unknown_key", "a different credential signed than the one enrolled under this kid")
        else:
            failure = keys_webauthn.check_assertion(full, p.payload["ctext"], sig, key, p.payload.get("allowed_aaguids") or {})
        result = {"header": full, "signature": sig, "status": failure[0] if failure else "verified",
                  "error": failure[1] if failure else None,
                  "uvm": (cred.get("clientExtensionResults") or {}).get("uvm")}
        p.finish(result=result)
        return {"ok": failure is None, "status": result["status"], "error": result["error"]}

    return app


def sign_challenge(header, ctext: str) -> bytes:
    """Convenience for callers building a sign request: the fixed challenge."""
    return keys_webauthn.challenge(header.signing_header().encode(), ctext)

