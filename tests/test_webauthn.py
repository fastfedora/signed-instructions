"""The ES256-webauthn path: header fields, every verifier status it can
produce, enrollment verification, the attestation record and the mode
default. Signed with the software authenticator in `fake_authenticator`;
a real assertion recorded on a laptop is checked when the fixture exists."""
import datetime as dt
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from sib import keys_webauthn
from sib.b64 import b64u_encode, b64u_decode
from sib.envelope import extract, render
from sib.header import Header, MalformedHeader
from sib.manifest import build_manifest, render_classifier_note
from sib.nonce_store import NoopNonceStore
from sib.registry import Registry, default_mode
from sib.verify import verify_block, clear_lines, STATUSES
from tests.conftest import ALICE, AUD, make_block
from tests.fake_authenticator import (FakeAuthenticator, enroll_fake, make_webauthn_block, make_attestation_ca,
                                      AAGUID, ORIGIN)

PKID = "alice@example.com#passkey-test"
FIXTURE = Path(__file__).parent / "fixtures" / "webauthn" / "real_assertion.json"


@pytest.fixture
def auth():
    return FakeAuthenticator()


@pytest.fixture
def passkey_registry(sib_home, auth):
    reg = Registry()
    enroll_fake(reg, auth, ALICE, PKID)
    reg.save()
    return reg


def _v(doc, registry, audience=AUD, mode="enforced", now=None):
    blocks = extract(doc)
    assert len(blocks) == 1
    return verify_block(blocks[0], now or dt.datetime.now(dt.timezone.utc), audience, registry, NoopNonceStore(), "s1", mode)


def _sign(auth, text="Deploy to staging with scripts/deploy.sh staging.", **kw):
    return make_webauthn_block(auth, text, kid=PKID, signer=ALICE, **kw)


# ---- header ----

def test_header_fields_required_with_webauthn_alg_and_rejected_without():
    base = dict(alg="ES256-webauthn", kid="k", canon="text/1", iss="a", iat="2026-01-01T00:00:00Z",
                exp="2026-01-01T01:00:00Z", jti="j", mode="enforced", typ="SIB/1", b64=False, crit=["b64"])
    with pytest.raises(MalformedHeader, match="requires credentialId"):
        Header.from_dict(base)
    h = Header.from_dict({**base, "credentialId": "c", "authenticatorData": "a", "clientDataJSON": "d"})
    assert h.credentialId == "c" and h.signing_header().credentialId is None
    assert set(h.to_dict()) >= {"credentialId", "authenticatorData", "clientDataJSON"}
    assert "credentialId" not in h.signing_header().to_dict()
    with pytest.raises(MalformedHeader, match="only valid with alg ES256-webauthn"):
        Header.from_dict({**base, "alg": "EdDSA", "credentialId": "c"})
    with pytest.raises(MalformedHeader, match="non-empty"):
        Header.from_dict({**base, "credentialId": "", "authenticatorData": "a", "clientDataJSON": "d"})


# ---- verifier statuses ----

def test_verified_in_enforced_and_dev_mode(passkey_registry, auth):
    doc, h = _sign(auth)
    for mode in ("enforced", "dev"):
        r = _v(doc, passkey_registry, mode=mode)
        assert r.status == "verified", r.error
        assert r.signer == ALICE and r.alg == "ES256-webauthn" and r.mode == "enforced"
        assert r.attestation_verified is False


def test_one_byte_of_text_changed_is_invalid_signature(passkey_registry, auth):
    doc, _ = _sign(auth)
    r = _v(doc.replace("to staging", "to stagink"), passkey_registry)
    assert r.status == "invalid_signature" and "challenge" in r.error and r.signer == ALICE


def test_verified_after_transport_mangling(passkey_registry, auth):
    doc, _ = _sign(auth, "Deploy “now” to staging\nwith scripts/deploy.sh staging.")
    mangled = "\n".join("> " + l for l in doc.splitlines()).replace("“now”", '"now"')
    mangled = mangled.replace("staging\n> with", "staging with")
    assert _v(mangled, passkey_registry).status == "verified"


def test_header_edit_is_invalid_signature(passkey_registry, auth):
    # the assertion covers the signing header, so a changed expiry breaks the challenge
    doc, h = _sign(auth)
    from dataclasses import replace
    tampered = replace(h, exp="2099-01-01T00:00:00Z")
    b = extract(doc)[0]
    doc2 = render(b.text, f"{tampered.encode()}..{b.compact.split('.')[2]}", clear_lines(tampered))
    assert _v(doc2, passkey_registry).status == "invalid_signature"


def test_forged_signature_is_invalid_signature(passkey_registry, auth):
    doc, _ = _sign(auth, signing_key=ec.generate_private_key(ec.SECP256R1()))
    r = _v(doc, passkey_registry)
    assert r.status == "invalid_signature" and "ES256" in r.error


def test_uv_cleared_is_uv_not_performed(passkey_registry, auth):
    doc, _ = _sign(auth, uv=False)
    r = _v(doc, passkey_registry)
    assert r.status == "uv_not_performed" and "UV" in r.error
    doc, _ = _sign(auth, up=False)
    assert _v(doc, passkey_registry).status == "uv_not_performed"


def test_aaguid_not_allowlisted_is_authenticator_not_allowed(sib_home):
    other = FakeAuthenticator(aaguid="11111111-2222-3333-4444-555555555555")
    reg = Registry()
    enroll_fake(reg, other, ALICE, PKID, allow=False)
    doc, _ = _sign(other)
    r = _v(doc, reg)
    assert r.status == "authenticator_not_allowed" and "11111111-2222" in r.error
    reg.allow_aaguid("11111111-2222-3333-4444-555555555555", "now allowed")
    assert _v(doc, reg).status == "verified"


def test_zero_aaguid_needs_verified_attestation(sib_home):
    apple = FakeAuthenticator(aaguid=keys_webauthn.ZERO_AAGUID)
    reg = Registry()
    enroll_fake(reg, apple, ALICE, PKID, allow=False)
    doc, _ = _sign(apple)
    assert _v(doc, reg).status == "authenticator_not_allowed"
    reg.lookup(PKID)[1]["attestation_verified"] = True
    r = _v(doc, reg)
    assert r.status == "verified" and r.attestation_verified is True


def test_origin_not_allowed(passkey_registry, auth):
    doc, _ = _sign(auth, origin="http://localhost:8000")
    r = _v(doc, passkey_registry)
    assert r.status == "origin_not_allowed" and "8000" in r.error
    # an origin added to the key's list is accepted
    passkey_registry.lookup(PKID)[1]["origins"].append("http://localhost:8000")
    assert _v(doc, passkey_registry).status == "verified"


def test_rp_id_mismatch(passkey_registry, auth):
    doc, _ = _sign(auth, rp_id="example.com")
    assert _v(doc, passkey_registry).status == "rp_id_mismatch"


def test_wrong_client_data_type_is_malformed(passkey_registry, auth):
    doc, _ = _sign(auth, typ="webauthn.create")
    r = _v(doc, passkey_registry)
    assert r.status == "malformed" and "webauthn.get" in r.error


def test_undecodable_webauthn_fields_are_malformed(passkey_registry, auth):
    doc, h = _sign(auth)
    from dataclasses import replace
    bad = replace(h, clientDataJSON=b64u_encode(b"not json"))
    b = extract(doc)[0]
    doc2 = render(b.text, f"{bad.encode()}..{b.compact.split('.')[2]}", b.clear)
    assert _v(doc2, passkey_registry).status == "malformed"


def test_credential_id_mismatch_is_unknown_key(passkey_registry, auth):
    doc, _ = _sign(auth, credential_id=b64u_encode(b"someone-else"))
    r = _v(doc, passkey_registry)
    assert r.status == "unknown_key" and "credentialId" in r.error


def test_dev_block_is_refused_once_a_passkey_exists(passkey_registry, auth, registry):
    # `registry` enrolls alice's dev key alongside the passkey; the default mode is now enforced
    reg = Registry()
    assert default_mode(reg) == "enforced"
    doc, _ = make_block("x")
    assert _v(doc, reg).status == "dev_key_in_enforced_mode"
    doc, _ = _sign(auth)
    assert _v(doc, reg).status == "verified"


def test_common_checks_still_run_after_the_assertion(passkey_registry, auth):
    now = dt.datetime.now(dt.timezone.utc)
    doc, _ = _sign(auth, iat=now - dt.timedelta(hours=3), exp=now - dt.timedelta(hours=1))
    assert _v(doc, passkey_registry).status == "expired"
    doc, _ = _sign(auth, aud="acme/ci-agent")
    assert _v(doc, passkey_registry).status == "audience_mismatch"
    doc, _ = _sign(auth, aud=None)
    assert _v(doc, passkey_registry, mode="enforced").status == "audience_mismatch"
    assert _v(doc, passkey_registry, mode="dev").status == "verified"
    doc, h = _sign(auth)
    assert _v(doc.replace(f"Expires: {h.exp}", "Expires: 2099-01-01T00:00:00Z"), passkey_registry).status == "metadata_mismatch"
    passkey_registry.lookup(PKID)[1]["revoked"] = True
    assert _v(doc, passkey_registry).status == "revoked"


def test_every_status_is_reachable():
    covered = {"verified", "invalid_signature", "unknown_signer", "unknown_key", "expired", "not_yet_valid",
               "audience_mismatch", "metadata_mismatch", "malformed", "nonce_replayed", "revoked",
               "dev_key_in_enforced_mode", "origin_not_allowed", "rp_id_mismatch", "uv_not_performed",
               "authenticator_not_allowed"}
    assert covered == set(STATUSES)


# ---- manifest ----

def test_manifest_span_reports_attestation_verified(passkey_registry, auth):
    doc, _ = _sign(auth)
    r = _v(doc, passkey_registry)
    m = build_manifest([(r, {"role": "file", "source": "cli"})], None, None, AUD, "enforced")
    s = m["spans"][0]
    assert s["attestation_verified"] is False and s["alg"] == "ES256-webauthn"
    assert "mode enforced" in render_classifier_note(m)


# ---- mode default ----

def test_default_mode(sib_home, monkeypatch, auth):
    monkeypatch.delenv("SIB_MODE", raising=False)
    assert default_mode(Registry()) == "dev"
    reg = Registry()
    enroll_fake(reg, auth, ALICE, PKID)
    reg.save()
    assert default_mode() == "enforced"
    monkeypatch.setenv("SIB_MODE", "dev")
    assert default_mode() == "dev"


# ---- enrollment ----

def test_enrollment_none_attestation_records_self_reported_aaguid(auth):
    chal = b"\x01" * 32
    entry = keys_webauthn.verify_enrollment(auth.register(chal, uvm=[[2, 4, 2]]), chal, ORIGIN, roots={})
    assert entry["aaguid"] == AAGUID and entry["attestation_verified"] is False
    assert entry["attestation"] == {"format": "none", "x5c_present": False, "roots": None}
    assert entry["credential_id"] == auth.credential_id_b64u and entry["origins"] == [ORIGIN]
    assert b64u_decode(entry["public_key"]) == auth.cose_public_key()
    assert entry["uvm"] == [[2, 4, 2]] and entry["user_verified_at_enrollment"] is True


def test_enrollment_packed_with_chain_to_a_known_root_is_verified(auth):
    from webauthn.helpers.structs import AttestationFormat
    chal = b"\x02" * 32
    root_pem, leaf_der, leaf_key = make_attestation_ca()
    cred = auth.register(chal, fmt="packed", attestation_key=leaf_key, x5c=[leaf_der])
    entry = keys_webauthn.verify_enrollment(cred, chal, ORIGIN, roots={AttestationFormat.PACKED: [root_pem]})
    assert entry["attestation_verified"] is True and entry["attestation"]["roots"] == "configured"
    # the same chain with no root configured is checked for nothing, so it is not "verified"
    entry = keys_webauthn.verify_enrollment(cred, chal, ORIGIN, roots={})
    assert entry["attestation_verified"] is False and entry["attestation"]["x5c_present"] is True
    # self attestation (no x5c) is never verified
    entry = keys_webauthn.verify_enrollment(auth.register(chal, fmt="packed"), chal, ORIGIN, roots={})
    assert entry["attestation_verified"] is False


def test_enrollment_refusals(auth, monkeypatch):
    chal = b"\x03" * 32
    with pytest.raises(keys_webauthn.EnrollmentRefused, match="did not verify"):
        keys_webauthn.verify_enrollment(auth.register(chal, uv=False), chal, ORIGIN, roots={})
    with pytest.raises(keys_webauthn.EnrollmentRefused, match="did not verify"):
        keys_webauthn.verify_enrollment(auth.register(chal), b"\x04" * 32, ORIGIN, roots={})
    with pytest.raises(keys_webauthn.EnrollmentRefused, match="SIB_REQUIRE_ATTESTATION"):
        keys_webauthn.verify_enrollment(auth.register(chal), chal, ORIGIN, roots={}, require_attestation=True)
    monkeypatch.setenv("SIB_REQUIRE_ATTESTATION", "1")
    with pytest.raises(keys_webauthn.EnrollmentRefused):
        keys_webauthn.verify_enrollment(auth.register(chal), chal, ORIGIN, roots={})


def test_attestation_roots_from_directory(tmp_path, monkeypatch):
    from webauthn.helpers.structs import AttestationFormat
    monkeypatch.delenv("SIB_ATTESTATION_ROOTS", raising=False)
    assert keys_webauthn.attestation_roots() == {}
    root_pem, _, _ = make_attestation_ca()
    (tmp_path / "vendor.pem").write_bytes(root_pem)
    monkeypatch.setenv("SIB_ATTESTATION_ROOTS", str(tmp_path))
    roots = keys_webauthn.attestation_roots()
    assert roots[AttestationFormat.PACKED] == [root_pem] and AttestationFormat.TPM in roots


# ---- a real assertion, when one has been recorded on a laptop ----

@pytest.mark.skipif(not FIXTURE.exists(), reason="no recorded assertion; see docs/guide/components/signing.qmd")
def test_recorded_real_assertion(sib_home):
    """`tests/fixtures/webauthn/real_assertion.json` holds a block signed with
    a real passkey and the registry entry for it, recorded with
    `sib sign` on the laptop. The verifier must accept it in enforced mode."""
    fx = json.loads(FIXTURE.read_text())
    reg = Registry()
    reg.signers = {s["signer"]: s["keys"] for s in fx["registry"]["signers"]}
    for k, v in (fx["registry"].get("allowed_aaguids") or {}).items():
        reg.allow_aaguid(k, v)
    now = dt.datetime.strptime(fx["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
    r = _v(fx["block"], reg, audience=fx.get("audience"), now=now)
    assert r.status == "verified", r.error
    assert _v(fx["block"].replace(fx["tamper"][0], fx["tamper"][1]), reg, audience=fx.get("audience"), now=now).status == "invalid_signature"
