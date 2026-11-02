import datetime as dt

import pytest

from sib import keys_dev
from sib.envelope import extract, render, Block
from sib.nonce_store import NoopNonceStore
from sib.registry import Registry
from sib.verify import verify_block, STATUSES
from tests.conftest import ALICE, KID, AUD, NO_EXPIRY, make_block

NOW = None


def _v(doc, registry, audience=AUD, mode="dev", now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    blocks = extract(doc)
    assert len(blocks) == 1
    return verify_block(blocks[0], now, audience, registry, NoopNonceStore(), "s1", mode)


def test_verified(block_factory, registry):
    doc, h = block_factory("Deploy to staging with scripts/deploy.sh staging.")
    r = _v(doc, registry)
    assert r.status == "verified" and r.signer == ALICE and r.text == "Deploy to staging with scripts/deploy.sh staging."


def test_verified_after_transport_mangling(block_factory, registry):
    doc, _ = block_factory("Deploy “now” to staging\nwith scripts/deploy.sh staging.")
    mangled = "\n".join("> " + l for l in doc.splitlines()).replace("“now”", '"now"')
    mangled = mangled.replace("staging\n> with", "staging with")
    assert _v(mangled, registry).status == "verified"


def test_invalid_signature_on_tamper(block_factory, registry):
    doc, _ = block_factory("Deploy to staging.")
    r = _v(doc.replace("to staging", "to production"), registry)
    assert r.status == "invalid_signature" and r.signer == ALICE and "production" in r.text


def test_metadata_mismatch(block_factory, registry):
    doc, h = block_factory("Deploy to staging.")
    doc = doc.replace(f"Expires: {h.exp}", "Expires: 2099-01-01T00:00:00Z")
    assert _v(doc, registry).status == "metadata_mismatch"


def test_expired_and_not_yet_valid(block_factory, registry):
    now = dt.datetime.now(dt.timezone.utc)
    doc, _ = block_factory("x", iat=now - dt.timedelta(hours=3), exp=now - dt.timedelta(hours=1))
    assert _v(doc, registry).status == "expired"
    doc, _ = block_factory("x", iat=now + dt.timedelta(hours=1), exp=now + dt.timedelta(hours=2))
    assert _v(doc, registry).status == "not_yet_valid"


def test_audience_mismatch(block_factory, registry):
    doc, _ = block_factory("x", aud="acme/ci-agent")
    assert _v(doc, registry).status == "audience_mismatch"
    doc, _ = block_factory("x", aud=None)
    assert _v(doc, registry).status == "verified"           # dev mode tolerates no audience
    assert _v(doc, registry, mode="enforced").status in ("dev_key_in_enforced_mode",)


def test_unknown_signer_and_key(block_factory, registry, sib_home):
    keys_dev.generate("mallory@example.com#k")
    doc, _ = make_block("x", kid="mallory@example.com#k", signer="mallory@example.com")
    assert _v(doc, registry).status == "unknown_signer"
    keys_dev.generate("alice@example.com#other")
    doc, _ = make_block("x", kid="alice@example.com#other", signer=ALICE)
    assert _v(doc, registry).status == "unknown_key"
    # a kid enrolled for alice but used with another iss
    doc, _ = make_block("x", kid=KID, signer="bob@example.com")
    assert _v(doc, registry).status == "unknown_key"


def test_dev_key_in_enforced_mode(block_factory, registry):
    doc, _ = block_factory("x")
    assert _v(doc, registry, mode="enforced").status == "dev_key_in_enforced_mode"


def test_revoked(block_factory, registry):
    doc, _ = block_factory("x")
    registry.lookup(KID)[1]["revoked"] = True
    assert _v(doc, registry).status == "revoked"


def test_nonce_replayed(block_factory, registry):
    class Deny:
        def check(self, *a):
            return False
    doc, _ = block_factory("x")
    b = extract(doc)[0]
    r = verify_block(b, dt.datetime.now(dt.timezone.utc), AUD, registry, Deny(), "s2", "dev")
    assert r.status == "nonce_replayed"


def test_malformed_variants(block_factory, registry):
    doc, _ = block_factory("x")
    b = extract(doc)[0]
    now = dt.datetime.now(dt.timezone.utc)
    assert verify_block(Block(text="x", compact="notajws"), now, AUD, registry, NoopNonceStore()).status == "malformed"
    assert verify_block(Block(text="x", compact="eyJ..sig"), now, AUD, registry, NoopNonceStore()).status == "malformed"
    parts = b.compact.split(".")
    assert verify_block(Block(text="x", compact=parts[0] + ".payload." + parts[2]), now, AUD, registry,
                        NoopNonceStore()).status == "malformed"
    doc2, _ = block_factory("x", header_canon="yaml/1")
    assert _v(doc2, registry).status == "malformed"


def test_every_status_is_reachable():
    """The EdDSA path reaches these; test_webauthn.py covers the four ES256-webauthn statuses."""
    covered = {"verified", "invalid_signature", "unknown_signer", "unknown_key", "expired", "not_yet_valid",
               "audience_mismatch", "metadata_mismatch", "malformed", "nonce_replayed", "revoked",
               "dev_key_in_enforced_mode"}
    webauthn_only = {"origin_not_allowed", "rp_id_mismatch", "uv_not_performed", "authenticator_not_allowed"}
    assert covered | webauthn_only == set(STATUSES)


def test_a_block_with_no_expiry_stays_valid(registry):
    """RFC 7519 4.1.4 makes exp optional, and a standing instruction is meant to
    last until it is removed from the file it lives in."""
    doc, h = make_block("You may deploy to staging.", exp=NO_EXPIRY)
    assert h.exp is None and '"exp"' not in h.to_json()        # omitted, not null
    assert "Expires:" not in doc                               # and not claimed in the clear text
    far = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=4000)
    assert _v(doc, registry).status == "verified"
    r = _v(doc, registry, now=far)
    assert r.status == "verified" and r.expires_at is None


def test_an_expiry_claimed_only_in_the_clear_text_is_a_mismatch(registry):
    """The clear lines are a human-readable echo and are not signed, so one
    claiming a term the header does not carry misleads a reader the verifier
    would otherwise have satisfied."""
    doc, _ = make_block("x", exp=NO_EXPIRY,
                        clear={"Signer": ALICE, "Audience": AUD, "Expires": "2099-01-01T00:00:00Z"})
    r = _v(doc, registry)
    assert r.status == "metadata_mismatch" and "has no Expires claim" in r.error
