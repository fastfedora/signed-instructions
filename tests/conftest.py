import datetime as dt
import os
import secrets

import pytest

from sib import keys_dev
from sib.b64 import b64u_encode
from sib.canon import canonicalize
from sib.envelope import render
from sib.header import Header, signing_input, format_time
from sib.registry import Registry
from sib.verify import clear_lines

ALICE = "alice@example.com"
KID = "alice@example.com#dev-test"
AUD = "acme/dev-agent"


@pytest.fixture
def sib_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SIB_HOME", str(tmp_path / ".sib"))
    keys_dev._warned = False
    return tmp_path / ".sib"


@pytest.fixture
def registry(sib_home):
    pub = keys_dev.generate(KID)
    reg = Registry()
    reg.add_key(ALICE, KID, "EdDSA", pub, mode="dev")
    reg.save()
    return reg


def make_block(text, *, kid=KID, signer=ALICE, aud=AUD, canon="text/1", iat=None, exp=None,
               mode="dev", clear=None, jti=None, header_canon=None):
    """header_canon lets a test claim a rule in the header that differs from the one applied."""
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    h = Header(alg="EdDSA", kid=kid, canon=header_canon or canon, iss=signer,
               iat=format_time(iat or now - dt.timedelta(minutes=1)),
               exp=format_time(exp or now + dt.timedelta(hours=2)),
               jti=jti or b64u_encode(secrets.token_bytes(12)), mode=mode, aud=aud)
    hb = h.encode()
    sig = keys_dev.sign(kid, signing_input(hb, canonicalize(canon, text)))
    return render(text, f"{hb}..{sig}", clear if clear is not None else clear_lines(h)), h


@pytest.fixture
def block_factory(registry):
    return make_block
