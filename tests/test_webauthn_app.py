"""The local signing app, driven the way the pages drive it, with the fake
authenticator answering the browser's part; and the CLI bridge against a
live server."""
import json
import threading

import httpx
import pytest
from fastapi.testclient import TestClient

from sib import keys_webauthn
from sib.envelope import extract, render
from sib.header import Header, format_time
from sib.nonce_store import NoopNonceStore
from sib.registry import Registry
from sib.verify import verify_block, clear_lines
from sib.webauthn_app import run_in_browser, BrowserFlowError
from sib.webauthn_app.app import AppState, create_app, sign_challenge
from tests.conftest import ALICE, AUD
from tests.fake_authenticator import FakeAuthenticator, enroll_fake, ORIGIN, AAGUID

import datetime as dt

PKID = "alice@example.com#passkey-app"


def _client():
    state = AppState()
    return state, TestClient(create_app(state, ORIGIN))


def _header(kid=PKID):
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    return Header(alg=keys_webauthn.ALG, kid=kid, canon="text/1", iss=ALICE, iat=format_time(now),
                  exp=format_time(now + dt.timedelta(hours=1)), jti="n0nce", mode="enforced", aud=AUD)


# ---- enroll ----

def test_enroll_flow():
    state, c = _client()
    auth = FakeAuthenticator()
    allowed = {**keys_webauthn.DEFAULT_ALLOWED_AAGUIDS, AAGUID: "fake"}
    token = state.add("enroll", {"signer": ALICE, "existing_credential_ids": [], "allowed_aaguids": allowed})
    page = c.get(f"/enroll/{token}")
    assert page.status_code == 200 and ALICE in page.text and "navigator.credentials.create" in page.text
    assert c.post(f"/api/enroll/{token}/finish", json={}).status_code == 409   # options first
    opts = c.post(f"/api/enroll/{token}/options").json()
    assert opts["rp"]["id"] == "localhost" and opts["authenticatorSelection"]["userVerification"] == "required"
    assert opts["attestation"] == "direct" and opts["authenticatorSelection"]["authenticatorAttachment"] == "platform"
    challenge = keys_webauthn.b64u_decode(opts["challenge"])
    r = c.post(f"/api/enroll/{token}/finish", json=auth.register(challenge, uvm=[[2, 4, 2]]))
    assert r.status_code == 200, r.text
    assert r.json() == {"ok": True, "aaguid": AAGUID, "aaguid_allowed": True, "aaguid_label": "fake",
                        "attestation_format": "none", "attestation_verified": False}
    p = state.pending[token]
    assert p.done.is_set() and p.result["credential_id"] == auth.credential_id_b64u and p.result["transports"] == ["internal"]
    assert p.result["uvm"] == [[2, 4, 2]]
    # one-time token
    assert c.get(f"/enroll/{token}").status_code == 404
    assert c.post(f"/api/enroll/{token}/options").status_code == 404


def test_enroll_refusal_and_wrong_kind():
    state, c = _client()
    auth = FakeAuthenticator()
    token = state.add("enroll", {"signer": ALICE, "existing_credential_ids": [auth.credential_id_b64u], "allowed_aaguids": {}})
    assert c.get(f"/sign/{token}").status_code == 404      # an enroll token does not open the sign page
    opts = c.post(f"/api/enroll/{token}/options").json()
    assert opts["excludeCredentials"][0]["id"] == auth.credential_id_b64u
    challenge = keys_webauthn.b64u_decode(opts["challenge"])
    r = c.post(f"/api/enroll/{token}/finish", json=auth.register(challenge, uv=False))
    assert r.status_code == 400 and "did not verify" in r.json()["detail"]
    assert state.pending[token].error and state.pending[token].done.is_set()
    assert c.get(f"/enroll/{token}").status_code == 404
    # an authenticator off the allowlist enrolls, with the warning in the answer
    state2, c2 = _client()
    other = FakeAuthenticator(aaguid="11111111-2222-3333-4444-555555555555")
    token = state2.add("enroll", {"signer": ALICE, "existing_credential_ids": [], "allowed_aaguids": {}})
    opts = c2.post(f"/api/enroll/{token}/options").json()
    r = c2.post(f"/api/enroll/{token}/finish", json=other.register(keys_webauthn.b64u_decode(opts["challenge"])))
    assert r.json()["aaguid_allowed"] is False and r.json()["aaguid_label"] is None


# ---- sign ----

def _sign_request(state, auth, reg, text="You may deploy to staging with scripts/deploy.sh staging."):
    key = reg.lookup(PKID)[1]
    h = _header()
    payload = {"header": h, "ctext": text, "key": key, "allowed_aaguids": reg.allowed_aaguids()}
    return state.add("sign", payload, sign_challenge(h, text)), h


def test_sign_flow(sib_home):
    auth = FakeAuthenticator()
    reg = Registry()
    enroll_fake(reg, auth, ALICE, PKID)
    state, c = _client()
    text = "You may deploy to staging with scripts/deploy.sh staging."
    token, h = _sign_request(state, auth, reg, text)
    page = c.get(f"/sign/{token}").text
    for needle in (text, ALICE, PKID, h.exp, AUD, h.jti, "navigator.credentials.get"):
        assert needle in page
    assert "<h1>Enroll" not in page and "credentials.create" not in page   # nothing else on the page
    opts = c.post(f"/api/sign/{token}/options").json()
    assert opts["userVerification"] == "required" and opts["allowCredentials"][0]["id"] == auth.credential_id_b64u
    assert opts["allowCredentials"][0]["transports"] == ["internal"]
    challenge = keys_webauthn.b64u_decode(opts["challenge"])
    assert challenge == sign_challenge(h, text)
    r = c.post(f"/api/sign/{token}/finish", json=auth.get(challenge))
    assert r.json() == {"ok": True, "status": "verified", "error": None}
    res = state.pending[token].result
    block = render(text, f"{res['header'].encode()}..{res['signature']}", clear_lines(h))
    v = verify_block(extract(block)[0], dt.datetime.now(dt.timezone.utc), AUD, reg, NoopNonceStore(), "s", "enforced")
    assert v.status == "verified", v.error
    assert c.post(f"/api/sign/{token}/finish", json=auth.get(challenge)).status_code == 404


def test_sign_flow_reports_a_failed_assertion(sib_home):
    auth = FakeAuthenticator()
    reg = Registry()
    enroll_fake(reg, auth, ALICE, PKID)
    state, c = _client()
    token, h = _sign_request(state, auth, reg)
    challenge = keys_webauthn.b64u_decode(c.post(f"/api/sign/{token}/options").json()["challenge"])
    r = c.post(f"/api/sign/{token}/finish", json=auth.get(challenge, uv=False))
    assert r.json()["ok"] is False and r.json()["status"] == "uv_not_performed"
    assert state.pending[token].result["status"] == "uv_not_performed"
    # a different credential answering
    state, c = _client()
    token, h = _sign_request(state, auth, reg)
    challenge = keys_webauthn.b64u_decode(c.post(f"/api/sign/{token}/options").json()["challenge"])
    r = c.post(f"/api/sign/{token}/finish", json=FakeAuthenticator().get(challenge))
    assert r.json()["status"] == "unknown_key"
    # a response missing fields
    state, c = _client()
    token, h = _sign_request(state, auth, reg)
    assert c.post(f"/api/sign/{token}/finish", json={"rawId": "x"}).status_code == 400


# ---- the bridge against a live server ----

def test_run_in_browser_round_trip(sib_home, monkeypatch):
    monkeypatch.setenv("SIB_WEBAUTHN_PORT", "17391")
    auth = FakeAuthenticator(origin=keys_webauthn.default_origin())
    reg = Registry()
    enroll_fake(reg, auth, ALICE, PKID)
    text = "Deploy to staging."
    h = _header()
    payload = {"header": h, "ctext": text, "key": reg.lookup(PKID)[1], "allowed_aaguids": reg.allowed_aaguids()}

    def browser():
        base = keys_webauthn.default_origin()
        # find the token the way a person would: it is in the URL the CLI printed; here, from the state
        for _ in range(200):
            try:
                httpx.get(base + "/nope", timeout=1)
                break
            except httpx.HTTPError:
                import time; time.sleep(0.05)
        token = holder["token"]
        assert text in httpx.get(f"{base}/sign/{token}").text
        opts = httpx.post(f"{base}/api/sign/{token}/options").json()
        httpx.post(f"{base}/api/sign/{token}/finish", json=auth.get(keys_webauthn.b64u_decode(opts["challenge"])))

    holder = {}
    import sib.webauthn_app as wa
    real_add = AppState.add

    def spy_add(self, kind, payload, challenge=None):
        holder["token"] = real_add(self, kind, payload, challenge)
        return holder["token"]
    monkeypatch.setattr(AppState, "add", spy_add)
    t = threading.Thread(target=browser, daemon=True)
    t.start()
    res = run_in_browser("sign", payload, sign_challenge(h, text), timeout=20, open_browser=False)
    t.join(5)
    assert res["status"] == "verified"
    # the server stopped: a second request on the same port starts a fresh one and times out cleanly
    with pytest.raises(BrowserFlowError, match="no answer"):
        run_in_browser("sign", payload, sign_challenge(h, text), timeout=0.5, open_browser=False)


def test_abort_ends_the_request_with_the_browser_error(sib_home):
    auth = FakeAuthenticator()
    reg = Registry()
    enroll_fake(reg, auth, ALICE, PKID)
    state, c = _client()
    token, h = _sign_request(state, auth, reg)
    assert c.post(f"/api/enroll/{token}/abort", json={"error": "x"}).status_code == 404   # wrong kind
    r = c.post(f"/api/sign/{token}/abort", json={"error": "The operation either timed out or was not allowed."})
    assert r.status_code == 200
    p = state.pending[token]
    assert p.done.is_set() and p.error == "the browser reported: The operation either timed out or was not allowed."
    assert c.get(f"/sign/{token}").status_code == 404


def test_open_url_picks_the_configured_browser(monkeypatch, tmp_path):
    import webbrowser
    from sib.webauthn_app import open_url, BrowserFlowError
    opened = []
    monkeypatch.setattr(webbrowser, "open", lambda url: opened.append(("default", url)))

    class Named:
        def open(self, url):
            opened.append(("named", url))

    def get(name):
        if name == "safari":
            return Named()
        raise webbrowser.Error(name)
    monkeypatch.setattr(webbrowser, "get", get)
    monkeypatch.delenv("SIB_BROWSER", raising=False)
    open_url("http://localhost:7391/x")
    assert opened[-1] == ("default", "http://localhost:7391/x")
    open_url("http://localhost:7391/x", "safari")
    assert opened[-1] == ("named", "http://localhost:7391/x")
    monkeypatch.setenv("SIB_BROWSER", "safari")
    open_url("http://localhost:7391/y")
    assert opened[-1] == ("named", "http://localhost:7391/y")
    # an unknown name is run as a command with the URL appended
    log = tmp_path / "log"
    script = tmp_path / "fakebrowser.sh"
    script.write_text(f'#!/bin/sh\necho "$@" > "{log}"\n')
    script.chmod(0o755)
    open_url("http://localhost:7391/z", f"{script} --new-window")
    import time
    for _ in range(50):
        if log.exists() and log.read_text().strip():
            break
        time.sleep(0.05)
    assert log.read_text().split() == ["--new-window", "http://localhost:7391/z"]
    with pytest.raises(BrowserFlowError, match="could not open"):
        open_url("http://localhost:7391/z", str(tmp_path / "missing-browser"))
