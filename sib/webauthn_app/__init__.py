"""Local WebAuthn signing app and the CLI bridge to it. `enroll_in_browser`
and `sign_in_browser` start the app on demand, open the page, wait for the
authenticator's answer and stop the app again."""
from __future__ import annotations

import sys
import threading
import time
import webbrowser

from .. import keys_webauthn
from .app import AppState, create_app, sign_challenge


class BrowserFlowError(RuntimeError):
    pass


def run_in_browser(kind: str, payload: dict, challenge: bytes | None = None, timeout: float = 180,
                   open_browser: bool = True) -> dict:
    """Serve one request on 127.0.0.1 and return its result. Raises
    BrowserFlowError on refusal, timeout or when the port is taken."""
    import uvicorn
    origin = keys_webauthn.default_origin()
    state = AppState()
    token = state.add(kind, payload, challenge)
    server = uvicorn.Server(uvicorn.Config(create_app(state, origin), host="127.0.0.1", port=keys_webauthn.port(),
                                           log_level="warning", access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        if not thread.is_alive() or time.time() > deadline:
            raise BrowserFlowError(f"could not start the signing app on {origin}; is another sib command using the port? "
                                   f"(SIB_WEBAUTHN_PORT changes it)")
        time.sleep(0.02)
    url = f"{origin}/{kind}/{token}"
    try:
        print(f"Opening {url}", file=sys.stderr, flush=True)
        if open_browser:
            webbrowser.open(url)
        p = state.pending[token]
        if not p.done.wait(timeout):
            raise BrowserFlowError(f"no answer from the browser within {timeout:.0f} s")
        if p.error:
            raise BrowserFlowError(p.error)
        return p.result
    finally:
        server.should_exit = True
        thread.join(5)


def enroll_in_browser(signer: str, existing_credential_ids: list[str], allowed_aaguids: dict, timeout: float = 180,
                      open_browser: bool = True) -> dict:
    """The registry entry fields for a passkey the signer just created."""
    return run_in_browser("enroll", {"signer": signer, "existing_credential_ids": existing_credential_ids,
                                     "allowed_aaguids": allowed_aaguids}, timeout=timeout, open_browser=open_browser)


def sign_in_browser(header, ctext: str, key: dict, allowed_aaguids: dict, timeout: float = 180,
                    open_browser: bool = True) -> dict:
    """`{"header": full header, "signature": b64url, "status": ..., "error": ..., "uvm": ...}`
    for the signing header `header` over the canonical text `ctext`."""
    return run_in_browser("sign", {"header": header, "ctext": ctext, "key": key, "allowed_aaguids": allowed_aaguids},
                          challenge=sign_challenge(header, ctext), timeout=timeout, open_browser=open_browser)


__all__ = ["run_in_browser", "enroll_in_browser", "sign_in_browser", "BrowserFlowError"]
