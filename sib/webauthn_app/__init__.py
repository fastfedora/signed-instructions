"""Local WebAuthn signing app and the CLI bridge to it. `enroll_in_browser`
and `sign_in_browser` start the app on demand, open the page, wait for the
authenticator's answer and stop the app again."""
from __future__ import annotations

import errno
import os
import shlex
import socket
import subprocess
import sys
import threading
import time
import webbrowser

from .. import keys_webauthn
from .app import AppState, create_app, sign_challenge


class BrowserFlowError(RuntimeError):
    pass


def check_can_listen(port: int, origin: str) -> None:
    """Bind-test before starting the server, so the three reasons it can fail do
    not share one message.

    uvicorn logs its own error and the thread simply dies, which left the caller
    guessing: the old message blamed port contention even when the real cause was
    a sandbox refusing to let the process listen at all. That is the common case
    for an agent running `sib sign` itself, and it is worth naming, because the
    answer is not a different port — it is that signing is the user's own act and
    belongs in the user's own shell.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
    except PermissionError as e:
        raise BrowserFlowError(
            f"not permitted to listen on {origin} ({e}). A sandbox is blocking the loopback "
            f"listener, which is what agent sandboxes normally do. The signing ceremony needs "
            f"this server and your authenticator, so run the command yourself, in your own "
            f"terminal, rather than through an agent.") from None
    except OSError as e:
        if e.errno in (errno.EADDRINUSE, errno.EACCES):
            raise BrowserFlowError(
                f"{origin} is already in use; another sib command may be waiting on it. "
                f"SIB_WEBAUTHN_PORT changes the port.") from None
        raise BrowserFlowError(f"could not listen on {origin}: {e}") from None
    finally:
        s.close()


def open_url(url: str, browser: str | None = None) -> subprocess.Popen | None:
    """Open the page in the default browser, or in `browser`, else in
    `SIB_BROWSER`. Either may be a name the `webbrowser` module knows, such as
    `safari`, `chrome` or `firefox`. Only `browser`, which comes from
    `--browser`, may also be a command to run with the URL appended, such as
    `open -a Safari`.

    `SIB_BROWSER` is deliberately the weaker of the two. The browser is where
    the signer reads the text they are about to approve, so whatever opens it is
    part of the signing path; and a command taken from the environment could be
    anything, including something that opens no page at all while the signer
    waits for a prompt it will supply itself. An environment variable is set by
    anything that can write a line into a shell startup file, which an agent can
    do; `--browser` is typed by the person at the terminal. So the variable may
    choose among installed browsers and may not name a program.

    Returns the child process when a command was run, so a caller can wait on
    it, and None when the `webbrowser` module handled the URL itself.
    """
    from_flag = browser is not None
    browser = browser or os.environ.get("SIB_BROWSER")
    if not browser:
        webbrowser.open(url)
        return None
    try:
        webbrowser.get(browser).open(url)
        return None
    except webbrowser.Error:
        pass
    if not from_flag:
        raise BrowserFlowError(
            f"SIB_BROWSER={browser!r} is not a browser this platform knows. The variable may name an "
            f"installed browser, such as safari, chrome or firefox, but not a command to run: the "
            f"browser shows you what you are about to sign, so what opens it is part of signing. "
            f"Pass --browser {browser!r} yourself to run it as a command.")
    try:
        return subprocess.Popen(shlex.split(browser) + [url], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as e:
        raise BrowserFlowError(f"could not open the browser {browser!r}: {e}")


def run_in_browser(kind: str, payload: dict, challenge: bytes | None = None, timeout: float = 180,
                   open_browser: bool = True, browser: str | None = None) -> dict:
    """Serve one request on 127.0.0.1 and return its result. Raises
    BrowserFlowError on refusal, timeout or when the port is taken."""
    import uvicorn
    origin = keys_webauthn.default_origin()
    state = AppState()
    check_can_listen(keys_webauthn.port(), origin)
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
            open_url(url, browser)
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
                      open_browser: bool = True, browser: str | None = None) -> dict:
    """The registry entry fields for a passkey the signer just created."""
    return run_in_browser("enroll", {"signer": signer, "existing_credential_ids": existing_credential_ids,
                                     "allowed_aaguids": allowed_aaguids}, timeout=timeout, open_browser=open_browser,
                          browser=browser)


def sign_in_browser(header, ctext: str, key: dict, allowed_aaguids: dict, timeout: float = 180,
                    open_browser: bool = True, browser: str | None = None, action: str = "") -> dict:
    """`{"header": full header, "signature": b64url, "status": ..., "error": ..., "uvm": ...}`
    for the signing header `header` over the canonical text `ctext`.

    `action` is what the CLI will do with the block once it is signed, shown on
    the page alongside the text: the page is where the signer approves, so every
    term they are approving has to reach it.
    """
    return run_in_browser("sign", {"header": header, "ctext": ctext, "key": key, "allowed_aaguids": allowed_aaguids,
                                   "action": action},
                          challenge=sign_challenge(header, ctext), timeout=timeout, open_browser=open_browser,
                          browser=browser)


__all__ = ["run_in_browser", "open_url", "enroll_in_browser", "sign_in_browser", "BrowserFlowError"]
