"""`sib` command line: keygen, enroll, sign, verify, inspect."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import secrets
import sys
import time
from pathlib import Path

from . import keys_dev, keys_webauthn
from .b64 import b64u_encode, b64u_decode
from .canon import canonicalize, RULES
from .envelope import render, extract
from .header import Header, signing_input, format_time
from .manifest import build_manifest, render_classifier_note, to_json
from .nonce_store import NoopNonceStore
from .registry import Registry, default_mode
from .verify import verify_block, clear_lines


def parse_duration(s: str) -> dt.timedelta:
    m = re.fullmatch(r"(\d+)([smhd])", s.strip())
    if not m:
        raise SystemExit(f"bad duration {s!r}; use e.g. 30m, 2h, 1d")
    n, unit = int(m.group(1)), m.group(2)
    return dt.timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]: n})


def default_kid(signer: str) -> str:
    """Convention: signer#dev-<year>-<month>."""
    return f"{signer}#dev-{dt.datetime.now(dt.timezone.utc).strftime('%Y-%m')}"


def passkey_kid(signer: str, credential_id_b64u: str) -> str:
    """Convention: signer#passkey-<first two bytes of the credential id, hex>."""
    return f"{signer}#passkey-{b64u_decode(credential_id_b64u)[:2].hex()}"


def resolve_signer_and_kid(reg: Registry, signer: str | None, kid: str | None, dev: bool = False) -> tuple[str, str]:
    """Either identifier is enough. A kid names its signer through the registry;
    a signer with exactly one enrolled key names that key. Without --dev a
    signer's passkeys are preferred over their dev keys; with it only dev
    keys are considered."""
    if kid:
        found = reg.lookup(kid)
        if found is None:
            raise SystemExit(f"kid {kid!r} is not enrolled; run `sib keygen --enroll` or `sib enroll` first")
        if signer and found[0] != signer:
            raise SystemExit(f"kid {kid!r} is enrolled for {found[0]!r}, not {signer!r}")
        if dev and found[1].get("alg") != "EdDSA":
            raise SystemExit(f"kid {kid!r} is a {found[1].get('alg')} key; --dev signs with a dev key")
        return found[0], kid
    if not signer:
        raise SystemExit("give --kid or --signer")
    keys = [k for k in reg.signers.get(signer, []) if not k.get("revoked")]
    if dev:
        keys = [k for k in keys if k.get("alg") == "EdDSA"]
    else:
        passkeys = [k for k in keys if k.get("alg") == keys_webauthn.ALG]
        keys = passkeys or keys
    if not keys:
        raise SystemExit(f"no enrolled {'dev ' if dev else ''}key for {signer!r}; run `sib enroll --signer {signer}` "
                         f"(passkey) or `sib keygen --signer {signer} --enroll` (dev key) first")
    if len(keys) > 1:
        raise SystemExit(f"{signer!r} has several keys; choose one with --kid: " + ", ".join(k["kid"] for k in keys))
    return signer, keys[0]["kid"]


def cmd_keygen(a):
    if not a.kid and not a.signer:
        raise SystemExit("give --signer (the kid is derived) or --kid")
    kid = a.kid or default_kid(a.signer)
    pub = keys_dev.generate(kid)
    print(f"dev key created for kid {kid}\npublic key: {pub}")
    if a.enroll:
        reg = Registry()
        reg.add_key(a.signer, kid, "EdDSA", pub, mode="dev")
        reg.save()
        print(f"enrolled {kid} for {a.signer} in {reg.path} (dev mode, attestation_verified=false)")


def cmd_enroll(a):
    reg = Registry()
    if a.public_key:
        if not a.kid:
            raise SystemExit("--kid is required with --public-key")
        reg.add_key(a.signer, a.kid, a.alg, a.public_key, mode="dev" if a.dev else "enforced")
        reg.save()
        print(f"enrolled {a.kid} for {a.signer} in {reg.path}")
        return
    from .webauthn_app import enroll_in_browser, BrowserFlowError
    existing = [k["credential_id"] for k in reg.signers.get(a.signer, []) if k.get("credential_id")]
    try:
        entry = enroll_in_browser(a.signer, existing, reg.allowed_aaguids(), timeout=a.timeout,
                                  open_browser=not a.no_browser, browser=a.browser)
    except BrowserFlowError as e:
        raise SystemExit(f"enrollment failed: {e}")
    kid = a.kid or passkey_kid(a.signer, entry["credential_id"])
    reg.add_key(a.signer, kid, keys_webauthn.ALG, entry.pop("public_key"), mode="enforced",
                attestation_verified=entry.pop("attestation_verified"), attestation=entry.pop("attestation"), **entry)
    reg.save()
    key = reg.lookup(kid)[1]
    allowed, label = keys_webauthn.aaguid_allowed(key, reg.allowed_aaguids())
    att = key["attestation"]
    print(f"enrolled {kid} for {a.signer} in {reg.path} (enforced mode, authenticator {key['aaguid']}"
          f"{' ' + label if allowed else ''}, attestation {att['format']}"
          f"{' verified' if key['attestation_verified'] else ' not verified'})")
    if not allowed:
        print(f"warning: authenticator {label} is not on the biometric-capable allowlist; blocks signed with {kid} "
              f"fail with authenticator_not_allowed until it is added under allowed_aaguids in {reg.path}",
              file=sys.stderr)
    if not key["attestation_verified"]:
        print("attestation_verified=false: the AAGUID is the authenticator's own claim; hardware backing is an "
              "enrollment assumption for this key", file=sys.stderr)


def cmd_sign(a):
    if a.text is not None and a.file:
        raise SystemExit("give --text or --file, not both")
    if a.text is not None:
        text = a.text
    else:
        text = Path(a.file).read_text() if a.file and a.file != "-" else sys.stdin.read()
    text = text.strip("\n")
    if not text.strip():
        raise SystemExit("nothing to sign")
    if a.canon not in RULES:
        raise SystemExit(f"unknown canonicalization {a.canon!r}; known: {', '.join(RULES)}")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    exp = now + parse_duration(a.expires)
    reg = Registry()
    signer, kid = resolve_signer_and_kid(reg, a.signer, a.kid, dev=a.dev)
    key = reg.lookup(kid)[1]
    webauthn = key.get("alg") == keys_webauthn.ALG
    if webauthn and a.audience is None:
        raise SystemExit("--audience is required for a passkey-signed block: enforced mode refuses a block with no audience")
    alg, mode = (keys_webauthn.ALG, "enforced") if webauthn else ("EdDSA", "dev")
    ctext = canonicalize(a.canon, text)
    h = Header(alg=alg, kid=kid, canon=a.canon, iss=signer, iat=format_time(now), exp=format_time(exp),
               jti=b64u_encode(secrets.token_bytes(12)), mode=mode, aud=a.audience)
    hb = h.encode()
    # What-you-see-is-what-you-sign: show the exact canonical text and terms before signing.
    print("About to sign (canonical form):", file=sys.stderr)
    print("  " + ctext, file=sys.stderr)
    print(f"  signer={signer} kid={kid} expires={h.exp} audience={a.audience or 'any'} canon={a.canon} mode={mode}",
          file=sys.stderr)
    if webauthn:
        from .webauthn_app import sign_in_browser, BrowserFlowError
        t0 = time.time()
        try:
            res = sign_in_browser(h, ctext, key, reg.allowed_aaguids(), timeout=a.timeout,
                                  open_browser=not a.no_browser, browser=a.browser)
        except BrowserFlowError as e:
            raise SystemExit(f"signing failed: {e}")
        if res["status"] != "verified":
            raise SystemExit(f"the assertion did not verify: {res['status']} ({res['error']}); no block written")
        compact = f"{res['header'].encode()}..{res['signature']}"
        print(f"signed with {kid} in {time.time() - t0:.1f} s" + (f", uvm {res['uvm']}" if res.get("uvm") else ""),
              file=sys.stderr)
    else:
        compact = f"{hb}..{keys_dev.sign(kid, signing_input(hb, ctext))}"
    block = render(text, compact, clear_lines(h))
    if a.out:
        Path(a.out).write_text(block + "\n")
        print(f"wrote {a.out}", file=sys.stderr)
    else:
        print(block)


def _verify_document(doc: str, audience: str | None, mode: str, reg: Registry):
    now = dt.datetime.now(dt.timezone.utc)
    blocks = extract(doc)
    results = [(verify_block(b, now, audience, reg, NoopNonceStore(), None, mode), {"role": "file", "source": "cli"})
               for b in blocks]
    return build_manifest(results, None, None, audience, mode)


def cmd_verify(a):
    doc = Path(a.file).read_text() if a.file != "-" else sys.stdin.read()
    reg = Registry()
    mode = "enforced" if a.enforced else "dev" if a.dev else default_mode(reg)
    if mode == "dev":
        keys_dev.dev_warning()
    m = _verify_document(doc, a.audience, mode, reg)
    if a.json:
        print(to_json(m))
    else:
        if not m["spans"]:
            print("no signed instruction blocks found")
        for s in m["spans"]:
            tag = "VERIFIED" if s["status"] == "verified" else s["status"].upper()
            who = f" {s['signer']}" if s.get("signer") else ""
            print(f"[{s['id']}] {tag}{who} exp={s.get('expires_at')} aud={s.get('audience')}"
                  + (f"\n     error: {s['error']}" if s.get("error") else ""))
            if s.get("text"):
                print(f"     text: {s['text']}")
        print("\nclassifier note:\n" + render_classifier_note(m))
    sys.exit(0 if m["spans"] and all(s["status"] == "verified" for s in m["spans"]) else 1)


def cmd_inspect(a):
    doc = Path(a.file).read_text() if a.file != "-" else sys.stdin.read()
    for i, b in enumerate(extract(doc), 1):
        parts = b.compact.split(".")
        print(f"--- block {i} (chars {b.start}-{b.end}, prefix {b.prefix!r})")
        print("text as written:\n" + b.text)
        print("clear lines:", json.dumps(b.clear))
        try:
            print("header:", json.dumps(Header.decode(parts[0]).to_dict(), indent=2))
        except Exception as e:  # noqa: BLE001
            print("header: MALFORMED:", e)
        print("signature:", parts[-1][:32] + "...")


def cmd_install_claude_code(a):
    from .hooks.claude_code.install import run_install
    run_install(project=a.project, settings_json=a.settings_json,
                layers=tuple(x for x in a.layers.split(",") if x),
                no_prose=a.no_prose, print_auto_mode=a.print_auto_mode)


def cmd_install_codex(a):
    from .codex.install import run_install
    run_install(config=a.config, audience=a.audience, sib_path=a.sib_path, home=a.home,
                print_only=a.print_only, assume_yes=a.assume_yes)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sib", description="Signed Instruction Blocks")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="create a dev-mode Ed25519 key")
    k.add_argument("--signer", help="signer id; the kid defaults to <signer>#dev-<year>-<month>")
    k.add_argument("--kid", help="key identifier (default: derived from --signer)")
    k.add_argument("--dev", action="store_true", default=True); k.add_argument("--enroll", action="store_true")
    k.set_defaults(fn=cmd_keygen)
    e = sub.add_parser("enroll", help="enroll a passkey in the browser, or add a public key given on the command line")
    e.add_argument("--signer", required=True)
    e.add_argument("--kid", help="key identifier (default: <signer>#passkey-<id>)")
    e.add_argument("--public-key", help="enroll this raw public key (base64url) instead of a passkey")
    e.add_argument("--alg", default="EdDSA", help="algorithm of --public-key"); e.add_argument("--dev", action="store_true")
    e.add_argument("--timeout", type=float, default=180, help="seconds to wait for the browser")
    e.add_argument("--no-browser", action="store_true", help="print the page URL instead of opening a browser")
    e.add_argument("--browser", help="browser to open the page in (default: SIB_BROWSER, else the system default): "
                   "a name such as safari, chrome or firefox, or a command such as 'open -a Safari'")
    e.set_defaults(fn=cmd_enroll)
    s = sub.add_parser("sign", help="clearsign an instruction; give --kid, or --signer when they hold one key")
    s.add_argument("--signer", help="signer id (derived from --kid through the registry when omitted)")
    s.add_argument("--kid", help="key identifier (derived from --signer when the signer has one enrolled key)")
    s.add_argument("--expires", default="2h"); s.add_argument("--audience")
    s.add_argument("--canon", default="text/1")
    s.add_argument("--text", help="the instruction to sign, given directly")
    s.add_argument("--file", help="file holding the instruction, or - for stdin (default when --text is absent)")
    s.add_argument("--out")
    s.add_argument("--dev", action="store_true", help="sign with a dev key even when a passkey is enrolled")
    s.add_argument("--timeout", type=float, default=180, help="seconds to wait for the browser")
    s.add_argument("--no-browser", action="store_true", help="print the page URL instead of opening a browser")
    s.add_argument("--browser", help="as for enroll")
    s.set_defaults(fn=cmd_sign)
    v = sub.add_parser("verify", help="verify every block in a file"); v.add_argument("file")
    v.add_argument("--audience"); v.add_argument("--json", action="store_true")
    v.add_argument("--enforced", action="store_true", help="enforced mode (the default once a passkey is enrolled)")
    v.add_argument("--dev", action="store_true", help="dev mode (the default until a passkey is enrolled)")
    v.set_defaults(fn=cmd_verify)
    n = sub.add_parser("install", help="install SIB into an agent harness")
    harness = n.add_subparsers(dest="harness", required=True)
    cc = harness.add_parser("claude-code", help="hooks that verify and report provenance to the classifier")
    from .hooks.claude_code.install import add_arguments as _cc_args
    _cc_args(cc); cc.set_defaults(fn=cmd_install_claude_code)
    cx = harness.add_parser("codex", help="auto-review policy that makes the reviewer verify signatures")
    from .codex.install import add_arguments as _cx_args
    _cx_args(cx); cx.set_defaults(fn=cmd_install_codex)
    i = sub.add_parser("inspect", help="decode blocks without verifying"); i.add_argument("file"); i.set_defaults(fn=cmd_inspect)
    a = ap.parse_args(argv)
    if a.cmd == "keygen" and a.enroll and not a.signer:
        ap.error("--enroll requires --signer")
    a.fn(a)


if __name__ == "__main__":
    main()
