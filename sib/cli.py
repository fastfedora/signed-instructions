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
from .first_run import confirm_on_terminal, git_signer
from .registry import Registry, resolve_audience, default_mode
from .verify import verify_block, clear_lines


def parse_duration(s: str) -> dt.timedelta:
    m = re.fullmatch(r"(\d+)([smhd])", s.strip())
    if not m:
        raise SystemExit(f"bad duration {s!r}; use e.g. 30m, 2h, 1d")
    n, unit = int(m.group(1)), m.group(2)
    return dt.timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]: n})


INSTRUCTION_FILES = ("AGENTS.md", "CLAUDE.md")


def find_instructions_file(start: Path | None = None) -> Path | None:
    """The nearest agent instructions file at or above `start`, or None.

    The nearest directory wins, and `AGENTS.md` wins over `CLAUDE.md` within
    one directory: a block belongs in the file the harness reading this
    checkout will actually load, and `AGENTS.md` is the one Codex reads.

    The walk stops at the repository root, or at the home directory outside a
    repository. Standing authorization is scoped to the project it was typed
    in; a block that drifted up into `~/CLAUDE.md` would authorize every
    checkout on the machine, which is not what anyone asked for by signing in
    one of them.
    """
    d = (start or Path.cwd()).resolve()
    home = Path.home().resolve()
    for p in (d, *d.parents):
        for name in INSTRUCTION_FILES:
            f = p / name
            if f.is_file():
                return f
        if (p / ".git").exists() or p == home:
            break
    return None


def resolve_destination(a) -> tuple[Path | None, bool]:
    """Where the block goes, as `(path, append)`; `(None, False)` is stdout.

    Resolved before the ceremony, so an unwritable path fails before the user
    is asked for a fingerprint rather than after.
    """
    if a.out and a.append:
        raise SystemExit("give --out or --append, not both")
    if a.append:
        return Path(a.append).expanduser(), True
    if a.out:
        return (None, False) if a.out == "-" else (Path(a.out).expanduser(), False)
    found = find_instructions_file()
    # Nothing found is not an error, and not a reason to create a file: without
    # instructions to append to there is nothing to be standing authorization
    # for, so the block goes to stdout and the caller decides.
    return (found, True) if found else (None, False)


def refuse_a_software_key_beside_a_passkey(reg: Registry, signer: str) -> None:
    """A software key enrolled for someone who already holds a passkey can only
    weaken what a signature from that person means.

    It signs from a file, with nobody present, and anything able to run `sib`
    can create one for any signer id it likes. Enforced mode is what keeps such
    a key from counting as authorization, which leaves a real guarantee resting
    on a single mode decision; refusing to enrol the key at all is the cheaper
    half of that defence, and costs nothing, because a signer who has a passkey
    has no need of a second weaker key under the same name.
    """
    held = [k["kid"] for k in reg.signers.get(signer, [])
            if k.get("alg") == keys_webauthn.ALG and not k.get("revoked")]
    if held:
        raise SystemExit(f"refusing to enroll a software key for {signer}: they already hold a passkey "
                         f"({', '.join(held)}), and a software key signs with no human present. Create "
                         f"the key without --enroll if you need the file, or enroll it for a signer id "
                         f"that is not {signer}.")


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
        # Nobody named: fall back to the identity this machine commits as, but only when
        # a key is enrolled for it. Guessing a signer with no key would turn a missing
        # flag into an unknown_signer block, discovered far from the cause.
        guess = git_signer()
        if guess and any(not k.get("revoked") for k in reg.signers.get(guess, [])):
            print(f"signing as {guess} (git config user.email)", file=sys.stderr)
            signer = guess
        elif guess:
            raise SystemExit(f"give --kid or --signer: nothing is enrolled for {guess!r}, which is "
                             f"this machine's git identity")
        else:
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
    if a.enroll or a.audience:
        reg = Registry()
        if a.enroll:
            refuse_a_software_key_beside_a_passkey(reg, a.signer)
            reg.add_key(a.signer, kid, "EdDSA", pub, mode="dev")
        if a.audience:
            reg.default_audience = a.audience
        reg.save()
        if a.enroll:
            print(f"enrolled {kid} for {a.signer} in {reg.path} (dev mode, attestation_verified=false)")
        if a.audience:
            print(f"default audience {a.audience} recorded in {reg.path}")


def cmd_enroll(a):
    reg = Registry()
    if a.public_key:
        if not a.kid:
            raise SystemExit("--kid is required with --public-key")
        if a.dev or a.alg != keys_webauthn.ALG:
            refuse_a_software_key_beside_a_passkey(reg, a.signer)
        reg.add_key(a.signer, a.kid, a.alg, a.public_key, mode="dev" if a.dev else "enforced")
        reg.save()
        print(f"enrolled {a.kid} for {a.signer} in {reg.path}")
        if not a.dev and a.alg == keys_webauthn.ALG:
            print("warning: a key enrolled this way records no AAGUID, so its assertions fail with "
                  "authenticator_not_allowed in enforced mode. Use `sib enroll` without --public-key "
                  "for a passkey the verifier can accept.", file=sys.stderr)
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
    if len([s for s in (a.text, a.text_flag, a.file) if s]) > 1:
        raise SystemExit("give the instruction once: as an argument, with --text, or with --file")
    text = a.text if a.text is not None else a.text_flag
    if text is None:
        if a.file:
            text = Path(a.file).read_text() if a.file != "-" else sys.stdin.read()
        elif sys.stdin.isatty():
            # Reading a terminal here would hang with no prompt and no hint.
            raise SystemExit('nothing to sign: give the instruction as an argument, as\n'
                             '  sib sign "You may deploy the current main branch to staging."\n'
                             'or pipe it in on stdin.')
        else:
            text = sys.stdin.read()
    text = text.strip("\n")
    if not text.strip():
        raise SystemExit("nothing to sign")
    dest, append = resolve_destination(a)
    if a.canon not in RULES:
        raise SystemExit(f"unknown canonicalization {a.canon!r}; known: {', '.join(RULES)}")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    exp = now + parse_duration(a.expires) if a.expires else None
    reg = Registry()
    signer, kid = resolve_signer_and_kid(reg, a.signer, a.kid, dev=a.dev)
    key = reg.lookup(kid)[1]
    webauthn = key.get("alg") == keys_webauthn.ALG
    audience, aud_source = resolve_audience(a.audience)
    if webauthn and audience is None:
        raise SystemExit("--audience is required for a passkey-signed block: enforced mode refuses a block with no audience")
    alg, mode = (keys_webauthn.ALG, "enforced") if webauthn else ("EdDSA", "dev")
    ctext = canonicalize(a.canon, text)
    h = Header(alg=alg, kid=kid, canon=a.canon, iss=signer, iat=format_time(now), exp=format_time(exp) if exp else None,
               jti=b64u_encode(secrets.token_bytes(12)), mode=mode, aud=audience)
    hb = h.encode()
    # What-you-see-is-what-you-sign: show the exact canonical text and terms before signing.
    print("About to sign (canonical form):", file=sys.stderr)
    print("  " + ctext, file=sys.stderr)
    print(f"  signer={signer} kid={kid} expires={h.exp or 'never, valid until removed'} "
          f"canon={a.canon} mode={mode}\n"
          f"  audience={audience or 'any'}" + (f" (from {aud_source})" if audience else ""),
          file=sys.stderr)
    print(f"  {'appending to' if append else 'writing'} {dest}" if dest else "  printing the block to stdout",
          file=sys.stderr)
    # The page the signer approves on is served from http://localhost, an origin
    # any local process can take, and WebAuthn shows the authenticator's prompt
    # without the text. The code ties this terminal to that page.
    code = keys_webauthn.code_for_challenge(
        keys_webauthn.challenge(h.signing_header().encode(), ctext)) if webauthn else None
    if code:
        print(f"  confirmation code {code}, which the sign page must show", file=sys.stderr)
    if not a.yes:
        ok = confirm_on_terminal("Sign this instruction?")
        if ok is None:
            raise SystemExit("not signing: there is no terminal to confirm at. Pass -y to sign without "
                             "confirming, which is for a signer running unattended.")
        if not ok:
            raise SystemExit("not signing")
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
    if dest is None:
        print(block)
    elif append:
        # One blank line before the block, whatever state the file was left in.
        prior = dest.read_text() if dest.exists() else ""
        prefix = "\n" if not prior or prior.endswith("\n") else "\n\n"
        with dest.open("a") as f:
            f.write(prefix + block + "\n")
        print(f"appended to {dest}", file=sys.stderr)
    else:
        dest.write_text(block + "\n")
        print(f"wrote {dest}", file=sys.stderr)


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
    audience, aud_source = resolve_audience(a.audience)
    m = _verify_document(doc, audience, mode, reg)
    if a.json:
        print(to_json(m))
    else:
        if not m["spans"]:
            print("no signed instruction blocks found")
        for s in m["spans"]:
            tag = "VERIFIED" if s["status"] == "verified" else s["status"].upper()
            who = f" {s['signer']}" if s.get("signer") else ""
            print(f"[{s['id']}] {tag}{who} exp={s.get('expires_at') or 'never'} aud={s.get('audience')}"
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


def cmd_install_codex(a):
    from .codex.install import run_install
    run_install(config=a.config, audience=a.audience, sib_path=a.sib_path, home=a.home,
                print_only=a.print_only, assume_yes=a.assume_yes)


def cmd_audience(a):
    reg = Registry()
    if a.value:
        reg.default_audience = a.value
        reg.save()
        print(f"default audience {a.value} recorded in {reg.path}")
        return
    audience, source = resolve_audience(None)
    if audience is None:
        raise SystemExit("no audience set. `sib audience <name>` records one; it names this "
                         "authorization context, not the vendor, and must match what signers put "
                         "in a block")
    print(f"{audience}   (from {source})")


def cmd_allow_authenticator(a):
    """Widen the allowlist deliberately. The default list holds models known to
    verify their user biometrically; adding one is a policy decision, which is
    why it is a command and not a flag on `enroll`."""
    from . import keys_webauthn
    reg = Registry()
    aaguid = a.aaguid.lower()
    # the shape check comes first: the all-zero value is in the default list, but only
    # under its own attestation-gated rule, so "already allowed" would mislead
    if not keys_webauthn.is_model_aaguid(aaguid):
        raise SystemExit(f"{a.aaguid!r} is not a model AAGUID: give the UUID `sib enroll` reported. "
                         f"The empty and all-zero values name no model, and allowing them would "
                         f"accept every key with the field missing.")
    if aaguid in keys_webauthn.DEFAULT_ALLOWED_AAGUIDS:
        print(f"{aaguid} is already allowed: {keys_webauthn.DEFAULT_ALLOWED_AAGUIDS[aaguid]}")
        return
    try:
        reg.allow_aaguid(aaguid, a.label)
    except ValueError as e:
        raise SystemExit(str(e))
    reg.save()
    print(f"allowed {aaguid} ({a.label}) in {reg.path}")
    print("This authenticator's assertions now count as user-verified here. With attestation "
          "`none` the AAGUID is the authenticator's own claim, and a synced credential is not "
          "bound to one device.", file=sys.stderr)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sib", description="Signed Instruction Blocks")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="create a dev-mode Ed25519 key")
    k.add_argument("--signer", help="signer id; the kid defaults to <signer>#dev-<year>-<month>")
    k.add_argument("--kid", help="key identifier (default: derived from --signer)")
    k.add_argument("--dev", action="store_true", default=True); k.add_argument("--enroll", action="store_true")
    k.add_argument("--audience", help="record this as the registry's default audience, used by sign, "
                                      "verify and install when none is given")
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
    s.add_argument("--expires", help="validity window from now, as 30m, 2h or 1d "
                                      "(default: none, valid until the block is removed)")
    s.add_argument("--audience")
    s.add_argument("--canon", default="text/1")
    s.add_argument("text", nargs="?", help="the instruction to sign; read from stdin when absent")
    s.add_argument("--text", dest="text_flag", metavar="TEXT", help="the instruction to sign, as a flag rather than an argument")
    s.add_argument("--file", help="file holding the instruction, or - for stdin")
    s.add_argument("--out", help="write the block to this file, or - for stdout (default: append to the "
                                 "nearest AGENTS.md or CLAUDE.md, else stdout)")
    s.add_argument("--append", help="append the block to this file instead of searching for one")
    s.add_argument("-y", "--yes", action="store_true",
                   help="sign without confirming the terms first; for an unattended signer")
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
    cx = harness.add_parser("codex", help="auto-review policy that makes the reviewer verify signatures")
    from .codex.install import add_arguments as _cx_args
    _cx_args(cx); cx.set_defaults(fn=cmd_install_codex)


    aa = sub.add_parser("allow-authenticator", help="add an authenticator model to this registry's allowlist")
    aa.add_argument("aaguid", help="the AAGUID as `sib enroll` reported it")
    aa.add_argument("label", help="a name for it, for the warning messages")
    aa.set_defaults(fn=cmd_allow_authenticator)
    au = sub.add_parser("audience", help="show or set the registry's default audience")
    au.add_argument("value", nargs="?",
                    help="the authorization context to record (omit to show)")
    au.set_defaults(fn=cmd_audience)
    i = sub.add_parser("inspect", help="decode blocks without verifying"); i.add_argument("file"); i.set_defaults(fn=cmd_inspect)
    a = ap.parse_args(argv)
    if a.cmd == "keygen" and a.enroll and not a.signer:
        ap.error("--enroll requires --signer")
    a.fn(a)


if __name__ == "__main__":
    main()
