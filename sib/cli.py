"""`sib` command line: keygen, enroll, sign, verify, inspect (dev mode)."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import secrets
import sys
from pathlib import Path

from . import keys_dev
from .b64 import b64u_encode
from .canon import canonicalize, RULES
from .envelope import render, extract
from .header import Header, signing_input, format_time
from .manifest import build_manifest, render_classifier_note, to_json
from .nonce_store import NoopNonceStore
from .registry import Registry
from .verify import verify_block, clear_lines


def parse_duration(s: str) -> dt.timedelta:
    m = re.fullmatch(r"(\d+)([smhd])", s.strip())
    if not m:
        raise SystemExit(f"bad duration {s!r}; use e.g. 30m, 2h, 1d")
    n, unit = int(m.group(1)), m.group(2)
    return dt.timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[unit]: n})


def cmd_keygen(a):
    pub = keys_dev.generate(a.kid)
    print(f"dev key created for kid {a.kid}\npublic key: {pub}")
    if a.enroll:
        reg = Registry()
        reg.add_key(a.signer, a.kid, "EdDSA", pub, mode="dev")
        reg.save()
        print(f"enrolled {a.kid} for {a.signer} in {reg.path} (dev mode, attestation_verified=false)")


def cmd_enroll(a):
    reg = Registry()
    reg.add_key(a.signer, a.kid, a.alg, a.public_key, mode="dev" if a.dev else "enforced")
    reg.save()
    print(f"enrolled {a.kid} for {a.signer} in {reg.path}")


def cmd_sign(a):
    text = Path(a.file).read_text() if a.file and a.file != "-" else sys.stdin.read()
    text = text.strip("\n")
    if not text.strip():
        raise SystemExit("nothing to sign")
    if a.canon not in RULES:
        raise SystemExit(f"unknown canonicalization {a.canon!r}; known: {', '.join(RULES)}")
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    exp = now + parse_duration(a.expires)
    reg = Registry()
    found = reg.lookup(a.kid)
    if found is None or found[0] != a.signer:
        raise SystemExit(f"kid {a.kid!r} is not enrolled for {a.signer!r}; run `sib keygen --enroll` first")
    ctext = canonicalize(a.canon, text)
    h = Header(alg="EdDSA", kid=a.kid, canon=a.canon, iss=a.signer, iat=format_time(now), exp=format_time(exp),
               jti=b64u_encode(secrets.token_bytes(12)), mode="dev", aud=a.audience)
    hb = h.encode()
    # What-you-see-is-what-you-sign: show the exact canonical text and terms before signing.
    print("About to sign (canonical form):", file=sys.stderr)
    print("  " + ctext, file=sys.stderr)
    print(f"  signer={a.signer} kid={a.kid} expires={h.exp} audience={a.audience or 'any'} canon={a.canon} mode=dev",
          file=sys.stderr)
    sig = keys_dev.sign(a.kid, signing_input(hb, ctext))
    block = render(text, f"{hb}..{sig}", clear_lines(h))
    if a.out:
        Path(a.out).write_text(block + "\n")
        print(f"wrote {a.out}", file=sys.stderr)
    else:
        print(block)


def _verify_document(doc: str, audience: str | None, mode: str):
    reg = Registry()
    now = dt.datetime.now(dt.timezone.utc)
    blocks = extract(doc)
    results = [(verify_block(b, now, audience, reg, NoopNonceStore(), None, mode), {"role": "file", "source": "cli"})
               for b in blocks]
    return build_manifest(results, None, None, audience, mode)


def cmd_verify(a):
    doc = Path(a.file).read_text() if a.file != "-" else sys.stdin.read()
    mode = "enforced" if a.enforced else "dev"
    if mode == "dev":
        keys_dev.dev_warning()
    m = _verify_document(doc, a.audience, mode)
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


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sib", description="Signed Instruction Blocks (dev mode)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="create a dev-mode Ed25519 key"); k.add_argument("--kid", required=True)
    k.add_argument("--dev", action="store_true", default=True); k.add_argument("--enroll", action="store_true")
    k.add_argument("--signer", help="signer id to enroll the key for (with --enroll)"); k.set_defaults(fn=cmd_keygen)
    e = sub.add_parser("enroll", help="add a public key to the registry"); e.add_argument("--signer", required=True)
    e.add_argument("--kid", required=True); e.add_argument("--public-key", required=True)
    e.add_argument("--alg", default="EdDSA"); e.add_argument("--dev", action="store_true"); e.set_defaults(fn=cmd_enroll)
    s = sub.add_parser("sign", help="clearsign an instruction"); s.add_argument("--signer", required=True)
    s.add_argument("--kid", required=True); s.add_argument("--expires", default="2h"); s.add_argument("--audience")
    s.add_argument("--canon", default="text/1"); s.add_argument("--file", help="file to sign, or - for stdin")
    s.add_argument("--out"); s.set_defaults(fn=cmd_sign)
    v = sub.add_parser("verify", help="verify every block in a file"); v.add_argument("file")
    v.add_argument("--audience"); v.add_argument("--enforced", action="store_true"); v.add_argument("--json", action="store_true")
    v.set_defaults(fn=cmd_verify)
    i = sub.add_parser("inspect", help="decode blocks without verifying"); i.add_argument("file"); i.set_defaults(fn=cmd_inspect)
    a = ap.parse_args(argv)
    if a.cmd == "keygen" and a.enroll and not a.signer:
        ap.error("--enroll requires --signer")
    a.fn(a)


if __name__ == "__main__":
    main()
