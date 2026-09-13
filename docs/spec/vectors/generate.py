#!/usr/bin/env python3
"""Generate the conformance test vectors and check each one against the
reference verifier before writing it.

  .venv/bin/python docs/spec/vectors/generate.py

Each vector is a JSON file holding the block, the registry the verifier is
given, the verification inputs, and the status a conforming verifier MUST
produce. A fixed dev key is generated fresh on every run, so the signatures
change between runs while the expected statuses do not.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))
os.environ["SIB_HOME"] = tempfile.mkdtemp(prefix="sib-vectors-")

from sib import keys_dev  # noqa: E402
from sib.b64 import b64u_encode  # noqa: E402
from sib.canon import canonicalize  # noqa: E402
from sib.envelope import extract, render  # noqa: E402
from sib.header import Header, format_time, signing_input  # noqa: E402
from sib.nonce_store import NoopNonceStore  # noqa: E402
from sib.registry import Registry  # noqa: E402
from sib.verify import clear_lines, verify_block  # noqa: E402

ALICE = "alice@example.com"
KID = "alice@example.com#dev-2026-09"
AUD = "acme/dev-agent"
NOW = dt.datetime(2026, 9, 13, 12, 0, 0, tzinfo=dt.timezone.utc)
TEXT = "You may deploy the current main branch to staging with\nscripts/deploy.sh staging whenever the test suite passes."


def make(text, *, kid=KID, signer=ALICE, aud=AUD, canon="text/1", header_canon=None, iat=None, exp=None,
         mode="dev", clear=None, jti=None):
    h = Header(alg="EdDSA", kid=kid, canon=header_canon or canon, iss=signer,
               iat=format_time(iat or NOW - dt.timedelta(minutes=5)),
               exp=format_time(exp or NOW + dt.timedelta(hours=8)),
               jti=jti or b64u_encode(secrets.token_bytes(12)), mode=mode, aud=aud)
    hb = h.encode()
    sig = keys_dev.sign(kid, signing_input(hb, canonicalize(canon, text)))
    return render(text, f"{hb}..{sig}", clear if clear is not None else clear_lines(h))


def registry_dict(reg: Registry) -> dict:
    return {"signers": [{"signer": s, "keys": ks} for s, ks in reg.signers.items()]}


def main() -> None:
    pub = keys_dev.generate(KID)
    reg = Registry()
    reg.add_key(ALICE, KID, "EdDSA", pub, mode="dev")
    keys_dev.generate("alice@example.com#other")
    keys_dev.generate("mallory@example.com#k")

    good = make(TEXT)
    vectors: list[dict] = []

    def add(name, block, expected, *, now=NOW, audience=AUD, mode="dev", registry=None, note=""):
        vectors.append({"name": name, "note": note, "block": block,
                        "registry": registry_dict(registry or reg),
                        "inputs": {"now": format_time(now), "audience": audience, "mode": mode},
                        "expected_status": expected})

    add("verified", good, "verified", note="The block as signed.")
    add("verified_after_transport", "\n".join("> " + l for l in good.replace("staging with\n", "staging with ").splitlines()),
        "verified", note="Quoted with '> ', one line re-wrapped: canonical text unchanged.")
    add("invalid_signature", good.replace("to staging", "to production"), "invalid_signature",
        note="One word of the instruction changed after signing.")
    add("metadata_mismatch", good.replace("Audience: acme/dev-agent", "Audience: acme/prod-agent"), "metadata_mismatch",
        note="A clear metadata line edited; the signed header is intact.")
    add("expired", make(TEXT, iat=NOW - dt.timedelta(hours=9), exp=NOW - dt.timedelta(hours=1)), "expired")
    add("not_yet_valid", make(TEXT, iat=NOW + dt.timedelta(hours=1), exp=NOW + dt.timedelta(hours=2)), "not_yet_valid",
        note="Issued more than 60 s after `now`.")
    add("audience_mismatch", make(TEXT, aud="acme/ci-agent"), "audience_mismatch",
        note="Block audience acme/ci-agent presented to acme/dev-agent.")
    add("unknown_signer", make(TEXT, kid="mallory@example.com#k", signer="mallory@example.com"), "unknown_signer",
        note="Signer not in the registry.")
    add("unknown_key", make(TEXT, kid="alice@example.com#other"), "unknown_key",
        note="Signer is enrolled, this kid is not.")
    add("unknown_key_wrong_signer", make(TEXT, kid=KID, signer="bob@example.com"), "unknown_key",
        note="An enrolled kid used with a different iss.")
    add("dev_key_in_enforced_mode", good, "dev_key_in_enforced_mode", mode="enforced",
        note="Same block, verifier in enforced mode.")
    add("malformed_not_detached", good.replace("..", ".Zm9v."), "malformed",
        note="A payload segment is present; a block must be a detached JWS.")
    add("malformed_unknown_canon", make(TEXT, header_canon="yaml/1"), "malformed",
        note="Header names a canonicalization rule the verifier does not know.")

    # revoked: a registry copy with the key revoked
    reg2 = Registry()
    reg2.signers = json.loads(json.dumps(reg.signers))
    reg2.lookup(KID)[1]["revoked"] = True
    add("revoked", good, "revoked", registry=reg2, note="The key is marked revoked in the registry.")

    # Check every vector against the reference verifier before writing it.
    for v in vectors:
        r = Registry(path=Path(os.environ["SIB_HOME"]) / "nonexistent.json")
        r.signers = {s["signer"]: s["keys"] for s in v["registry"]["signers"]}
        blocks = extract(v["block"])
        assert len(blocks) == 1, v["name"]
        now = dt.datetime.strptime(v["inputs"]["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
        res = verify_block(blocks[0], now, v["inputs"]["audience"], r, NoopNonceStore(), "vectors", v["inputs"]["mode"])
        assert res.status == v["expected_status"], f"{v['name']}: got {res.status}, expected {v['expected_status']} ({res.error})"
        v["expected_text"] = res.text
        (HERE / f"{v['name']}.json").write_text(json.dumps(v, indent=2, ensure_ascii=False) + "\n")
    (HERE / "index.json").write_text(json.dumps([{"name": v["name"], "expected_status": v["expected_status"], "note": v["note"]}
                                                 for v in vectors], indent=2) + "\n")
    print(f"wrote {len(vectors)} vectors, all checked against the reference verifier")


if __name__ == "__main__":
    main()
