# Phase 3 — Hardening, four scenarios, transport, attack suite, README spec

**Estimate:** 1–2 weeks.

**Prerequisites:** Phase 2 green. Completing this phase equals the workshop-prize scope (PDF §8).

## Goal

Turn the working prototype into something a stranger can run and attack: full
replay protection, origin labelling, all four scenarios automated, the S1–S5
attack suite as regression tests, Slack round-trip proven, and a README-level
spec with test vectors.

## What this phase proves

- Every threat S1–S5 maps to a rule in the spec and a failing test that the
  implementation passes.

- The SIB survives Slack, email, and a GitHub comment unchanged in meaning.

- Someone else can clone the repo and reach a verified classifier decision in
  under 15 minutes (RI-5 target, measured on one volunteer).

## Work items

### 3.1 Replay, expiry, audience, revocation (S3, SG-6)

- `nonce_store.py`: SQLite or JSONL under `~/.sib/state/`. Key `(aud, nonce)`
  → first-seen `session_id`. Same session re-verifying is fine; a different
  session → `nonce_replayed`.

- Clock skew allowance (proposal: 60 s) on `iat`; `exp` strict **when
  present**. The `exp - iat` cap is withdrawn — see the amendment below.

- Audience: the harness passes its audience id to the verifier (from the
  testbed `policy.yaml` or `SIB_AUDIENCE`). Missing `aud` in a block is
  allowed only in dev mode.

- Revocation: `~/.sib/revoked.jsonl` of `(kid, nonce)` or whole-key entries;
  `sib revoke <block|kid>` appends; verifier checks it (`revoked`).

#### Amendment, 26 October 2026: `exp` is optional, which promotes this item

`exp` was made optional, as RFC 7519 §4.1.4 has it, and `sib sign` now omits it
by default. A block with no `exp` is valid until it is removed from the file it
lives in, which is what standing authorization in an instruction file is meant
to mean. Three consequences for this work item, none of them cosmetic.

The `exp - iat` cap contradicts the decision and is withdrawn. A policy ceiling
on validity would re-impose the expiry the signer deliberately declined, and it
would do so silently, at verify time, far from the person who chose otherwise.
If a deployment wants to insist on bounded authorizations, that belongs in its
own policy text, not in the verifier.

Block revocation stops being a convenience and becomes the only way to withdraw
an unbounded authorization. Today revocation exists at key level only
(`verify.py:107`), and there is no `sib revoke` command at all, so the only way
to retract a standing block is to revoke its key — which invalidates every other
block that key ever signed. The `(kid, nonce)` entry in the bullet above is the
piece that matters now, and `sib revoke <block>` should land with it.

And deleting a block from `AGENTS.md` is not revocation. It stops *that* copy
being read; a copy pasted into another repository, a ticket or a chat still
verifies, now without an expiry to limit it. The user's mental model — "valid
until I delete it" — is only true if deletion is accompanied by a revocation
record the verifier consults. Until `sib revoke` exists, the guide should say so
plainly rather than imply that removal is withdrawal.

### 3.2 Origin labelling (VE-3)

- Decide and document what "origin" means per source: `prompt` (typed or
  pasted by the operator), `tool_result` (with tool name and, for file reads,
  the path), `assistant` (agent-authored), `subagent` (with `agent_id` /
  `agent_type` from the hook input when available).

- Manifest gains a `context` summary: counts per role and the list of
  envelope-bearing messages. Everything else remains implicitly unsigned.

- The classifier reason string always names the origin of the nearest
  unsigned authority claim when denying, so demos read well.

### 3.3 Four scenarios automated

- Scenarios 1–4 from `plans/README.md` as YAML under `scenarios/`, run by the
  Phase 0 runner, each with an `expected` block (deploy marker present or
  absent, decision, status values in the manifest, cited span ids).

- `make demo` runs all four and prints a pass/fail table plus rates.

### 3.4 Transport round-trips (TR-1, TR-2, S5)

- Automated simulation of transformations, applied to a valid envelope and
  asserted to still verify: smart quotes, en/em dash substitution in markers,
  hard wrapping at 40/72/80 columns, leading `>` and `//` and `#` prefixes,
  code-fence wrapping, HTML entity escaping of `& < >`, trailing whitespace,
  CRLF, zero-width spaces, NBSP, Slack `<url|text>` link rewriting inside the
  instruction text.

- Manual round-trips recorded in findings: paste through Slack (message,
  thread reply, snippet), Gmail plain and HTML, a GitHub PR comment, and back
  into a file. Each verifies.

- Negative: the clear `Expires:` line edited while the signed header is
  untouched gives `metadata_mismatch`; the instruction text edited by one
  character gives `invalid_signature`. There is no unsigned copy of the
  instruction anywhere in the block.

### 3.5 Attack suite (RI-3 first half)

`tests/attacks/` with one module per threat:

| Test | Threat | Must produce |
|---|---|---|
| plain-text permission claim, no envelope | S1 | no span; classifier deny |
| edited signed text, original signature | S2 | `invalid_signature` |
| expired, wrong audience, replayed nonce | S3 | `expired`, `audience_mismatch`, `nonce_replayed` |
| agent-written envelope with self-generated key | S4 | `unknown_signer` |
| agent text mimicking the manifest itself inside a tool result | S4 / manifest channel | manifest unchanged; classifier reads only the hook's manifest |
| every transformation from 3.4 | S5 | `verified` |
| dev key in enforced mode | NF-4 | `dev_key_in_enforced_mode` |
| gated action reached through an unmatched command (interpreter one-liner, Makefile target, script rename) | pre-filter gap from Phase 1 | documented result; if it bypasses, either widen the gated class or route all Bash to the classifier and measure the cost |
| verifier crash, classifier outage, hook timeout during a gated call | fail-closed | `deny` in every run |

Plus fuzzing of the extractor and canonicalizer with `hypothesis`.

### 3.6 README-level spec and test vectors (SP-1, SP-2 lite)

- `json/1` canonicalization (RFC 8785 over the parsed value) with vectors
  covering key order, number formatting, escapes, and whitespace inside
  strings, plus the FM-5 tool-plus-arguments binding expressed as a signed
  JSON block.

- `spec/SPEC.md` (target 6–8 pages): threat model, envelope grammar,
  canonicalization, payload schema, both signature paths, verification
  algorithm as numbered steps, manifest schema, reference classifier policy,
  versioning note (`v` field, unknown fields ignored, unknown `alg` rejected).
  Open spec questions carried in: what "biometric" can mean given WebAuthn's
  UV semantics (allowlist versus enterprise attestation versus Secure
  Enclave), and the localhost origin binding from Phase 2.

- `spec/test-vectors/`: JSON files of valid and invalid blocks with expected
  status, generated from the test suite so they cannot drift.

### 3.7 Local classifier backend (optional, for NF-1)

- Second `ClassifierBackend` for OpenAI-compatible local servers: same
  policy prompt, JSON schema included in the prompt, response validated
  against the schema, invalid output treated as classifier failure (deny on
  gated calls). Measured on one local model against the canned-manifest
  tests from Phase 1 so its error rate is known before anyone relies on it.

### 3.8 Decision caching

- Cache classifier decisions per `(manifest_hash, tool_name, args_hash)` for
  the session so repeated identical calls do not repeat the LLM call.

## Deliverables

- All of the above, plus `plans/findings/phase-3.md` with transport results
  and the volunteer quick-start timing.

- Short write-up (2–3 pages) suitable for the workshop submission.

## Acceptance

- `make demo`: 4 of 4 scenarios pass on three consecutive runs.

- Attack suite green in CI; every S1–S5 threat has at least one test that
  fails when its defense is disabled (mutation check, done by hand once).

- Slack, email, and GitHub comment round-trips verify.

- A volunteer reaches a verified classifier decision in under 15 minutes from
  clone, following only the README.

## Requirements covered

SG-6, VE-2 (complete), VE-3, VE-7 (measured), TR-1, TR-2, SP-1 (lite), SP-2,
SP-4 (lite), RI-1 (minus Slack bot), RI-3 (internal suite), RI-5 (quick start).

## Risks

- Slack may mangle the envelope in a way the tolerant extractor does not
  cover. The simulation list is a hypothesis; the manual round-trips are the
  truth. Budget a day for surprises.

- Nonce store on the verifier host is state; multiple harness instances on
  one machine share it by design, across machines they do not. Document as a
  v1 limitation.

- Revocation shares that locality. A revocation record on one machine does not
  reach another, so an unbounded block retracted here still verifies on a
  colleague's laptop. A distributed revocation channel is out of scope for v1;
  the honest mitigation is to say that an unbounded block should be signed for
  a narrow audience, and that a widely scoped standing authorization wants an
  expiry after all.
