# Phase 5 — Spec v1.0, second biometric platform, Slack bot, red team, release

**Estimate:** 4–5 weeks. **Prerequisites:** Phase 4 green.
Completing this phase equals the full 12-week plan (PDF §7 Phases 3–4 plus
the items §8 cut).

## Goal

Everything the PDF lists as an output: public spec with conformance vectors,
open-source reference implementation on two biometric platforms with a Slack
flow, and a red-team report of what the design blocks and what it does not.

## Work items, grouped as sub-milestones

### 5A — Second biometric platform, adoption examples, external harness (1 week)

- YubiKey Bio path through the same WebAuthn app (roaming authenticator,
  `authenticatorAttachment: "cross-platform"`); Windows Hello smoke test on a
  Windows machine or VM (RI-4).
- Claude Agent SDK adoption example (1–2 days): a small Python harness whose
  `can_use_tool` callback runs the verifier and classifier with the manifest
  as structured input. No patching needed, so it is the reference for
  "adopt in your harness" and the cleanest VE-4 illustration.
- Inspect (UK AISI) integration as the external harness the PDF names: a
  custom approver that calls the verifier and classifier. This is the
  "≥ 1 external harness integration" metric.
- `docs/adopt.md`: Claude Code path (hooks plus autoMode prose), Codex path
  (hooks, and the reviewer patch), Agent SDK path, generic sidecar path, each
  with expected latency and the trust statement for that harness.

### 5B — Slack flow (1 week; TR-3, TR-4, SG-5 should-have)

- Slack app with `/sib request "<text>" --expires 2h --audience x` that DMs the
  named signer a link to the local sign page (the signer's own machine runs
  the app; Slack only carries the request and the result).
- The bot posts the resulting envelope back into the channel as a snippet, so
  the round-trip from Phase 3 is exercised by real users.
- Agent-initiated requests (TR-4): a tool the agent can call that files a
  signing request and returns nothing but a request id. The request never
  grants anything.
- Multi-signer (SG-7, could-have): only if time allows; spec the `threshold`
  field, do not implement.

### 5C — External red team (1.5 weeks including fixes)

- Brief from the PDF §7 week 8 list: prompt injection, replay,
  canonicalization, TOCTOU between verification and execution, transport
  mangling, signing-UI deception (what the sign page can be tricked into
  showing), classifier-directed provenance spoofing, manifest-channel
  injection.
- Triage, fix, re-run the attack suite, add regression tests for every fixed
  finding.
- Red-team report: blocked, not blocked, and out of scope, each with severity
  and mitigation path (M3 acceptance).

### 5D — Spec v1.0 and release (1.5 weeks)

- `spec/SPEC.md` promoted to v1.0 (≤ 10 pages): incorporate red-team lessons,
  add the standards mapping (WebAuthn L3, COSE/JOSE, RFC 8785, RFC 8949 if a
  CBOR encoding is added), versioning and extension policy, conformance
  requirements (SP-1, SP-3, SP-4).
- Conformance package: the test vectors with a small runner that a third-party
  implementation can point at (SP-2). Solicit one external implementation
  attempt.
- Licensing: Apache-2.0 for code, CC-BY for the spec (SP-5).
- Docs: quick start, architecture, threat model, adoption guide, final.
- Public release: repo, spec, write-up, short demo video, outreach to harness
  maintainers (Claude Code, Codex, Inspect).

## Acceptance (M3 + M4 from the PDF)

- All must-have threats blocked with regression tests; every unblocked finding
  documented with severity and mitigation.
- A stranger reaches a verified classifier decision in under 15 minutes from
  clone.
- Spec published with test vectors; at least one external harness maintainer
  has reviewed the integration; at least one external implementation attempt
  against the vectors.
- SIB survives Slack, email, GitHub comment round-trips with real users.

## Requirements covered

Everything remaining: SG-6/7, FM-5 (specified, optional), TR-3, TR-4, SP-1–5,
RI-1 (Slack bot), RI-3 (red-team suite), RI-4 (both platforms), CI-3 (Inspect,
Agent SDK), RI-5 (adoption guide).

## Budget mapping (PDF §9)

Red-teaming $4k covers 5C. Hardware ($500) covers 5A. The rest is engineering
time across all phases.
