# Phase 2 — Biometric signing via WebAuthn passkey

**Estimate:** 1 week. **Prerequisites:** Phase 1 green.
**Platform:** macOS with Touch ID first (matches the development machine).
Windows Hello and YubiKey Bio are Phase 5.

## Goal

Replace the dev key with a hardware-backed, biometric-gated signature so a SIB
really proves a named person approved the exact text (SG-2, SG-3, SG-4). The
verifier gains an `ES256-webauthn` path and checks the user-verification flag.

## What this phase proves

- Signing cannot happen without user verification on the enrolled
  authenticator; the WebAuthn assertion's UV bit is set and the verifier
  refuses assertions without it.
- Hardware backing is an enrollment assumption in this prototype, not a
  verified property. With attestation `none` or `self`, the AAGUID is
  self-reported and the WebAuthn spec gives no authenticator provenance
  guarantee. The registry records whether attestation was verified; enforced
  mode can be configured to require it, and the demo runs without it.
- Biometric-specific verification cannot be proven from the assertion alone.
  WebAuthn's UV flag covers PIN and password as well as biometrics, and the
  platform falls back to the login password after failed Touch ID attempts.
  The prototype narrows this by allowlisting authenticator models (AAGUID)
  known to be biometric-capable, records the `uvm` extension result when the
  browser supplies it, and states the residual gap against SG-2 in the
  threat model. The allowlist is only as strong as the attestation behind
  the AAGUID, see the previous point.
- The signed challenge is the SHA-256 of the exact canonical payload the human
  saw on screen (what-you-see-is-what-you-sign).
- Enforced mode runs with no dev-mode warning and Scenarios 1 and 2 still pass.

## Work items

### 2.1 Local signing app (`sib/webauthn_app/`)

- FastAPI app bound to `127.0.0.1` on a fixed port (proposal: 7391), started
  on demand by the CLI. `localhost` is a secure context, so WebAuthn works
  without TLS. RP ID `localhost`.
- **Enroll** page: `navigator.credentials.create` with
  `userVerification: "required"`, `authenticatorAttachment: "platform"`,
  `residentKey: "preferred"`. Server verifies with `py_webauthn`, stores
  `{signer, kid = credential id, alg: "ES256-webauthn", public_key (COSE),
  enrolled_at, attestation_format, aaguid, attestation_verified}` in the
  registry. Request `attestation: "direct"`; verify `apple` or `packed`
  attestation with `py_webauthn` against the vendor roots when present and
  set `attestation_verified: true`. Apple platform passkeys often return
  `none`, in which case the AAGUID is self-reported and
  `attestation_verified` is false. Enrollment policy
  (`SIB_REQUIRE_ATTESTATION`) decides whether unverified enrollments are
  accepted; the demo accepts them and says so.
- **Sign** page: shows the canonical text in a monospace box, the signer,
  expiry, audience, and nonce. Nothing else on the page. The Sign button runs
  `navigator.credentials.get` with `challenge = SHA-256(signing input)`, where the signing input is the RFC 7797 form `BASE64URL(header) || "." || canonical text` with the WebAuthn fields omitted from the header and
  `userVerification: "required"`. The response (`authenticatorData`,
  `clientDataJSON`, `signature`, `credentialId`) is posted back to the CLI.
- Every signing request has a one-time request token so a stray browser tab
  cannot sign a different payload than the CLI asked for.

### 2.2 CLI bridge

- `sib enroll --signer alice@example.com` opens the enroll page.
- `sib sign ...` without `--dev` builds the payload, starts the app if needed,
  opens the sign page, waits for the assertion, and emits the envelope.
- Envelope v0 gains optional fields for the WebAuthn path:
  `authenticatorData`, `clientDataJSON`, `credentialId` (all base64url).
  `alg` distinguishes the two paths.

### 2.3 Verifier WebAuthn path (`sib/verify.py`)

Checks, in order, each producing a distinct status on failure:

1. `clientDataJSON.type == "webauthn.get"`.
2. `clientDataJSON.challenge == base64url(SHA-256(signing input))`, recomputed from the header (minus the WebAuthn fields) and the canonical instruction text.
3. `clientDataJSON.origin` is in the registry's allowed origins for the signer
   (recorded at enrollment; default `http://localhost:7391`).
4. `authenticatorData.rpIdHash == SHA-256("localhost")`.
5. Flags: UP set and UV set. Missing UV → `uv_not_performed`.
5a. Authenticator AAGUID (recorded at enrollment) is on the registry's
   biometric-capable allowlist (Apple platform authenticator, YubiKey Bio,
   Windows Hello). Otherwise → `authenticator_not_allowed`. The allowlist is
   policy, not proof: it authenticates hardware provenance only when the
   enrollment carried verified attestation. The manifest span reports
   `attestation_verified` so a classifier policy can require it.
6. ES256 signature over `authenticatorData || SHA-256(clientDataJSON)` with the
   enrolled public key, via `py_webauthn` helpers.
7. Then the common checks: expiry, audience, nonce.

Signature counter is recorded but not enforced (Apple passkeys report 0).

### 2.4 Modes (NF-4)

- `SIB_MODE=enforced` (default once a WebAuthn key is enrolled): EdDSA dev
  blocks verify with status `dev_key_in_enforced_mode` and confer nothing.
- `SIB_MODE=dev`: both paths verify; the warning banner prints on every
  operation and the manifest carries `mode: "dev"`.

### 2.5 Re-run scenarios

- Scenarios 1 and 2 in enforced mode with a Touch ID signed SIB.
- Negative test: a WebAuthn assertion produced with `userVerification:
  "discouraged"` (possible on some authenticators) is rejected with
  `uv_not_performed`.

## Deliverables

- Signing app, CLI bridge, verifier path, registry changes, tests using
  `py_webauthn` test vectors plus a recorded real assertion from the laptop.
- Screenshots of the enroll and sign pages in the findings memo.
- `docs/signing.md`: how enrollment binds a person to a key, and what the
  registry does and does not attest.

## Acceptance

- `sib sign` on the laptop prompts Touch ID and produces a block that
  `sib verify` accepts in enforced mode; the same block with one byte of
  `text` changed fails with `invalid_signature`.
- An assertion whose UV bit is cleared fails with `uv_not_performed`.
- An assertion from an authenticator whose AAGUID is not allowlisted fails
  with `authenticator_not_allowed`.
- `docs/signing.md` states that UV does not prove a biometric was used, that
  hardware backing is verified only with verified attestation, what the
  allowlist does and does not guarantee, and the password-fallback behavior
  on macOS.
- Enrolling with a YubiKey Bio (or any authenticator returning `packed`
  attestation) sets `attestation_verified: true`; enrolling an Apple passkey
  with `none` sets it false, and the registry and manifest show the
  difference.
- Scenarios 1 and 2 pass in enforced mode with the same numbers as Phase 1.
- Time from `sib sign` to envelope on screen is under 15 seconds.

## Requirements covered

SG-2 (partial: UV on the enrolled key is enforced; hardware backing is
verified only when attestation is verified at enrollment, otherwise an
assumption; biometric-only is policy via AAGUID allowlist), SG-3 (partial:
enrollment attestation recorded, verified when available), SG-4, SG-5 (app
half), FM-4 (ES256 path), NF-4 fully, RI-4 (Touch ID half).

## Risks

- WebAuthn does not distinguish biometric from PIN or password user
  verification, and the `uvm` extension that would report the method has
  poor browser support. The PDF's SG-2 asks for biometric verification
  specifically. Options if the allowlist is judged insufficient: enterprise
  attestation to pin authenticator models, or a Secure Enclave key created
  with a biometry-only access-control flag via a Swift helper, which is
  macOS-only. Raise as a spec question in Phase 3.
- WebAuthn is built for challenges, not documents (PDF §10). Binding the
  payload hash to the challenge is the standard workaround; the sign page is
  the WYSIWYS surface. If browser UX makes this awkward, the fallback is a
  Secure Enclave key via a small Swift helper, documented but not built here.
- Origin binding to `localhost:7391` means a SIB signed on one laptop verifies
  anywhere only if the verifier's allowed-origin list includes that origin.
  Store origin in the registry per signer and revisit in the Phase 3 spec.
- Browser passkey sync (iCloud Keychain) means the "hardware-backed" key can
  exist on several of the signer's devices. Acceptable for v1; note it in the
  threat model.
