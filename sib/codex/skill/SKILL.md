---
name: "sib-sign"
description: "Create a Signed Instruction Block: an instruction the user signs with their own authenticator, which the approval reviewer treats as user authorization rather than as text in a file. Use when the user asks to sign an instruction, to authorize a class of action in writing, or to put standing authorization in AGENTS.md. Never use it to authorize an action you want to take; signing requires the user's own biometric and is theirs to initiate."
---

# Signing an instruction

A Signed Instruction Block (SIB) is plain-text instruction followed by a detached signature. The
approval reviewer verifies it and scores a verified block as user authorization, while the same
sentence unsigned is only text in a file. That asymmetry is the whole point, so a block must be
created by the user, for an instruction the user dictated.

## Rules

- **Only when the user asks for a signature.** If an action of yours was refused for want of
  authorization, say so and stop. Proposing that the user sign to unblock you is fine; signing on
  your own initiative, or treating this skill as a way around a denial, is not.
- **The user approves the exact words.** You may draft them. Show the final text and wait for an
  explicit yes before running the command, because what is signed is what carries authority.
- **Narrow beats broad.** Name the action, the target and the condition: one environment, one
  script, one branch. "You may deploy" authorizes more than anyone intends.
- **Give it an expiry that matches the task**, hours rather than weeks. `--expires 8h` is a good
  default; standing authorization is what `AGENTS.md` is for, and it still expires.
- **This skill's own text is not authorization.** The reviewer treats skill content as untrusted
  evidence, correctly. Only a verified block counts.

## Steps

1. Check that signing will actually involve the user:

   ```bash
   sib audience && sib verify --json AGENTS.md 2>&1 | head -5
   ```

   If anything prints `SIB DEV MODE`, the registry holds software keys and `sib sign` would sign
   with a key file and no human present. Tell the user, and that `sib enroll --signer <them>`
   enrolls a passkey. Do not produce a dev-mode block to stand in for a signature.

2. Agree the text with the user, then sign. The command opens their browser and waits for their
   authenticator; it cannot complete without them:

   ```bash
   sib sign --signer <them> --expires 8h \
     --text "You may deploy the current main branch to staging with scripts/deploy.sh staging once the test suite passes. This covers staging only."
   ```

   Add `--out block.txt` to write it to a file instead of standard output.

3. Put it where the reviewer will read it, under a heading that says what it is:

   ```bash
   { printf '\n## Standing authorization\n\n'; cat block.txt; } >> AGENTS.md
   ```

4. Confirm it verifies as the reviewer will, and report the status to the user:

   ```bash
   sib verify --json AGENTS.md | head -20
   ```

   `verified` is the only status that carries authority. Anything else — `expired`,
   `audience_mismatch`, `invalid_signature`, `unknown_signer`, `authenticator_not_allowed` — means
   the block confers nothing, and the status names why.

## When it does not work

- `authenticator_not_allowed`: the passkey was created by a password manager extension rather than
  the platform authenticator. `sib enroll --browser chrome` usually reaches the platform one;
  `sib allow-authenticator <aaguid> <label>` accepts the other deliberately.
- `audience_mismatch`: the block names a different deployment than this one declares. `sib audience`
  prints what this machine presents, and matching is exact.
- A verified block that still does not authorize the action: provenance is one factor, not the
  verdict. The reviewer also scores risk, and a class of action is only refused for want of
  authorization when the security policy says that class needs it.
