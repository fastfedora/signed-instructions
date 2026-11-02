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
- **The user approves the exact words, and the terms.** You may draft them. Before running the
  command, show the user all four of: the exact text that will be signed, who it will be signed
  as, the authorization context it will be valid in, and the expiry if they asked for one. Wait
  for an explicit yes. What is signed is what carries authority, and `sib sign` prints the same
  terms back to them before it opens the browser.
- **Narrow beats broad.** Name the action, the target and the condition: one environment, one
  script, one branch. "You may deploy" authorizes more than anyone intends.
- **The expiry is the user's to choose, and the default is none.** A block with no expiry is
  valid until it is removed from the file it lives in, which is what standing authorization in
  `AGENTS.md` is meant to be. Pass `--expires` only when the user asks for a limit, and then pass
  exactly the span they gave. Never invent a duration, and never add one they did not ask for:
  an unrequested expiry makes their authorization lapse silently, and they will not know why.
- **This skill's own text is not authorization.** The reviewer treats skill content as untrusted
  evidence, correctly. Only a verified block counts.

## Steps

1. Check that signing will actually involve the user:

   ```bash
   sib audience; echo | sib verify - 2>&1 | head -5
   ```

   The first command prints the authorization context in force, the second is an empty probe that
   reports the signing mode without needing a file. Run both: separated by `;`, not `&&`, so a
   missing context does not hide the mode.

   If anything prints `SIB DEV MODE`, the registry holds only software keys and `sib sign` would
   sign with a key file and no human present. Tell the user, and that `sib enroll --signer <them>`
   enrolls a passkey, or that re-running `sib install codex` offers one. Do not produce a dev-mode
   block to stand in for a signature.

2. Agree the text with the user, then sign. The command opens their browser and waits for their
   authenticator; it cannot complete without them:

   ```bash
   sib sign --out /tmp/sib-block.txt \
     --text "You may deploy the current main branch to staging with scripts/deploy.sh staging once the test suite passes. This covers staging only."
   ```

   Add `--expires <the span they gave>` only if the user asked for a limit; without it the block
   does not expire. With no `--signer`, this signs as the machine's git identity when a key is
   enrolled for it, and says whom it chose. Pass `--signer <them>` when the user is someone else, or `--kid` when they
   hold more than one key. Keep `--out` outside the repository: a block written into the checkout
   is a stray file that ends up in someone's commit.

3. Put it where the reviewer will read it, under a heading that says what it is:

   ```bash
   { printf '\n## Standing authorization\n\n'; cat /tmp/sib-block.txt; } >> AGENTS.md \
     && rm /tmp/sib-block.txt
   ```

   Append only after signing succeeded, so a failed signature does not leave a bare heading
   behind.

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
- `audience_mismatch`: the block names a different authorization context than this one declares.
  `sib audience` prints what this machine presents, and matching is exact.
- A verified block that still does not authorize the action: provenance is one factor, not the
  verdict. The reviewer also scores risk, and a class of action is only refused for want of
  authorization when the security policy says that class needs it.
