# Signed Instruction Blocks (SIB)

An AI agent's permissions are plain text in a prompt, and text can be written
by anyone, including another agent. A Signed Instruction Block is a clearsigned
instruction: the text stays readable, a detached signature proves a named
human wrote it and when, and a deterministic verifier in the harness tells the
permission classifier which text is human-signed and which is not.

This repository holds the phased plans, the Phase 0 experiments, and the
Phase 1 reference implementation (dev-mode keys, Claude Code integration).

- `plans/`: phase plans, the worked format example, and findings memos.
- `sib/`: the library and `sib` CLI (canonicalization, header, envelope,
  verifier, manifest, classifier, Claude Code hooks).
- `testbed/`: the small project the scenarios run against.
- `scenarios/`: headless runners for Claude Code and Codex, the usage gate,
  and result files.
- `tests/`: unit tests, property tests, and hook fault-injection tests.

## Quick start (dev mode)

```bash
uv sync
export SIB_HOME=$PWD/.sib-local          # keys and registry live here

# 1. A dev key for alice, enrolled in the registry
.venv/bin/sib keygen --kid "alice@example.com#dev-2026-09" --enroll --signer alice@example.com

# 2. Sign an instruction (the canonical text is shown before signing)
printf 'You may deploy the current main branch to staging with\nscripts/deploy.sh staging whenever the test suite passes.\n' \
  | .venv/bin/sib sign --signer alice@example.com --kid "alice@example.com#dev-2026-09" \
      --expires 8h --audience acme/dev-agent --file - --out block.txt

# 3. Paste block.txt anywhere (CLAUDE.md, Slack, email) and verify it later
.venv/bin/sib verify block.txt --audience acme/dev-agent
sed 's/to staging/to production/' block.txt > tampered.txt
.venv/bin/sib verify tampered.txt --audience acme/dev-agent    # invalid_signature
```

Every dev-mode operation prints a warning: a software key proves possession
of a file, not a person. Biometric (WebAuthn) signing is Phase 2.

## Claude Code integration

```bash
# hooks into a project's .claude/settings.json, plus the autoMode rule to add by hand
.venv/bin/python -m sib.hooks.claude_code.install --project /path/to/repo
```

The project needs a `.sib-policy.json` naming the audience and the gated
actions (see `testbed/.sib-policy.json`). Three hooks then run:

- **UserPromptSubmit** stores signed blocks pasted into the prompt and tells
  the model which instructions are verified.
- **PreToolUse** verifies every block in context on every tool call, writes
  the provenance manifest, and gates policy-covered actions: `deny` when no
  verified instruction covers the action, `ask` when the classifier is unsure,
  no decision when a verified instruction covers it.
- **PostToolUse** hands the auto-mode classifier a short provenance note
  through `classifierContext`, the channel Phase 0 found decisive.

The reference classifier uses the Anthropic SDK when `ANTHROPIC_API_KEY` is
set, otherwise `claude -p` on the subscription login
(`SIB_CLASSIFIER_BACKEND`, `SIB_CLASSIFIER_MODEL`).

## Running the scenarios

```bash
python3 scenarios/run_scenario.py --hooks sib --variant signed_claudemd -n 10 --claudemd-policy none
python3 scenarios/run_scenario.py --hooks sib --variant claudemd -n 10 --claudemd-policy none
python3 scenarios/run_scenario.py --summarize scenarios/results/phase1_s2.jsonl
```

Runs draw on the Claude subscription; `scenarios/usage_gate.py` refuses to
start a run when the five-hour window is above the cap.

## Tests

```bash
.venv/bin/python -m pytest -q
```
