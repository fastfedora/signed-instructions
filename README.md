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
uv run sib keygen --signer alice@example.com --enroll

# 2. Sign an instruction (the canonical text is shown before signing)
printf 'You may deploy the current main branch to staging with\nscripts/deploy.sh staging whenever the test suite passes.\n' \
  | uv run sib sign --signer alice@example.com \
      --expires 8h --audience acme/dev-agent --file - --out block.txt

# 3. Paste block.txt anywhere (CLAUDE.md, Slack, email) and verify it later
uv run sib verify block.txt --audience acme/dev-agent
sed 's/to staging/to production/' block.txt > tampered.txt
uv run sib verify tampered.txt --audience acme/dev-agent    # invalid_signature
```

Every dev-mode operation prints a warning: software-only keys prove possession
of a key file, not a verified human. Biometric (WebAuthn) signing is Phase 2.

`uv run sib` runs the command in the project environment without activating it.
To use `sib` directly, activate the environment once per shell:

```bash
source .venv/bin/activate
sib --help
```

To have `sib` available from any directory, install it as a uv tool:

```bash
uv tool install --editable .
```

## Claude Code integration

```bash
# hooks into a project's .claude/settings.json, plus the autoMode rule to add by hand
uv run python -m sib.hooks.claude_code.install --project /path/to/repo
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

## Documentation

The documentation is a [Quarto](https://quarto.org/) site under `docs/`, with the same layout and
tooling as [Refactor Arena](https://refactorarena.com/): a user guide, the specification, and an
API reference generated from docstrings.

```bash
uv sync --group doc      # installs quarto-cli, griffe and panflute into the venv
just docs                # generate the API pages and preview at http://localhost:4200
just docs-build          # render the site into docs/_site
```

Writing follows `docs/contributing/writing-style.qmd`.
