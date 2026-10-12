# Signed Instruction Blocks (SIB)

An AI agent's permissions are plain text in a prompt, and text can be written
by anyone, including another agent. A Signed Instruction Block is a clearsigned
instruction: the text stays readable, a detached signature proves a named
human wrote it and when, and a deterministic verifier in the harness tells the
permission classifier which text is human-signed and which is not.

This repository holds the phased plans, the Phase 0 experiments, and the
reference implementation: dev-mode keys (Phase 1), passkey signing with Touch
ID or another WebAuthn authenticator (Phase 2), and the Claude Code
integration.

- `plans/`: phase plans, the worked format example, and findings memos.
- `sib/`: the library and `sib` CLI (canonicalization, header, envelope,
  verifier, manifest, classifier, Claude Code hooks, the local signing app).
- `testbed/`: the small project the scenarios run against.
- `scenarios/`: headless runners for Claude Code and Codex, the usage gate,
  and result files.
- `tests/`: unit tests, property tests, hook fault-injection tests, and the
  WebAuthn path driven by a software authenticator.

## Quick start (dev mode)

```bash
uv sync
export SIB_HOME=$PWD/.sib-local          # keys and registry live here

# 1. A dev key for alice, enrolled in the registry
uv run sib keygen --signer alice@example.com --enroll

# 2. Sign an instruction (the canonical text is shown before signing)
uv run sib sign --signer alice@example.com --expires 8h --audience acme/dev-agent \
  --text "You may deploy the current main branch to staging with scripts/deploy.sh staging whenever the test suite passes." --out block.txt

# 3. Paste block.txt anywhere (CLAUDE.md, Slack, email) and verify it later
uv run sib verify block.txt --audience acme/dev-agent
sed 's/to staging/to production/' block.txt > tampered.txt
uv run sib verify tampered.txt --audience acme/dev-agent    # invalid_signature
```

Every dev-mode operation prints a warning: software-only keys prove possession
of a key file, not a verified human.

## Signing with a passkey (enforced mode)

```bash
# 1. Enroll a passkey: opens a page on http://localhost:7391 that creates one
#    with user verification required (Touch ID, Windows Hello, a security key)
uv run sib enroll --signer alice@example.com

# 2. Sign: the sign page shows the canonical text and the terms; the
#    authenticator signs a challenge that is the hash of exactly that
uv run sib sign --signer alice@example.com --expires 8h --audience acme/dev-agent \
  --text "You may deploy the current main branch to staging with scripts/deploy.sh staging whenever the test suite passes." --out block.txt

# 3. Verify runs in enforced mode once a passkey is enrolled: no warning,
#    dev-mode blocks confer nothing
uv run sib verify block.txt --audience acme/dev-agent
```

The verifier requires the user-verification flag, binds the assertion to the
enrolled origin and RP ID, and accepts only authenticator models on a
biometric-capable allowlist. What that does and does not prove (user
verification is not biometric verification; the model identifier is
self-reported unless attestation was verified) is spelled out in the
[Biometric Signing](docs/guide/components/signing.qmd) page.

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
# one settings file carrying the hooks and the autoMode rule, scoped to the run
uv run python -m sib.hooks.claude_code.install --settings-json sib-settings.json
claude --settings sib-settings.json
```

Scoping both halves to the invocation keeps them together and leaves your other
projects alone. To install into a repository instead, `--project` writes the
hooks to its `.claude/settings.json` and prints the autoMode rule to add to
`~/.claude/settings.json`, which Claude Code reads in every project.

Set `SIB_AUDIENCE` to the identifier this harness presents to the verifier.
Two hooks then run:

- **UserPromptSubmit** stores signed blocks pasted into the prompt and tells
  the model which instructions are verified.
- **PostToolUse** verifies every block in context, writes the provenance
  manifest, and hands the harness's own classifier a short note through
  `classifierContext`, the channel Phase 0 found decisive.

SIB takes no permission decisions. It verifies signatures and reports
provenance; the harness's classifier decides what may run.

The hooks run in enforced mode once a passkey is enrolled in `SIB_HOME` and in
dev mode before that; `SIB_MODE` overrides either.

SIB ships no classifier. `sib/classifier/policy.md` is the reference policy text an
integrator gives their own classifier so it knows how to weigh the manifest.

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
