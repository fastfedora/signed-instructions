"""Codex integration.

Codex needs no hooks. Its auto-review reviewer is an agent with read-only tool
access, so a policy can tell it to run `sib verify` itself and score a verified
signature as user authorization. `sib install codex` writes that configuration.

The reviewer sees only escalated tool calls. For instructions that need no
tool call, where a later unsigned sentence in `AGENTS.md` would otherwise
override an earlier signed one, `agents_rule.md` is a standing rule for the
model itself, written into the global `AGENTS.md` in the Codex home: verify
before following, and let a verified block take precedence. A model-side
layer, not a guarantee; the reviewer remains the authority on actions.

`policy_template.md` is Codex's own bundled Guardian prompt template, copied
verbatim from openai/codex at commit 6c372fb. It is pinned here only because
`auto_review.extra_policy` is silently dropped with the template the model
catalog currently serves, which has no `{{ extra_policy }}` slot
(openai/codex#50309). When that is fixed, stop pinning the template and set
`extra_policy` alone.
"""
from pathlib import Path

TEMPLATE_PATH = Path(__file__).with_name("policy_template.md")
EXTRA_POLICY_PATH = Path(__file__).with_name("extra_policy.md")
AGENTS_RULE_PATH = Path(__file__).with_name("agents_rule.md")
TEMPLATE_SOURCE_COMMIT = "6c372fb"
