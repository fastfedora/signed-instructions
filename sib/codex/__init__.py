"""Codex integration.

Codex needs no hooks. Its auto-review reviewer is an agent with read-only tool
access, so a policy can tell it to run `sib verify` itself and score a verified
signature as user authorization. `sib install codex` writes that configuration.

`policy_template.md` is Codex's own bundled Guardian prompt template, copied
verbatim from openai/codex at commit 6c372fb. It is pinned here only because
`auto_review.extra_policy` is silently dropped with the template the model
catalog currently serves, which has no `{{ extra_policy }}` slot
(openai/codex#50309). When that is fixed, stop pinning the template and set
`extra_policy` alone.
"""
from pathlib import Path

TEMPLATE_PATH = Path(__file__).with_name("policy_template.md")
SKILL_PATH = Path(__file__).parent / "skill" / "SKILL.md"
EXTRA_POLICY_PATH = Path(__file__).with_name("extra_policy.md")
TEMPLATE_SOURCE_COMMIT = "6c372fb"
