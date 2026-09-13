#!/usr/bin/env python3
"""Generate Quarto API reference pages using `api` fenced blocks that the
reference filter expands into module documentation. Adapted from
refactor-arena's generator.

Usage:
  uv run python scripts/gen_quarto_api.py
"""
from __future__ import annotations

import pathlib

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = "sib"
OUT_DIR = PROJECT_ROOT / "docs" / "reference"

MODULE_DESCRIPTIONS = {
    "canon": "Canonicalization rules (`text/1`, `raw/1`) and the rule registry",
    "header": "The signed header, its serialization, and the RFC 7797 signing input",
    "envelope": "Rendering and extracting clearsigned blocks",
    "keys_dev": "Dev-mode Ed25519 keys (sign, verify, key storage)",
    "registry": "Flat-file signer registry",
    "verify": "The deterministic verifier and its statuses",
    "manifest": "Provenance manifest and the classifier note",
    "nonce_store": "Replay control (no-op in Phase 1)",
    "classifier": "Reference permission classifier and its backends",
    "hooks": "Claude Code hooks (UserPromptSubmit, PreToolUse, PostToolUse) and installer",
    "cli": "The `sib` command-line interface",
    "b64": "base64url helpers",
}
ORDER = ["canon", "header", "envelope", "keys_dev", "registry", "verify", "manifest", "nonce_store",
         "classifier", "hooks", "cli", "b64"]

TEMPLATE = """---
title: {package}.{module}
---

```api
package: {package}.{module}
source: .
members: true
inherited: false
```
"""


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    pkg = PROJECT_ROOT / PACKAGE
    modules = [m for m in ORDER if (pkg / f"{m}.py").exists() or (pkg / m / "__init__.py").exists()]
    for module in modules:
        (OUT_DIR / f"{module}.qmd").write_text(TEMPLATE.format(package=PACKAGE, module=module), encoding="utf-8")
    lines = ["---", "title: Reference", "---", "",
             "The Python API, one page per module. The [CLI](../guide/basics/cli.qmd) is documented in the guide.",
             "", "## Python API", "", "| Module | Description |", "| ------ | ----------- |"]
    for module in modules:
        lines.append(f"| [{PACKAGE}.{module}]({module}.qmd) | {MODULE_DESCRIPTIONS.get(module, '')} |")
    (OUT_DIR / "index.qmd").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
