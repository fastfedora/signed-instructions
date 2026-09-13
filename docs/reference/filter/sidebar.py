"""Pre-render: build the Reference sidebar and the interlink index (refs.json)
by introspecting the documented modules. Adapted from refactor-arena."""
import json
import os
import sys
import yaml
from pathlib import Path

# only execute if a reference doc is in the inputs
input_files = os.getenv("QUARTO_PROJECT_INPUT_FILES", "")
if "reference/index.qmd" not in input_files:
    exit(0)

project_root = Path(__file__).resolve().parents[3]
filter_dir = str(Path(__file__).resolve().parent)
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))
if filter_dir not in sys.path:
    sys.path.insert(0, filter_dir)

from documented_symbols import documented_functions_and_classes  # noqa: E402

REFERENCE_MODULES = ["canon", "header", "envelope", "keys_dev", "registry", "verify", "manifest",
                     "nonce_store", "classifier", "hooks", "cli", "b64"]


def build_sidebar() -> None:
    sidebar = yaml.safe_load(
        """
website:
  sidebar:
    - title: Reference
      style: docked
      collapse-level: 2
      contents:
        - reference/index.qmd
        - section: Python API
          contents: []
      """
    )
    contents, index_json = _generate_api_sidebar_contents()
    sidebar["website"]["sidebar"][0]["contents"][1]["contents"] = contents

    docs_dir = project_root / "docs"
    (docs_dir / "reference/refs.json").write_text(json.dumps(index_json, indent=2))
    sidebar_yaml = yaml.dump(sidebar, sort_keys=False).strip()
    sidebar_file = docs_dir / "reference/_sidebar.yml"
    previous = sidebar_file.read_text().strip() if sidebar_file.exists() else ""
    if sidebar_yaml != previous:
        sidebar_file.write_text(sidebar_yaml + "\n", encoding="utf-8")


def _generate_api_sidebar_contents() -> tuple[list[dict], dict[str, str]]:
    contents: list[dict] = []
    index: dict[str, str] = {}
    docs_dir = project_root / "docs"
    for module in REFERENCE_MODULES:
        doc = f"reference/{module}.qmd"
        if not (docs_dir / doc).exists():
            continue
        refs = _function_and_class_sidebar_refs(f"sib.{module}", doc)
        for ref in refs:
            index[ref["text"]] = ref["href"].removeprefix("reference/")
        contents.append(dict(section=module, href=doc, contents=refs))
    return contents, index


def _function_and_class_sidebar_refs(module_name: str, doc: str) -> list[dict[str, str]]:
    try:
        pairs = documented_functions_and_classes(module_name)
    except Exception as error:  # noqa: BLE001
        print(f"Warning: Could not list documented API symbols for {module_name}: {error}", file=sys.stderr)
        return []
    return [dict(text=name, href=f"{doc}#{anchor}") for name, anchor in pairs]


build_sidebar()
