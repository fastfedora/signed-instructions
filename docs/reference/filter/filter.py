#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from typing import cast

from griffe import Module
import griffe
import panflute as pf  # type: ignore

from parse import parse_docs
from render import render_docs
from documented_symbols import (
    api_heading_identifier,
    build_doc_parse_options,
    package_directory_for_module,
    parent_segments_for_h2,
    title_case_submodule_segment,
)


def main() -> None:
    parse_options = build_doc_parse_options()

    def python_api(elem: pf.Element, doc: pf.Doc):
        if isinstance(elem, pf.Header) and elem.level == 3:
            title = _metadata_title_string(doc)
            if title.startswith("sib"):
                if title.startswith("sib."):
                    mod_path = title.removeprefix("sib.")
                    target = f"{mod_path}.{pf.stringify(elem.content)}"
                else:
                    target = pf.stringify(elem.content)

                docs = parse_docs(target, parse_options)
                return render_docs(elem, docs)

    def api_block(elem: pf.Element, doc: pf.Doc):
        if isinstance(elem, pf.CodeBlock) and ("api" in (elem.classes or [])):
            # expect a 'package: sib.module' line in the block
            text = elem.text
            package = None
            for line in text.splitlines():
                if line.strip().startswith("package:"):
                    package = line.split(":", 1)[1].strip()
                    break
            if not package:
                return None

            # load module via griffe and render all public members
            root = cast(Module, griffe.load(str(package)))
            blocks: list[pf.Element] = []
            package_directory = package_directory_for_module(root)

            # derive a clean prefix (relative to project root)
            base = str(package).removeprefix("sib.")
            base = base if base != "sib" else ""

            # depth-first traversal collecting only functions/classes/attributes
            stack: list[tuple[str, griffe.Object]] = []  # type: ignore[name-defined]
            for name, member in root.members.items():
                if not name.startswith("_"):
                    prefix = f"{base}.{name}" if base else name
                    stack.append((prefix, member))

            collected: list[tuple[tuple[str, ...], str, list[pf.Element]]] = []

            while stack:
                path, obj = stack.pop()
                # descend into submodules/packages
                if isinstance(obj, griffe.Module):
                    for sub_name, sub_member in obj.members.items():
                        if sub_name.startswith("_"):
                            continue
                        stack.append((f"{path}.{sub_name}", sub_member))
                    continue

                # only render supported object types (Function, Class, Attribute)
                # Handle aliases that may point outside this package
                if isinstance(obj, griffe.Alias):
                    # Skip aliases to avoid resolution errors (internal or external)
                    continue
                else:
                    # skip objects without docstrings to avoid assertion in read_source
                    try:
                        if getattr(obj, "docstring", None) is None:
                            continue
                    except Exception:
                        continue
                try:
                    docs = parse_docs(path, parse_options)
                except ValueError:
                    continue

                short = path.split(".")[-1]
                parent_segments = parent_segments_for_h2(base, path, package_directory)
                header = pf.Header(
                    pf.Str(short),
                    level=3,
                    identifier=api_heading_identifier(short),
                )
                rendered = render_docs(header, docs)
                collected.append((parent_segments, path, rendered))

            collected.sort(key=lambda item: (item[0], item[1]))
            last_parent: tuple[str, ...] = ()
            for parent_segments, _path, rendered in collected:
                blocks.extend(_h2_for_submodule_descent(last_parent, parent_segments))
                blocks.extend(rendered)
                last_parent = parent_segments

            return blocks

    pf.run_filters([python_api, api_block])


def _metadata_title_string(doc: pf.Doc) -> str:
    raw = doc.metadata.get("title", "")
    if isinstance(raw, str):
        return raw
    if raw is None:
        return ""
    return pf.stringify(raw)


def _h2_for_submodule_descent(
    from_segments: tuple[str, ...], to_segments: tuple[str, ...]
) -> list[pf.Header]:
    common = 0
    for left, right in zip(from_segments, to_segments, strict=False):
        if left == right:
            common += 1
        else:
            break
    headers: list[pf.Header] = []
    for segment in to_segments[common:]:
        headers.append(pf.Header(pf.Str(title_case_submodule_segment(segment)), level=2))
    return headers


if __name__ == "__main__":
    main()
