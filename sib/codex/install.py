"""Write the Codex auto-review configuration: `sib install codex`.

Codex reviews escalated actions with an LLM subagent that scores
`user_authorization`. Four things make it honour signatures:

  approvals_reviewer                     put the reviewer in the loop at all
  auto_review.extra_policy               the SIB rules it reads
  auto_review.experimental_policy_template   a template with a slot to put them in
  a deployment or release rule           yours to write; see the closing note
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from . import EXTRA_POLICY_PATH, TEMPLATE_PATH, TEMPLATE_SOURCE_COMMIT
from ..keys_dev import sib_home

DEFAULT_CONFIG = Path.home() / ".codex" / "config.toml"


def toml_literal(s: str) -> str:
    """A TOML multi-line literal string: no escaping, so Markdown stays readable."""
    if "'''" in s:
        raise ValueError("policy text contains ''' and cannot be a TOML literal string")
    return "'''\n" + s.rstrip("\n") + "\n'''"


def render_extra_policy(sib_path: str, home: Path, audience: str) -> str:
    text = EXTRA_POLICY_PATH.read_text()
    return (text.replace("{SIB}", sib_path)
                .replace("{SIB_HOME}", str(home))
                .replace("{SIB_AUDIENCE}", audience))


def build_fragment(sib_path: str, home: Path, audience: str, set_reviewer: bool) -> str:
    extra = render_extra_policy(sib_path, home, audience)
    lines = ["# Signed Instruction Blocks: the reviewer verifies signatures itself.",
             f"# Written by `sib install codex`. Audience {audience}; registry {home}."]
    if set_reviewer:
        lines += ["", 'approvals_reviewer = "auto_review"']
    lines += ["", "[auto_review]",
              "# Pinned only because auto_review.extra_policy is dropped with the catalog",
              f"# template (openai/codex#50309). Codex's own template at {TEMPLATE_SOURCE_COMMIT}.",
              "experimental_policy_template = " + toml_literal(TEMPLATE_PATH.read_text()),
              "", "extra_policy = " + toml_literal(extra), ""]
    return "\n".join(lines)


def _ask(question: str, default: bool) -> bool:
    if not sys.stdin.isatty():
        return default
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        answer = input(question + suffix).strip().lower()
    except EOFError:
        return default
    return default if not answer else answer.startswith("y")


def check_environment(sib_path: str, home: Path) -> list[str]:
    """Things that silently break the integration if wrong."""
    warnings = []
    if not Path(sib_path).is_file() or not os.access(sib_path, os.X_OK):
        warnings.append(f"{sib_path} is not an executable file. The reviewer runs this command "
                        f"literally, so give --sib-path the absolute path to the `sib` binary.")
    if not home.is_absolute():
        warnings.append(f"The registry path {home} is relative. The reviewer may run from elsewhere; "
                        f"use an absolute path.")
    try:
        if Path.cwd() in home.parents or home == Path.cwd():
            warnings.append(f"The registry {home} is inside the working directory. An agent that can "
                            f"write there can enroll its own key. Keep SIB_HOME outside any repository.")
    except OSError:
        pass
    if not (home / "registry.json").exists():
        warnings.append(f"No registry at {home}/registry.json yet. Run `sib keygen --signer <you> "
                        f"--enroll`, or `sib enroll`, before the reviewer will verify anything.")
    return warnings


def run_install(config: str | None = None, audience: str | None = None, sib_path: str | None = None,
                home: str | None = None, print_only: bool = False, assume_yes: bool = False) -> None:
    audience = audience or os.environ.get("SIB_AUDIENCE")
    if not audience:
        raise SystemExit("give --audience (or set SIB_AUDIENCE): the reviewer needs it to verify blocks")
    resolved_home = Path(home).expanduser() if home else sib_home()
    resolved_sib = sib_path or shutil.which("sib") or str(Path(sys.executable).with_name("sib"))

    for w in check_environment(resolved_sib, resolved_home):
        print(f"warning: {w}\n", file=sys.stderr)

    set_reviewer = assume_yes or _ask(
        "Set approvals_reviewer = \"auto_review\" in the config? Say no to enable it per run "
        "with `codex exec --approve-for-me` or `-c approvals_reviewer=\"auto_review\"`.", default=False)
    fragment = build_fragment(resolved_sib, resolved_home, audience, set_reviewer)

    target = Path(config).expanduser() if config else DEFAULT_CONFIG
    write = False
    if not print_only:
        write = assume_yes or _ask(f"Append this configuration to {target}?", default=False)
    if write:
        target.parent.mkdir(parents=True, exist_ok=True)
        existing = target.read_text() if target.exists() else ""
        if "[auto_review]" in existing:
            raise SystemExit(f"{target} already has an [auto_review] section. Merge by hand, or pass "
                             f"--print and edit it yourself.")
        with target.open("a") as f:
            f.write(("\n" if existing and not existing.endswith("\n") else "") + "\n" + fragment)
        print(f"appended to {target}")
    else:
        print(fragment)
        if not print_only:
            print(f"# Not written. Add the above to {target}, or a project `.codex/config.toml`.",
                  file=sys.stderr)

    if not set_reviewer:
        print("# Enable the reviewer per run: codex exec --approve-for-me", file=sys.stderr)
    print("# SIB scores authorization, not risk. A deploy or release is only refused when your own\n"
          "# policy says that class of action needs authorization; add that rule under [auto_review].",
          file=sys.stderr)


def add_arguments(ap) -> None:
    ap.add_argument("--audience", help="the identifier this harness presents to the verifier "
                                       "(default: SIB_AUDIENCE)")
    ap.add_argument("--config", help=f"config file to append to (default: {DEFAULT_CONFIG})")
    ap.add_argument("--sib-path", help="absolute path to the sib binary the reviewer will run "
                                       "(default: the one on PATH)")
    ap.add_argument("--home", help="registry directory, as SIB_HOME (default: ~/.sib)")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="print the configuration and write nothing")
    ap.add_argument("--yes", dest="assume_yes", action="store_true",
                    help="answer yes to both questions, for scripting")
