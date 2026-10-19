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
import re
import shutil
import sys
import tomllib
from pathlib import Path

from . import EXTRA_POLICY_PATH, TEMPLATE_PATH, TEMPLATE_SOURCE_COMMIT
from ..keys_dev import sib_home
from ..registry import resolve_audience

def default_config() -> Path:
    """Where Codex itself reads its configuration.

    CODEX_HOME relocates the whole of it, config and auth and state alike, so
    an isolated home is the way to try configurations without touching the
    real one. Honour it here, or the installer would write to ~/.codex while
    the run under test reads somewhere else.
    """
    home = os.environ.get("CODEX_HOME")
    return (Path(home).expanduser() if home else Path.home() / ".codex") / "config.toml"


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


def build_auto_review_lines(sib_path: str, home: Path, audience: str) -> list[str]:
    """The keys this installer owns, as lines to place inside [auto_review]."""
    extra = render_extra_policy(sib_path, home, audience)
    return ["# Signed Instruction Blocks, written by `sib install codex`.",
            f"# Audience {audience}; registry {home}.",
            "# The template is pinned only because auto_review.extra_policy is dropped with the",
            f"# catalog template (openai/codex#50309). Codex's own template at {TEMPLATE_SOURCE_COMMIT}.",
            "experimental_policy_template = " + toml_literal(TEMPLATE_PATH.read_text()),
            "", "extra_policy = " + toml_literal(extra)]


OUR_KEYS = ("experimental_policy_template", "extra_policy")


def _section_span(text: str, header: str) -> tuple[int, int] | None:
    """Character span of a top-level table's body, from its header to the next one."""
    m = re.search(rf"^\[{re.escape(header)}\]\s*$", text, re.M)
    if not m:
        return None
    nxt = re.search(r"^\[", text[m.end():], re.M)
    return m.end(), (m.end() + nxt.start()) if nxt else len(text)


def _drop_key(body: str, key: str) -> str:
    """Remove `key = ...` from a table body, including a multi-line literal value."""
    m = re.search(rf"^[ \t]*{re.escape(key)}[ \t]*=[ \t]*('''|\"\"\")?", body, re.M)
    if not m:
        return body
    if m.group(1):
        close = body.find(m.group(1), m.end())
        end = (body.find("\n", close + 3) + 1) if close != -1 else len(body)
    else:
        nl = body.find("\n", m.end())
        end = (nl + 1) if nl != -1 else len(body)
    return body[: m.start()] + body[end:]


def merge(text: str, auto_review_lines: list[str], reviewer: str | None) -> str:
    """Add our keys to an existing config, leaving every other setting alone."""
    if reviewer is not None:
        line = f'approvals_reviewer = "{reviewer}"'
        existing = re.search(r"^approvals_reviewer[ \t]*=.*$", text, re.M)
        first_table = re.search(r"^\[", text, re.M)
        if existing and (not first_table or existing.start() < first_table.start()):
            text = text[: existing.start()] + line + text[existing.end():]
        else:
            at = first_table.start() if first_table else len(text)
            prefix = text[:at]
            if prefix and not prefix.endswith("\n"):
                prefix += "\n"
            text = prefix + line + "\n\n" + text[at:]

    block = "\n".join(auto_review_lines).rstrip("\n") + "\n"
    span = _section_span(text, "auto_review")
    if span is None:
        joiner = "" if not text or text.endswith("\n\n") else ("\n" if text.endswith("\n") else "\n\n")
        return text + joiner + "[auto_review]\n" + block
    start, end = span
    body = text[start:end]
    for key in OUR_KEYS:
        body = _drop_key(body, key)
    body = body.lstrip("\n")
    return text[:start] + "\n" + block + ("\n" + body if body.strip() else "") + text[end:]


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
    return warnings


def run_install(config: str | None = None, audience: str | None = None, sib_path: str | None = None,
                home: str | None = None, print_only: bool = False, assume_yes: bool = False) -> None:
    audience, audience_source = resolve_audience(audience)
    if not audience:
        raise SystemExit("no audience: the reviewer needs one to verify blocks. Record it once with "
                         "`sib audience <name>`, or give --audience. It names this deployment, not "
                         "the vendor, and must match what signers put in a block.")
    resolved_home = Path(home).expanduser() if home else sib_home()
    resolved_sib = sib_path or shutil.which("sib") or str(Path(sys.executable).with_name("sib"))

    print(f"# Audience {audience} (from {audience_source}), baked into the reviewer's command.",
          file=sys.stderr)
    for w in check_environment(resolved_sib, resolved_home):
        print(f"warning: {w}\n", file=sys.stderr)

    target = Path(config).expanduser() if config else default_config()
    text = target.read_text() if target.exists() else ""
    try:
        current = tomllib.loads(text) if text.strip() else {}
    except tomllib.TOMLDecodeError as e:
        raise SystemExit(f"{target} is not valid TOML ({e}); fix it or use --print")

    # approvals_reviewer: default to enabling it, but never quietly discard a
    # different choice the user already made.
    existing_reviewer = current.get("approvals_reviewer")
    reviewer: str | None
    if existing_reviewer == "auto_review":
        reviewer = None
        print(f"# approvals_reviewer is already \"auto_review\" in {target}.", file=sys.stderr)
    elif existing_reviewer is None:
        reviewer = "auto_review" if (assume_yes or _ask(
            'Set approvals_reviewer = "auto_review"? Say no to enable it per run with '
            '`codex exec --approve-for-me`.', default=True)) else None
    else:
        reviewer = "auto_review" if _ask(
            f'approvals_reviewer is currently "{existing_reviewer}". Replace it with "auto_review"? '
            f'Saying no keeps your setting; enable the reviewer per run instead.', default=False) else None

    existing_ours = [k for k in OUR_KEYS if k in (current.get("auto_review") or {})]
    if existing_ours and not (assume_yes or _ask(
            f"{target} already sets {' and '.join(existing_ours)} under [auto_review]. Replace "
            f"{'them' if len(existing_ours) > 1 else 'it'}?", default=False)):
        raise SystemExit("left unchanged; use --print to see what would have been written")

    lines = build_auto_review_lines(resolved_sib, resolved_home, audience)
    merged = merge(text, lines, reviewer)

    write = False
    if not print_only:
        write = assume_yes or _ask(f"Write this configuration to {target}?", default=True)
    if write:
        target.parent.mkdir(parents=True, exist_ok=True)
        if text:
            backup = target.with_suffix(target.suffix + ".sib-bak")
            backup.write_text(text)
            print(f"backed up {target} to {backup}", file=sys.stderr)
        target.write_text(merged)
        print(f"wrote {target}")
    else:
        print(merged if not text else "\n".join(["[auto_review]", *lines]))
        if not print_only:
            print(f"# Not written. Merge the above into {target}, or a project `.codex/config.toml`.",
                  file=sys.stderr)

    if reviewer is None and existing_reviewer != "auto_review":
        print("# The reviewer is not enabled in the config. Per run: codex exec --approve-for-me",
              file=sys.stderr)
    if not (resolved_home / "registry.json").exists():
        print(f"# No keys enrolled yet at {resolved_home}. Until `sib keygen --signer <you> --enroll`\n"
              f"# runs, every block verifies as unknown_signer, which is safe: nothing is authorized.",
              file=sys.stderr)
    print("# SIB scores authorization, not risk. A deploy or release is only refused when your own\n"
          "# policy says that class of action needs authorization; add that rule under [auto_review].",
          file=sys.stderr)


def add_arguments(ap) -> None:
    ap.add_argument("--audience", help="the identifier this harness presents to the verifier "
                                       "(default: SIB_AUDIENCE, else the registry's default_audience)")
    ap.add_argument("--config", help="config file to merge into "
                                     "(default: $CODEX_HOME/config.toml, else ~/.codex/config.toml)")
    ap.add_argument("--sib-path", help="absolute path to the sib binary the reviewer will run "
                                       "(default: the one on PATH)")
    ap.add_argument("--home", help="registry directory, as SIB_HOME (default: ~/.sib)")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="print the configuration and write nothing")
    ap.add_argument("--yes", dest="assume_yes", action="store_true",
                    help="answer yes to both questions, for scripting")
