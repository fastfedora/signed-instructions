"""First-run setup, shared by the installers.

An integration needs two pieces of local state that no package can ship: a name
for this authorization context, and a key to sign with. Both used to be prerequisites the
user discovered by being refused. They are questions instead, so that
`sib install <harness>` is the first and only command before launching the
agent.
"""
from __future__ import annotations

import getpass
import os
import socket
import subprocess
import sys
from pathlib import Path

from .registry import Registry


# ---- asking ----

def ask_yes_no(question: str, default: bool) -> bool:
    if not sys.stdin.isatty():
        return default
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        answer = input(question + suffix).strip().lower()
    except EOFError:
        return default
    return default if not answer else answer.startswith("y")


def ask_text(question: str, default: str | None = None) -> str | None:
    """Free text, with the default shown in brackets. Returns None when there is
    nothing to fall back on and the user gave nothing."""
    if not sys.stdin.isatty():
        return default
    prompt = f"{question} [{default}] " if default else f"{question} "
    try:
        answer = input(prompt).strip()
    except EOFError:
        return default
    return answer or default


# ---- the audience ----

def confirm_on_terminal(question: str, default: bool = False, device: str = "/dev/tty") -> bool | None:
    """Ask on the controlling terminal, not on stdin, and return None when there
    is no terminal to ask at.

    The thing being confirmed may itself have arrived on stdin, which leaves
    nothing there to read an answer from; and where the question is whether a
    person approves, the answer has to come from the person at the keyboard
    rather than from whatever filled the pipe. Writing the prompt to the
    terminal too means a redirected stderr cannot hide it.

    Two handles, rather than one opened `r+`: a terminal is not seekable, and
    Python's buffered read-write mode insists that it is, so `r+` raises
    `io.UnsupportedOperation` every time, on every platform. That exception
    subclasses OSError, so it arrived here indistinguishable from having no
    terminal at all -- the first version of this function could only ever
    return None, which turned the confirmation into an unconditional refusal.

    `device` is the seam the test uses to point this at a pty, because the real
    path cannot be exercised anywhere that lacks a controlling terminal, which
    includes most places tests run.
    """
    try:
        reader = open(device, "r")
    except OSError:
        return None
    try:
        with open(device, "w") as writer:
            writer.write(question + (" [Y/n] " if default else " [y/N] "))
            writer.flush()
        line = reader.readline()
    except OSError:
        return None
    finally:
        reader.close()
    if not line:
        return None
    answer = line.strip().lower()
    return default if not answer else answer in ("y", "yes")


def suggest_audience() -> str:
    """A name scoped to this machine and account.

    A default for the common case, not the whole concept: an authorization
    context can be anything signed instructions should be valid within, a bot
    or a team as readily as a laptop. Deliberately not the harness vendor.
    `openai/codex` would be byte-identical in everyone's install, so one
    laptop's signature would verify in CI and in anyone else's copy of the same
    tool; matching is exact string equality, and the audience is the only thing
    confining a block to the context it was minted for.
    """
    host = (socket.gethostname().split(".")[0] or "localhost").lower()
    try:
        user = getpass.getuser()
    except Exception:            # no passwd entry, e.g. some containers
        user = "agent"
    return f"{host}/{user}-dev"


AUDIENCE_REFUSAL = (
    "no audience: the reviewer needs one to verify blocks, and this is not a terminal so there is "
    "nobody to ask. Give --audience, record one with `sib audience <name>`, or run "
    "`sib install codex` interactively and it will offer {suggestion}. It names the context the "
    "instructions are valid in, not the vendor, and must match what signers put in a block."
)


def ensure_audience(reg: Registry, explicit: str | None, assume_yes: bool,
                    may_write: bool = True) -> tuple[str, str]:
    """Resolve the audience, asking for one and recording it if there is none.

    Resolution order is unchanged: an explicit flag, then SIB_AUDIENCE, then the
    registry. Only the empty case is new.
    """
    if explicit:
        return explicit, "--audience"
    env = os.environ.get("SIB_AUDIENCE")
    if env:
        return env, "SIB_AUDIENCE"
    if reg.default_audience:
        return reg.default_audience, f"default_audience in {reg.path}"

    suggestion = suggest_audience()
    # Never invent one silently. A wrong audience is not a visible failure: it
    # verifies nothing and nobody is at the terminal to notice.
    if not may_write or not (sys.stdin.isatty() or assume_yes):
        raise SystemExit(AUDIENCE_REFUSAL.format(suggestion=suggestion))
    if not sys.stdin.isatty():
        chosen = suggestion
        print(f"# No terminal to ask; --yes takes the suggested name {chosen}.", file=sys.stderr)
    else:
        print("# The authorization context determines where signed instructions are valid.\n"
              "# Instructions signed with one context are not valid in other contexts. Specify a\n"
              "# context for which instructions signed by this install are valid, such as your user\n"
              "# on this machine, a specific company team or bot deployment. Avoid contexts that are\n"
              "# generic like \"openai/codex\".",
              file=sys.stderr)
        chosen = ask_text("Name for this authorization context?", suggestion)
    if not chosen:
        raise SystemExit(AUDIENCE_REFUSAL.format(suggestion=suggestion))
    reg.default_audience = chosen
    reg.save()
    return chosen, f"your answer, recorded in {reg.path}"


# ---- the signing key ----

def git_signer() -> str | None:
    """Whoever this machine already says its commits come from, or None.

    Used as the signer of last resort by `sib sign`, so it is deliberately the
    email and not `user.name`: a signer id has to be an identifier a verifier
    can match, not a display name.
    """
    try:
        out = subprocess.run(["git", "config", "--get", "user.email"], capture_output=True,
                             text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def suggest_signer() -> str:
    """As `git_signer`, with something to show in a prompt when git has no answer."""
    email = git_signer()
    if email:
        return email
    host = (socket.gethostname().split(".")[0] or "localhost").lower()
    try:
        return f"{getpass.getuser()}@{host}"
    except Exception:
        return f"agent@{host}"


NO_KEY_NOTE = (
    "# No signing key enrolled at {home}. Until one is, every block verifies as unknown_signer,\n"
    "# which is safe: nothing is authorized. Enroll a passkey with `sib enroll --signer <you>`."
)

DEV_ONLY_NOTE = (
    "# Only software keys are enrolled at {home}, so this install signs in dev mode, and a\n"
    "# dev-mode block confers nothing once any passkey exists. Enroll one with\n"
    "# `sib enroll --signer <you>`."
)


def ensure_key(reg: Registry, home: Path) -> None:
    """Offer to enroll a signing key when the install would otherwise be unable
    to produce a signature that proves a person was there.

    The test is a passkey, not any key: a registry holding only software keys
    leaves the install in dev mode, where a signature proves possession of a
    file rather than the presence of a person, and where a block confers nothing
    as soon as any passkey is enrolled anywhere in the registry. Skipping the
    offer because some key exists is how someone ends up unable to sign for
    real and unable to see why.

    Only ever interactive. A passkey cannot be enrolled without the person at
    the authenticator, and a software key is a security choice, so neither is a
    thing to do silently on behalf of a script.
    """
    if reg.has_webauthn_key():
        return
    dev_only = bool(reg.signers)
    note = (DEV_ONLY_NOTE if dev_only else NO_KEY_NOTE).format(home=home)
    if not sys.stdin.isatty():
        print(note, file=sys.stderr)
        return

    if dev_only:
        print("# Only software keys are enrolled, so this install signs in dev mode: a signature\n"
              "# would prove possession of a key file rather than the presence of a person.",
              file=sys.stderr)
        question = "Enroll a passkey now?"
    else:
        print("# Nothing can be signed yet: the registry has no keys, so every block would verify as\n"
              "# unknown_signer. That is safe but inert.", file=sys.stderr)
        question = "Enroll a signing key now?"
    if not ask_yes_no(question, default=True):
        print(note, file=sys.stderr)
        return

    # whoever already signs here, when there is no ambiguity about who that is
    default_signer = next(iter(reg.signers)) if len(reg.signers) == 1 else suggest_signer()
    signer = ask_text("Who signs instructions here?", default_signer)
    if not signer:
        print(note, file=sys.stderr)
        return

    passkey = dev_only or ask_yes_no(
        "Use a passkey, so signing needs your fingerprint or face? Saying no makes a software key, "
        "which proves only possession of a file.",
        default=True)
    _enroll(signer, passkey, home)


def _enroll(signer: str, passkey: bool, home: Path) -> None:
    """Enroll through the CLI's own commands, so the warnings a user would see
    from `sib enroll` are the warnings they see here.

    Imported late: `cli` imports this module, and the registry those commands
    open must be the one whose path is baked into the policy we just wrote.
    """
    import argparse
    from . import cli

    os.environ["SIB_HOME"] = str(home)
    try:
        if passkey:
            cli.cmd_enroll(argparse.Namespace(
                signer=signer, kid=None, public_key=None, alg="EdDSA", dev=False,
                timeout=120.0, no_browser=False, browser=None))
        else:
            cli.cmd_keygen(argparse.Namespace(signer=signer, kid=None, enroll=True, audience=None))
    except SystemExit as e:
        print(f"# Enrollment did not finish ({e}). Retry with `sib enroll --signer {signer}`.",
              file=sys.stderr)
