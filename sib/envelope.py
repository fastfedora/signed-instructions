"""The clearsigned block: instruction in plain text, then a detached signature.

-----BEGIN SIB SIGNED INSTRUCTION-----
<instruction as written>
-----BEGIN SIB SIGNATURE-----
Signer: alice@example.com
Expires: 2026-09-12T18:00:00Z
Audience: acme/dev-agent

<header..signature, base64url, wrapped at 64 columns>
-----END SIB SIGNATURE-----
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

BEGIN_TEXT = "BEGIN SIB SIGNED INSTRUCTION"
BEGIN_SIG = "BEGIN SIB SIGNATURE"
END_SIG = "END SIB SIGNATURE"

# Marker lines tolerate dash variants editors substitute, and a leading prefix
# such as "> ", "# " or "// " that the transport added.
_DASH = r"[-‐‑‒–—―−]{3,}"
_MARK = re.compile(rf"^(?P<prefix>.*?)(?:{_DASH})\s*(?P<name>{BEGIN_TEXT}|{BEGIN_SIG}|{END_SIG})\s*(?:{_DASH})\s*$")
_B64URL = re.compile(r"[^A-Za-z0-9_.\-]")
_CLEAR = re.compile(r"^([A-Za-z][A-Za-z0-9 -]*):\s*(.*)$")


@dataclass
class Block:
    text: str                      # instruction as written (before canonicalization)
    compact: str                   # header..signature
    clear: dict = field(default_factory=dict)   # Signer/Expires/Audience lines as found
    start: int = 0                 # character offsets in the source document
    end: int = 0
    prefix: str = ""               # transport prefix that was stripped, if any


def render(text: str, compact: str, clear: dict | None = None, width: int = 64) -> str:
    lines = [f"-----{BEGIN_TEXT}-----", text.rstrip("\n"), f"-----{BEGIN_SIG}-----"]
    for k, v in (clear or {}).items():
        lines.append(f"{k}: {v}")
    if clear:
        lines.append("")
    lines += [compact[i:i + width] for i in range(0, len(compact), width)]
    lines.append(f"-----{END_SIG}-----")
    return "\n".join(lines)


def _strip_prefix(line: str, prefix: str) -> str:
    if prefix and line.startswith(prefix):
        return line[len(prefix):]
    # Slack and email often turn "> " into ">" on blank lines.
    if prefix and line.strip() == prefix.strip():
        return ""
    return line


def extract(document: str) -> list[Block]:
    """Every clearsigned block in the document, in order. Malformed fragments
    (a BEGIN without its END) are skipped, never guessed at."""
    blocks: list[Block] = []
    lines = document.splitlines(keepends=True)
    i = 0
    while i < len(lines):
        m = _MARK.match(lines[i].rstrip("\r\n"))
        if not m or m.group("name") != BEGIN_TEXT:
            i += 1
            continue
        prefix = m.group("prefix")
        start = sum(len(l) for l in lines[:i])
        text_lines: list[str] = []
        j = i + 1
        state = "text"
        clear: dict = {}
        sig_lines: list[str] = []
        end_idx = None
        while j < len(lines):
            raw = lines[j].rstrip("\r\n")
            mm = _MARK.match(raw)
            if mm and mm.group("name") == BEGIN_SIG and state == "text":
                state = "clear"
            elif mm and mm.group("name") == END_SIG and state in ("clear", "sig"):
                end_idx = j
                break
            elif mm and mm.group("name") == BEGIN_TEXT:
                break  # nested/unterminated block: abandon this one
            else:
                body = _strip_prefix(raw, prefix)
                if state == "text":
                    text_lines.append(body)
                elif state == "clear":
                    if body.strip() == "":
                        state = "sig"
                    else:
                        cm = _CLEAR.match(body.strip())
                        if cm:
                            clear[cm.group(1).strip()] = cm.group(2).strip()
                        else:
                            state = "sig"
                            sig_lines.append(body)
                else:
                    sig_lines.append(body)
            j += 1
        if end_idx is None:
            i += 1
            continue
        compact = _B64URL.sub("", "".join(sig_lines))
        end = sum(len(l) for l in lines[:end_idx + 1])
        blocks.append(Block(text="\n".join(text_lines).strip("\n"), compact=compact, clear=clear,
                            start=start, end=end, prefix=prefix))
        i = end_idx + 1
    return blocks
