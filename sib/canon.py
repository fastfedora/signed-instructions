"""Canonicalization rules. The rule name travels in the signed header (`canon`),
so a verifier applies exactly the rule the signer used and never guesses.
Rules are versioned and never change in place."""
import unicodedata

# Characters chat clients and editors substitute silently. Folded so a signed
# instruction survives the trip; the fold is part of the rule's definition.
_FOLD = {
    "‘": "'", "’": "'", "‚": "'", "‛": "'",   # single quotes
    "“": '"', "”": '"', "„": '"', "‟": '"',   # double quotes
    " ": " ", " ": " ", " ": " ",                  # non-breaking spaces
    "​": "", "‌": "", "‍": "", "﻿": "",       # zero-width characters
}


class UnknownCanonicalization(ValueError):
    pass


def text_1(text: str) -> str:
    """text/1: NFC; typographic quotes and NBSP folded to ASCII; zero-width
    characters removed; every whitespace run (including line breaks) collapsed
    to one space; trimmed. Immune to re-wrapping; does not sign line structure."""
    t = unicodedata.normalize("NFC", text)
    t = "".join(_FOLD.get(c, c) for c in t)
    return " ".join(t.split())


def raw_1(text: str) -> str:
    """raw/1: exact text after NFC. No transport tolerance."""
    return unicodedata.normalize("NFC", text)


RULES = {
    "text/1": text_1,
    "raw/1": raw_1,
}


def canonicalize(rule: str, text: str) -> str:
    try:
        fn = RULES[rule]
    except KeyError:
        raise UnknownCanonicalization(rule) from None
    return fn(text)
