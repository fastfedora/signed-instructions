import string

import pytest
from hypothesis import given, strategies as st

from sib.canon import canonicalize, text_1, raw_1, UnknownCanonicalization

TEXT = "You may deploy to staging with\nscripts/deploy.sh staging whenever the tests pass."


def test_text_1_collapses_whitespace_and_folds_quotes():
    assert text_1("a  b\n\tc") == "a b c"
    assert text_1("“smart” ‘quotes’ and nbsp") == '"smart" \'quotes\' and nbsp'
    assert text_1("zero​width") == "zerowidth"


def test_text_1_rewrap_and_crlf_invariant():
    a = text_1(TEXT)
    assert text_1(TEXT.replace("\n", "\r\n")) == a
    assert text_1(TEXT.replace(" ", "\n")) == a
    assert text_1("   " + TEXT + "\n\n") == a


def test_text_1_detects_content_change():
    assert text_1(TEXT) != text_1(TEXT.replace("staging", "production"))


def test_raw_1_keeps_lines():
    assert raw_1(TEXT) == TEXT
    assert raw_1(TEXT.replace("\n", " ")) != TEXT


def test_unknown_rule():
    with pytest.raises(UnknownCanonicalization):
        canonicalize("yaml/1", "x")


@given(st.text(alphabet=string.printable + "“”‘’ ", max_size=200))
def test_text_1_idempotent(s):
    assert text_1(text_1(s)) == text_1(s)


@given(st.text(alphabet=string.ascii_letters + " \n\t", max_size=200))
def test_text_1_wrap_invariant(s):
    import re
    rewrapped = re.sub(r" ", "\n", s)
    assert text_1(rewrapped) == text_1(s)
