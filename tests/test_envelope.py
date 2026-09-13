from sib.envelope import render, extract, BEGIN_TEXT


def test_roundtrip_and_offsets():
    doc = "intro\n\n" + render("hello\nworld", "aGVhZGVy..c2ln", {"Signer": "a@b", "Expires": "x"}) + "\n\nafter\n"
    blocks = extract(doc)
    assert len(blocks) == 1
    b = blocks[0]
    assert b.text == "hello\nworld"
    assert b.compact == "aGVhZGVy..c2ln"
    assert b.clear == {"Signer": "a@b", "Expires": "x"}
    assert doc[b.start:b.end].startswith("-----" + BEGIN_TEXT)


def test_quote_prefix_dash_variants_and_rewrap():
    block = render("hello world", "aGVhZGVy..c2lnbmF0dXJl", {"Signer": "a@b"})
    quoted = "\n".join("> " + l for l in block.splitlines())
    quoted = quoted.replace("-----BEGIN", "—---BEGIN").replace("-----END", "—---END")
    # re-wrap the signature line and add a blank quoted line
    quoted = quoted.replace("aGVhZGVy..c2lnbmF0dXJl", "aGVhZGVy..c2ln\n> bmF0dXJl").replace("> \n", ">\n")
    blocks = extract(quoted)
    assert len(blocks) == 1
    assert blocks[0].text == "hello world"
    assert blocks[0].compact == "aGVhZGVy..c2lnbmF0dXJl"
    assert blocks[0].prefix == "> "


def test_multiple_blocks_and_unterminated_skipped():
    a = render("one", "aA..bB")
    b = render("two", "cC..dD")
    doc = a + "\n-----BEGIN SIB SIGNED INSTRUCTION-----\nnever closed\n" + b
    texts = [x.text for x in extract(doc)]
    assert texts == ["one", "two"]


def test_no_blocks():
    assert extract("plain text with -----BEGIN nothing-----") == []
