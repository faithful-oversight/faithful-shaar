# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for safe XML parsing."""

from __future__ import annotations

import contextlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from faithful_shaar.formats import xmlsafe

DOC = '<?xml version="1.0" encoding="{enc}"?><r xmlns="urn:x"><a k="v">one<b/>two</a></r>'


def test_namespaces_use_the_uri_not_the_prefix() -> None:
    root = xmlsafe.parse(b'<p:r xmlns:p="urn:x" xmlns:q="urn:y" q:at="1"><q:c/></p:r>')
    assert root.tag == "{urn:x}r"
    assert root.attrib == {"{urn:y}at": "1"}
    assert root[0].tag == "{urn:y}c"
    assert xmlsafe.split(root.tag) == ("urn:x", "r")
    assert xmlsafe.split("plain") == ("", "plain")


def test_text_and_tail_are_kept() -> None:
    root = xmlsafe.parse(DOC.format(enc="utf-8").encode())
    a = root[0]
    assert (a.text, a[0].tail, a.get("k")) == ("one", "two", "v")


def test_cdata_and_surroundings_are_fine() -> None:
    root = xmlsafe.parse(b"<!--c-->\n<?pi x?>\n<r><![CDATA[<x>]]></r>\n<!--d-->\n")
    assert root.text == "<x>"


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"\xef\xbb\xbf" + DOC.format(enc="utf-8").encode(), id="utf-8 bom"),
        pytest.param(b"\xff\xfe" + DOC.format(enc="utf-16").encode("utf-16-le"), id="utf-16le bom"),
        pytest.param(b"\xfe\xff" + DOC.format(enc="utf-16").encode("utf-16-be"), id="utf-16be bom"),
        pytest.param(DOC.format(enc="utf-16").encode("utf-8"), id="utf-8 declaring utf-16"),
        pytest.param(DOC.format(enc="utf-8").encode("utf-16-le"), id="utf-16le no bom"),
        pytest.param(DOC.format(enc="utf-8").encode("utf-16-be"), id="utf-16be no bom"),
        pytest.param(DOC.format(enc="iso-8859-1").encode("utf-8"), id="utf-8 declaring latin-1"),
    ],
)
def test_every_encoding_gives_the_same_tree(data: bytes) -> None:
    root = xmlsafe.parse(data)
    assert root.tag == "{urn:x}r"
    assert root[0].text == "one"


def test_utf8_text_is_not_mangled() -> None:
    root = xmlsafe.parse("<r>café 中</r>".encode())
    assert root.text == "café 中"


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"\xef\xbb\xbf\xff\xfe", "UTF-8"),
        (b"\xff\xfe<", "UTF-16-LE"),
        (b"\xfe\xff\x00", "UTF-16-BE"),
        (b"\x80\x81\x82", "neither UTF-8 nor UTF-16"),
        (b"", "not well-formed"),
        (b"<a><b></a>", "not well-formed"),
        (b"<a>", "not well-formed"),
        (b"just text", "not well-formed"),
        (b"<a>&xxe;</a>", "not well-formed"),
    ],
)
def test_bad_bytes_are_refused(data: bytes, reason: str) -> None:
    with pytest.raises(xmlsafe.XmlError, match=reason):
        xmlsafe.parse(data)


@pytest.mark.parametrize(
    "doc",
    [
        '<!DOCTYPE r [<!ENTITY x "boom">]><r>&x;</r>',
        '<!DOCTYPE r SYSTEM "http://192.0.2.1/evil.dtd"><r/>',
        '<!DOCTYPE r [<!ENTITY % p SYSTEM "file:///etc/passwd">%p;]><r/>',
        '<!DOCTYPE lol [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;">]><lol>&b;</lol>',
        '<?xml version="1.0"?><!DOCTYPE r><r/>',
    ],
)
@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_doctype_and_entities_are_refused(doc: str, encoding: str) -> None:
    data = doc.encode(encoding) if encoding == "utf-8" else b"\xff\xfe" + doc.encode("utf-16-le")
    with pytest.raises(xmlsafe.XmlError, match="DOCTYPE"):
        xmlsafe.parse(data)


def test_depth_limit_counts_every_element() -> None:
    limit = xmlsafe.MAX_DEPTH
    ok = "<a>" * limit + "</a>" * limit
    assert xmlsafe.parse(ok.encode()).tag == "a"
    too_deep = "<a>" * (limit + 1) + "</a>" * (limit + 1)
    with pytest.raises(xmlsafe.XmlError, match=f"more than {limit} levels"):
        xmlsafe.parse(too_deep.encode())
    # Elements nobody reads still count, and so does unclosed nesting.
    with pytest.raises(xmlsafe.XmlError, match="levels"):
        xmlsafe.parse(("<x:a xmlns:x='u'>" * (limit + 1)).encode())


def test_size_limit_is_checked_before_decoding() -> None:
    assert xmlsafe.parse(b"<r/>", max_bytes=4).tag == "r"
    with pytest.raises(xmlsafe.XmlError, match="larger than 3 bytes"):
        xmlsafe.parse(b"<r/>", max_bytes=3)
    assert xmlsafe.MAX_BYTES >= 64 * 1024 * 1024


def test_huge_text_is_read_in_one_piece() -> None:
    text = "x" * (3 << 20)
    root = xmlsafe.parse(f"<r>{text}</r>".encode())
    assert root.text == text


@given(st.binary(max_size=300))
def test_arbitrary_bytes_never_raise_anything_else(data: bytes) -> None:
    with contextlib.suppress(xmlsafe.XmlError):
        xmlsafe.parse(data)
