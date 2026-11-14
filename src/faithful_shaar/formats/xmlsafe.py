# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Parse XML from untrusted files with the standard library's expat parser.

The protections are the same as in the other Faithful Oversight tools:

* A DOCTYPE (and so every entity declaration, internal or external) is refused. An
  entity reference that was never declared is not well-formed, so it is refused too.
  Nothing is ever fetched, and no entity is ever expanded.
* Elements may nest at most :data:`MAX_DEPTH` levels, counted on every element.
* A file larger than :data:`MAX_BYTES` is refused before it is decoded.
* The declared encoding is ignored. The bytes are decoded here, from the byte order
  mark if there is one, otherwise as UTF-8, otherwise as UTF-16. Spreadsheet programs
  do not always declare what they write, so the declaration is not trusted. The decoded
  text is handed to expat as text, which makes expat read it as UTF-8 whatever the
  declaration says.

The result is a tree of :class:`xml.etree.ElementTree.Element` objects built from
expat events. Names that have a namespace are written ``{uri}local``, and identity is by
URI, never by prefix. Text before a child is ``text`` and text after it is the child's
``tail``, as in ElementTree.
"""

from __future__ import annotations

import codecs
from xml.etree import ElementTree as ET
from xml.parsers import expat

MAX_DEPTH = 64
"""Deepest element nesting accepted, counted on every element."""
MAX_BYTES = 256 * 1024 * 1024
"""Largest file accepted, in bytes."""

_BOMS = (
    (codecs.BOM_UTF8, "utf-8"),
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
)
_CHECK_CHARS = 256


class XmlError(ValueError):
    """The bytes are not XML that shaar is willing to read."""


def decode(data: bytes) -> str:
    """Decode the bytes of an XML file, ignoring any declared encoding.

    Args:
        data: The file's bytes.

    Returns:
        The text, without a byte order mark.

    Raises:
        XmlError: The bytes are neither UTF-8 nor UTF-16.
    """
    for mark, codec in _BOMS:
        if data.startswith(mark):
            try:
                return data[len(mark) :].decode(codec)
            except UnicodeDecodeError:
                msg = f"the text is not valid {codec.upper()}"
                raise XmlError(msg) from None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if text and "\x00" not in text[:_CHECK_CHARS]:
        return text
    # No byte order mark: UTF-16 text shows as NUL bytes in the first characters.
    codec = "utf-16-be" if data[:1] == b"\x00" else "utf-16-le"
    try:
        return data.decode(codec)
    except UnicodeDecodeError:
        msg = "the text is neither UTF-8 nor UTF-16"
        raise XmlError(msg) from None


def split(tag: str) -> tuple[str, str]:
    """Split ``{uri}local`` into ``(uri, local)``; the URI is empty with no namespace."""
    if tag.startswith("{"):
        uri, _sep, local = tag[1:].partition("}")
        return uri, local
    return "", tag


class _Builder:
    """Collects expat events into an element tree."""

    def __init__(self) -> None:
        self.stack: list[ET.Element] = []
        self.root: ET.Element | None = None

    @staticmethod
    def _name(name: str) -> str:
        uri, sep, local = name.rpartition("}")
        return f"{{{uri}}}{local}" if sep else local

    def start(self, name: str, attributes: dict[str, str]) -> None:
        if len(self.stack) >= MAX_DEPTH:
            msg = f"elements are nested more than {MAX_DEPTH} levels deep"
            raise XmlError(msg)
        element = ET.Element(self._name(name), {self._name(k): v for k, v in attributes.items()})
        if self.stack:
            self.stack[-1].append(element)
        else:
            self.root = element
        self.stack.append(element)

    def end(self, _name: str) -> None:
        self.stack.pop()

    def characters(self, data: str) -> None:
        current = self.stack[-1]  # expat reports text only inside the root element
        if len(current):
            last = current[-1]
            last.tail = (last.tail or "") + data
        else:
            current.text = (current.text or "") + data


def _refuse_doctype(*_args: object) -> None:
    msg = "it declares a DOCTYPE or an entity; shaar refuses to parse those"
    raise XmlError(msg)


def parse(data: bytes, *, max_bytes: int | None = None) -> ET.Element:
    """Parse an XML file safely.

    Args:
        data: The file's bytes.
        max_bytes: The largest size accepted; the default is :data:`MAX_BYTES`.

    Returns:
        The root element.

    Raises:
        XmlError: The file is too large, is not UTF-8 or UTF-16, declares a DOCTYPE or
            an entity, nests too deeply, or is not well-formed.
    """
    limit = MAX_BYTES if max_bytes is None else max_bytes
    if len(data) > limit:
        msg = f"it is larger than {limit} bytes"
        raise XmlError(msg)
    text = decode(data)
    builder = _Builder()
    parser = expat.ParserCreate(namespace_separator="}")
    parser.buffer_text = True
    parser.buffer_size = 1 << 20
    parser.StartDoctypeDeclHandler = _refuse_doctype
    parser.StartElementHandler = builder.start
    parser.EndElementHandler = builder.end
    parser.CharacterDataHandler = builder.characters
    try:
        parser.Parse(text, True)  # noqa: FBT003 - expat's own signature
    except expat.ExpatError as exc:
        reason = expat.ErrorString(exc.code)
        msg = f"the XML is not well-formed: {reason} at line {exc.lineno}, column {exc.offset}"
        raise XmlError(msg) from None
    assert builder.root is not None  # noqa: S101 - expat refuses a document with no root
    return builder.root
