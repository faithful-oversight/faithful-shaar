# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Parse XML from untrusted files with the standard library's expat parser.

The protections are the same as in the other Faithful Oversight tools:

* A DOCTYPE (and so every entity declaration, internal or external) is refused. An
  entity reference that was never declared is not well-formed, so it is refused too.
  Nothing is ever fetched, and no entity is ever expanded.
* Elements may nest at most :data:`MAX_DEPTH` levels, counted on every element.
* A file larger than :data:`MAX_BYTES` is refused before it is decoded.
* At most :data:`MAX_ELEMENTS` elements are held in memory at once (``max_elements``).
  Byte limits do not bound objects: a 12 MB file of empty ``<c s="1"/>`` cells made a tree
  of about 3 GB. Elements the caller takes with ``take`` are handed over one by one and
  dropped, so a large worksheet is read in constant memory; ``max_total`` caps all the
  elements read, taken or not.
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
from collections.abc import Callable
from xml.etree import ElementTree as ET
from xml.parsers import expat

MAX_DEPTH = 64
"""Deepest element nesting accepted, counted on every element."""
MAX_BYTES = 256 * 1024 * 1024
"""Largest file accepted, in bytes."""
MAX_ELEMENTS = 1_000_000
"""Most elements held at once by default; about 0.7 GB of memory in the worst case."""

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


Take = tuple[tuple[str, ...], Callable[[ET.Element], None]]
"""A path of local element names from the root (``"*"`` matches any name) and the function
that receives each complete element at that path before it is dropped from the tree."""


class _Builder:
    """Collects expat events into an element tree."""

    def __init__(
        self, max_elements: int, max_total: int | None = None, take: Take | None = None
    ) -> None:
        self.stack: list[ET.Element] = []
        self.before: list[int] = []  # elements held when each open element started
        self.root: ET.Element | None = None
        self.held = 0
        self.total = 0
        self.max_elements = max_elements
        self.max_total = max_total
        self.take = take

    @staticmethod
    def _name(name: str) -> str:
        uri, sep, local = name.rpartition("}")
        return f"{{{uri}}}{local}" if sep else local

    def start(self, name: str, attributes: dict[str, str]) -> None:
        if len(self.stack) >= MAX_DEPTH:
            msg = f"elements are nested more than {MAX_DEPTH} levels deep"
            raise XmlError(msg)
        self.held += 1
        self.total += 1
        if self.held > self.max_elements:
            msg = f"it holds more than {self.max_elements} elements at once"
            raise XmlError(msg)
        if self.max_total is not None and self.total > self.max_total:
            msg = f"it has more than {self.max_total} elements"
            raise XmlError(msg)
        self.before.append(self.held - 1)
        element = ET.Element(self._name(name), {self._name(k): v for k, v in attributes.items()})
        if self.stack:
            self.stack[-1].append(element)
        else:
            self.root = element
        self.stack.append(element)

    def end(self, _name: str) -> None:
        if self.take is not None and len(self.stack) == len(self.take[0]):
            path, receive = self.take
            names = [split(e.tag)[1] for e in self.stack]
            if all(want in {"*", have} for want, have in zip(path, names, strict=True)):
                element = self.stack[-1]
                receive(element)
                if len(self.stack) > 1:
                    self.stack[-2].remove(element)
                    self.held = self.before[-1]  # its whole subtree is gone
        self.before.pop()
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


def parse(
    data: bytes,
    *,
    max_bytes: int | None = None,
    max_elements: int = MAX_ELEMENTS,
    max_total: int | None = None,
    take: Take | None = None,
) -> ET.Element:
    """Parse an XML file safely.

    Args:
        data: The file's bytes.
        max_bytes: The largest size accepted; the default is :data:`MAX_BYTES`.
        max_elements: The most elements held at once.
        max_total: The most elements in the whole document; ``None`` for no separate limit.
        take: Hand each complete element at a path to a function and drop it (see
            :data:`Take`); an exception the function raises ends the parse.

    Returns:
        The root element.

    Raises:
        XmlError: The file is too large, is not UTF-8 or UTF-16, declares a DOCTYPE or
            an entity, nests too deeply, holds too many elements, or is not well-formed.
    """
    limit = MAX_BYTES if max_bytes is None else max_bytes
    if len(data) > limit:
        msg = f"it is larger than {limit} bytes"
        raise XmlError(msg)
    text = decode(data)
    builder = _Builder(max_elements, max_total, take)
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
