# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""The AD collector's messages escape bidirectional and format characters too."""

from __future__ import annotations

from faithful_shaar.collect import ad

RLO = chr(0x202E)
ZWSP = chr(0x200B)


def test_collector_messages_escape_bidi_and_line_breaks() -> None:
    shown = ad.terminal(f"group{RLO}eman\nfake line{ZWSP}")
    assert RLO not in shown
    assert ZWSP not in shown
    assert "\n" not in shown
    assert "\\u202e" in shown
