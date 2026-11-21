# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Exceptions raised by shaar.

The classes come from faithful-core. ``ShaarError`` is its ``FaithfulError``, so
one ``except ShaarError`` also catches an error raised inside the library.
"""

from faithful_core.errors import (
    CollectionError,
    FaithfulError,
    InputError,
    OutputError,
    UsageError,
)

__all__ = [
    "CollectionError",
    "InputError",
    "OutputError",
    "ShaarError",
    "UsageError",
]

ShaarError = FaithfulError
"""Base class for errors shaar reports to the user."""
