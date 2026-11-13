# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Exceptions raised by shaar."""


class ShaarError(Exception):
    """Base class for errors shaar reports to the user."""


class InputError(ShaarError):
    """An input file or configuration cannot be read or has the wrong shape."""


class CollectionError(ShaarError):
    """Live collection could not connect, authenticate, or read what it needs."""


class UsageError(ShaarError):
    """The command's options do not fit together, so nothing was attempted."""
