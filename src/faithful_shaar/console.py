# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Printing that never changes how a command ends.

A command writes its files first and decides its exit code, then prints a summary. Two
things can go wrong while printing, and neither means the work failed:

- the reader of the output went away (``shaar ... | head``), which is a closed pipe;
- the terminal or the environment cannot encode the text (``PYTHONIOENCODING=ascii``
  with a path that has an accent in it).

:func:`prepare` makes the streams unable to fail on encoding; :func:`say` and
:func:`finish` stop printing when the pipe is closed and point ``sys.stdout`` at the null
device, so that the interpreter does not fail again when it flushes at exit. The exit
code the caller already decided is what the process returns.
"""

from __future__ import annotations

import contextlib
import os
import sys


def prepare() -> None:
    """Make stdout and stderr write what they cannot encode as visible escapes."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(Exception):  # a stream that refuses is left as it is
                reconfigure(errors="backslashreplace")


def _silence() -> None:
    """Point stdout at the null device, as the Python documentation shows for SIGPIPE."""
    with contextlib.suppress(Exception):  # a replaced stream may have no file descriptor
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)
    sys.stdout = open(os.devnull, "w", encoding="utf-8")  # noqa: SIM115, PTH123 - kept for the process


def say(text: str = "", *, error: bool = False, end: str = "\n") -> None:
    """Print ``text``; a closed pipe or an unencodable character never raises."""
    stream = sys.stderr if error else sys.stdout
    try:
        stream.write(text + end)
    except UnicodeEncodeError:
        stream.write((text + end).encode("ascii", "backslashreplace").decode("ascii"))
    except (OSError, ValueError):
        # BrokenPipeError on POSIX; Windows reports a closed pipe as OSError EINVAL. Either
        # way stdout is replaced, so the flush at interpreter shutdown cannot fail again.
        if not error:
            _silence()


def finish() -> None:
    """Flush the output buffers, ignoring a closed pipe."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):
            if stream is sys.stdout:
                _silence()
