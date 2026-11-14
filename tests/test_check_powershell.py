# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the PowerShell syntax check in scripts/check.sh."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CHECK = (ROOT / "scripts" / "check.sh").read_text(encoding="utf-8")
BASH = shutil.which("bash")


def _function() -> str:
    match = re.search(r"^check_powershell\(\) \{.*?^\}", CHECK, re.DOTALL | re.MULTILINE)
    assert match is not None
    return match.group()


def test_the_config_stage_runs_the_powershell_check() -> None:
    stage = re.search(r"^stage_config\(\) \{.*?^\}", CHECK, re.DOTALL | re.MULTILINE)
    assert stage is not None
    assert "check_powershell" in stage.group()


def test_the_check_parses_every_tracked_script_with_the_real_parser() -> None:
    text = _function()
    assert "git ls-files -z '*.ps1'" in text
    assert "System.Management.Automation.Language.Parser" in text
    assert "SHAAR_REQUIRE_PWSH" in text


def _run_without_pwsh(tmp_path: Path, require: str | None) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    # A PATH holding only a bash link: no pwsh, and nothing else the function needs.
    tools = tmp_path / "bin"
    tools.mkdir(exist_ok=True)
    if not (tools / "bash").exists():
        (tools / "bash").symlink_to(BASH)
    env = {"PATH": str(tools)}
    if require is not None:
        env["SHAAR_REQUIRE_PWSH"] = require
    script = f"{_function()}\ncheck_powershell"
    return subprocess.run(  # noqa: S603
        [str(tools / "bash"), "-c", script], env=env, capture_output=True, text=True, check=False
    )


@pytest.mark.skipif(os.name != "posix" or BASH is None, reason="needs a POSIX shell")
def test_a_missing_pwsh_is_skipped_with_a_note_unless_it_is_required(tmp_path: Path) -> None:
    skipped = _run_without_pwsh(tmp_path, None)
    assert skipped.returncode == 0
    assert "skipping the PowerShell syntax check" in skipped.stderr
    refused = _run_without_pwsh(tmp_path, "1")
    assert refused.returncode == 1
    assert "SHAAR_REQUIRE_PWSH is set but pwsh is not installed" in refused.stderr
