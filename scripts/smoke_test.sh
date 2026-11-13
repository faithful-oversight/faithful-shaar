#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Install the exact wheel in a directory into a clean environment and run it.
# CI and the release workflow both run this on the files they publish.
#
# Usage: scripts/smoke_test.sh <dist-directory>
#
# Products extend the marked section to run their real workflow end to end on
# synthetic data, so a broken package cannot be released.

set -euo pipefail

dist="${1:?dist directory required}"
shopt -s nullglob
wheels=("$dist"/*.whl)
[[ ${#wheels[@]} -eq 1 ]] || { echo "expected exactly one wheel in $dist" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

uv venv --quiet "$work/venv"
uv pip install --quiet --python "$work/venv" --no-deps "${wheels[0]}"
if [[ -x "$work/venv/bin/shaar" ]]; then
  tool="$work/venv/bin/shaar"
else
  tool="$work/venv/Scripts/shaar"
fi

"$tool" --version
"$tool" --help > /dev/null

# --- Product end-to-end run ---
# TODO(core team): replace this block with the installed-wheel workflow, as
# faithful-mishpat's smoke_test.sh does for `example` and `compare`:
#   1. `"$tool" example "$work/demo"`: the synthetic example must write its inputs.
#   2. `"$tool" campaign ...`: build a campaign from the example; check the exit code
#      and that every expected output (JSON, Markdown, HTML, CSVs, manifest) is non-empty.
#   3. `"$tool" decisions ...`: apply the example decisions; check outputs and exit code.
#   4. `"$tool" verify ...`: verify the result against the campaign; check the exit code
#      and that the manifest lists every report.
# Pick the interpreter for manifest checks the way mishpat does: "$work/venv/bin/python"
# or "$work/venv/Scripts/python" on Windows. Until these steps exist this script proves
# only that the wheel installs and starts.
# --- End of product end-to-end run ---

echo "smoke test passed: ${wheels[0]}"
