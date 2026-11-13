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
  python="$work/venv/bin/python"
else
  tool="$work/venv/Scripts/shaar"
  python="$work/venv/Scripts/python"
fi

"$tool" --version
"$tool" --help > /dev/null

# --- Product end-to-end run ---
# The installed wheel runs a whole review on the synthetic example: a new campaign from
# its exports, then decisions from its returned packets, then verification.
demo="$work/demo"
"$tool" example "$demo" > /dev/null

expect() {  # expect CODE COMMAND...: run a command and require its exit code
  local want="$1"; shift
  set +e; "$@" > /dev/null; local got=$?; set -e
  [[ $got -eq $want ]] || { echo "expected exit $want, got $got: $*" >&2; exit 1; }
}

before="$demo/before"
expect 1 "$tool" campaign "$before/ad.jsonl" "$before/entra.jsonl" "$before/ledger.csv" \
  --map "$before/ledger-map.toml" --name "Smoke test" --reviewers manager --due 2026-11-16 \
  -o "$work/campaign"
# Fill in the packets of the campaign just made, as the example's reviewers would, so the
# rest of the run uses what this wheel wrote, not the example's committed packets.
"$python" - "$work/campaign" "$work/returned" <<'PY'
import pathlib, sys
from faithful_shaar import campaign, example
made = campaign.load(pathlib.Path(sys.argv[1], "campaign.json").read_bytes())
out = pathlib.Path(sys.argv[2])
out.mkdir()
for name, data in example._returned(made).items():
    (out / name).write_bytes(data)
assert sorted(out.glob("*.xlsx")), "no packets were filled in"
PY
expect 1 "$tool" decisions "$work/campaign" "$work"/returned/*.xlsx -o "$work/decisions"
"$python" - "$work/decisions/decisions.json" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
assert data["packets"] and all(p["status"] == "read" for p in data["packets"]), data["packets"]
assert any(r["state"] == "accepted" for r in data["rows"]), "no decision was accepted"
PY
expect 1 "$tool" verify "$work/campaign" "$work/decisions" "$demo/after/ad.jsonl" \
  "$demo/after/entra.jsonl" "$demo/after/ledger.csv" --map "$demo/after/ledger-map.toml" \
  -o "$work/verification"

# Every folder has its reports, each non-empty, and a manifest listing every other file.
"$python" - "$work/campaign" "$work/decisions" "$work/verification" <<'PY'
import hashlib, json, pathlib, sys
for folder in map(pathlib.Path, sys.argv[1:]):
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    listed = {entry["name"]: entry for entry in manifest["files"]}
    present = {p.name for p in folder.iterdir()} - {"manifest.json"}
    if set(listed) != present:
        sys.exit(f"{folder.name}: the manifest lists {sorted(listed)}, the folder holds {sorted(present)}")
    kinds = [name for name in present if name.endswith(("-report.json", "-report.md", "-report.html"))]
    if len(kinds) != 3:
        sys.exit(f"{folder.name}: expected three reports, found {sorted(kinds)}")
    for name, entry in listed.items():
        data = (folder / name).read_bytes()
        if not data or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            sys.exit(f"{folder.name}/{name} is empty or does not match the manifest")
PY
# --- End of product end-to-end run ---

echo "smoke test passed: ${wheels[0]}"
