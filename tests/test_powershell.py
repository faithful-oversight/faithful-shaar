# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: E501 - embedded PowerShell keeps its own line layout
"""The PowerShell exporter.

The text checks run everywhere. Where PowerShell is installed, the script's own
functions also run, with only the directory (RootDSE, searches, SID name lookup)
replaced by a synthetic stand-in; the output is checked by a reader written here.
Set ``SHAAR_REQUIRE_PWSH=1`` to fail instead of skipping when PowerShell is missing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from typing import TYPE_CHECKING, Any

import pytest

from faithful_shaar.campaign import build
from faithful_shaar.collect import script
from faithful_shaar.decide import read_decisions
from faithful_shaar.inputs import read_inputs
from faithful_shaar.verify import verify
from tests.core_fixtures import reader, returned

if TYPE_CHECKING:
    from pathlib import Path

    from faithful_shaar.model import Snapshot

TEXT = script.text()

# Commands the script may call. Anything that changes a directory object or runs
# arbitrary code would make the scan fail.
ALLOWED = {
    "Set-StrictMode", "New-Object", "Write-Output", "Get-Date", "Sort-Object",
    "ForEach-Object", "Where-Object", "Select-Object",
}  # fmt: skip
_FUNCTION = re.compile(r"^function ([A-Za-z]+-[A-Za-z]+)", re.MULTILINE)
_COMMAND = re.compile(r"(?<![\w$.-])([A-Z][a-z]+-[A-Z][A-Za-z]+)\b")
FORBIDDEN_TEXT = (
    "CommitChanges", ".Put(", ".PutEx(", "SetInfo", ".Invoke(", "InvokeSet", ".Rename(",
    ".MoveTo(", ".DeleteTree(", ".DeleteObject", "Children.Add", "Invoke-Expression",
    "Start-Process", "ActiveDirectory", "Get-AD", "Set-AD", "New-AD", "Remove-AD", "Add-AD",
    "Invoke-Command", "Out-File", "Set-Content", "Remove-Item",
)  # fmt: skip


def code() -> str:
    """The script without comments, so help text cannot hide or fake a command."""
    without_blocks = re.sub(r"<#.*?#>", "", TEXT, flags=re.DOTALL)
    without_blocks = re.sub(r"'[^'\n]*'", "''", without_blocks)
    return "\n".join(
        line.split(" #")[0]
        for line in without_blocks.splitlines()
        if not line.lstrip().startswith("#")
    )


def test_the_script_is_pure_ascii_for_windows_powershell() -> None:
    assert TEXT.isascii()
    assert "\r" not in TEXT


def test_the_script_states_the_version_it_writes() -> None:
    assert script.version() == "0.1.1"
    assert "$CollectorVersion = '0.1.1'" in TEXT
    assert "$CollectorName = 'Export-ShaarAccess.ps1'" in TEXT
    assert script.NAME == "Export-ShaarAccess.ps1"


def test_the_script_only_reads() -> None:
    body = code()
    defined = set(_FUNCTION.findall(body))
    called = set(_COMMAND.findall(body)) - defined
    assert called <= ALLOWED, called - ALLOWED
    for forbidden in FORBIDDEN_TEXT:
        assert forbidden not in body, forbidden
    # No assignment to a directory property value, and no Set-/New-/Remove-/Add- cmdlet
    # other than the two the script is allowed (strict mode, objects).
    assert not re.search(r"\.Value\s*=[^=]", body)
    cmdlets = {c for c in called if c.split("-")[0] in {"Set", "New", "Remove", "Add", "Clear"}}
    assert cmdlets == {"Set-StrictMode", "New-Object"}
    assert "Set-StrictMode -Version 3.0" in TEXT
    assert "\n$ErrorActionPreference = 'Stop'\n" in TEXT
    assert "[adsisearcher]" in TEXT
    assert "[adsi]" in TEXT


def test_the_script_uses_only_windows_powershell_5_1_syntax() -> None:
    body = code()
    for modern in ("??", "?.", "&&", "||", "-Parallel", "ForEach-Object -Parallel"):
        assert modern not in body, modern
    assert not re.search(r"\)\s*\?\s*[^\s]+\s*:", body)  # no ternary
    assert not re.search(r"^\s*class\s+\w+", body, re.MULTILINE)
    assert not re.search(r"^\s*enum\s+\w+", body, re.MULTILINE)
    assert "::new(" not in body


def test_the_output_file_is_never_overwritten_without_force() -> None:
    assert "[System.IO.FileMode]::CreateNew" in TEXT
    assert "[System.IO.FileMode]::Create " not in TEXT
    assert "[System.IO.File]::Move($Writer.TempPath, $Path)" in TEXT
    assert "UTF8Encoding -ArgumentList $false" in TEXT


# --- running the script's functions -----------------------------------------------------

_PWSH = shutil.which("pwsh") or shutil.which("powershell")
if _PWSH is None and os.environ.get("SHAAR_REQUIRE_PWSH") == "1":  # pragma: no cover
    msg = "SHAAR_REQUIRE_PWSH is set but PowerShell is not installed"
    raise RuntimeError(msg)
needs_pwsh = pytest.mark.skipif(_PWSH is None, reason="PowerShell is not installed")

PARAMETERS = """
$Group = $null; $SearchBase = $null; $Privileged = $false; $Server = $null
$OutFile = $null; $ToPipeline = $false; $Force = $false
"""


def functions() -> str:
    """The script's definitions, without its parameter block or its call to run."""
    start = TEXT.index("Set-StrictMode")
    end = TEXT.index("if ($MyInvocation.InvocationName")
    return PARAMETERS + TEXT[start:end]


# The stand-in directory. Only RootDSE, the searches, and the SID name lookup are
# replaced; everything the script does with what they return runs for real. Values are
# arrays, as ADSI gives them (objectSid is an array holding one byte array).
STUB = r"""
$script:Dir = New-Object System.Collections.Generic.List[object]
function Sid-Bytes([string] $Text) {
    $parts = $Text.Split('-')
    $n = $parts.Count - 3
    $b = New-Object byte[] (8 + 4 * $n)
    $b[0] = 1; $b[1] = $n; $b[7] = [byte] [int] $parts[2]
    for ($i = 0; $i -lt $n; $i++) {
        $v = [System.BitConverter]::GetBytes([uint32] $parts[3 + $i])
        [System.Array]::Copy($v, 0, $b, 8 + 4 * $i, 4)
    }
    , $b
}
$D = 'S-1-5-21-1000-1000-1000'
function Add-Obj([string] $Dn, [string] $Sid, [string[]] $Classes, [hashtable] $More) {
    $o = @{ dn = $Dn; sid = $Sid; classes = $Classes; more = $More }
    $script:Dir.Add($o)
}
function Row($o, [string[]] $Wanted) {
    $r = @{}
    $r['distinguishedname'] = @($o.dn)
    $r['objectclass'] = @($o.classes)
    if ($o.sid) { $r['objectsid'] = @(, (Sid-Bytes $o.sid)) }
    foreach ($k in $o.more.Keys) { $r[$k] = @($o.more[$k]) }
    $r
}
function G([string] $Cn, [int] $Rid, [hashtable] $More = @{}) {
    $More['samaccountname'] = $Cn; $More['name'] = $Cn
    Add-Obj ('CN=' + $Cn + ',OU=Groups,DC=corp,DC=example') ($D + '-' + $Rid) @('top', 'group') $More
}
function U([string] $Cn, [int] $Rid, [hashtable] $More = @{}) {
    $More['samaccountname'] = ($Cn -replace ' ', '.').ToLower(); $More['name'] = $Cn; $More['displayname'] = $Cn
    Add-Obj ('CN=' + $Cn + ',OU=People,DC=corp,DC=example') ($D + '-' + $Rid) @('top', 'person', 'organizationalPerson', 'user') $More
}
function Dn([string] $Cn, [string] $Ou = 'People') { 'CN=' + $Cn + ',OU=' + $Ou + ',DC=corp,DC=example' }

# groups
G 'Tier0 Admins' 1100 @{ managedby = (Dn 'Blake Example') }
G 'Server Ops' 1101
G 'Loop A' 1102
G 'Loop B' 1103
G 'Big Group' 1104
G 'Locked' 1105
G 'Flaky' 1106
G 'Ghosts' 1107
G 'Dup' 1108
G 'Dup' 1109
G 'Domain Admins' 512
G 'Domain Users' 513
G 'DnsAdmins' 1110
G 'Starred (x*)' 1111
Add-Obj 'CN=Administrators,CN=Builtin,DC=corp,DC=example' 'S-1-5-32-544' @('top', 'group') @{ samaccountname = 'Administrators'; name = 'Administrators' }
# people
$LastLogon = [datetime]::new(2026, 10, 1, 12, 30, 0, [System.DateTimeKind]::Utc).ToFileTimeUtc()
U 'Avery Example' 1201 @{ manager = (Dn 'Blake Example'); mail = 'avery@corp.example'; userprincipalname = 'avery@corp.example'; useraccountcontrol = 512; lastlogontimestamp = $LastLogon; primarygroupid = 513 }
U 'Blake Example' 1202 @{ manager = (Dn 'Casey Example'); mail = 'blake@corp.example'; useraccountcontrol = 66048; lastlogontimestamp = 0 }
U 'Casey Example' 1203 @{ mail = 'casey@corp.example'; useraccountcontrol = 514; lastlogontimestamp = 9223372036854775807 }
U 'Dana Example' 1204 @{ primarygroupid = 513; useraccountcontrol = 512 }
U 'Evan Example' 1205 @{ primarygroupid = 1100; useraccountcontrol = 512; manager = 'CN=Gone,OU=Elsewhere,DC=other,DC=example' }
Add-Obj 'CN=svc-ledger$,OU=Service,DC=corp,DC=example' ($D + '-1301') @('top', 'person', 'organizationalPerson', 'user', 'computer', 'msDS-GroupManagedServiceAccount') @{ samaccountname = 'svc-ledger$'; name = 'svc-ledger'; useraccountcontrol = 4096 }
Add-Obj 'CN=SRV01,OU=Servers,DC=corp,DC=example' ($D + '-1401') @('top', 'person', 'organizationalPerson', 'user', 'computer') @{ samaccountname = 'SRV01$'; name = 'SRV01'; useraccountcontrol = 4130 }
Add-Obj 'CN=Printer Contact,OU=People,DC=corp,DC=example' '' @('top', 'contact') @{ name = 'Printer Contact' }
foreach ($i in 1..7) { U ('Member ' + $i) (2000 + $i) @{ useraccountcontrol = 512 } }
foreach ($i in 1..4) { U ('Flake ' + $i) (2100 + $i) @{ useraccountcontrol = 512 } }
Add-Obj 'CN=S-1-5-21-2000-2000-2000-500,CN=ForeignSecurityPrincipals,DC=corp,DC=example' 'S-1-5-21-2000-2000-2000-500' @('top', 'foreignSecurityPrincipal') @{ name = 'S-1-5-21-2000-2000-2000-500' }
Add-Obj 'CN=S-1-5-21-2000-2000-2000-501,CN=ForeignSecurityPrincipals,DC=corp,DC=example' '' @('top', 'foreignSecurityPrincipal') @{ name = 'S-1-5-21-2000-2000-2000-501' }

$script:Members = @{
    (Dn 'Tier0 Admins' 'Groups') = @((Dn 'Avery Example'), (Dn 'Server Ops' 'Groups'), 'CN=S-1-5-21-2000-2000-2000-500,CN=ForeignSecurityPrincipals,DC=corp,DC=example', 'CN=S-1-5-21-2000-2000-2000-501,CN=ForeignSecurityPrincipals,DC=corp,DC=example')
    (Dn 'Server Ops' 'Groups') = @((Dn 'Blake Example'), (Dn 'Casey Example'), (Dn 'Tier0 Admins' 'Groups'), (Dn 'Avery Example'), (Dn 'svc-ledger$' 'Service'), (Dn 'SRV01' 'Servers'), (Dn 'Printer Contact'))
    (Dn 'Loop A' 'Groups') = @((Dn 'Loop B' 'Groups'), (Dn 'Dana Example'))
    (Dn 'Loop B' 'Groups') = @((Dn 'Loop A' 'Groups'))
    (Dn 'Big Group' 'Groups') = @(1..7 | ForEach-Object { Dn ('Member ' + $_) })
    (Dn 'Flaky' 'Groups') = @(1..4 | ForEach-Object { Dn ('Flake ' + $_) })
    (Dn 'Ghosts' 'Groups') = @((Dn 'Avery Example'), 'CN=Nobody,OU=Elsewhere,DC=other,DC=example')
    (Dn 'Locked' 'Groups') = @()
    (Dn 'Domain Admins' 'Groups') = @((Dn 'Avery Example'))
}
$script:RangeSize = 3

function Resolve-SidName([string] $Sid) {
    if ($Sid -eq 'S-1-5-21-2000-2000-2000-500') { return 'PARTNER\Fran Example' }
    $null
}
function Get-DomainFacts { [ordered] @{ DomainDn = 'DC=corp,DC=example' } }
function Search-Directory([string] $BaseDn, [string] $Filter, [string[]] $Properties, [string] $Scope) {
    $script:Searches.Add($Scope + ' ' + $BaseDn + ' ' + $Filter + ' ' + ($Properties -join ','))
    if ($Filter -eq '(objectClass=domain)') { return @{ objectsid = @(, (Sid-Bytes $D)) } }
    if ($Scope -eq 'Base' -and $Properties[0] -match '^member;range=(\d+)-\*$') {
        $start = [int] $Matches[1]
        if ($BaseDn -like 'CN=Locked,*') { throw [System.UnauthorizedAccessException] 'Access is denied.' }
        if ($BaseDn -like 'CN=Flaky,*' -and $start -ge 3) { throw 'The server is unwilling to process the request.' }
        $all = @($script:Members[$BaseDn])
        $obj = $script:Dir | Where-Object { $_.dn -eq $BaseDn }
        if ($null -eq $obj) { return @() }
        $row = @{ distinguishedname = @($BaseDn) }
        if ($all.Count -gt 0) {
            $end = [Math]::Min($start + $script:RangeSize, $all.Count) - 1
            $values = @($all[$start..$end])
            if ($end -ge $all.Count - 1) { $row['member;range=' + $start + '-*'] = $values }
            else { $row['member;range=' + $start + '-' + $end] = $values }
        }
        return $row
    }
    $hits = New-Object System.Collections.Generic.List[object]
    if ($Filter -match '^\(\|\(distinguishedName=') {
        foreach ($m in [regex]::Matches($Filter, '\(distinguishedName=((?:[^()\\]|\\[0-9a-f]{2})*)\)')) {
            $dn = $m.Groups[1].Value.Replace('\28', '(').Replace('\29', ')').Replace('\2a', '*').Replace('\5c', '\')
            foreach ($o in $script:Dir) { if ($o.dn -eq $dn) { $hits.Add((Row $o)) } }
        }
    } elseif ($Filter -match '^\(primaryGroupID=(\d+)\)$') {
        foreach ($o in $script:Dir) { if ($o.more.ContainsKey('primarygroupid') -and [string] $o.more['primarygroupid'] -eq $Matches[1]) { $hits.Add((Row $o)) } }
    } elseif ($Filter -match '^\(&\(objectClass=group\)\(objectSid=(S-[0-9-]+)\)\)$') {
        foreach ($o in $script:Dir) { if ($o.sid -eq $Matches[1] -and $o.classes -contains 'group') { $hits.Add((Row $o)) } }
    } elseif ($Filter -match '^\(&\(objectClass=group\)\(\|\(sAMAccountName=(.*)\)\(name=(.*)\)\)\)$' -or $Filter -match '^\(&\(objectClass=group\)\((sAMAccountName)=(.*)\)\)$') {
        $want = $Matches[2]
        if ($Matches[1] -eq 'sAMAccountName') { $want = $Matches[2] }
        $want = $want.Replace('\28', '(').Replace('\29', ')').Replace('\2a', '*').Replace('\5c', '\')
        foreach ($o in $script:Dir) { if ($o.classes -contains 'group' -and [string] $o.more['samaccountname'] -eq $want) { $hits.Add((Row $o)) } }
    } elseif ($Filter -eq '(objectClass=group)' -and $Scope -eq 'Base') {
        foreach ($o in $script:Dir) { if ($o.dn -eq $BaseDn -and $o.classes -contains 'group') { $hits.Add((Row $o)) } }
    } elseif ($Filter -eq '(objectClass=group)') {
        if ($BaseDn -like '*DENY*') { throw [System.UnauthorizedAccessException] 'Access is denied.' }
        foreach ($o in $script:Dir) { if ($o.dn.EndsWith($BaseDn) -and $o.classes -contains 'group') { $hits.Add((Row $o)) } }
    } else { throw "unexpected search $Filter" }
    $hits.ToArray()
}
$script:Searches = New-Object System.Collections.Generic.List[string]
"""

EXPORT_PARAMS = "$ToPipeline = $true; "


def run_pwsh(
    tmp_path: Path, body: str, env: dict[str, str] | None = None, *, stub: bool = True
) -> subprocess.CompletedProcess[str]:
    assert _PWSH is not None
    path = tmp_path / "run.ps1"
    path.write_text(functions() + "\n" + (STUB if stub else "") + "\n" + body, encoding="utf-8")
    return subprocess.run(  # noqa: S603 - a fixed interpreter and a script built here
        [_PWSH, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
        # Opt out of PowerShell's start-up telemetry: a test run should not phone home.
        env={**os.environ, "POWERSHELL_TELEMETRY_OPTOUT": "1", **(env or {})},
    )


def encoded(value: str) -> str:
    raw = value.encode("utf-16-le", "surrogatepass")
    return f"[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{base64.b64encode(raw).decode()}'))"


class Export:
    """A parsed export, read with the standard library only."""

    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        assert not raw.startswith(b"\xef\xbb\xbf")
        assert b"\r" not in raw
        assert raw.endswith(b"\n")
        text = raw.decode("utf-8")
        assert text.isascii()
        self.lines = [json.loads(line) for line in text.splitlines()]
        self.header = self.lines[0]
        self.trailer = self.lines[-1]
        body = self.lines[1:-1]
        self.principals = {r["principal"]["id"]: r["principal"] for r in body if "principal" in r}
        self.resources = {r["resource"]["name"]: r["resource"] for r in body if "resource" in r}
        self.grants = [r["grant"] for r in body if "grant" in r]
        self.gaps = [r["gap"] for r in body if "gap" in r]
        assert len(self.principals) + len(self.resources) + len(self.grants) + len(
            self.gaps
        ) == len(body)
        # The trailer: records and hash over every byte before the end line.
        before = raw[: raw.rindex(b'{"end":')]
        assert self.trailer["end"] is True
        assert self.trailer["records"] == len(body)
        assert self.trailer["sha256"] == hashlib.sha256(before).hexdigest()

    def sid(self, rid: int) -> str:
        return f"S-1-5-21-1000-1000-1000-{rid}"

    def grants_of(self, resource: str) -> dict[str, dict[str, Any]]:
        rid = self.resources[resource]["id"]
        return {
            self.principals[g["principal_id"]]["name"]: g
            for g in self.grants
            if g["resource_id"] == rid
        }


def export(tmp_path: Path, args: str, env: dict[str, str] | None = None) -> Export:
    result = run_pwsh(tmp_path, f"$ToPipeline = $true\n{args}\nInvoke-Export", env)
    assert result.returncode == 0, result.stderr
    return Export(("\n".join(result.stdout.splitlines()) + "\n").encode("utf-8"))


@needs_pwsh
def test_the_json_writer_agrees_with_python(tmp_path: Path) -> None:
    hostile = ["", "plain", 'q " b \\', "ctl \x00\x01\t\n\r\x7f", "é 漢字 😀 \u2028", "(&(a=*))"]
    lines = "\n".join(f"ConvertTo-JsonText ({encoded(v)})" for v in hostile)
    result = run_pwsh(tmp_path, lines + "\nConvertTo-JsonText $null", stub=False)
    assert result.returncode == 0, result.stderr
    out = result.stdout.splitlines()
    assert all(line.isascii() for line in out)
    assert [json.loads(line) for line in out] == [*hostile, None]


@needs_pwsh
def test_small_helpers(tmp_path: Path) -> None:
    body = r"""
ConvertFrom-FileTime 133901106000000000
'[' + (ConvertFrom-FileTime ([int64] 0)) + ']'
'[' + (ConvertFrom-FileTime $null) + ']'
'[' + (ConvertFrom-FileTime 9223372036854775807) + ']'
'[' + (ConvertFrom-FileTime 'not a number') + ']'
ConvertTo-LdapFilterText 'a(b)*c\d'
ConvertTo-DnsName 'dc=Sub,dc=corp,DC=example'
ConvertTo-SidText 's-1-5-21-1-2-3-500'
'[' + (ConvertTo-SidText 'nonsense') + ']'
'[' + (ConvertTo-SidText $null) + ']'
ConvertTo-SidText ([byte[]] @(1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0))
'[' + (ConvertTo-SidText ([byte[]] @(1, 1, 0, 0, 0, 0, 0, 5, 18))) + ']'
'[' + (ConvertTo-SidText ([byte[]] @(2, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0))) + ']'
'[' + (ConvertTo-SidText ([byte[]] @(1, 0, 0, 0, 0, 0, 0, 5))) + ']'
ConvertTo-SidText ([byte[]] @(1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0))
(Sort-Ordinal @(@{ k = 'b' }, @{ k = 'B' }, @{ k = 'a' }) 'k' | ForEach-Object { $_.k }) -join ''
Get-LdapPath 'OU=A/B,DC=corp,DC=example'
$Server = 'dc01.corp.example'
Get-LdapPath 'DC=corp,DC=example'
(ConvertTo-ExtraJson @{ b = 'x'; a = 'y'; c = '' })
"""
    result = run_pwsh(tmp_path, body, stub=False)
    assert result.returncode == 0, result.stderr
    out = result.stdout.splitlines()
    # 133901106000000000 ticks since 1601: checked against Python below.
    assert out[0].endswith("Z")
    assert out[1:] == [
        "[]", "[]", "[]", "[]",
        r"a\28b\29\2ac\5cd",
        "Sub.corp.example",
        "S-1-5-21-1-2-3-500",
        "[]", "[]",
        "S-1-5-18", "[]", "[]", "[]", "S-1-5-32-544",
        "Bab",
        r"LDAP://OU=A\/B,DC=corp,DC=example",
        "LDAP://dc01.corp.example/DC=corp,DC=example",
        '{"a":"y","b":"x"}',
    ]  # fmt: skip
    from datetime import UTC, datetime  # noqa: PLC0415

    expected = datetime(1601, 1, 1, tzinfo=UTC).timestamp() + 133901106000000000 / 1e7
    assert out[0] == datetime.fromtimestamp(expected, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@needs_pwsh
def test_a_search_result_is_converted_with_every_value_and_range_names(tmp_path: Path) -> None:
    body = r"""
$props = [ordered] @{ 'Member;range=0-1' = @('a', 'b'); 'objectsid' = @(, [byte[]] @(1, 2)); empty = @() }
Add-Member -InputObject $props -MemberType ScriptProperty -Name PropertyNames -Value { $this.Keys }
$row = ConvertFrom-SearchResult ([pscustomobject] @{ Properties = $props })
($row.Keys | Sort-Object) -join ','
$row['member;range=0-1'] -join '+'
$row['objectsid'][0].GetType().Name + $row['objectsid'][0].Length
$row['empty'].Count
"""
    result = run_pwsh(tmp_path, body, stub=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["empty,member;range=0-1,objectsid", "a+b", "Byte[]2", "0"]


@needs_pwsh
def test_ranged_retrieval_reads_every_range_and_nested_groups_with_a_cycle(tmp_path: Path) -> None:
    out = export(tmp_path, "$Group = @('Big Group', 'Tier0 Admins', 'Loop A')")
    assert out.header["shaar_export"] == 1
    assert out.header["system"] == "ad"
    assert out.header["domain"] == "corp.example"
    assert out.header["collector"] == {"name": "Export-ShaarAccess.ps1", "version": "0.1.1"}
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", out.header["collected_at"])
    assert out.header["scope"]["groups"] == ["Big Group", "Tier0 Admins", "Loop A"]
    # 7 members read as ranges 0-2, 3-5 and 6-*.
    big = out.grants_of("Big Group")
    assert sorted(big) == [f"Member {i}" for i in range(1, 8)]
    assert all(g["via"] == [] and g["entitlement"] == "member" for g in big.values())
    assert out.resources["Big Group"]["complete"] is True
    # Loop A and B are nested in each other: each is read once, nothing loops.
    loop = out.grants_of("Loop A")
    assert sorted(loop) == ["Dana Example", "Loop A", "Loop B"]
    assert loop["Loop B"]["via"] == []
    assert loop["Loop A"]["via"] == ["Loop A", "Loop B"]
    assert "Loop A > Loop B > Loop A" in out.resources["Loop A"]["extra"]["nesting_cycles"]
    assert out.resources["Loop A"]["complete"] is True


@needs_pwsh
def test_more_than_five_cycles_are_counted_and_marked(tmp_path: Path) -> None:
    # A hub with six spokes, each nesting the hub again: six cycles, five written out.
    setup = """
G 'Hub' 3000
foreach ($i in 1..6) { G ('Spoke ' + $i) (3000 + $i) }
$script:Members[(Dn 'Hub' 'Groups')] = @(1..6 | ForEach-Object { Dn ('Spoke ' + $_) 'Groups' })
foreach ($i in 1..6) { $script:Members[(Dn ('Spoke ' + $i) 'Groups')] = @((Dn 'Hub' 'Groups')) }
$Group = @('Hub')
"""
    out = export(tmp_path, setup)
    extra = out.resources["Hub"]["extra"]
    assert extra["nesting_cycle_count"] == "6"
    assert extra["nesting_cycles"].count(" > ") >= 5
    assert extra["nesting_cycles"].endswith("; and 1 more")
    assert out.resources["Hub"]["complete"] is True
    loop = export(tmp_path, "$Group = @('Loop A')").resources["Loop A"]["extra"]
    assert loop["nesting_cycle_count"] == "1"
    assert "more" not in loop["nesting_cycles"]


@needs_pwsh
def test_nesting_via_chains_primary_group_and_every_path(tmp_path: Path) -> None:
    out = export(tmp_path, "$Group = @('Tier0 Admins')")
    grants = out.grants_of("Tier0 Admins")
    # Avery is direct and also reached through Server Ops: the shortest path wins, all are kept.
    assert grants["Avery Example"]["via"] == []
    assert grants["Avery Example"]["extra"]["paths"] == "Tier0 Admins > Server Ops; direct"
    assert grants["Blake Example"]["via"] == ["Tier0 Admins", "Server Ops"]
    assert "extra" in grants["Blake Example"]
    assert grants["Server Ops"]["via"] == []
    assert grants["Tier0 Admins"]["via"] == ["Tier0 Admins", "Server Ops"]  # the cycle back
    # Evan has Tier0 Admins as primary group: not in "member", found by primaryGroupID.
    assert grants["Evan Example"]["via"] == []
    assert grants["Evan Example"]["extra"] == {"through": "primary group"}


@needs_pwsh
def test_the_primary_group_is_queried_by_its_rid_only_for_domain_groups(tmp_path: Path) -> None:
    body = (
        "$ToPipeline = $true; $Group = @('Domain Users', 'S-1-5-32-544')\n"
        "Invoke-Export | Out-Null\n"
        "$script:Searches | Where-Object { $_ -like '*primaryGroupID*' }"
    )
    result = run_pwsh(tmp_path, body)
    assert result.returncode == 0, result.stderr
    queried = [line for line in result.stdout.splitlines() if "(primaryGroupID=" in line]
    assert [q.split()[2] for q in queried] == ["(primaryGroupID=513)"]


@needs_pwsh
def test_foreign_security_principals_resolved_and_unresolved(tmp_path: Path) -> None:
    out = export(tmp_path, "$Group = @('Tier0 Admins')")
    grants = out.grants_of("Tier0 Admins")
    resolved = grants["PARTNER\\Fran Example"]
    principal = out.principals[resolved["principal_id"]]
    assert principal["id"] == "S-1-5-21-2000-2000-2000-500"
    assert principal["kind"] == "unknown"
    assert principal["extra"]["foreign"] == "true"
    unresolved = out.principals["S-1-5-21-2000-2000-2000-501"]
    assert unresolved["name"] == "S-1-5-21-2000-2000-2000-501"
    gaps = [g for g in out.gaps if g["what"] == "foreign security principals"]
    assert len(gaps) == 1
    assert "S-1-5-21-2000-2000-2000-501" in gaps[0]["reason"]
    assert "-500" not in gaps[0]["reason"]
    assert out.resources["Tier0 Admins"]["complete"] is True


@needs_pwsh
def test_access_denied_on_one_group_is_a_gap_and_the_rest_is_still_written(tmp_path: Path) -> None:
    out = export(tmp_path, "$Group = @('Locked', 'Big Group')")
    assert out.resources["Locked"]["complete"] is False
    assert out.resources["Big Group"]["complete"] is True
    gaps = [g for g in out.gaps if g["what"] == "members of group Locked"]
    assert len(gaps) == 1
    assert "Access is denied." in gaps[0]["reason"]
    assert len(out.grants_of("Big Group")) == 7
    assert out.grants_of("Locked") == {}


@needs_pwsh
def test_a_range_that_fails_midway_keeps_what_was_read(tmp_path: Path) -> None:
    out = export(tmp_path, "$Group = @('Flaky')")
    assert sorted(out.grants_of("Flaky")) == ["Flake 1", "Flake 2", "Flake 3"]
    assert out.resources["Flaky"]["complete"] is False
    assert any("unwilling" in g["reason"] for g in out.gaps)


MALFORMED_RANGE = """
$script:RealSearch = ${function:Search-Directory}
function Search-Directory([string] $BaseDn, [string] $Filter, [string[]] $Properties, [string] $Scope) {
    $r = & $script:RealSearch $BaseDn $Filter $Properties $Scope
    if ($BaseDn -like 'CN=Big Group,*' -and $Properties[0] -match '^member;range=(\\d+)-\\*$' -and [int] $Matches[1] -eq %(ASKED)d) {
        $old = @($r.Keys | Where-Object { $_ -like 'member;range=*' })[0]
        $values = $r[$old]
        $r.Remove($old)
        $r['member;range=%(ANSWERED)d-*'] = $values
    }
    $r
}
"""


@needs_pwsh
@pytest.mark.parametrize(("asked", "answered"), [(0, 9), (3, 4)])
def test_a_terminal_range_must_start_where_it_was_asked(
    tmp_path: Path, asked: int, answered: int
) -> None:
    setup = MALFORMED_RANGE % {"ASKED": asked, "ANSWERED": answered}
    out = export(tmp_path, setup + "\n$Group = @('Big Group')")
    assert out.resources["Big Group"]["complete"] is False
    gap = next(g for g in out.gaps if g["what"] == "members of group Big Group")
    assert f"unexpected range, member;range={answered}-*, after {asked}" in gap["reason"]


def build_graph(extra: str = "") -> str:
    """Root > A > Shared and Root > B > Shared, with Dana a member of Shared."""
    return (
        "G 'Dia Root' 3001; G 'Dia A' 3002; G 'Dia B' 3003; G 'Dia Shared' 3004\n"
        "$script:Members[(Dn 'Dia Root' 'Groups')] = @((Dn 'Dia A' 'Groups'), (Dn 'Dia B' 'Groups'))\n"
        "$script:Members[(Dn 'Dia A' 'Groups')] = @((Dn 'Dia Shared' 'Groups'))\n"
        "$script:Members[(Dn 'Dia B' 'Groups')] = @((Dn 'Dia Shared' 'Groups'))\n"
        "$script:Members[(Dn 'Dia Shared' 'Groups')] = @((Dn 'Dana Example')" + extra + ")\n"
        "$Group = @('Dia Root')"
    )


@needs_pwsh
def test_a_shared_group_gives_one_shortest_route_per_nesting_group(tmp_path: Path) -> None:
    out = export(tmp_path, build_graph())
    dana = out.grants_of("Dia Root")["Dana Example"]
    # via is a shortest path; paths hold one shortest route per group that nests the holder.
    assert dana["via"] == ["Dia Root", "Dia A", "Dia Shared"]
    assert dana["extra"]["paths"] == "Dia Root > Dia A > Dia Shared; Dia Root > Dia B > Dia Shared"
    assert "nesting_cycles" not in out.resources["Dia Root"]["extra"]
    assert out.resources["Dia Root"]["complete"] is True


@needs_pwsh
def test_a_cycle_across_branches_is_reported(tmp_path: Path) -> None:
    out = export(tmp_path, build_graph(", (Dn 'Dia B' 'Groups')"))
    cycles = out.resources["Dia Root"]["extra"]["nesting_cycles"]
    # Dia B > Dia Shared > Dia B: neither group is an ancestor of the other in the tree.
    assert "Dia Root > Dia B > Dia Shared (also reaches back to Dia B)" in cycles
    assert "Dia Root > Dia A > Dia Shared > Dia B (also reaches back to Dia Shared)" in cycles
    dana = out.grants_of("Dia Root")["Dana Example"]
    assert dana["via"] == ["Dia Root", "Dia A", "Dia Shared"]
    assert dana["extra"]["paths"] == "Dia Root > Dia A > Dia Shared; Dia Root > Dia B > Dia Shared"
    # Dia B is a direct member of the root and also nested below Dia Shared.
    dia_b = out.grants_of("Dia Root")["Dia B"]
    assert dia_b["via"] == []
    assert dia_b["extra"]["paths"] == "Dia Root > Dia A > Dia Shared; direct"


UNREADABLE_SID = """
$script:Members[(Dn 'Domain Admins' 'Groups')] = @((Dn 'Avery Example'), (Dn 'Tier0 Admins' 'Groups'))
($script:Dir | Where-Object { $_.dn -eq (Dn 'Domain Admins' 'Groups') }).more['managedby'] = (Dn 'Blake Example')
$Group = @('Domain Admins')
"""


@needs_pwsh
def test_an_unreadable_nested_group_sid_makes_every_expanded_root_incomplete(
    tmp_path: Path,
) -> None:
    lost = "($script:Dir | Where-Object { $_.dn -eq (Dn 'Tier0 Admins' 'Groups') }).sid = ''\n"
    out = export(tmp_path, UNREADABLE_SID + lost + "$Group = @('Domain Admins', 'Tier0 Admins')")
    for root in ("Domain Admins", "Tier0 Admins"):
        assert out.resources[root]["complete"] is False
    assert any(
        g["what"] == "primary group members of Tier0 Admins" and "objectSid" in g["reason"]
        for g in out.gaps
    )
    # Builtin groups have no primary members by design: that is not a gap.
    empty = "$script:Members['CN=Administrators,CN=Builtin,DC=corp,DC=example'] = @()\n"
    builtin = export(tmp_path, empty + "$Group = @('S-1-5-32-544')")
    assert builtin.resources["Administrators"]["complete"] is True
    assert not [g for g in builtin.gaps if "primary" in g["what"]]


def snapshot_of(tmp_path: Path, name: str, out: Export, label: str) -> Snapshot:
    path = tmp_path / f"{name}.jsonl"
    path.write_bytes(out.raw)
    return read_inputs([path], label=label)


@needs_pwsh
@pytest.mark.parametrize("readable", [False, True])
def test_a_nested_group_with_an_unreadable_sid_is_unknown_not_removed(
    tmp_path: Path,
    readable: bool,  # noqa: FBT001 - a test parameter
) -> None:
    before_dir = tmp_path / "b"
    after_dir = tmp_path / "a"
    before_dir.mkdir()
    after_dir.mkdir()
    before = export(before_dir, UNREADABLE_SID)
    evan = before.grants_of("Domain Admins")["Evan Example"]
    assert evan["extra"] == {"through": "primary group"}
    if readable:
        # Control: Evan really moved to another primary group, and every read succeeded.
        change = "($script:Dir | Where-Object { $_.dn -eq (Dn 'Evan Example') }).more['primarygroupid'] = 513\n"
    else:
        change = (
            "($script:Dir | Where-Object { $_.dn -eq (Dn 'Tier0 Admins' 'Groups') }).sid = ''\n"
        )
    after = export(after_dir, UNREADABLE_SID + change)
    assert after.resources["Domain Admins"]["complete"] is readable
    assert "Evan Example" not in after.grants_of("Domain Admins")

    first = snapshot_of(tmp_path, "before", before, "before")
    campaign = build(
        first, name="Q4", created_at="2020-01-01T00:00:00Z", due="2099-01-01", rule="owner"
    )
    reviewer = next(r.key for r in campaign.reviewers if r.name == "Blake Example")
    record = read_decisions(
        campaign,
        [("m.xlsx", b"")],
        read=reader(
            {"m.xlsx": returned(campaign, reviewer, {"Evan Example|Domain Admins": "Remove"})}
        ),
        created_at="2020-01-02T00:00:00Z",
    )
    outcome = verify(campaign, record, snapshot_of(tmp_path, "after", after, "after"))
    checks = [c for c in outcome.checks if "Evan Example" in c.reason or c.result != "keep"]
    results = {c.result for c in checks}
    assert results == ({"removed"} if readable else {"unknown"})


@needs_pwsh
def test_a_member_that_cannot_be_looked_up_makes_the_group_incomplete(tmp_path: Path) -> None:
    out = export(tmp_path, "$Group = @('Ghosts')")
    assert out.resources["Ghosts"]["complete"] is False
    ghost = out.principals["CN=Nobody,OU=Elsewhere,DC=other,DC=example"]
    assert ghost["kind"] == "unknown"
    gap = next(g for g in out.gaps if g["what"] == "members of group Ghosts")
    assert "CN=Nobody" in gap["reason"]
    assert "1 member(s) could not be read" in gap["reason"]


@needs_pwsh
def test_accounts_enablement_managers_last_logon_and_kinds(tmp_path: Path) -> None:
    out = export(tmp_path, "$Group = @('Server Ops')")
    by_name = {p["name"]: p for p in out.principals.values()}
    avery = by_name["Avery Example"]
    assert avery["id"] == out.sid(1201)
    assert avery["kind"] == "user"
    assert avery["enabled"] is True
    assert avery["email"] == "avery@corp.example"
    assert avery["upn"] == "avery@corp.example"
    assert avery["last_sign_in"] == "2026-10-01T12:30:00Z"
    assert avery["manager_id"] == out.sid(1202)
    assert avery["extra"]["sam_account_name"] == "avery.example"
    assert avery["extra"]["distinguished_name"] == "CN=Avery Example,OU=People,DC=corp,DC=example"
    # Disabled user; "never" and zero are not times.
    assert by_name["Casey Example"]["enabled"] is False
    assert by_name["Casey Example"]["last_sign_in"] == ""
    assert by_name["Blake Example"]["enabled"] is True
    assert by_name["Blake Example"]["last_sign_in"] == ""
    # Managers are written as principals too, up the chain (Blake's manager is Casey).
    assert by_name["Blake Example"]["manager_id"] == out.sid(1203)
    assert by_name["Casey Example"]["manager_id"] is None
    # Kinds.
    assert by_name["svc-ledger$"]["kind"] == "service"
    assert by_name["svc-ledger$"]["enabled"] is True
    assert by_name["SRV01$"]["kind"] == "device"
    assert by_name["SRV01$"]["enabled"] is False
    assert by_name["Printer Contact"]["kind"] == "other"
    assert by_name["Printer Contact"]["id"] == "CN=Printer Contact,OU=People,DC=corp,DC=example"
    assert by_name["Server Ops"]["kind"] == "group"
    assert by_name["Server Ops"]["enabled"] is None
    assert by_name["Tier0 Admins"]["kind"] == "group"
    no_sid = next(g for g in out.gaps if g["what"] == "objects without a readable SID")
    assert "Printer Contact" in no_sid["reason"]


@needs_pwsh
def test_owners_unresolvable_managers_and_group_resource_fields(tmp_path: Path) -> None:
    out = export(tmp_path, "$Group = @('Tier0 Admins', 'Server Ops')")
    tier0 = out.resources["Tier0 Admins"]
    assert tier0["kind"] == "group"
    assert tier0["id"] == out.sid(1100)
    assert tier0["owner_ids"] == [out.sid(1202)]
    assert out.resources["Server Ops"]["owner_ids"] == []
    # Evan's manager is in another domain: a gap, and manager_id stays null.
    evan = next(p for p in out.principals.values() if p["name"] == "Evan Example")
    assert evan["manager_id"] is None
    gap = next(g for g in out.gaps if g["what"].startswith("manager CN=Gone"))
    assert "1 account(s)" in gap["reason"]
    # Files are in id order.
    ids = list(out.principals)
    assert ids == sorted(ids)


@needs_pwsh
def test_privileged_by_sid_and_by_name_with_missing_ones_as_gaps(tmp_path: Path) -> None:
    out = export(tmp_path, "$Privileged = $true")
    assert out.header["scope"]["privileged"] is True
    assert set(out.resources) == {"Administrators", "Domain Admins", "DnsAdmins"}
    assert out.resources["Administrators"]["id"] == "S-1-5-32-544"
    assert out.resources["Domain Admins"]["id"] == out.sid(512)
    assert out.resources["DnsAdmins"]["id"] == out.sid(1110)
    missing = {g["what"] for g in out.gaps if g["what"].startswith("privileged group")}
    assert missing == {
        "privileged group Account Operators", "privileged group Server Operators",
        "privileged group Print Operators", "privileged group Backup Operators",
        "privileged group Schema Admins", "privileged group Enterprise Admins",
        "privileged group Group Policy Creator Owners", "privileged group Key Admins",
        "privileged group Enterprise Key Admins",
    }  # fmt: skip
    schema = next(g for g in out.gaps if g["what"].endswith("Schema Admins"))
    assert "forest root domain" in schema["reason"]
    assert "Avery Example" in out.grants_of("Domain Admins")


@needs_pwsh
def test_group_specs_by_dn_sid_name_search_base_and_their_failures(tmp_path: Path) -> None:
    group = (
        "$Group = @('CN=Server Ops,OU=Groups,DC=corp,DC=example', 'S-1-5-21-1000-1000-1000-1102', "
        "'Dup', 'No Such Group', 'Starred (x*)', 'CN=Nope,OU=Groups,DC=corp,DC=example', "
        "'S-1-5-21-1000-1000-1000-9999')"
    )
    out = export(tmp_path, group)
    assert set(out.resources) == {"Server Ops", "Loop A", "Starred (x*)"}
    what = {g["what"]: g["reason"] for g in out.gaps}
    assert "2 groups match" in what["-Group Dup"]
    assert "no group has that name" in what["-Group No Such Group"]
    assert "distinguished name" in what["-Group CN=Nope,OU=Groups,DC=corp,DC=example"]
    assert "SID" in what["-Group S-1-5-21-1000-1000-1000-9999"]


@needs_pwsh
def test_search_base_exports_every_group_below_it_and_failures_are_gaps(tmp_path: Path) -> None:
    out = export(tmp_path, "$SearchBase = 'OU=Groups,DC=corp,DC=example'")
    assert {"Tier0 Admins", "Server Ops", "Big Group", "Domain Users"} <= set(out.resources)
    assert "Administrators" not in out.resources
    assert out.header["scope"]["search_base"] == "OU=Groups,DC=corp,DC=example"
    result = run_pwsh(
        tmp_path,
        "$ToPipeline = $true; $Group = @('Big Group'); $SearchBase = 'OU=DENY,DC=corp,DC=example'\nInvoke-Export",
    )
    assert result.returncode == 0, result.stderr
    again = Export(("\n".join(result.stdout.splitlines()) + "\n").encode())
    assert any(
        g["what"].startswith("-SearchBase") and "Access is denied" in g["reason"]
        for g in again.gaps
    )
    assert set(again.resources) == {"Big Group"}
    empty = export(tmp_path, "$Group = @('Big Group'); $SearchBase = 'OU=Empty,DC=corp,DC=example'")
    assert any("no group was found below" in g["reason"] for g in empty.gaps)


@needs_pwsh
def test_a_scope_that_finds_no_group_stops_and_names_why(tmp_path: Path) -> None:
    result = run_pwsh(tmp_path, "$ToPipeline = $true; $Group = @('No Such Group')\nInvoke-Export")
    assert result.returncode != 0
    assert "No group could be exported" in result.stderr
    assert "no group has that name" in result.stderr


@needs_pwsh
def test_a_scope_switch_is_required(tmp_path: Path) -> None:
    result = run_pwsh(tmp_path, "$ToPipeline = $true\nInvoke-Export")
    assert result.returncode != 0
    assert "Give at least one of -Group, -SearchBase and -Privileged" in result.stderr


@needs_pwsh
def test_a_domain_whose_sid_cannot_be_read_stops(tmp_path: Path) -> None:
    body = "function Get-DomainSid { throw 'The domain SID could not be read.' }\n$ToPipeline = $true; $Group = @('Big Group')\nInvoke-Export"
    result = run_pwsh(tmp_path, body)
    assert result.returncode != 0
    assert "domain SID" in result.stderr


@needs_pwsh
def test_the_real_domain_sid_function_reads_the_domain_object(tmp_path: Path) -> None:
    result = run_pwsh(
        tmp_path,
        "$script:DomainDn = 'DC=corp,DC=example'; Get-DomainSid\n"
        "function Search-Directory { @() }\n"
        "try { Get-DomainSid } catch { 'refused: ' + $_.Exception.Message }",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "S-1-5-21-1000-1000-1000",
        "refused: The domain SID could not be read, so primary group members cannot be found.",
    ]


def run_script(tmp_path: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    assert _PWSH is not None
    return subprocess.run(  # noqa: S603
        [_PWSH, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
         str(tmp_path / "Export-ShaarAccess.ps1"), *arguments],
        capture_output=True, text=True, encoding="utf-8", timeout=120, check=False, cwd=tmp_path,
    )  # fmt: skip


@needs_pwsh
def test_file_output_is_private_published_and_never_overwritten(tmp_path: Path) -> None:
    body = (
        "$OutFile = "
        + encoded(str(tmp_path / "out.jsonl"))
        + "\n$Group = @('Big Group')\nInvoke-Export"
    )
    first = run_pwsh(tmp_path, body)
    assert first.returncode == 0, first.stderr
    target = tmp_path / "out.jsonl"
    assert Export(target.read_bytes()).resources["Big Group"]["complete"] is True
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.endswith(".part")) == []
    before = target.read_bytes()
    second = run_pwsh(tmp_path, body)
    assert second.returncode != 0
    assert "already exists" in second.stderr
    assert target.read_bytes() == before
    forced = run_pwsh(tmp_path, body.replace("Invoke-Export", "$Force = $true\nInvoke-Export"))
    assert forced.returncode == 0, forced.stderr
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.endswith(".part")) == []


@needs_pwsh
def test_a_failure_leaves_no_partial_file(tmp_path: Path) -> None:
    body = (
        "$OutFile = " + encoded(str(tmp_path / "out.jsonl")) + "\n$Group = @('Big Group')\n"
        "function Get-HashText($Writer) { throw 'disk on fire' }\nInvoke-Export"
    )
    result = run_pwsh(tmp_path, body)
    assert result.returncode != 0
    assert not (tmp_path / "out.jsonl").exists()
    assert [p.name for p in tmp_path.iterdir() if p.suffix == ".part"] == []


@needs_pwsh
def test_the_real_script_refuses_bad_parameters_before_touching_anything(tmp_path: Path) -> None:
    (tmp_path / "Export-ShaarAccess.ps1").write_text(TEXT, encoding="ascii")
    none = run_script(tmp_path, "-OutFile", "x.jsonl")
    assert none.returncode != 0
    assert "Give at least one of" in none.stderr
    bad = run_script(tmp_path, "-OutFile", "x.jsonl", "-SearchBase", "not a dn")
    assert bad.returncode != 0
    assert "SearchBase" in bad.stderr
    no_out = run_script(tmp_path, "-Privileged")
    assert no_out.returncode != 0
    assert list(tmp_path.glob("x.jsonl*")) == []
    (tmp_path / "x.jsonl").write_text("keep", encoding="ascii")
    exists = run_script(tmp_path, "-Privileged", "-OutFile", "x.jsonl")
    assert exists.returncode != 0
    assert "already exists" in exists.stderr
    assert (tmp_path / "x.jsonl").read_text() == "keep"


@pytest.mark.skipif(
    sys.platform != "win32" or _PWSH is None or os.environ.get("SHAAR_LAB_DOMAIN") != "1",
    reason="run by hand on a domain-joined computer: set SHAAR_LAB_DOMAIN=1",
)
def test_the_real_script_exports_a_real_group(tmp_path: Path) -> None:  # pragma: no cover
    """Runs the packaged script against the computer's own domain. Never point it at production."""
    (tmp_path / "Export-ShaarAccess.ps1").write_text(TEXT, encoding="ascii")
    result = run_script(tmp_path, "-Group", "Domain Admins", "-OutFile", "lab.jsonl")
    assert result.returncode == 0, result.stderr
    out = Export((tmp_path / "lab.jsonl").read_bytes())
    assert "Domain Admins" in out.resources


# --- the script's own search code, with only the directory object and searcher replaced ----

SEARCH_SEAMS = r"""
$FakeRows = @{}
function New-DirectoryEntry([string] $DistinguishedName) {
    $entry = [pscustomobject] @{ DistinguishedName = $DistinguishedName }
    Add-Member -InputObject $entry -MemberType ScriptMethod -Name Dispose -Value { }
    $entry
}
function New-DirectorySearcher([string] $Filter) {
    $searcher = [pscustomobject] @{
        Filter = $Filter; SearchRoot = $null; PageSize = 0; SearchScope = $null
        PropertiesToLoad = (New-Object System.Collections.ArrayList)
    }
    Add-Member -InputObject $searcher -MemberType ScriptMethod -Name Dispose -Value { }
    Add-Member -InputObject $searcher -MemberType ScriptMethod -Name FindAll -Value {
        $found = New-Object System.Collections.ArrayList
        foreach ($row in $FakeRows[$this.Filter]) {
            $properties = [ordered] @{}
            foreach ($name in $row.Keys) { $properties[$name] = @($row[$name]) }
            Add-Member -InputObject $properties -MemberType ScriptProperty -Name PropertyNames -Value { $this.Keys }
            [void] $found.Add([pscustomobject] @{ Properties = $properties })
        }
        Add-Member -InputObject $found -MemberType ScriptMethod -Name Dispose -Value { }
        , $found
    }
    $searcher
}
"""


@needs_pwsh
def test_search_directory_hands_its_callers_one_hashtable_per_object(tmp_path: Path) -> None:
    """The row contract: ``@(Search-Directory ...)`` counts objects for none, one and several."""
    body = (
        SEARCH_SEAMS
        + r"""
$props = @('distinguishedName')
$FakeRows['(none)'] = @()
$FakeRows['(one)'] = @(@{ distinguishedname = 'CN=Only'; member = @('a') })
$FakeRows['(many)'] = @(@{ distinguishedname = 'CN=A' }, @{ distinguishedname = 'CN=B' }, @{ distinguishedname = 'CN=C' })
foreach ($filter in '(none)', '(one)', '(many)') {
    $rows = @(Search-Directory 'DC=corp,DC=example' $filter $props 'Subtree')
    $kinds = (@($rows | ForEach-Object { $_.GetType().Name }) | Sort-Object -Unique) -join ','
    "$filter|$($rows.Count)|$kinds|" + ((@($rows | ForEach-Object { $_['distinguishedname'][0] })) -join ';')
}
$one = @(Search-Directory 'DC=corp,DC=example' '(one)' $props 'Base')[0]
"$($one['member'].GetType().Name)|$($one['member'].Count)|" + (($one.Keys | Sort-Object) -join ',')
"""
    )
    result = run_pwsh(tmp_path, body, stub=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "(none)|0||",
        "(one)|1|Hashtable|CN=Only",
        "(many)|3|Hashtable|CN=A;CN=B;CN=C",
        "Object[]|1|distinguishedname,member",
    ]


@needs_pwsh
def test_find_groups_counts_the_groups_a_real_search_returns(tmp_path: Path) -> None:
    body = (
        SEARCH_SEAMS
        + r"""
$script:DomainDn = 'DC=corp,DC=example'
$script:Gaps = New-Object System.Collections.Generic.List[object]
$group = @{ distinguishedname = 'CN=G1,OU=Groups,DC=corp,DC=example'; objectclass = @('top', 'group'); name = 'G1'; samaccountname = 'G1' }
$user = @{ distinguishedname = 'CN=U1,OU=People,DC=corp,DC=example'; objectclass = @('top', 'person', 'user'); name = 'U1' }
$FakeRows['(none)'] = @()
$FakeRows['(one)'] = @($group)
$group2 = @{ distinguishedname = 'CN=G2,OU=Groups,DC=corp,DC=example'; objectclass = @('top', 'group'); name = 'G2' }
$FakeRows['(mixed)'] = @($group, $user, $group2)
foreach ($filter in '(none)', '(one)', '(mixed)') {
    $found = @(Find-Groups $script:DomainDn $filter 'Subtree' 'test')
    "$filter|$($found.Count)|" + ((@($found | ForEach-Object { $_.Kind })) -join ',')
}
"""
    )
    result = run_pwsh(tmp_path, body, stub=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["(none)|0|", "(one)|1|group", "(mixed)|2|group,group"]


@needs_pwsh
def test_sort_ordinal_gives_callers_items_not_a_wrapped_array(tmp_path: Path) -> None:
    body = r"""
$none = @(Sort-Ordinal @() 'k')
$one = @(Sort-Ordinal @(@{ k = 'a' }) 'k')
$many = @(Sort-Ordinal @(@{ k = 'b' }, @{ k = 'a' }) 'k')
$objects = @(Sort-Ordinal @([pscustomobject] @{ k = 'z' }) 'k')
"$($none.Count) $($one.Count) $($one[0].GetType().Name) $($many.Count) $($many[0].k) $($objects.Count) $($objects[0].k)"
"""
    result = run_pwsh(tmp_path, body, stub=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["0", "1", "Hashtable", "2", "a", "1", "z"]


def test_no_function_sends_a_whole_array_as_one_object() -> None:
    """A leading comma before ``ToArray()`` hides every row inside one ``Object[]``."""
    assert not re.search(r"^\s*,\s*\$\w+\.ToArray\(\)", code(), re.MULTILINE)
