# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
<#
.SYNOPSIS
    Export who is a member of which Active Directory groups, for shaar. Read-only.

.DESCRIPTION
    Reads the membership of the groups you choose and writes it to one file in the shaar
    export format (JSON Lines, pure ASCII, "\n" line endings, no byte order mark):

      1. a header line: {"shaar_export":1, "system":"ad", collector, collected_at, scope, domain}
      2. {"principal":{...}} lines: accounts, groups, computers and service accounts that
         hold access, and the managers and owners they refer to
      3. {"resource":{...}} lines: the groups you chose, each with "complete": true or false
      4. {"grant":{...}} lines: one per account and group, "member", with the chain of
         nested groups it came through in "via" (empty when the account is a direct member)
      5. {"gap":{"what","reason"}} lines for everything that could not be read
      6. an end line {"end":true,"records":N,"sha256":"<hex>"}, where N counts the lines
         between the header and the end line and the hash covers every byte before the
         end line

    The script only reads. It uses ADSI searches (no ActiveDirectory module) and never
    calls anything that changes a directory object. Its only write is the output file,
    which it never overwrites unless -Force is given. Nothing secret is read or written.

    What is read: for each group, the "member" attribute with ranged retrieval (so a
    group of any size is read completely), the accounts whose primary group it is (they
    are not in "member"), and every nested group, once, with cycles detected. Each member
    is looked up for its name, SID, user principal name, mail, manager, account control
    flags and last logon. A foreign security principal is turned into its SID, and its
    name when Windows can resolve it. Groups are not expanded across a trust, so a
    foreign group's own members are not listed.

    Anything that cannot be read becomes a gap line, and the group that was affected is
    written with "complete": false. Partial data is kept. A group the account may not
    read at all is a gap; an attribute that Active Directory hides from the account is
    indistinguishable from an empty one, and nothing can detect that from here.

    last_sign_in is lastLogonTimestamp, which controllers replicate with up to about
    14 days of lag, so it can be that much out of date.

    Rights needed: read access to the groups and their members (Authenticated Users have
    it by default). Runs on Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Group
    Groups to export, each as a name (sAMAccountName or common name), a distinguished
    name, or a SID. A name that matches no group or more than one is a gap.

.PARAMETER SearchBase
    A distinguished name. Every group below it is exported.

.PARAMETER Privileged
    Export the well-known privileged groups: Administrators, Account Operators, Server
    Operators, Print Operators, Backup Operators, Domain Admins, Schema Admins, Enterprise
    Admins, Group Policy Creator Owners, Key Admins, Enterprise Key Admins and DnsAdmins.
    One that does not exist in this domain is a gap.

.PARAMETER Server
    The domain controller to read from. Default: any controller. When the script runs
    over PowerShell remoting, name the controller the session is on to avoid a second hop.

.PARAMETER OutFile
    The file to write, for example corp-access.jsonl.

.PARAMETER Force
    Replace -OutFile if it exists.

.PARAMETER ToPipeline
    Write the lines to the output stream instead of a file. shaar's remote collection
    uses this.

.EXAMPLE
    .\Export-ShaarAccess.ps1 -Privileged -OutFile corp-access.jsonl

.EXAMPLE
    .\Export-ShaarAccess.ps1 -Group 'Finance Approvers' -SearchBase 'OU=Groups,DC=corp,DC=example' -OutFile finance.jsonl
#>
[CmdletBinding(DefaultParameterSetName = 'File')]
param(
    [ValidateCount(1, 10000)]
    [ValidateNotNullOrEmpty()]
    [string[]] $Group,
    [ValidatePattern('^[A-Za-z][A-Za-z0-9-]*=.+')]
    [string] $SearchBase,
    [switch] $Privileged,
    [string] $Server,
    [Parameter(Mandatory = $true, ParameterSetName = 'File')]
    [string] $OutFile,
    [Parameter(ParameterSetName = 'Pipeline')]
    [switch] $ToPipeline,
    [Parameter(ParameterSetName = 'File')]
    [switch] $Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$CollectorName = 'Export-ShaarAccess.ps1'
$CollectorVersion = '0.1.0'
$Invariant = [System.Globalization.CultureInfo]::InvariantCulture
$LookupBatch = 25
$MaxRanges = 100000
$MaxNestedGroups = 5000
$MaxManagerRounds = 100
$MaxListedInGap = 10
$LastLogonLimit = [int64] 2650467743999999999
$ObjectProperties = @(
    'distinguishedName', 'objectSid', 'objectClass', 'sAMAccountName', 'name', 'displayName',
    'userPrincipalName', 'mail', 'manager', 'managedBy', 'userAccountControl',
    'lastLogonTimestamp', 'primaryGroupID')
# Well-known privileged groups. Sid is a complete SID; Rid is relative to the domain SID;
# a group with neither is found by name.
$PrivilegedGroups = @(
    [pscustomobject] @{ Name = 'Administrators'; Sid = 'S-1-5-32-544'; Rid = 0 }
    [pscustomobject] @{ Name = 'Account Operators'; Sid = 'S-1-5-32-548'; Rid = 0 }
    [pscustomobject] @{ Name = 'Server Operators'; Sid = 'S-1-5-32-549'; Rid = 0 }
    [pscustomobject] @{ Name = 'Print Operators'; Sid = 'S-1-5-32-550'; Rid = 0 }
    [pscustomobject] @{ Name = 'Backup Operators'; Sid = 'S-1-5-32-551'; Rid = 0 }
    [pscustomobject] @{ Name = 'Domain Admins'; Sid = ''; Rid = 512 }
    [pscustomobject] @{ Name = 'Schema Admins'; Sid = ''; Rid = 518 }
    [pscustomobject] @{ Name = 'Enterprise Admins'; Sid = ''; Rid = 519 }
    [pscustomobject] @{ Name = 'Group Policy Creator Owners'; Sid = ''; Rid = 520 }
    [pscustomobject] @{ Name = 'Key Admins'; Sid = ''; Rid = 526 }
    [pscustomobject] @{ Name = 'Enterprise Key Admins'; Sid = ''; Rid = 527 }
    [pscustomobject] @{ Name = 'DnsAdmins'; Sid = ''; Rid = 0 }
)

# --- Text and JSON ------------------------------------------------------------------

$JsonPattern = New-Object System.Text.RegularExpressions.Regex -ArgumentList @(
    '[\x00-\x1f"\\\u007f-\uffff]', [System.Text.RegularExpressions.RegexOptions]::Compiled)
$JsonEscape = [System.Text.RegularExpressions.MatchEvaluator] {
    param($Match)
    $c = $Match.Value[0]
    switch ([int] $c) {
        0x22 { return '\"' }
        0x5C { return '\\' }
        0x0A { return '\n' }
        0x0D { return '\r' }
        0x09 { return '\t' }
        default { return '\u' + ([int] $c).ToString('x4', $Invariant) }
    }
}

function ConvertTo-JsonText($Value) {
    # Every character outside printable ASCII is written as \uXXXX, so each line is
    # plain ASCII (and so valid UTF-8) whatever a name holds. An unpaired surrogate
    # stays visible as its own escape.
    if ($null -eq $Value) { return 'null' }
    '"' + $JsonPattern.Replace([string] $Value, $JsonEscape) + '"'
}

function ConvertTo-JsonBool([bool] $Value) {
    if ($Value) { 'true' } else { 'false' }
}

function ConvertTo-JsonTextArray($Values) {
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($value in $Values) { $parts.Add((ConvertTo-JsonText $value)) }
    '[' + ($parts.ToArray() -join ',') + ']'
}

function ConvertTo-ExtraJson($Pairs) {
    # An object of text values, keys in ordinal order, empty values left out.
    $items = New-Object System.Collections.Generic.List[object]
    foreach ($key in $Pairs.Keys) {
        if ($Pairs[$key]) { $items.Add([pscustomobject] @{ Key = [string] $key; Value = [string] $Pairs[$key] }) }
    }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($item in @(Sort-Ordinal $items 'Key')) {
        $parts.Add((ConvertTo-JsonText $item.Key) + ':' + (ConvertTo-JsonText $item.Value))
    }
    '{' + ($parts.ToArray() -join ',') + '}'
}

function Get-Text($Value) {
    # A directory attribute that is missing is empty text, never null.
    if ($null -eq $Value) { '' } else { [string] $Value }
}

function Format-UtcTime([datetime] $Time) {
    $Time.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", $Invariant)
}

function ConvertFrom-FileTime($Value) {
    # lastLogonTimestamp is a FILETIME: 100 ns ticks since 1601-01-01 UTC. Zero, the
    # "never" value and anything that is not a number are not a time.
    if ($null -eq $Value) { return '' }
    try { $ticks = [int64] $Value } catch { return '' }
    if ($ticks -le 0 -or $ticks -ge $LastLogonLimit) { return '' }
    Format-UtcTime ([datetime]::FromFileTimeUtc($ticks))
}

function Sort-Ordinal($Items, [string] $Property) {
    # Sort objects or hashtables by one text property, by code point, so the file does
    # not depend on the culture of the computer that wrote it. Wrap the call in @().
    $list = New-Object System.Collections.Generic.List[object]
    foreach ($item in $Items) { $list.Add($item) }
    $list.Sort([System.Comparison[object]] {
            param($a, $b)
            [string]::CompareOrdinal([string] $a.$Property, [string] $b.$Property)
        })
    $list.ToArray()
}

function ConvertTo-DnsName([string] $DistinguishedName) {
    # DC=corp,DC=example becomes corp.example.
    $labels = New-Object System.Collections.Generic.List[string]
    foreach ($part in ($DistinguishedName -split ',')) {
        if ($part.Trim() -match '^(?i)DC=(.+)$') { $labels.Add($Matches[1]) }
    }
    $labels -join '.'
}

function ConvertTo-LdapFilterText([string] $Text) {
    # RFC 4515 escaping, backslash first.
    $Text.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char] 0, '\00')
}

function ConvertTo-SidText($Value) {
    # A SID as text, upper case, from the bytes of objectSid or from text. '' if it is neither.
    if ($null -eq $Value) { return '' }
    if ($Value -is [byte[]]) {
        # The binary form: revision, sub-authority count, a 6-byte big-endian identifier
        # authority, then little-endian 32-bit sub-authorities. Decoded here rather than
        # with SecurityIdentifier, which needs Windows.
        if ($Value.Length -lt 8 -or $Value[0] -ne 1) { return '' }
        $count = [int] $Value[1]
        if ($count -lt 1 -or $Value.Length -ne 8 + 4 * $count) { return '' }
        $authority = [int64] 0
        for ($i = 2; $i -lt 8; $i++) { $authority = $authority * 256 + $Value[$i] }
        $text = 'S-1-' + $authority.ToString($Invariant)
        for ($i = 0; $i -lt $count; $i++) {
            $text += '-' + [System.BitConverter]::ToUInt32($Value, 8 + 4 * $i).ToString($Invariant)
        }
        return $text
    }
    $text = ([string] $Value).Trim().ToUpperInvariant()
    if ($text -match '^S-1-[0-9]+(-[0-9]+)+$') { return $text }
    ''
}

# --- Output -------------------------------------------------------------------------

function New-LineWriter([string] $Path, [bool] $Pipeline) {
    # Writes lines as UTF-8 (no byte order mark) with "\n" endings and keeps a running
    # SHA-256 of them. A file is never written under its final name: lines go to a new
    # temporary file next to it, created with CreateNew so it cannot be a file that
    # already exists, and Publish-Output moves it into place only once the end line is
    # written.
    $writer = [pscustomobject] @{
        Stream = $null; Hash = [System.Security.Cryptography.SHA256]::Create()
        Pipeline = $Pipeline; Count = 0; TempPath = $null
    }
    if (-not $Pipeline) {
        $writer.TempPath = $Path + '.' + [guid]::NewGuid().ToString('N') + '.part'
        $writer.Stream = New-Object System.IO.FileStream -ArgumentList @(
            $writer.TempPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None)
    }
    $writer
}

function Write-Line($Writer, [string] $Line, [switch] $Last) {
    $bytes = (New-Object System.Text.UTF8Encoding -ArgumentList $false).GetBytes($Line + "`n")
    if (-not $Last) { [void] $Writer.Hash.TransformBlock($bytes, 0, $bytes.Length, $null, 0) }
    if ($Writer.Pipeline) { Write-Output $Line } else { $Writer.Stream.Write($bytes, 0, $bytes.Length) }
}

function Get-HashText($Writer) {
    [void] $Writer.Hash.TransformFinalBlock([byte[]] @(), 0, 0)
    -join ($Writer.Hash.Hash | ForEach-Object { $_.ToString('x2', $Invariant) })
}

function Close-LineWriter($Writer) {
    # Safe to call twice: the stream is released the first time.
    if ($null -ne $Writer.Stream) { $Writer.Stream.Flush(); $Writer.Stream.Dispose(); $Writer.Stream = $null }
    $Writer.Hash.Dispose()
}

function Publish-Output($Writer, [string] $Path, [bool] $Replace) {
    # Called after the stream is closed. Without -Force the move fails if the name is
    # taken, even by a file that appeared after the start. With -Force the old file is
    # replaced in one step where the file system allows. File.Move with overwrite is
    # .NET Core 3.0 and later only, and this script must also run on Windows PowerShell
    # 5.1 (.NET Framework), so File.Replace is used when the target exists and a plain
    # move when it does not.
    if ($Replace -and [System.IO.File]::Exists($Path)) {
        # [NullString]::Value, because PowerShell turns a plain $null into "" for a
        # string argument, and "" is refused as the backup name.
        [System.IO.File]::Replace($Writer.TempPath, $Path, [NullString]::Value)
    } else {
        [System.IO.File]::Move($Writer.TempPath, $Path)
    }
}

# --- Directory access ---------------------------------------------------------------
# Everything that talks to Active Directory is in the three small functions of this
# section, so the tests can replace them. All reads are searches and gets; nothing here
# writes.

function Get-LdapPath([string] $DistinguishedName) {
    # An ADsPath. A "/" in a distinguished name must be escaped in an ADsPath.
    $where = ''
    if ($Server) { $where = $Server + '/' }
    'LDAP://' + $where + $DistinguishedName.Replace('/', '\/')
}

function Get-DomainFacts {
    # Returns the domain's distinguished name.
    $where = ''
    if ($Server) { $where = $Server + '/' }
    $root = [adsi] ('LDAP://' + $where + 'RootDSE')
    try {
        [ordered] @{ DomainDn = [string] $root.Properties['defaultNamingContext'][0] }
    } finally {
        $root.Dispose()
    }
}

function ConvertFrom-SearchResult($Result) {
    # One hashtable per directory object: every property under its lower-case name,
    # with all of its values as an array. A ranged property keeps the name the server
    # gave it, such as "member;range=0-1499".
    $row = @{}
    foreach ($name in $Result.Properties.PropertyNames) {
        $values = New-Object System.Collections.Generic.List[object]
        foreach ($value in $Result.Properties[$name]) { $values.Add($value) }
        $row[([string] $name).ToLowerInvariant()] = $values.ToArray()
    }
    $row
}

function Search-Directory([string] $BaseDn, [string] $Filter, [string[]] $Properties, [string] $Scope) {
    # Returns one hashtable per object found (see ConvertFrom-SearchResult). A base that
    # does not exist returns nothing. $Scope is Base, OneLevel or Subtree. Any other
    # failure, such as access denied, is thrown.
    $entry = [adsi] (Get-LdapPath $BaseDn)
    $searcher = [adsisearcher] $Filter
    $found = $null
    try {
        $searcher.SearchRoot = $entry
        if ($Scope -ne 'Base') { $searcher.PageSize = 500 }
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::$Scope
        [void] $searcher.PropertiesToLoad.AddRange($Properties)
        try {
            $found = $searcher.FindAll()
        } catch [System.Runtime.InteropServices.COMException] {
            if ($_.Exception.ErrorCode -eq -2147016656) { return @() }  # no such object
            throw
        }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($result in $found) { $rows.Add((ConvertFrom-SearchResult $result)) }
        $rows.ToArray()
    } finally {
        if ($null -ne $found) { $found.Dispose() }
        $searcher.Dispose()
        $entry.Dispose()
    }
}

function Resolve-SidName([string] $Sid) {
    # The account name of a SID (DOMAIN\name) when Windows can resolve it, else $null.
    try {
        $account = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $Sid
        [string] $account.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        $null
    }
}

# --- State and gaps -----------------------------------------------------------------

function Initialize-State([string] $DomainDn) {
    $comparer = [System.StringComparer]::OrdinalIgnoreCase
    $script:DomainDn = $DomainDn
    $script:DomainSid = ''
    $script:Objects = New-Object 'System.Collections.Generic.Dictionary[string,object]' -ArgumentList $comparer
    $script:Unresolved = New-Object 'System.Collections.Generic.Dictionary[string,string]' -ArgumentList $comparer
    $script:Groups = New-Object 'System.Collections.Generic.Dictionary[string,object]' -ArgumentList $comparer
    $script:Gaps = New-Object System.Collections.Generic.List[object]
    $script:Roots = New-Object System.Collections.Generic.List[object]
    $script:RootSeen = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList $comparer
}

function Add-Gap([string] $What, [string] $Reason) {
    $script:Gaps.Add([pscustomobject] @{ What = $What; Reason = $Reason })
}

function Add-ListGap([string] $What, [string] $Reason, $Items) {
    # One gap for many items: the first few are named, the rest are counted.
    $all = @($Items)
    $shown = @($all | Select-Object -First $MaxListedInGap)
    $text = $Reason + ': ' + ($shown -join '; ')
    if ($all.Count -gt $shown.Count) { $text += '; and ' + ($all.Count - $shown.Count) + ' more' }
    Add-Gap $What $text
}

function Get-GapLine($Gap) {
    '{"gap":{"what":' + (ConvertTo-JsonText $Gap.What) + ',"reason":' + (ConvertTo-JsonText $Gap.Reason) + '}}'
}

# --- Directory objects --------------------------------------------------------------

function Get-First($Row, [string] $Name) {
    # The first value of a property, or $null when it is absent or empty.
    if ($Row.ContainsKey($Name)) {
        $values = $Row[$Name]
        if ($values.Count -gt 0) { return $values[0] }
    }
    $null
}

function Get-RowSid($Row) {
    # The SID text of a row's objectSid. Read here rather than through Get-First: a
    # function would unroll the byte array it returns into single bytes.
    if ($Row.ContainsKey('objectsid') -and $Row['objectsid'].Count -gt 0) {
        return ConvertTo-SidText $Row['objectsid'][0]
    }
    ''
}

function Get-ObjectKind($Classes) {
    if ($Classes -contains 'msds-groupmanagedserviceaccount' -or $Classes -contains 'msds-managedserviceaccount') { return 'service' }
    if ($Classes -contains 'computer') { return 'device' }
    if ($Classes -contains 'group') { return 'group' }
    if ($Classes -contains 'foreignsecurityprincipal') { return 'unknown' }
    if ($Classes -contains 'user') { return 'user' }
    if (@($Classes).Count -gt 0) { return 'other' }
    'unknown'
}

function ConvertTo-ObjectInfo($Row) {
    # The fields shaar uses, as one hashtable. Id is the SID, or the distinguished name
    # when no SID could be read (NoSid is then true).
    $classes = New-Object System.Collections.Generic.List[string]
    if ($Row.ContainsKey('objectclass')) {
        foreach ($class in $Row['objectclass']) { $classes.Add(([string] $class).ToLowerInvariant()) }
    }
    $kind = Get-ObjectKind $classes.ToArray()
    $dn = Get-Text (Get-First $Row 'distinguishedname')
    $common = Get-Text (Get-First $Row 'name')
    $foreign = $classes.Contains('foreignsecurityprincipal')
    $sid = Get-RowSid $Row
    if (-not $sid -and $foreign) { $sid = ConvertTo-SidText $common }
    $noSid = $false
    $id = $sid
    if (-not $id) { $id = $dn; $noSid = $true }
    $sam = Get-Text (Get-First $Row 'samaccountname')
    $display = Get-Text (Get-First $Row 'displayname')
    if ($kind -eq 'group') {
        $candidates = @($sam, $common, $display, $id)
    } else {
        $candidates = @($display, $sam, $common, $id)
    }
    $name = ''
    foreach ($candidate in $candidates) { if (-not $name -and $candidate) { $name = $candidate } }
    $enabled = $null
    $control = Get-First $Row 'useraccountcontrol'
    if ($null -ne $control -and ($kind -eq 'user' -or $kind -eq 'device' -or $kind -eq 'service')) {
        try { $enabled = ((([int64] $control) -band 2) -eq 0) } catch { $enabled = $null }
    }
    @{
        Dn = $dn; Id = $id; NoSid = $noSid; Sam = $sam; Name = $name; Kind = $kind
        Enabled = $enabled; Email = (Get-Text (Get-First $Row 'mail'))
        Upn = (Get-Text (Get-First $Row 'userprincipalname'))
        ManagerDn = (Get-Text (Get-First $Row 'manager'))
        ManagedByDn = (Get-Text (Get-First $Row 'managedby'))
        LastSignIn = (ConvertFrom-FileTime (Get-First $Row 'lastlogontimestamp'))
        Foreign = $foreign; Unresolved = $false
    }
}

function Add-ObjectToCache($Info) {
    if ($Info.Dn) { $script:Objects[$Info.Dn] = $Info }
}

function Resolve-Objects($Dns) {
    # Looks up distinguished names that are not in the cache yet, 25 to a search. One
    # that is not found is remembered in $script:Unresolved with the reason. Members
    # of another domain are not found here: this domain's directory does not hold them.
    $todo = New-Object System.Collections.Generic.List[string]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($dn in $Dns) {
        if ($dn -and -not $script:Objects.ContainsKey($dn) -and -not $script:Unresolved.ContainsKey($dn) -and $seen.Add($dn)) {
            $todo.Add($dn)
        }
    }
    for ($start = 0; $start -lt $todo.Count; $start += $LookupBatch) {
        $chunk = $todo.GetRange($start, [Math]::Min($LookupBatch, $todo.Count - $start))
        $terms = New-Object System.Collections.Generic.List[string]
        foreach ($dn in $chunk) { $terms.Add('(distinguishedName=' + (ConvertTo-LdapFilterText $dn) + ')') }
        $filter = '(|' + ($terms.ToArray() -join '') + ')'
        try {
            $rows = @(Search-Directory $script:DomainDn $filter $ObjectProperties 'Subtree')
        } catch {
            foreach ($dn in $chunk) { $script:Unresolved[$dn] = $_.Exception.Message }
            continue
        }
        foreach ($row in $rows) { Add-ObjectToCache (ConvertTo-ObjectInfo $row) }
        foreach ($dn in $chunk) {
            if (-not $script:Objects.ContainsKey($dn)) {
                $script:Unresolved[$dn] = 'no such object in this domain, or it cannot be read'
            }
        }
    }
}

function New-UnresolvedInfo([string] $Dn) {
    @{
        Dn = $Dn; Id = $Dn; NoSid = $false; Sam = ''; Name = $Dn; Kind = 'unknown'
        Enabled = $null; Email = ''; Upn = ''; ManagerDn = ''; ManagedByDn = ''; LastSignIn = ''
        Foreign = $false; Unresolved = $true
    }
}

# --- Groups and their members -------------------------------------------------------

function Get-MemberDns($Info, $Record) {
    # Every distinguished name in the "member" attribute, read by range. A failure is a
    # gap, and the record is marked incomplete, but what was read so far is kept.
    $dns = New-Object System.Collections.Generic.List[string]
    $what = 'members of group ' + $Info.Name
    $start = [int64] 0
    for ($count = 0; $count -lt $MaxRanges; $count++) {
        try {
            $rows = @(Search-Directory $Info.Dn '(objectClass=group)' @('member;range=' + $start + '-*') 'Base')
        } catch {
            Add-Gap $what $_.Exception.Message
            $Record.Complete = $false
            return , $dns
        }
        if ($rows.Count -eq 0) {
            Add-Gap $what 'the group could not be read (no result, perhaps access denied)'
            $Record.Complete = $false
            return , $dns
        }
        $row = $rows[0]
        $key = $null
        foreach ($name in $row.Keys) {
            if ($name -eq 'member' -or $name.StartsWith('member;range=', [System.StringComparison]::Ordinal)) { $key = $name }
        }
        if ($null -eq $key) {
            # No member values: an empty group, or the end of a group whose last range
            # was complete.
            return , $dns
        }
        foreach ($value in $row[$key]) { $dns.Add([string] $value) }
        if ($key -eq 'member') {
            # Unranged values are the whole attribute, but only to a request from 0.
            if ($start -ne 0) {
                Add-Gap $what ('the server answered with an unranged member list to a request from ' + $start)
                $Record.Complete = $false
            }
            return , $dns
        }
        if ($key -notmatch '^member;range=([0-9]+)-([0-9]+|\*)$') {
            Add-Gap $what ('the server answered with an unexpected range, ' + $key)
            $Record.Complete = $false
            return , $dns
        }
        # The lower bound must be the one asked for, also on the last range (N-*).
        $from = [int64]::Parse($Matches[1], $Invariant)
        if ($from -ne $start) {
            Add-Gap $what ('the server answered with an unexpected range, ' + $key + ', after ' + $start)
            $Record.Complete = $false
            return , $dns
        }
        if ($Matches[2] -eq '*') { return , $dns }
        $to = [int64]::Parse($Matches[2], $Invariant)
        if ($to -lt $start) {
            Add-Gap $what ('the server answered with an unexpected range, ' + $key + ', after ' + $start)
            $Record.Complete = $false
            return , $dns
        }
        $start = $to + 1
    }
    Add-Gap $what ('more than ' + $MaxRanges + ' ranges; the rest was not read')
    $Record.Complete = $false
    , $dns
}

function Get-PrimaryGroupMembers($Info, $Record) {
    # Accounts whose primaryGroupID is this group's RID are not in "member".
    $found = New-Object System.Collections.Generic.List[object]
    if ($Info.Kind -ne 'group' -or -not $script:DomainSid) { return @() }
    $what = 'primary group members of ' + $Info.Name
    if ($Info.NoSid) {
        # Without the SID there is no RID to search for: that read cannot be done, and
        # saying nothing would let accounts that have this group as primary group
        # look removed.
        Add-Gap $what 'the group has no readable objectSid, so the accounts that have it as their primary group were not looked up'
        $Record.Complete = $false
        return @()
    }
    # A builtin group (S-1-5-32-*) or a group of another domain has no primary group
    # members in this domain, by design: not a gap.
    if (-not $Info.Id.StartsWith($script:DomainSid + '-', [System.StringComparison]::OrdinalIgnoreCase)) { return @() }
    $rid = $Info.Id.Substring($Info.Id.LastIndexOf('-') + 1)
    if ($rid -notmatch '^[0-9]+$') {
        Add-Gap $what ('the relative id of ' + $Info.Id + ' could not be read, so the accounts that have it as their primary group were not looked up')
        $Record.Complete = $false
        return @()
    }
    try {
        $rows = @(Search-Directory $script:DomainDn ('(primaryGroupID=' + $rid + ')') $ObjectProperties 'Subtree')
    } catch {
        Add-Gap $what $_.Exception.Message
        $Record.Complete = $false
        return @()
    }
    foreach ($row in $rows) {
        $member = ConvertTo-ObjectInfo $row
        Add-ObjectToCache $member
        $found.Add($member)
    }
    $found.ToArray()
}

function Read-Group($Info) {
    # Reads one group once: its direct members, including accounts that have it as their
    # primary group. Returns @{ Info; Members; Complete }, where each member is
    # @{ Info; Primary }.
    if ($script:Groups.ContainsKey($Info.Dn)) { return $script:Groups[$Info.Dn] }
    $record = @{ Info = $Info; Members = (New-Object System.Collections.Generic.List[object]); Complete = $true }
    $script:Groups[$Info.Dn] = $record
    $dns = Get-MemberDns $Info $record
    Resolve-Objects $dns
    $taken = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    $missing = New-Object System.Collections.Generic.List[string]
    foreach ($dn in $dns) {
        if (-not $taken.Add($dn)) { continue }
        if ($script:Objects.ContainsKey($dn)) {
            $record.Members.Add(@{ Info = $script:Objects[$dn]; Primary = $false })
        } else {
            $missing.Add($dn + ' (' + $script:Unresolved[$dn] + ')')
            $record.Members.Add(@{ Info = (New-UnresolvedInfo $dn); Primary = $false })
        }
    }
    if ($missing.Count -gt 0) {
        $record.Complete = $false
        Add-ListGap ('members of group ' + $Info.Name) ([string] $missing.Count + ' member(s) could not be read, so the list of who has access may be incomplete') $missing.ToArray()
    }
    foreach ($member in @(Get-PrimaryGroupMembers $Info $record)) {
        if ($taken.Add($member.Dn)) { $record.Members.Add(@{ Info = $member; Primary = $true }) }
    }
    $record
}

function Add-Path($Grants, $Member, [string[]] $Via) {
    # One grant per account; the shortest chain wins and every chain is kept.
    $info = $Member.Info
    $primary = [bool] $Member.Primary
    if ($Via.Count -eq 0) {
        if ($primary) { $text = 'primary group' } else { $text = 'direct' }
    } else {
        $text = $Via -join ' > '
        if ($primary) { $text += ' (primary group)' }
    }
    if (-not $Grants.ContainsKey($info.Id)) {
        $paths = New-Object System.Collections.Generic.List[string]
        $paths.Add($text)
        $Grants[$info.Id] = @{ Info = $info; Via = $Via; Paths = $paths; AllPrimary = $primary }
        return
    }
    $grant = $Grants[$info.Id]
    if (-not $grant.Paths.Contains($text)) { $grant.Paths.Add($text) }
    $grant.AllPrimary = $grant.AllPrimary -and $primary
    $shorter = $Via.Count -lt $grant.Via.Count
    if ($Via.Count -eq $grant.Via.Count) {
        $shorter = [string]::CompareOrdinal(($Via -join ' > '), ($grant.Via -join ' > ')) -lt 0
    }
    if ($shorter) { $grant.Via = $Via }
}

function Get-ComponentIds($Adjacency) {
    # Strongly connected components of a directed graph (Tarjan, without recursion).
    # $Adjacency is a list with, for each node number, the list of node numbers it points
    # to. Returns one component number per node; two nodes share a number exactly when
    # each can reach the other.
    $n = $Adjacency.Count
    $index = New-Object int[] $n
    $low = New-Object int[] $n
    $next = New-Object int[] $n
    $component = New-Object int[] $n
    $onStack = New-Object bool[] $n
    for ($i = 0; $i -lt $n; $i++) { $index[$i] = -1; $component[$i] = -1 }
    $counter = 0
    $components = 0
    $stack = New-Object 'System.Collections.Generic.Stack[int]'
    $calls = New-Object 'System.Collections.Generic.Stack[int]'
    for ($start = 0; $start -lt $n; $start++) {
        if ($index[$start] -ge 0) { continue }
        $index[$start] = $counter; $low[$start] = $counter; $counter++
        $stack.Push($start); $onStack[$start] = $true
        $calls.Push($start)
        while ($calls.Count -gt 0) {
            $v = $calls.Peek()
            if ($next[$v] -lt $Adjacency[$v].Count) {
                $w = $Adjacency[$v][$next[$v]]
                $next[$v]++
                if ($index[$w] -lt 0) {
                    $index[$w] = $counter; $low[$w] = $counter; $counter++
                    $stack.Push($w); $onStack[$w] = $true
                    $calls.Push($w)
                } elseif ($onStack[$w]) {
                    $low[$v] = [Math]::Min($low[$v], $index[$w])
                }
            } else {
                [void] $calls.Pop()
                if ($low[$v] -eq $index[$v]) {
                    do {
                        $w = $stack.Pop()
                        $onStack[$w] = $false
                        $component[$w] = $components
                    } while ($w -ne $v)
                    $components++
                }
                if ($calls.Count -gt 0) {
                    $parent = $calls.Peek()
                    $low[$parent] = [Math]::Min($low[$parent], $low[$v])
                }
            }
        }
    }
    , $component
}

function Expand-Group($Root) {
    # Breadth first through the nested groups, each group read once, building the graph
    # of the nesting that was discovered. Then, from that graph:
    #   - via of a grant is a shortest path (ties go to the path that sorts first);
    #   - the paths of a grant are one shortest route to each direct holding group, per
    #     group that nests it: for each group the account is a direct member of, and
    #     each group that nests that group, the shortest route to the nesting group and
    #     then the holder. Not every route: that count can grow exponentially;
    #   - a cycle is reported for every membership edge to a group already seen that
    #     lies on a cycle, whether the group is an ancestor on the path or not.
    # Returns @{ Grants; Complete; Cycles }.
    $result = @{
        Grants = (New-Object 'System.Collections.Generic.Dictionary[string,object]' -ArgumentList ([System.StringComparer]::Ordinal))
        Complete = $true
        Cycles = (New-Object System.Collections.Generic.List[string])
    }
    $visited = New-Object 'System.Collections.Generic.Dictionary[string,object]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    $nodes = New-Object System.Collections.Generic.List[object]
    $edges = New-Object System.Collections.Generic.List[object]
    $queue = New-Object 'System.Collections.Generic.Queue[object]'
    $first = @{ Info = $Root; Parent = $null; Chain = @($Root.Name); ChainDns = @($Root.Dn); Number = 0; Record = $null
        Parents = (New-Object System.Collections.Generic.List[object]); Nested = (New-Object System.Collections.Generic.List[int]) }
    $visited[$Root.Dn] = $first
    $nodes.Add($first)
    $queue.Enqueue($first)
    while ($queue.Count -gt 0) {
        $node = $queue.Dequeue()
        $record = Read-Group $node.Info
        $node.Record = $record
        if (-not $record.Complete) { $result.Complete = $false }
        foreach ($member in $record.Members) {
            $info = $member.Info
            if ($info.Kind -ne 'group' -or $info.Unresolved -or -not $info.Dn) { continue }
            if ($visited.ContainsKey($info.Dn)) {
                $target = $visited[$info.Dn]
                $target.Parents.Add($node)
                $node.Nested.Add($target.Number)
                $edges.Add(@{ From = $node; To = $target; Tree = $false })
                continue
            }
            if ($visited.Count -ge $MaxNestedGroups) {
                Add-Gap ('nested groups of ' + $Root.Name) ('more than ' + $MaxNestedGroups + ' nested groups; ' + $info.Name + ' and any others were not expanded')
                $result.Complete = $false
                continue
            }
            $child = @{ Info = $info; Parent = $node; Chain = (@($node.Chain) + $info.Name); ChainDns = (@($node.ChainDns) + $info.Dn); Number = $nodes.Count; Record = $null
                Parents = (New-Object System.Collections.Generic.List[object]); Nested = (New-Object System.Collections.Generic.List[int]) }
            $child.Parents.Add($node)
            $node.Nested.Add($child.Number)
            $visited[$info.Dn] = $child
            $nodes.Add($child)
            $queue.Enqueue($child)
            $edges.Add(@{ From = $node; To = $child; Tree = $true })
        }
    }
    # Grants: every node has been read, so every group that nests it is known.
    foreach ($node in $nodes) {
        $routes = New-Object System.Collections.Generic.List[object]
        if ($null -eq $node.Parent) {
            $routes.Add(@{ Via = [string[]] @(); Dns = @($node.Info.Dn) })
        } else {
            foreach ($parent in $node.Parents) {
                # A group that is itself below this one closes a cycle: not a route to it.
                if ($parent.ChainDns -contains $node.Info.Dn) { continue }
                $routes.Add(@{ Via = [string[]] @($parent.Chain + $node.Info.Name); Dns = @($parent.ChainDns + $node.Info.Dn) })
            }
        }
        foreach ($member in $node.Record.Members) {
            foreach ($route in $routes) {
                # A group already on the route is a cycle, not another way to hold access.
                # The exported group itself is kept: it is shown as a member through its cycle.
                if ($member.Info.Kind -eq 'group' -and $member.Info.Dn -and $member.Info.Dn -ne $Root.Dn -and ($route.Dns -contains $member.Info.Dn)) { continue }
                Add-Path $result.Grants $member ([string[]] $route.Via)
            }
        }
    }
    # Cycles: an edge to a group already discovered that can get back to the group the
    # edge starts from (the same strongly connected component).
    if ($edges.Count -gt 0) {
        $adjacency = New-Object System.Collections.Generic.List[object]
        foreach ($node in $nodes) { $adjacency.Add($node.Nested) }
        $component = Get-ComponentIds $adjacency
        foreach ($edge in $edges) {
            if ($edge.Tree -or $component[$edge.From.Number] -ne $component[$edge.To.Number]) { continue }
            $text = (@($edge.From.Chain) + $edge.To.Info.Name) -join ' > '
            if (-not ($edge.From.ChainDns -contains $edge.To.Info.Dn)) { $text += ' (also reaches back to ' + $edge.From.Info.Name + ')' }
            $result.Cycles.Add($text)
        }
    }
    $result
}

# --- Scope --------------------------------------------------------------------------

function Assert-Scope {
    if ((-not $Group -or @($Group).Count -eq 0) -and -not $SearchBase -and -not $Privileged) {
        throw 'Give at least one of -Group, -SearchBase and -Privileged.'
    }
}

function Add-Root($Info) {
    $key = $Info.Dn
    if ($script:RootSeen.Add($key)) { $script:Roots.Add($Info) }
}

function Find-Groups([string] $BaseDn, [string] $Filter, [string] $Scope, [string] $What) {
    # Groups found by one search. A failure is a gap and finds nothing.
    try {
        $rows = @(Search-Directory $BaseDn $Filter $ObjectProperties $Scope)
    } catch {
        Add-Gap $What $_.Exception.Message
        return @()
    }
    $found = New-Object System.Collections.Generic.List[object]
    foreach ($row in $rows) {
        $info = ConvertTo-ObjectInfo $row
        if ($info.Kind -eq 'group') { $found.Add($info) }
    }
    $found.ToArray()
}

function Add-ExactlyOne($Found, [string] $What, [string] $NotFound) {
    $list = @($Found)
    if ($list.Count -eq 1) { Add-Root $list[0]; return }
    if ($list.Count -eq 0) { Add-Gap $What $NotFound; return }
    $dns = @($list | ForEach-Object { $_.Dn })
    Add-Gap $What ([string] $list.Count + ' groups match: ' + ($dns -join '; ') + '. Name one by its distinguished name or SID.')
}

function Find-GroupBySpec([string] $Spec) {
    $text = $Spec.Trim()
    $what = '-Group ' + $text
    if ($text -match '^[Ss]-1-[0-9]+(-[0-9]+)+$') {
        $found = @(Find-Groups $script:DomainDn ('(&(objectClass=group)(objectSid=' + $text.ToUpperInvariant() + '))') 'Subtree' $what)
        Add-ExactlyOne $found $what 'no group in this domain has that SID'
    } elseif ($text -match '^[A-Za-z][A-Za-z0-9-]*=.+,[A-Za-z][A-Za-z0-9-]*=.+') {
        $found = @(Find-Groups $text '(objectClass=group)' 'Base' $what)
        Add-ExactlyOne $found $what 'no group has that distinguished name, or it cannot be read'
    } else {
        $escaped = ConvertTo-LdapFilterText $text
        $filter = '(&(objectClass=group)(|(sAMAccountName=' + $escaped + ')(name=' + $escaped + ')))'
        $found = @(Find-Groups $script:DomainDn $filter 'Subtree' $what)
        Add-ExactlyOne $found $what 'no group has that name'
    }
}

function Find-PrivilegedGroups {
    foreach ($entry in $PrivilegedGroups) {
        $what = 'privileged group ' + $entry.Name
        $sid = $entry.Sid
        if (-not $sid -and $entry.Rid -gt 0) {
            $sid = $script:DomainSid + '-' + $entry.Rid
        }
        if ($sid) {
            $found = @(Find-Groups $script:DomainDn ('(&(objectClass=group)(objectSid=' + $sid + '))') 'Subtree' $what)
            $reason = 'not found in this domain (' + $sid + ')'
            if ($entry.Rid -eq 518 -or $entry.Rid -eq 519) { $reason += '; Schema Admins and Enterprise Admins exist only in the forest root domain' }
            if ($entry.Rid -eq 526 -or $entry.Rid -eq 527) { $reason += '; Key Admins groups exist only in domains at Windows Server 2016 level or later' }
        } else {
            $filter = '(&(objectClass=group)(sAMAccountName=' + (ConvertTo-LdapFilterText $entry.Name) + '))'
            $found = @(Find-Groups $script:DomainDn $filter 'Subtree' $what)
            $reason = 'not found in this domain (DnsAdmins exists only where DNS Server is installed)'
        }
        Add-ExactlyOne $found $what $reason
    }
}

function Find-RootGroups {
    foreach ($spec in @($Group)) {
        if ($spec) { Find-GroupBySpec $spec }
    }
    if ($SearchBase) {
        $what = '-SearchBase ' + $SearchBase
        $found = @(Find-Groups $SearchBase '(objectClass=group)' 'Subtree' $what)
        if ($found.Count -eq 0 -and -not ($script:Gaps | Where-Object { $_.What -eq $what })) {
            Add-Gap $what 'no group was found below that base, or the base does not exist'
        }
        foreach ($info in $found) { Add-Root $info }
    }
    if ($Privileged) { Find-PrivilegedGroups }
}

function Get-DomainSid {
    $rows = @(Search-Directory $script:DomainDn '(objectClass=domain)' @('objectSid') 'Base')
    $sid = ''
    if ($rows.Count -gt 0) { $sid = Get-RowSid $rows[0] }
    if (-not $sid) { throw 'The domain SID could not be read, so primary group members cannot be found.' }
    $sid
}

# --- Records ------------------------------------------------------------------------

function Get-PrincipalLine($Info, [string] $Name, $ManagerId) {
    $enabled = 'null'
    if ($null -ne $Info.Enabled) { $enabled = ConvertTo-JsonBool ([bool] $Info.Enabled) }
    $manager = 'null'
    if ($null -ne $ManagerId) { $manager = ConvertTo-JsonText $ManagerId }
    $extra = @{ distinguished_name = $Info.Dn; sam_account_name = $Info.Sam }
    if ($Info.Foreign) { $extra['foreign'] = 'true' }
    '{"principal":{"id":' + (ConvertTo-JsonText $Info.Id) +
    ',"name":' + (ConvertTo-JsonText $Name) +
    ',"kind":"' + $Info.Kind + '"' +
    ',"enabled":' + $enabled +
    ',"email":' + (ConvertTo-JsonText $Info.Email) +
    ',"upn":' + (ConvertTo-JsonText $Info.Upn) +
    ',"manager_id":' + $manager +
    ',"last_sign_in":' + (ConvertTo-JsonText $Info.LastSignIn) +
    ',"extra":' + (ConvertTo-ExtraJson $extra) + '}}'
}

function Get-InfoId($Info) {
    $Info.Id
}

function Build-Records($Roots) {
    # Reads everything, then returns the record lines in file order: principals, then
    # resources, then grants (each in ordinal order of their ids), then gaps.
    $expansions = New-Object System.Collections.Generic.List[object]
    foreach ($root in @(Sort-Ordinal $Roots 'Id')) {
        $expansions.Add(@{ Root = $root; Result = (Expand-Group $root) })
    }
    $emit = New-Object 'System.Collections.Generic.Dictionary[string,object]' -ArgumentList ([System.StringComparer]::Ordinal)
    foreach ($expansion in $expansions) {
        foreach ($id in $expansion.Result.Grants.Keys) {
            if (-not $emit.ContainsKey($id)) { $emit[$id] = $expansion.Result.Grants[$id].Info }
        }
    }
    # Owners (managedBy) of the exported groups.
    $ownerDns = New-Object System.Collections.Generic.List[string]
    foreach ($expansion in $expansions) {
        if ($expansion.Root.ManagedByDn) { $ownerDns.Add($expansion.Root.ManagedByDn) }
    }
    Resolve-Objects $ownerDns
    $ownerLost = New-Object System.Collections.Generic.List[string]
    foreach ($expansion in $expansions) {
        $owners = New-Object System.Collections.Generic.List[string]
        $dn = $expansion.Root.ManagedByDn
        if ($dn) {
            if ($script:Objects.ContainsKey($dn)) {
                $owner = $script:Objects[$dn]
                $owners.Add($owner.Id)
                if (-not $emit.ContainsKey($owner.Id)) { $emit[$owner.Id] = $owner }
            } else {
                $ownerLost.Add($expansion.Root.Name + ': ' + $dn + ' (' + $script:Unresolved[$dn] + ')')
            }
        }
        $expansion.Owners = $owners
    }
    if ($ownerLost.Count -gt 0) {
        Add-ListGap 'group owners (managedBy)' 'an owner could not be read, so that group has no owner here' $ownerLost.ToArray()
    }
    # Managers, and their managers, so a reviewer can be found for every account.
    $handled = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([System.StringComparer]::Ordinal)
    $round = 0
    for (; $round -lt $MaxManagerRounds; $round++) {
        $dns = New-Object System.Collections.Generic.List[string]
        foreach ($info in @($emit.Values)) {
            if ($info.ManagerDn -and $handled.Add($info.Id)) { $dns.Add($info.ManagerDn) }
        }
        if ($dns.Count -eq 0) { break }
        Resolve-Objects $dns
        foreach ($dn in $dns) {
            if ($script:Objects.ContainsKey($dn)) {
                $manager = $script:Objects[$dn]
                if (-not $emit.ContainsKey($manager.Id)) { $emit[$manager.Id] = $manager }
            }
        }
    }
    if ($round -ge $MaxManagerRounds) {
        Add-Gap 'managers' ('the chain of managers is deeper than ' + $MaxManagerRounds + ' levels; the rest was not read')
    }

    $principalLines = New-Object System.Collections.Generic.List[object]
    $lostManagers = @{}
    $noSid = New-Object System.Collections.Generic.List[string]
    $noName = New-Object System.Collections.Generic.List[string]
    foreach ($id in $emit.Keys) {
        $info = $emit[$id]
        $name = $info.Name
        if ($info.Foreign) {
            $resolved = Resolve-SidName $info.Id
            if ($resolved) { $name = $resolved } else { $name = $info.Id; $noName.Add($info.Id) }
        }
        if ($info.NoSid) { $noSid.Add($info.Dn) }
        $managerId = $null
        if ($info.ManagerDn) {
            if ($script:Objects.ContainsKey($info.ManagerDn)) {
                $managerId = $script:Objects[$info.ManagerDn].Id
            } else {
                if (-not $lostManagers.ContainsKey($info.ManagerDn)) { $lostManagers[$info.ManagerDn] = 0 }
                $lostManagers[$info.ManagerDn]++
            }
        }
        $principalLines.Add([pscustomobject] @{ Key = $id; Line = (Get-PrincipalLine $info $name $managerId) })
    }
    if ($noName.Count -gt 0) {
        Add-ListGap 'foreign security principals' 'the name of a member from another domain could not be resolved, so it is shown as its SID' $noName.ToArray()
    }
    if ($noSid.Count -gt 0) {
        Add-ListGap 'objects without a readable SID' 'identified by distinguished name instead' $noSid.ToArray()
    }
    foreach ($dn in @($lostManagers.Keys | Sort-Object)) {
        Add-Gap ('manager ' + $dn) ([string] $lostManagers[$dn] + ' account(s) name this manager, but it could not be read: ' + $script:Unresolved[$dn])
    }

    $resourceLines = New-Object System.Collections.Generic.List[object]
    $grantLines = New-Object System.Collections.Generic.List[object]
    foreach ($expansion in $expansions) {
        $root = $expansion.Root
        $result = $expansion.Result
        $extra = @{ distinguished_name = $root.Dn; sam_account_name = $root.Sam }
        if ($result.Cycles.Count -gt 0) {
            $extra['nesting_cycles'] = (@($result.Cycles | Select-Object -First 5) -join '; ')
        }
        $resourceLines.Add([pscustomobject] @{ Key = $root.Id; Line = ('{"resource":{"id":' + (ConvertTo-JsonText $root.Id) +
                    ',"name":' + (ConvertTo-JsonText $root.Name) + ',"kind":"group"' +
                    ',"owner_ids":' + (ConvertTo-JsonTextArray $expansion.Owners.ToArray()) +
                    ',"complete":' + (ConvertTo-JsonBool $result.Complete) +
                    ',"extra":' + (ConvertTo-ExtraJson $extra) + '}}') })
        foreach ($id in $result.Grants.Keys) {
            $grant = $result.Grants[$id]
            $grantExtra = @{}
            if ($grant.AllPrimary) { $grantExtra['through'] = 'primary group' }
            if ($grant.Paths.Count -gt 1) { $grantExtra['paths'] = (@(Sort-Ordinal ($grant.Paths | ForEach-Object { [pscustomobject] @{ P = $_ } }) 'P' | ForEach-Object { $_.P }) -join '; ') }
            $grantLines.Add([pscustomobject] @{ Key = ($root.Id + '|' + $id); Line = ('{"grant":{"principal_id":' + (ConvertTo-JsonText $id) +
                        ',"resource_id":' + (ConvertTo-JsonText $root.Id) +
                        ',"entitlement":"member","via":' + (ConvertTo-JsonTextArray $grant.Via) +
                        ',"extra":' + (ConvertTo-ExtraJson $grantExtra) + '}}') })
        }
    }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($item in @(Sort-Ordinal $principalLines 'Key')) { $lines.Add($item.Line) }
    foreach ($item in @(Sort-Ordinal $resourceLines 'Key')) { $lines.Add($item.Line) }
    foreach ($item in @(Sort-Ordinal $grantLines 'Key')) { $lines.Add($item.Line) }
    foreach ($gap in $script:Gaps) { $lines.Add((Get-GapLine $gap)) }
    , $lines
}

# --- Export -------------------------------------------------------------------------

function Get-HeaderLine([string] $DomainDn) {
    $groups = @()
    if ($Group) { $groups = @($Group | Where-Object { $_ }) }
    $baseJson = 'null'
    if ($SearchBase) { $baseJson = ConvertTo-JsonText $SearchBase }
    $serverText = 'null'
    if ($Server) { $serverText = ConvertTo-JsonText $Server }
    $note = 'last_sign_in is lastLogonTimestamp, which controllers replicate with up to about 14 days of lag'
    '{"shaar_export":1,"system":"ad"' +
    ',"collector":{"name":"' + $CollectorName + '","version":"' + $CollectorVersion + '"}' +
    ',"collected_at":"' + (Format-UtcTime (Get-Date)) + '"' +
    ',"scope":{"groups":' + (ConvertTo-JsonTextArray $groups) +
    ',"search_base":' + $baseJson +
    ',"privileged":' + (ConvertTo-JsonBool ([bool] $Privileged)) +
    ',"server":' + $serverText +
    ',"notes":[' + (ConvertTo-JsonText $note) + ']}' +
    ',"domain":' + (ConvertTo-JsonText (ConvertTo-DnsName $DomainDn)) + '}'
}

function Invoke-Export {
    Assert-Scope
    if (-not $ToPipeline) {
        # .NET resolves a relative path against the process directory, which is not
        # PowerShell's current location; resolve it the way the user sees it.
        $script:OutFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutFile)
        if (-not $Force -and [System.IO.File]::Exists($OutFile)) {
            throw "$OutFile already exists. Use -Force to replace it."
        }
    }
    # Everything that can fail on the choice of scope happens before a file is made.
    $facts = Get-DomainFacts
    Initialize-State $facts.DomainDn
    $script:DomainSid = Get-DomainSid
    Find-RootGroups
    if ($script:Roots.Count -eq 0) {
        $reasons = @($script:Gaps | ForEach-Object { $_.What + ': ' + $_.Reason }) -join ' '
        throw "No group could be exported. $reasons"
    }
    $lines = Build-Records $script:Roots.ToArray()
    $writer = New-LineWriter $OutFile ([bool] $ToPipeline)
    $published = $false
    try {
        Write-Line $writer (Get-HeaderLine $facts.DomainDn)
        foreach ($line in $lines) {
            Write-Line $writer $line
            $writer.Count++
        }
        $hash = Get-HashText $writer
        Write-Line $writer ('{"end":true,"records":' + $writer.Count + ',"sha256":"' + $hash + '"}') -Last
        Close-LineWriter $writer
        if (-not $ToPipeline) {
            Publish-Output $writer $OutFile ([bool] $Force)
            $published = $true
        }
    } finally {
        Close-LineWriter $writer
        # Whatever went wrong, OutFile is untouched and no partial file is left.
        if (-not $ToPipeline -and -not $published) { [System.IO.File]::Delete($writer.TempPath) }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-Export
}
