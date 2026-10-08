#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Read-only check of dynamic group membership against each group's rule.

.DESCRIPTION
    For every dynamic membership group in the tenant, the script:

      1. Reads the membership rule and its processing state.
      2. Evaluates the rule itself against every user's current attributes
         to work out who SHOULD be a member.
      3. Compares that with who actually IS a member.
      4. Reports missing members (match the rule, not in the group) and
         unexpected members (in the group, do not match the rule).

    A mismatch usually means one of three things: rule processing has not
    caught up after an attribute change, processing is paused, or the rule
    does not do what its author intended.

    Supported rule syntax: expressions of the form user.<property> <operator> <value>
    joined with -and / -or, where the operator is -eq, -ne, -startsWith, or -in.
    -and binds tighter than -or, as in Entra. Rules using anything else (-not,
    -match, -contains, nested groups of -or inside -and, direct reports, memberOf,
    multi-value properties) are reported as "Not evaluated" rather than guessed.

    The script only reads. It makes no changes to the tenant.

    Lab project. Built and tested in a Microsoft 365 trial tenant, not in production.

.NOTES
    Written with AI assistance (Anthropic Claude). Reviewed, tested, and run
    by Paul Hwang in a Microsoft 365 trial lab tenant. Lab work, not production.

.PARAMETER TenantId
    Tenant to connect to (GUID or domain). Recommended.

.PARAMETER OutputPath
    Folder for the CSV export. Created if it does not exist.

.PARAMETER UseExistingConnection
    Skip Connect-MgGraph and use the current session.

.EXAMPLE
    .\Test-DynamicGroupMembership.ps1 -TenantId "contoso.onmicrosoft.com"
#>
[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$OutputPath = ".\sample-output",
    [switch]$UseExistingConnection
)

#region Connection ----------------------------------------------------------------

# Read-only scopes
$RequiredScopes = @(
    'User.Read.All'          # User attributes, including accountEnabled and extension attributes
    'Group.Read.All'         # Group membership rules and processing state
    'GroupMember.Read.All'   # Actual group membership
)

if (-not $UseExistingConnection) {
    $connectParams = @{ Scopes = $RequiredScopes; NoWelcome = $true }
    if ($TenantId) { $connectParams.TenantId = $TenantId }
    try { Connect-MgGraph @connectParams -ErrorAction Stop }
    catch { Write-Error "Could not connect to Microsoft Graph: $($_.Exception.Message)"; return }
}

$context = Get-MgContext
if (-not $context) { Write-Error "No Microsoft Graph connection."; return }

Write-Host "`nDynamic group membership check" -ForegroundColor Cyan
Write-Host "  Tenant:  $($context.TenantId)"
Write-Host "  Run as:  $($context.Account)"
Write-Host "  Started: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC"
Write-Host "  Mode:    Read-only. No changes are made to the tenant."

#endregion

#region Data collection -----------------------------------------------------------

try {
    $dynamicGroups = @(Get-MgGroup -All -Filter "groupTypes/any(g:g eq 'DynamicMembership')" `
        -Property id, displayName, membershipRule, membershipRuleProcessingState -ErrorAction Stop)
}
catch {
    Write-Error "Could not read groups: $($_.Exception.Message)"
    return
}

if ($dynamicGroups.Count -eq 0) {
    Write-Host "`nNo dynamic membership groups found."
    return
}

$userProps = 'id', 'displayName', 'userPrincipalName', 'department', 'city', 'jobTitle', 'country',
             'state', 'companyName', 'employeeId', 'usageLocation', 'userType', 'accountEnabled',
             'mail', 'onPremisesExtensionAttributes'
try {
    $users = @(Get-MgUser -All -Property ($userProps -join ',') -ErrorAction Stop)
}
catch {
    Write-Error "Could not read users: $($_.Exception.Message)"
    return
}

Write-Host ("  Dynamic groups: {0}   Users: {1}" -f $dynamicGroups.Count, $users.Count)

#endregion

#region Rule evaluation -----------------------------------------------------------

# Read the value a rule property refers to. extensionAttribute1-15 live under
# onPremisesExtensionAttributes on the user object.
function Get-RuleValue {
    param($User, [string]$Property)
    if ($Property -match '^extensionAttribute(\d{1,2})$') {
        return $User.OnPremisesExtensionAttributes."ExtensionAttribute$($Matches[1])"
    }
    $prop = $User.PSObject.Properties | Where-Object { $_.Name -eq $Property } | Select-Object -First 1
    if ($prop) { return $prop.Value }
    return $null
}

# Parse a rule into a list of OR-clauses, each a list of AND-ed expressions.
# Returns $null if any part uses syntax this script does not evaluate.
function ConvertFrom-MembershipRule {
    param([string]$Rule)

    $atomPattern = '^\(?\s*user\.(?<prop>\w+)\s+-(?<op>eq|ne|startsWith|in)\s+(?<val>"[^"]*"|true|false|null|\[[^\]]*\])\s*\)?$'

    $clauses = @()
    foreach ($orPart in ($Rule -split '\s+-or\s+')) {
        $orPart = $orPart.Trim()
        $exprs = @()
        foreach ($andPart in ($orPart -split '\s+-and\s+')) {
            $m = [regex]::Match($andPart.Trim(), $atomPattern, 'IgnoreCase')
            if (-not $m.Success) { return $null }

            $raw = $m.Groups['val'].Value
            $value = switch -Regex ($raw) {
                '^"(.*)"$'  { $Matches[1]; break }
                '^\[(.*)\]$' { @($Matches[1] -split ',' | ForEach-Object { $_.Trim().Trim('"') }); break }
                '^true$'    { $true; break }
                '^false$'   { $false; break }
                '^null$'    { $null; break }
            }
            $exprs += [PSCustomObject]@{ Property = $m.Groups['prop'].Value; Operator = $m.Groups['op'].Value.ToLower(); Value = $value; Raw = $raw }
        }
        $clauses += , $exprs
    }
    return , $clauses
}

# Evaluate one expression against one user. String comparisons are
# case-insensitive, as they are in Entra.
function Test-Expression {
    param($User, $Expr)
    $actual = Get-RuleValue -User $User -Property $Expr.Property

    switch ($Expr.Operator) {
        'eq' {
            if ($Expr.Raw -eq 'null') { return [string]::IsNullOrEmpty("$actual") }
            if ($Expr.Value -is [bool]) { return [bool]$actual -eq $Expr.Value }
            return "$actual" -ieq "$($Expr.Value)"
        }
        'ne' {
            if ($Expr.Raw -eq 'null') { return -not [string]::IsNullOrEmpty("$actual") }
            if ($Expr.Value -is [bool]) { return [bool]$actual -ne $Expr.Value }
            return "$actual" -ine "$($Expr.Value)"
        }
        'startswith' { return "$actual".StartsWith("$($Expr.Value)", [StringComparison]::OrdinalIgnoreCase) }
        'in'         { return @($Expr.Value | Where-Object { $_ -ieq "$actual" }).Count -gt 0 }
    }
    return $false
}

function Test-Rule {
    param($User, $Clauses)
    foreach ($clause in $Clauses) {
        $allTrue = $true
        foreach ($expr in $clause) {
            if (-not (Test-Expression -User $User -Expr $expr)) { $allTrue = $false; break }
        }
        if ($allTrue) { return $true }   # Any OR-clause satisfied
    }
    return $false
}

#endregion

#region Compare rule vs actual ----------------------------------------------------

$userById = @{}
foreach ($u in $users) { $userById[$u.Id] = $u }

$results = foreach ($g in ($dynamicGroups | Sort-Object DisplayName)) {
    $clauses = ConvertFrom-MembershipRule -Rule $g.MembershipRule

    try {
        $actualIds = @(Get-MgGroupMember -GroupId $g.Id -All -ErrorAction Stop | ForEach-Object { $_.Id })
    }
    catch {
        [PSCustomObject]@{
            Group = $g.DisplayName; Processing = $g.MembershipRuleProcessingState; Rule = $g.MembershipRule
            Expected = ''; Actual = ''; Status = 'ERROR: membership could not be read'; Missing = ''; Unexpected = ''
        }
        continue
    }

    if ($null -eq $clauses) {
        [PSCustomObject]@{
            Group = $g.DisplayName; Processing = $g.MembershipRuleProcessingState; Rule = $g.MembershipRule
            Expected = ''; Actual = $actualIds.Count; Status = 'Not evaluated (unsupported rule syntax)'; Missing = ''; Unexpected = ''
        }
        continue
    }

    $expectedIds = @($users | Where-Object { Test-Rule -User $_ -Clauses $clauses } | ForEach-Object { $_.Id })

    $missing    = @($expectedIds | Where-Object { $actualIds -notcontains $_ })
    $unexpected = @($actualIds   | Where-Object { $expectedIds -notcontains $_ })

    $status = if ($g.MembershipRuleProcessingState -ne 'On') { 'PAUSED: rule processing is not On' }
              elseif ($missing.Count -or $unexpected.Count) { 'MISMATCH' }
              else { 'OK' }

    [PSCustomObject]@{
        Group      = $g.DisplayName
        Processing = $g.MembershipRuleProcessingState
        Rule       = $g.MembershipRule
        Expected   = $expectedIds.Count
        Actual     = $actualIds.Count
        Status     = $status
        Missing    = ($missing    | ForEach-Object { $userById[$_].DisplayName ?? $_ }) -join ', '
        Unexpected = ($unexpected | ForEach-Object { $userById[$_].DisplayName ?? $_ }) -join ', '
    }
}
$results = @($results)

#endregion

#region Output --------------------------------------------------------------------

Write-Host "`n=== Rule vs actual membership ===" -ForegroundColor Cyan
$results | Format-Table Group, Processing, Expected, Actual, Status -AutoSize | Out-Host

$problems = @($results | Where-Object { $_.Status -ne 'OK' })
if ($problems.Count -eq 0) {
    Write-Host "All evaluated groups match their rules." -ForegroundColor Green
}
else {
    Write-Host "=== Details ===" -ForegroundColor Cyan
    foreach ($p in $problems) {
        Write-Host "`n--- $($p.Group) [$($p.Status)]" -ForegroundColor Yellow
        Write-Host "  Rule:       $($p.Rule)"
        if ($p.Missing)    { Write-Host "  Missing:    $($p.Missing)    (match the rule, not in the group)" }
        if ($p.Unexpected) { Write-Host "  Unexpected: $($p.Unexpected)    (in the group, do not match the rule)" }
    }
    Write-Host "`nA mismatch right after an attribute change is normal while Entra reprocesses the rule. A mismatch that persists is worth investigating."
}

try {
    if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmm')
    $file  = Join-Path $OutputPath "DynamicGroupCheck-$stamp.csv"
    $results | Export-Csv $file -NoTypeInformation -Encoding utf8
    Write-Host "`nExport written to $file" -ForegroundColor Cyan
}
catch {
    Write-Warning "Export failed: $($_.Exception.Message)"
}

#endregion
