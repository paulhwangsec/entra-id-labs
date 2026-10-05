#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Applications, Microsoft.Graph.Identity.DirectoryManagement

<#
.SYNOPSIS
    Read-only audit of Microsoft Entra Conditional Access configuration.

.DESCRIPTION
    Inventories every Conditional Access policy in a tenant and reports on
    targeting, exclusions, break-glass coverage, MFA coverage gaps, stalled
    report-only policies, and legacy authentication blocking.

    The script only reads. It requests read-only Microsoft Graph scopes and
    makes no changes to the tenant.

    Lab project. Built and tested in a Microsoft 365 trial tenant, not in production.

.NOTES
    Written with AI assistance (Anthropic Claude). Reviewed, tested, and run
    by Paul Hwang in a Microsoft 365 trial lab tenant. Lab work, not production.

.PARAMETER BreakGlassUpn
    UPNs of emergency access accounts. The script checks that each one is
    excluded from every policy, directly or through group or role membership.
    If omitted, the script lists users who look like break-glass accounts.

.PARAMETER OutputPath
    Folder for CSV and JSON exports. Created if it does not exist.

.PARAMETER TenantId
    Tenant to connect to (GUID or domain). Recommended, so a cached account
    on the workstation cannot point the audit at the wrong tenant.

.PARAMETER UseExistingConnection
    Skip Connect-MgGraph and use the current session. Scopes are still checked.

.EXAMPLE
    .\Invoke-CAAudit.ps1 -TenantId "contoso.onmicrosoft.com" -BreakGlassUpn "bg-admin01@contoso.onmicrosoft.com","bg-admin02@contoso.onmicrosoft.com"
#>
[CmdletBinding()]
param(
    [string[]]$BreakGlassUpn = @(),
    [string]$OutputPath = ".\sample-output",
    [string]$TenantId,
    [switch]$UseExistingConnection
)

#region Configuration -------------------------------------------------------------

# Least-privilege, read-only scopes. Each one is listed with what it is used for.
$RequiredScopes = @(
    'Policy.Read.All'                # CA policies, named locations, Security Defaults status
    'User.ReadBasic.All'             # Resolve user IDs to names; list users for coverage analysis
    'GroupMember.Read.All'           # Resolve group names and expand group membership
    'RoleManagement.Read.Directory'  # Resolve role template IDs to names and list role members
    'Application.Read.All'           # Resolve application IDs to app names
)

# Graph stores policy state as an API value. These are the labels the portal shows.
$StateLabels = @{
    'enabled'                           = 'On'
    'disabled'                          = 'Off'
    'enabledForReportingButNotEnforced' = 'Report-only'
}

# Sort order for the findings summary
$SeverityOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2; 'Info' = 3 }

#endregion

#region Findings collector --------------------------------------------------------

# Every check adds its findings here. The summary and the export both read from this list.
$Findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('High', 'Medium', 'Low', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Check,
        [string]$Policy = '',
        [Parameter(Mandatory)][string]$Finding
    )
    $Findings.Add([PSCustomObject]@{
        Severity = $Severity
        Check    = $Check
        Policy   = $Policy
        Finding  = $Finding
    })
}

#endregion

#region Connection and permission checks ------------------------------------------

if (-not $UseExistingConnection) {
    $connectParams = @{ Scopes = $RequiredScopes; NoWelcome = $true }
    if ($TenantId) { $connectParams.TenantId = $TenantId }
    try {
        Connect-MgGraph @connectParams -ErrorAction Stop
    }
    catch {
        Write-Error "Could not connect to Microsoft Graph: $($_.Exception.Message)"
        return
    }
}

$context = Get-MgContext
if (-not $context) {
    Write-Error "No Microsoft Graph connection. Run without -UseExistingConnection, or run Connect-MgGraph first."
    return
}

# Missing scopes are a warning, not a failure. The script degrades instead of
# crashing: anything it cannot resolve is shown as a raw ID and flagged.
$missingScopes = @($RequiredScopes | Where-Object { $context.Scopes -notcontains $_ })
if ($missingScopes.Count -gt 0) {
    Write-Warning "Missing scopes: $($missingScopes -join ', '). Some results will show raw IDs or be skipped."
}

# Flag write scopes in the session. The audit never needs them. Delegated consent
# accumulates, so a session can carry write scopes granted earlier for other work.
$writeScopes = @($context.Scopes | Where-Object { $_ -match 'ReadWrite' })
if ($writeScopes.Count -gt 0) {
    Write-Warning "Session holds write scopes ($($writeScopes -join ', ')). This audit only needs read access."
}

#endregion

#region Data collection -----------------------------------------------------------

Write-Host "`nConditional Access audit" -ForegroundColor Cyan
Write-Host "  Tenant:  $($context.TenantId)"
Write-Host "  Run as:  $($context.Account)"
Write-Host "  Started: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')) UTC"
Write-Host "  Mode:    Read-only. No changes are made to the tenant."

# Policies are the one thing the audit cannot run without, so this failure is fatal.
try {
    $policies = @(Get-MgIdentityConditionalAccessPolicy -All -ErrorAction Stop)
}
catch {
    Write-Error ("Could not read Conditional Access policies. This needs Policy.Read.All and a role " +
                 "such as Global Reader or Security Reader. Details: $($_.Exception.Message)")
    return
}

if ($policies.Count -eq 0) {
    Write-Warning "No Conditional Access policies found."
}

# Named locations: used to show location names instead of IDs. Non-fatal if unavailable.
$locationNameById = @{}
try {
    Get-MgIdentityConditionalAccessNamedLocation -All -ErrorAction Stop | ForEach-Object {
        $locationNameById[$_.Id] = $_.DisplayName
    }
}
catch {
    Write-Warning "Could not read named locations. Location conditions will show raw IDs."
}

# Role templates: CA policies reference directory roles by template ID. Non-fatal if unavailable.
$roleNameById = @{}
try {
    Get-MgDirectoryRoleTemplate -All -ErrorAction Stop | ForEach-Object {
        $roleNameById[$_.Id] = $_.DisplayName
    }
}
catch {
    Write-Warning "Could not read directory role templates. Role conditions will show raw IDs."
}

# Activated directory roles: needed to list who holds a role. A role that has never
# been assigned in the tenant has no activated object and therefore no members.
$roleObjectIdByTemplate = @{}
$roleReadFailed = $false
try {
    Get-MgDirectoryRole -All -ErrorAction Stop | ForEach-Object {
        if ($_.RoleTemplateId) { $roleObjectIdByTemplate[$_.RoleTemplateId] = $_.Id }
    }
}
catch {
    $roleReadFailed = $true
    Write-Warning "Could not read directory roles. Role-based targeting cannot be expanded to members."
}

# Security Defaults: relevant context for MFA coverage, especially in tenants with no CA policies.
$securityDefaults = 'Unknown'
try {
    $sd = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
    $securityDefaults = if ($sd.IsEnabled) { 'Enabled' } else { 'Disabled' }
}
catch {
    Write-Warning "Could not read Security Defaults status."
}

# All users: needed for MFA coverage and break-glass candidate detection. Non-fatal if unavailable.
$allUsers = @()
try {
    $allUsers = @(Get-MgUser -All -Property id, displayName, userPrincipalName -ErrorAction Stop)
}
catch {
    Write-Warning "Could not list users. Per-user MFA coverage will be skipped."
}

Write-Host ("  Policies: {0}   Named locations: {1}   Role templates: {2}   Users: {3}   Security Defaults: {4}" -f `
    $policies.Count, $locationNameById.Count, $roleNameById.Count, $allUsers.Count, $securityDefaults)

#endregion

#region Name resolution -----------------------------------------------------------

# Values Graph uses in place of object IDs. These are keywords, not directory objects.
$SpecialValues = @{
    'All'                   = 'All'
    'None'                  = 'None'
    'GuestsOrExternalUsers' = 'All guests and external users'
    'Office365'             = 'Office 365 (app group)'
    'MicrosoftAdminPortals' = 'Microsoft Admin Portals (app group)'
    'AllTrusted'            = 'All trusted locations'
}

# Cache so each object is looked up once, no matter how many policies reference it.
$NameCache = @{}

function Resolve-ObjectName {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][ValidateSet('User', 'Group', 'Role', 'App', 'Location')][string]$Type
    )

    if ($SpecialValues.ContainsKey($Id)) { return $SpecialValues[$Id] }

    $key = "$Type|$Id"
    if ($NameCache.ContainsKey($key)) { return $NameCache[$key] }

    $name = $null
    try {
        switch ($Type) {
            'User' {
                $usr = Get-MgUser -UserId $Id -Property displayName, userPrincipalName -ErrorAction Stop
                $name = "$($usr.DisplayName) ($($usr.UserPrincipalName))"
            }
            'Group' {
                $name = (Get-MgGroup -GroupId $Id -Property displayName -ErrorAction Stop).DisplayName
            }
            'Role' {
                $name = $roleNameById[$Id]
            }
            'App' {
                $sp = Get-MgServicePrincipal -Filter "appId eq '$Id'" -Property displayName -ErrorAction Stop |
                      Select-Object -First 1
                $name = $sp.DisplayName
            }
            'Location' {
                $name = $locationNameById[$Id]
            }
        }
    }
    catch {
        $name = $null
    }

    # Unresolved usually means a deleted object or a missing permission. Both are worth flagging.
    if (-not $name) { $name = "[UNRESOLVED $Type] $Id" }

    $NameCache[$key] = $name
    return $name
}

#endregion

#region Display helpers -----------------------------------------------------------

# Graph returns timestamps in UTC. Label them so nobody compares against local-time logs by mistake.
function Format-Utc ($dt) {
    if (-not $dt) { return 'Never' }
    return ([datetime]$dt).ToString('yyyy-MM-dd HH:mm') + ' UTC'
}

# Resolve a list of IDs to names and join them for display. Empty lists return an empty string.
function Join-Names {
    param([object[]]$Ids, [string]$Type)
    $clean = @($Ids | Where-Object { $_ })
    if ($clean.Count -eq 0) { return '' }
    return (($clean | ForEach-Object { Resolve-ObjectName -Id $_ -Type $Type }) -join '; ')
}

# Client app types as Graph stores them, mapped to the portal's wording.
# "all" is a single value meaning every client type, which is why the portal shows "1 included".
$ClientAppLabels = @{
    'all'                         = 'All client apps'
    'browser'                     = 'Browser'
    'mobileAppsAndDesktopClients' = 'Mobile apps and desktop clients'
    'exchangeActiveSync'          = 'Exchange ActiveSync (legacy)'
    'easSupported'                = 'Exchange ActiveSync (legacy)'
    'other'                       = 'Other clients (legacy)'
}

# Grant controls as Graph stores them, mapped to the portal's wording.
$GrantLabels = @{
    'mfa'                  = 'Require multifactor authentication'
    'block'                = 'Block access'
    'compliantDevice'      = 'Require compliant device'
    'domainJoinedDevice'   = 'Require Microsoft Entra hybrid joined device'
    'approvedApplication'  = 'Require approved client app'
    'compliantApplication' = 'Require app protection policy'
    'passwordChange'       = 'Require password change'
}

#endregion

#region Membership expansion ------------------------------------------------------

# Transitive group membership (includes nested groups), cached per group.
# Returns an array of members, an EMPTY array for an empty group, or $null if
# membership could not be read. Callers rely on that difference.
$GroupMemberCache = @{}

function Get-GroupMembers {
    param([Parameter(Mandatory)][string]$GroupId)

    if ($GroupMemberCache.ContainsKey($GroupId)) {
        $cached = $GroupMemberCache[$GroupId]
        if ($null -eq $cached) { return $null }
        return , $cached
    }

    try {
        $members = @(Get-MgGroupTransitiveMember -GroupId $GroupId -All -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Id   = $_.Id
                Type = ($_.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.', '')
                Name = $_.AdditionalProperties['displayName']
                Upn  = $_.AdditionalProperties['userPrincipalName']
            }
        })
    }
    catch {
        $GroupMemberCache[$GroupId] = $null
        return $null
    }

    $GroupMemberCache[$GroupId] = $members
    return , $members   # Leading comma keeps an empty array from collapsing to $null
}

# Active members of a directory role, by role template ID. Members that are
# role-assignable groups are expanded to their users. Same return contract as above.
# Note: PIM-eligible assignments are not active members and are not included.
$RoleMemberCache = @{}

function Get-RoleMemberIds {
    param([Parameter(Mandatory)][string]$RoleTemplateId)

    if ($RoleMemberCache.ContainsKey($RoleTemplateId)) {
        $cached = $RoleMemberCache[$RoleTemplateId]
        if ($null -eq $cached) { return $null }
        return , $cached
    }

    if ($roleReadFailed) {
        $RoleMemberCache[$RoleTemplateId] = $null
        return $null
    }

    $roleObjectId = $roleObjectIdByTemplate[$RoleTemplateId]
    if (-not $roleObjectId) {
        # Role has never been assigned in this tenant, so it has no members
        $RoleMemberCache[$RoleTemplateId] = @()
        return , @()
    }

    try {
        $ids = [System.Collections.Generic.List[string]]::new()
        foreach ($m in Get-MgDirectoryRoleMember -DirectoryRoleId $roleObjectId -All -ErrorAction Stop) {
            if ($m.AdditionalProperties['@odata.type'] -eq '#microsoft.graph.group') {
                $groupMembers = Get-GroupMembers -GroupId $m.Id
                if ($groupMembers) { foreach ($gm in $groupMembers) { $ids.Add($gm.Id) } }
            }
            else {
                $ids.Add($m.Id)
            }
        }
        $result = @($ids)
    }
    catch {
        $RoleMemberCache[$RoleTemplateId] = $null
        return $null
    }

    $RoleMemberCache[$RoleTemplateId] = $result
    return , $result
}

#endregion

#region Policy scope evaluation ---------------------------------------------------

# Decide whether a policy targets a given user, based on the user conditions only.
# Returns Result = Excluded, Included, NotInScope, or Unknown, plus Via (the reason).
# Exclusions take precedence over inclusions in Conditional Access, so they are checked first.
# Other conditions (apps, platforms, locations, risk) are evaluated separately by each check.
function Get-PolicyScope {
    param(
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)][string]$UserId
    )

    $u = $Policy.Conditions.Users
    $unknown = $false

    # --- Exclusions ---
    if (@($u.ExcludeUsers) -contains $UserId) {
        return [PSCustomObject]@{ Result = 'Excluded'; Via = 'Direct user exclusion' }
    }
    foreach ($gid in @($u.ExcludeGroups | Where-Object { $_ })) {
        $m = Get-GroupMembers -GroupId $gid
        if ($null -eq $m) { $unknown = $true; continue }
        if (@($m.Id) -contains $UserId) {
            return [PSCustomObject]@{ Result = 'Excluded'; Via = "Group: $(Resolve-ObjectName -Id $gid -Type 'Group')" }
        }
    }
    foreach ($rid in @($u.ExcludeRoles | Where-Object { $_ })) {
        $m = Get-RoleMemberIds -RoleTemplateId $rid
        if ($null -eq $m) { $unknown = $true; continue }
        if ($m -contains $UserId) {
            return [PSCustomObject]@{ Result = 'Excluded'; Via = "Role: $(Resolve-ObjectName -Id $rid -Type 'Role')" }
        }
    }

    # --- Inclusions ---
    $included = $null
    $includeUsers = @($u.IncludeUsers)

    if ($includeUsers -contains 'All') {
        $included = 'All users'
    }
    elseif ($includeUsers -contains $UserId) {
        $included = 'Direct user inclusion'
    }

    if (-not $included) {
        foreach ($gid in @($u.IncludeGroups | Where-Object { $_ })) {
            $m = Get-GroupMembers -GroupId $gid
            if ($null -eq $m) { $unknown = $true; continue }
            if (@($m.Id) -contains $UserId) { $included = "Group: $(Resolve-ObjectName -Id $gid -Type 'Group')"; break }
        }
    }

    if (-not $included) {
        foreach ($rid in @($u.IncludeRoles | Where-Object { $_ })) {
            $m = Get-RoleMemberIds -RoleTemplateId $rid
            if ($null -eq $m) { $unknown = $true; continue }
            if ($m -contains $UserId) { $included = "Role: $(Resolve-ObjectName -Id $rid -Type 'Role')"; break }
        }
    }

    # If any membership lookup failed, an exclusion may have been missed, so do not claim certainty.
    if ($unknown -and $included) {
        return [PSCustomObject]@{ Result = 'Unknown'; Via = "Included ($included), but some exclusion memberships could not be read" }
    }
    if ($included) {
        return [PSCustomObject]@{ Result = 'Included'; Via = $included }
    }
    if ($unknown) {
        return [PSCustomObject]@{ Result = 'Unknown'; Via = 'Some group or role memberships could not be read' }
    }
    return [PSCustomObject]@{ Result = 'NotInScope'; Via = '' }
}

# Does the policy's grant require MFA? Authentication strength counts as an MFA requirement.
function Test-RequiresMfa {
    param([Parameter(Mandatory)]$Policy)
    $g = $Policy.GrantControls
    if (-not $g) { return $false }
    return ((@($g.BuiltInControls) -contains 'mfa') -or [bool]$g.AuthenticationStrength.Id)
}

# Classify an enabled MFA policy as Full coverage or Partial coverage.
# Full means: all resources, no narrowing conditions, and MFA cannot be bypassed
# by satisfying a different control. Anything else is Partial, with reasons.
# Returns $null for policies that are not enabled or do not require MFA.
function Get-MfaCoverage {
    param([Parameter(Mandatory)]$Policy)

    if ($Policy.State -ne 'enabled') { return $null }
    if (-not (Test-RequiresMfa -Policy $Policy)) { return $null }

    $c = $Policy.Conditions
    $reasons = @()

    $apps = @($c.Applications.IncludeApplications | Where-Object { $_ })
    if ($apps -notcontains 'All') { $reasons += "apps: $(Join-Names $apps 'App')" }
    if (@($c.Applications.ExcludeApplications | Where-Object { $_ }).Count -gt 0) { $reasons += 'some apps excluded' }

    if ($c.Platforms -and @($c.Platforms.IncludePlatforms | Where-Object { $_ }).Count -gt 0) { $reasons += 'platform condition' }
    if ($c.Locations -and @($c.Locations.IncludeLocations | Where-Object { $_ }).Count -gt 0) { $reasons += 'location condition' }
    if (@($c.SignInRiskLevels | Where-Object { $_ }).Count -gt 0) { $reasons += 'sign-in risk condition' }
    if (@($c.UserRiskLevels | Where-Object { $_ }).Count -gt 0) { $reasons += 'user risk condition' }

    $clientTypes = @($c.ClientAppTypes | Where-Object { $_ })
    if ($clientTypes.Count -gt 0 -and $clientTypes -notcontains 'all') { $reasons += 'client app condition' }

    # With OR, a user can satisfy a different control (for example a compliant device) instead of MFA
    $g = $Policy.GrantControls
    $otherControls = @($g.BuiltInControls | Where-Object { $_ -and $_ -ne 'mfa' })
    if ($g.Operator -eq 'OR' -and $otherControls.Count -gt 0) {
        $reasons += "MFA OR $($otherControls -join '/')"
    }

    return [PSCustomObject]@{
        Type    = if ($reasons.Count -gt 0) { 'Partial' } else { 'Full' }
        Reasons = $reasons -join '; '
    }
}

#endregion

#region Check 1: Policy inventory -------------------------------------------------

$inventory = foreach ($p in $policies) {
    [PSCustomObject]@{
        Name     = $p.DisplayName
        State    = $StateLabels[$p.State] ?? $p.State
        Created  = Format-Utc $p.CreatedDateTime
        Modified = Format-Utc $p.ModifiedDateTime
        Id       = $p.Id
    }
}

Write-Host "`n=== Check 1: Policy inventory ===" -ForegroundColor Cyan
if (@($inventory).Count -eq 0) {
    Write-Host "  No policies to list."
    Add-Finding -Severity 'High' -Check 'Inventory' -Finding "No Conditional Access policies exist. Security Defaults: $securityDefaults."
}
else {
    $inventory | Sort-Object Name | Format-Table Name, State, Created, Modified -AutoSize | Out-Host
}

#endregion

#region Check 2: Policy targeting -------------------------------------------------

# Flatten each policy into readable fields. This object feeds both the console and the export.
$policyDetails = foreach ($p in $policies) {
    $c = $p.Conditions
    $u = $c.Users
    $a = $c.Applications

    # The SDK returns an empty guest object even when no guest condition is set,
    # so test the guest types value, not just whether the object exists.
    $inclGuests = if ($u.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes) { "Guest types: $($u.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes)" } else { '' }
    $exclGuests = if ($u.ExcludeGuestsOrExternalUsers.GuestOrExternalUserTypes) { "Guest types: $($u.ExcludeGuestsOrExternalUsers.GuestOrExternalUserTypes)" } else { '' }

    # Platforms: no condition means the policy applies on any platform
    $platformText = 'Any'
    if ($c.Platforms -and @($c.Platforms.IncludePlatforms | Where-Object { $_ }).Count -gt 0) {
        $platformText = "Include: $($c.Platforms.IncludePlatforms -join ', ')"
        if (@($c.Platforms.ExcludePlatforms | Where-Object { $_ }).Count -gt 0) {
            $platformText += "; Exclude: $($c.Platforms.ExcludePlatforms -join ', ')"
        }
    }

    # Locations: no condition means the policy applies from any location
    $locationText = 'Any'
    if ($c.Locations -and @($c.Locations.IncludeLocations | Where-Object { $_ }).Count -gt 0) {
        $locationText = "Include: $(Join-Names $c.Locations.IncludeLocations 'Location')"
        $exclLoc = Join-Names $c.Locations.ExcludeLocations 'Location'
        if ($exclLoc) { $locationText += "; Exclude: $exclLoc" }
    }

    $clientApps = (@($c.ClientAppTypes | Where-Object { $_ }) | ForEach-Object { $ClientAppLabels[$_] ?? $_ }) -join '; '

    # Grant controls can be null when a policy only uses session controls
    $g = $p.GrantControls
    $grantParts = @()
    if ($g.BuiltInControls)                    { $grantParts += @($g.BuiltInControls | ForEach-Object { $GrantLabels[$_] ?? $_ }) }
    if ($g.AuthenticationStrength.DisplayName) { $grantParts += "Authentication strength: $($g.AuthenticationStrength.DisplayName)" }
    if ($g.TermsOfUse)                         { $grantParts += 'Terms of use' }
    $grantText = if ($grantParts.Count -gt 0) { $grantParts -join " $($g.Operator) " } else { 'None (session controls only)' }

    [PSCustomObject]@{
        Policy        = $p.DisplayName
        State         = $StateLabels[$p.State] ?? $p.State
        IncludeUsers  = Join-Names $u.IncludeUsers 'User'
        IncludeGroups = Join-Names $u.IncludeGroups 'Group'
        IncludeRoles  = Join-Names $u.IncludeRoles 'Role'
        IncludeGuests = $inclGuests
        ExcludeUsers  = Join-Names $u.ExcludeUsers 'User'
        ExcludeGroups = Join-Names $u.ExcludeGroups 'Group'
        ExcludeRoles  = Join-Names $u.ExcludeRoles 'Role'
        ExcludeGuests = $exclGuests
        IncludeApps   = Join-Names $a.IncludeApplications 'App'
        ExcludeApps   = Join-Names $a.ExcludeApplications 'App'
        UserActions   = (@($a.IncludeUserActions | Where-Object { $_ }) -join '; ')
        Platforms     = $platformText
        Locations     = $locationText
        ClientApps    = $clientApps
        SignInRisk    = (@($c.SignInRiskLevels | Where-Object { $_ }) -join ', ')
        UserRisk      = (@($c.UserRiskLevels | Where-Object { $_ }) -join ', ')
        Grant         = $grantText
        Created       = Format-Utc $p.CreatedDateTime
        Modified      = Format-Utc $p.ModifiedDateTime
        Id            = $p.Id
    }
}
$policyDetails = @($policyDetails)

# Any reference that could not be resolved is a finding: usually a deleted user or group
foreach ($d in $policyDetails) {
    foreach ($prop in $d.PSObject.Properties) {
        if ("$($prop.Value)" -match '\[UNRESOLVED') {
            Add-Finding -Severity 'Medium' -Check 'Targeting' -Policy $d.Policy `
                -Finding "$($prop.Name) references an object that could not be resolved (deleted object or missing permission)."
        }
    }
}

# Print one block per policy, skipping empty lines so each block shows only what is configured
Write-Host "`n=== Check 2: Policy targeting ===" -ForegroundColor Cyan
foreach ($d in ($policyDetails | Sort-Object Policy)) {
    Write-Host "`n--- $($d.Policy) [$($d.State)]" -ForegroundColor White
    $lines = [ordered]@{
        'Include users'  = $d.IncludeUsers
        'Include groups' = $d.IncludeGroups
        'Include roles'  = $d.IncludeRoles
        'Include guests' = $d.IncludeGuests
        'Exclude users'  = $d.ExcludeUsers
        'Exclude groups' = $d.ExcludeGroups
        'Exclude roles'  = $d.ExcludeRoles
        'Exclude guests' = $d.ExcludeGuests
        'Include apps'   = $d.IncludeApps
        'Exclude apps'   = $d.ExcludeApps
        'User actions'   = $d.UserActions
        'Platforms'      = $d.Platforms
        'Locations'      = $d.Locations
        'Client apps'    = $d.ClientApps
        'Sign-in risk'   = $d.SignInRisk
        'User risk'      = $d.UserRisk
        'Grant'          = $d.Grant
    }
    foreach ($k in $lines.Keys) {
        if ($lines[$k]) { Write-Host ("  {0,-15} {1}" -f "$($k):", $lines[$k]) }
    }
}

#endregion

#region Check 3: Exclusions -------------------------------------------------------

# Every exclusion on its own row. Excluded groups are expanded so the report shows
# who is actually excluded, and empty or unreadable groups are flagged.
$exclusions = foreach ($p in $policies) {
    $u     = $p.Conditions.Users
    $state = $StateLabels[$p.State] ?? $p.State

    foreach ($id in @($u.ExcludeUsers | Where-Object { $_ })) {
        [PSCustomObject]@{ Policy = $p.DisplayName; State = $state; Type = 'User'
                           Name = Resolve-ObjectName -Id $id -Type 'User'; Detail = '' }
    }

    foreach ($id in @($u.ExcludeGroups | Where-Object { $_ })) {
        $groupName = Resolve-ObjectName -Id $id -Type 'Group'
        $members = Get-GroupMembers -GroupId $id
        $detail = if ($null -eq $members)        { 'Membership could not be read' }
                  elseif ($members.Count -eq 0)  { 'EMPTY GROUP' }
                  elseif ($members.Count -le 10) { "$($members.Count) member(s): " + (($members | ForEach-Object { $_.Name }) -join ', ') }
                  else                           { "$($members.Count) members" }

        if ($null -ne $members -and $members.Count -eq 0) {
            Add-Finding -Severity 'Low' -Check 'Exclusions' -Policy $p.DisplayName `
                -Finding "Excluded group '$groupName' is empty. Likely a stale exception; confirm whether it is still needed."
        }

        [PSCustomObject]@{ Policy = $p.DisplayName; State = $state; Type = 'Group'
                           Name = $groupName; Detail = $detail }
    }

    foreach ($id in @($u.ExcludeRoles | Where-Object { $_ })) {
        [PSCustomObject]@{ Policy = $p.DisplayName; State = $state; Type = 'Role'
                           Name = Resolve-ObjectName -Id $id -Type 'Role'; Detail = 'Everyone holding this role' }
    }

    if ($u.ExcludeGuestsOrExternalUsers.GuestOrExternalUserTypes) {
        [PSCustomObject]@{ Policy = $p.DisplayName; State = $state; Type = 'Guests'
                           Name = $u.ExcludeGuestsOrExternalUsers.GuestOrExternalUserTypes; Detail = '' }
    }

    foreach ($id in @($p.Conditions.Applications.ExcludeApplications | Where-Object { $_ })) {
        [PSCustomObject]@{ Policy = $p.DisplayName; State = $state; Type = 'App'
                           Name = Resolve-ObjectName -Id $id -Type 'App'; Detail = '' }
    }

    if ($p.Conditions.Locations) {
        foreach ($id in @($p.Conditions.Locations.ExcludeLocations | Where-Object { $_ })) {
            [PSCustomObject]@{ Policy = $p.DisplayName; State = $state; Type = 'Location'
                               Name = Resolve-ObjectName -Id $id -Type 'Location'; Detail = '' }
        }
    }
}
$exclusions = @($exclusions)

Write-Host "`n=== Check 3: Exclusions ===" -ForegroundColor Cyan
if ($exclusions.Count -eq 0) {
    Write-Host "  No exclusions found in any policy."
}
else {
    $exclusions | Sort-Object Policy, Type | Format-Table Policy, State, Type, Name, Detail -AutoSize -Wrap | Out-Host
}

#endregion

#region Check 4: Break-glass exclusions -------------------------------------------

# Emergency access accounts must be excluded from every policy that targets them.
# A missed exclusion is how an organization locks itself out of its own tenant.
Write-Host "`n=== Check 4: Break-glass exclusions ===" -ForegroundColor Cyan

$activePolicies    = @($policies | Where-Object { $_.State -in 'enabled', 'enabledForReportingButNotEnforced' })
$bgUsers           = @()
$breakGlassResults = @()

if ($BreakGlassUpn.Count -eq 0) {
    Write-Host "  No -BreakGlassUpn provided. Looking for likely emergency access accounts instead." -ForegroundColor Yellow
    Add-Finding -Severity 'Info' -Check 'Break-glass' `
        -Finding 'No break-glass accounts were specified. Rerun with -BreakGlassUpn to verify their exclusions.'

    # Heuristic: in an inherited tenant you may not know which accounts are break-glass.
    # Accounts excluded from at least half of the active policies are good candidates.
    if ($activePolicies.Count -gt 0 -and $allUsers.Count -gt 0) {
        $threshold = [math]::Ceiling($activePolicies.Count / 2)
        $candidates = foreach ($usr in $allUsers) {
            $excludedCount = @($activePolicies | Where-Object { (Get-PolicyScope -Policy $_ -UserId $usr.Id).Result -eq 'Excluded' }).Count
            if ($excludedCount -ge $threshold) {
                [PSCustomObject]@{
                    User         = "$($usr.DisplayName) ($($usr.UserPrincipalName))"
                    ExcludedFrom = "$excludedCount of $($activePolicies.Count) active policies"
                }
            }
        }
        if (@($candidates).Count -gt 0) {
            Write-Host "  Users excluded from at least half of the active policies (possible break-glass accounts):"
            $candidates | Format-Table -AutoSize | Out-Host
        }
        else {
            Write-Host "  No likely candidates found."
        }
    }
}
else {
    # Resolve each UPN. A break-glass UPN that does not exist is itself a finding.
    $bgUsers = @(foreach ($upn in $BreakGlassUpn) {
        $usr = $null
        try {
            $usr = Get-MgUser -Filter "userPrincipalName eq '$upn'" -Property id, displayName, userPrincipalName -ErrorAction Stop |
                   Select-Object -First 1
        }
        catch { $usr = $null }

        if (-not $usr) {
            Write-Warning "Break-glass account not found: $upn"
            Add-Finding -Severity 'Medium' -Check 'Break-glass' -Finding "Break-glass account $upn was not found in the tenant."
            continue
        }
        $usr
    })

    $breakGlassResults = @(foreach ($bg in $bgUsers) {
        foreach ($p in $policies) {
            $scope = Get-PolicyScope -Policy $p -UserId $bg.Id
            $state = $StateLabels[$p.State] ?? $p.State

            $status = switch ($scope.Result) {
                'Excluded'   { 'OK: excluded' }
                'NotInScope' { 'OK: not targeted' }
                'Unknown'    { 'UNKNOWN' }
                default      { 'NOT EXCLUDED' }
            }

            if ($scope.Result -eq 'Included') {
                # Severity depends on whether the policy is enforcing today
                $severity = switch ($p.State) {
                    'enabled'                           { 'High' }
                    'enabledForReportingButNotEnforced' { 'Medium' }
                    default                             { 'Low' }
                }
                $impact = switch ($p.State) {
                    'enabled'                           { 'This applies now.' }
                    'enabledForReportingButNotEnforced' { 'This will apply if the policy is promoted to On.' }
                    default                             { 'This will apply if the policy is turned on.' }
                }
                Add-Finding -Severity $severity -Check 'Break-glass' -Policy $p.DisplayName `
                    -Finding "$($bg.UserPrincipalName) is targeted and not excluded ($($scope.Via)). $impact"
            }
            elseif ($scope.Result -eq 'Unknown') {
                Add-Finding -Severity 'Medium' -Check 'Break-glass' -Policy $p.DisplayName `
                    -Finding "Could not confirm whether $($bg.UserPrincipalName) is excluded: $($scope.Via)."
            }

            [PSCustomObject]@{
                Account = $bg.UserPrincipalName
                Policy  = $p.DisplayName
                State   = $state
                Status  = $status
                Via     = $scope.Via
            }
        }
    })

    if ($breakGlassResults.Count -gt 0) {
        $breakGlassResults | Sort-Object Account, Policy | Format-Table Account, Policy, State, Status, Via -AutoSize -Wrap | Out-Host
    }
}

#endregion

#region Check 5: MFA coverage -----------------------------------------------------

# Conditional Access is default-allow: a user or app that no policy targets has no
# MFA requirement at all. This check looks for those gaps.
Write-Host "`n=== Check 5: MFA coverage ===" -ForegroundColor Cyan
Write-Host "  Security Defaults: $securityDefaults"
Write-Host "  Only enabled policies count. Report-only and Off policies enforce nothing."

$mfaPolicies = @(foreach ($p in $policies) {
    $cov = Get-MfaCoverage -Policy $p
    if ($cov) {
        [PSCustomObject]@{ Policy = $p; Name = $p.DisplayName; Type = $cov.Type; Reasons = $cov.Reasons }
    }
})

# --- 5a: Applications ---
Write-Host "`n  Applications" -ForegroundColor White

$allUsersAllApps = @($mfaPolicies | Where-Object {
    (@($_.Policy.Conditions.Applications.IncludeApplications) -contains 'All') -and
    (@($_.Policy.Conditions.Users.IncludeUsers) -contains 'All')
})
$appScoped = @($mfaPolicies | Where-Object { @($_.Policy.Conditions.Applications.IncludeApplications) -notcontains 'All' })

if ($allUsersAllApps.Count -gt 0) {
    Write-Host "    Enabled MFA policies targeting all users and all resources: $(($allUsersAllApps.Name) -join ', ')"
}
else {
    Write-Host "    No enabled MFA policy targets all users and all resources." -ForegroundColor Yellow
    Add-Finding -Severity 'High' -Check 'MFA coverage' `
        -Finding "No enabled policy requires MFA for all users across all resources. Security Defaults: $securityDefaults."
}

foreach ($mp in $appScoped) {
    Write-Host "    App-scoped MFA policy: $($mp.Name) ($($mp.Reasons))"
}

foreach ($mp in $mfaPolicies) {
    foreach ($id in @($mp.Policy.Conditions.Applications.ExcludeApplications | Where-Object { $_ })) {
        $appName = Resolve-ObjectName -Id $id -Type 'App'
        Write-Host "    Excluded from MFA by $($mp.Name): $appName" -ForegroundColor Yellow
        Add-Finding -Severity 'Medium' -Check 'MFA coverage' -Policy $mp.Name `
            -Finding "App '$appName' is excluded from this MFA policy."
    }
}

# --- 5b: Users ---
Write-Host "`n  Users" -ForegroundColor White
$coverage = @()

if ($allUsers.Count -eq 0) {
    Write-Host "    User list unavailable. Per-user coverage skipped."
}
else {
    $bgIds = @($bgUsers | ForEach-Object { $_.Id })

    $coverage = @(foreach ($usr in $allUsers) {
        $full    = @()
        $partial = @()

        foreach ($mp in $mfaPolicies) {
            $scope = Get-PolicyScope -Policy $mp.Policy -UserId $usr.Id
            if ($scope.Result -ne 'Included') { continue }
            if ($mp.Type -eq 'Full') { $full += $mp.Name }
            else                     { $partial += "$($mp.Name) [$($mp.Reasons)]" }
        }

        $isBreakGlass = $bgIds -contains $usr.Id
        $status = if ($full.Count -gt 0)        { 'Covered' }
                  elseif ($partial.Count -gt 0) { 'Partial' }
                  elseif ($isBreakGlass)        { 'Not covered (break-glass, expected)' }
                  else                          { 'NOT COVERED' }

        [PSCustomObject]@{
            User            = $usr.DisplayName
            UPN             = $usr.UserPrincipalName
            Status          = $status
            FullCoverage    = $full -join '; '
            PartialCoverage = $partial -join '; '
        }
    })

    $covered    = @($coverage | Where-Object { $_.Status -eq 'Covered' })
    $partialAll = @($coverage | Where-Object { $_.Status -eq 'Partial' })
    $notCovered = @($coverage | Where-Object { $_.Status -eq 'NOT COVERED' })
    $bgExpected = @($coverage | Where-Object { $_.Status -like '*break-glass*' })

    Write-Host ("    Covered: {0}   Partial: {1}   Not covered: {2}   Break-glass (expected): {3}" -f `
        $covered.Count, $partialAll.Count, $notCovered.Count, $bgExpected.Count)

    $gaps = @($coverage | Where-Object { $_.Status -ne 'Covered' })
    if ($gaps.Count -gt 0) {
        $gaps | Sort-Object Status, User | Format-Table User, Status, PartialCoverage -AutoSize -Wrap | Out-Host
    }

    if ($notCovered.Count -gt 0) {
        $names = ($notCovered | Select-Object -First 10 | ForEach-Object { $_.User }) -join ', '
        $more  = if ($notCovered.Count -gt 10) { " and $($notCovered.Count - 10) more (see export)" } else { '' }
        Add-Finding -Severity 'High' -Check 'MFA coverage' `
            -Finding "$($notCovered.Count) user(s) are not targeted by any enabled MFA policy: $names$more."
    }
    if ($partialAll.Count -gt 0) {
        $names = ($partialAll | Select-Object -First 10 | ForEach-Object { "$($_.User) via $($_.PartialCoverage)" }) -join '; '
        Add-Finding -Severity 'Medium' -Check 'MFA coverage' `
            -Finding "$($partialAll.Count) user(s) have MFA only for specific apps or under conditions: $names."
    }
}

#endregion

#region Check 6: Report-only and disabled policies --------------------------------

# Report-only policies log what they would do but enforce nothing. In an inherited
# tenant they are often rollouts that stalled. Graph does not expose when a policy's
# state last changed, so the last-modified date is used as the closest indicator.
Write-Host "`n=== Check 6: Report-only and disabled policies ===" -ForegroundColor Cyan

$nowUtc = (Get-Date).ToUniversalTime()
$notEnforced = @($policies | Where-Object { $_.State -in 'enabledForReportingButNotEnforced', 'disabled' })

$notEnforcedRows = @(foreach ($p in $notEnforced) {
    $ref  = $p.ModifiedDateTime ?? $p.CreatedDateTime
    $days = if ($ref) { [int][math]::Floor(($nowUtc - [datetime]$ref).TotalDays) } else { $null }
    $state = $StateLabels[$p.State] ?? $p.State

    if ($p.State -eq 'enabledForReportingButNotEnforced') {
        Add-Finding -Severity 'Medium' -Check 'Report-only' -Policy $p.DisplayName `
            -Finding "Policy is report-only and enforces nothing. Last changed $days day(s) ago. Review sign-in logs and decide whether to promote it."
    }
    else {
        Add-Finding -Severity 'Low' -Check 'Report-only' -Policy $p.DisplayName `
            -Finding "Policy is Off. Last changed $days day(s) ago. Confirm whether it is still needed or should be removed."
    }

    [PSCustomObject]@{
        Policy             = $p.DisplayName
        State              = $state
        Created            = Format-Utc $p.CreatedDateTime
        LastModified       = Format-Utc $p.ModifiedDateTime
        DaysSinceLastChange = $days
    }
})

if ($notEnforcedRows.Count -eq 0) {
    Write-Host "  All policies are enforced."
}
else {
    $notEnforcedRows | Sort-Object State, Policy | Format-Table -AutoSize | Out-Host
}

#endregion

#region Check 7: Legacy authentication blocking -----------------------------------

# Legacy protocols cannot perform MFA, so an attacker with a password can use them
# to bypass MFA policies entirely. A block needs to cover both legacy client types.
Write-Host "`n=== Check 7: Legacy authentication blocking ===" -ForegroundColor Cyan

$legacyPolicies = @(foreach ($p in $policies) {
    $types  = @($p.Conditions.ClientAppTypes | Where-Object { $_ })
    $blocks = @($p.GrantControls.BuiltInControls) -contains 'block'
    $eas    = ($types -contains 'exchangeActiveSync') -or ($types -contains 'easSupported')
    $other  = $types -contains 'other'

    if ($blocks -and ($eas -or $other)) {
        [PSCustomObject]@{
            Policy       = $p.DisplayName
            State        = $StateLabels[$p.State] ?? $p.State
            RawState     = $p.State
            CoversEAS    = $eas
            CoversOther  = $other
            AllUsers     = @($p.Conditions.Users.IncludeUsers) -contains 'All'
            AllResources = @($p.Conditions.Applications.IncludeApplications) -contains 'All'
        }
    }
})

$fullEnforced = @($legacyPolicies | Where-Object {
    $_.RawState -eq 'enabled' -and $_.CoversEAS -and $_.CoversOther -and $_.AllUsers -and $_.AllResources
})
$anyEnforced    = @($legacyPolicies | Where-Object { $_.RawState -eq 'enabled' })
$reportOnlyOnly = @($legacyPolicies | Where-Object { $_.RawState -eq 'enabledForReportingButNotEnforced' })

if ($fullEnforced.Count -gt 0) {
    Write-Host "  PRESENT and enforced: $(($fullEnforced.Policy) -join ', ')" -ForegroundColor Green
}
elseif ($anyEnforced.Count -gt 0) {
    Write-Host "  PARTIAL: enforced, but not for all users, all resources, and both legacy client types." -ForegroundColor Yellow
    Add-Finding -Severity 'Medium' -Check 'Legacy auth' -Policy (($anyEnforced.Policy) -join ', ') `
        -Finding 'Legacy authentication is blocked only partially (scope or client types are narrowed).'
}
elseif ($reportOnlyOnly.Count -gt 0) {
    Write-Host "  NOT ENFORCED: a legacy auth block exists only in report-only." -ForegroundColor Yellow
    Add-Finding -Severity 'High' -Check 'Legacy auth' -Policy (($reportOnlyOnly.Policy) -join ', ') `
        -Finding 'Legacy authentication block exists but is report-only, so legacy protocols are still allowed.'
}
else {
    Write-Host "  ABSENT: no policy blocks legacy authentication." -ForegroundColor Red
    Add-Finding -Severity 'High' -Check 'Legacy auth' `
        -Finding 'No policy blocks legacy authentication. Legacy protocols can bypass MFA.'
}

if ($legacyPolicies.Count -gt 0) {
    $legacyPolicies | Format-Table Policy, State, CoversEAS, CoversOther, AllUsers, AllResources -AutoSize | Out-Host
}

#endregion

#region Summary -------------------------------------------------------------------

Write-Host "`n=== Findings summary ===" -ForegroundColor Cyan

$sortedFindings = @($Findings | Sort-Object { $SeverityOrder[$_.Severity] }, Check, Policy)

if ($sortedFindings.Count -eq 0) {
    Write-Host "  No findings."
}
else {
    $counts = foreach ($sev in 'High', 'Medium', 'Low', 'Info') {
        $n = @($sortedFindings | Where-Object { $_.Severity -eq $sev }).Count
        if ($n -gt 0) { "$($sev): $n" }
    }
    Write-Host "  $($counts -join '   ')"
    $sortedFindings | Format-Table Severity, Check, Policy, Finding -AutoSize -Wrap | Out-Host
}

#endregion

#region Export --------------------------------------------------------------------

# CSVs for spreadsheet review, plus one JSON file with everything for scripting or diffing.
try {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmm')
    $base  = Join-Path $OutputPath "CAAudit-$stamp"

    $policyDetails  | Export-Csv "$base-policies.csv" -NoTypeInformation -Encoding utf8
    $sortedFindings | Export-Csv "$base-findings.csv" -NoTypeInformation -Encoding utf8
    if ($exclusions.Count -gt 0)        { $exclusions        | Export-Csv "$base-exclusions.csv"   -NoTypeInformation -Encoding utf8 }
    if ($breakGlassResults.Count -gt 0) { $breakGlassResults | Export-Csv "$base-breakglass.csv"   -NoTypeInformation -Encoding utf8 }
    if ($coverage.Count -gt 0)          { $coverage          | Export-Csv "$base-mfa-coverage.csv" -NoTypeInformation -Encoding utf8 }

    $report = [ordered]@{
        GeneratedUtc     = $nowUtc.ToString('o')
        TenantId         = $context.TenantId
        RunAs            = $context.Account
        SecurityDefaults = $securityDefaults
        PolicyCount      = $policies.Count
        Findings         = $sortedFindings
        Policies         = $policyDetails
        Exclusions       = $exclusions
        BreakGlass       = $breakGlassResults
        MfaCoverage      = $coverage
        LegacyAuth       = $legacyPolicies
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content "$base-report.json" -Encoding utf8

    Write-Host "`nExports written to $((Resolve-Path $OutputPath).Path) with prefix CAAudit-$stamp" -ForegroundColor Cyan
}
catch {
    Write-Warning "Export failed: $($_.Exception.Message). Console results above are still valid."
}

#endregion