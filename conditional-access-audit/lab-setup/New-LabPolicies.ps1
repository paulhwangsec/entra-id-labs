<#
.SYNOPSIS
    Creates deliberately flawed Conditional Access policies for the entra-ca-audit lab.

.DESCRIPTION
    Lab setup only. Builds an "inherited" CA environment with planted problems
    so the audit tool has real findings to report. Safe to re-run: policies and
    the named location are skipped if they already exist.

    Requires: Connect-MgGraph with Policy.ReadWrite.ConditionalAccess,
    Policy.Read.All, Application.Read.All, Group.ReadWrite.All, User.ReadWrite.All.
    This is NOT part of the audit tool. The audit tool is read-only.

    Run New-LabUsers.ps1 and New-LabGroups.ps1 first.
.NOTES
    Written with AI assistance (Anthropic Claude). Reviewed, tested, and run
    by Paul Hwang in a Microsoft 365 trial lab tenant. Lab work, not production.
#>

$context = Get-MgContext
if (-not $context) {
    Write-Error "Not connected to Microsoft Graph. Run Connect-MgGraph first."
    return
}
$domain = ($context.Account -split '@')[1]
Write-Host "Creating lab CA policies in tenant: $domain" -ForegroundColor Cyan

# --- Look up the object IDs the policies reference ------------------------------

function Get-GroupId ($name) {
    $g = Get-MgGroup -Filter "displayName eq '$name'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $g) { throw "Group '$name' not found. Run New-LabGroups.ps1 first." }
    return $g.Id
}

try {
    $grpEmergency = Get-GroupId "SG-Emergency-Access"
    $grpExempt    = Get-GroupId "SG-MFA-Exempt"
    $grpPilot     = Get-GroupId "SG-CA-Pilot"
    $grpLegacy    = Get-GroupId "SG-Legacy-Auth-Exceptions"

    $bg01 = Get-MgUser -Filter "userPrincipalName eq 'bg-admin01@$domain'" -ErrorAction Stop
    if (-not $bg01) { throw "bg-admin01 not found." }
}
catch {
    Write-Error $_.Exception.Message
    return
}

# --- Named location for CA007 ------------------------------------------------------

$locName  = "Allowed-Countries-US"
$location = Get-MgIdentityConditionalAccessNamedLocation -All |
            Where-Object { $_.DisplayName -eq $locName } | Select-Object -First 1

if ($location) {
    Write-Host "  SKIP    Named location $locName (already exists)" -ForegroundColor Yellow
}
else {
    $location = New-MgIdentityConditionalAccessNamedLocation -BodyParameter @{
        "@odata.type"                     = "#microsoft.graph.countryNamedLocation"
        displayName                       = $locName
        countriesAndRegions               = @("US")
        includeUnknownCountriesAndRegions = $false
    }
    Write-Host "  CREATED Named location $locName" -ForegroundColor Green
    Start-Sleep -Seconds 5   # Give the location a moment to propagate before policies reference it
}

# --- Policy definitions --------------------------------------------------------------
# State values in Graph: enabled, disabled, enabledForReportingButNotEnforced (report-only)

$policies = @(

    # CA002: MFA for everyone, but a vendor exemption group is excluded (coverage gap).
    # Break-glass is excluded through a GROUP here, not directly.
    @{
        displayName   = "CA002-Require-MFA-AllUsers"
        state         = "enabled"
        conditions    = @{
            users          = @{ includeUsers = @("All"); excludeGroups = @($grpEmergency, $grpExempt) }
            applications   = @{ includeApplications = @("All") }
            clientAppTypes = @("all")
        }
        grantControls = @{ operator = "OR"; builtInControls = @("mfa") }
    }

    # CA003: Legacy auth block left in report-only. Excludes an empty exceptions group.
    @{
        displayName   = "CA003-Block-Legacy-Auth"
        state         = "enabledForReportingButNotEnforced"
        conditions    = @{
            users          = @{ includeUsers = @("All"); excludeGroups = @($grpEmergency, $grpLegacy) }
            applications   = @{ includeApplications = @("All") }
            clientAppTypes = @("exchangeActiveSync", "other")
        }
        grantControls = @{ operator = "OR"; builtInControls = @("block") }
    }

    # CA004: Block high sign-in risk. Excludes bg-admin01 directly but FORGETS bg-admin02.
    @{
        displayName   = "CA004-Block-High-SignIn-Risk"
        state         = "enabled"
        conditions    = @{
            users            = @{ includeUsers = @("All"); excludeUsers = @($bg01.Id) }
            applications     = @{ includeApplications = @("All") }
            signInRiskLevels = @("high")
            clientAppTypes   = @("all")
        }
        grantControls = @{ operator = "OR"; builtInControls = @("block") }
    }

    # CA005: Compliant device requirement, switched off and abandoned.
    @{
        displayName   = "CA005-Require-Compliant-Device"
        state         = "disabled"
        conditions    = @{
            users          = @{ includeUsers = @("All"); excludeGroups = @($grpEmergency) }
            applications   = @{ includeApplications = @("All") }
            clientAppTypes = @("all")
        }
        grantControls = @{ operator = "OR"; builtInControls = @("compliantDevice") }
    }

    # CA006: MFA scoped to Office 365 only. Combined with CA002's exemption,
    # SG-MFA-Exempt members get MFA for Office 365 and nothing else.
    @{
        displayName   = "CA006-MFA-Office365-Only"
        state         = "enabled"
        conditions    = @{
            users          = @{ includeUsers = @("All"); excludeGroups = @($grpEmergency) }
            applications   = @{ includeApplications = @("Office365") }
            clientAppTypes = @("all")
        }
        grantControls = @{ operator = "OR"; builtInControls = @("mfa") }
    }

    # CA007: Block mobile access from outside the US, pilot group only, report-only.
    # Exercises location, platform, and client app condition parsing.
    @{
        displayName   = "CA007-Block-Mobile-Outside-US"
        state         = "enabledForReportingButNotEnforced"
        conditions    = @{
            users          = @{ includeGroups = @($grpPilot) }
            applications   = @{ includeApplications = @("All") }
            locations      = @{ includeLocations = @("All"); excludeLocations = @($location.Id) }
            platforms      = @{ includePlatforms = @("android", "iOS") }
            clientAppTypes = @("browser", "mobileAppsAndDesktopClients")
        }
        grantControls = @{ operator = "OR"; builtInControls = @("block") }
    }
)

# --- Create policies, skipping any that already exist ------------------------------

$existingNames = @(Get-MgIdentityConditionalAccessPolicy -All | ForEach-Object { $_.DisplayName })

foreach ($p in $policies) {
    if ($existingNames -contains $p.displayName) {
        Write-Host "  SKIP    $($p.displayName) (already exists)" -ForegroundColor Yellow
        continue
    }
    try {
        New-MgIdentityConditionalAccessPolicy -BodyParameter $p -ErrorAction Stop | Out-Null
        Write-Host "  CREATED $($p.displayName)  [$($p.state)]" -ForegroundColor Green
    }
    catch {
        Write-Host "  FAILED  $($p.displayName) : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "Done." -ForegroundColor Cyan