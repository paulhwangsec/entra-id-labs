<#
.SYNOPSIS
    Creates test security groups for the entra-ca-audit lab environment.

.DESCRIPTION
    Lab setup only. Creates 4 security groups and adds members.
    Safe to re-run: existing groups and memberships are skipped.

    Requires: Connect-MgGraph with Group.ReadWrite.All and User.ReadWrite.All.
    This is NOT part of the audit tool. The audit tool is read-only.
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
Write-Host "Creating lab groups in tenant: $domain" -ForegroundColor Cyan

# Group definitions. Members are UPN prefixes; the domain is appended at runtime.
$labGroups = @(
    @{ Name = "SG-Emergency-Access";        Desc = "Break-glass accounts. Exclude from all CA policies.";      Members = @("bg-admin01", "bg-admin02") }
    @{ Name = "SG-MFA-Exempt";              Desc = "Vendor MFA exemption. Approved 2024, review pending.";     Members = @("tom.becker", "raj.patel") }
    @{ Name = "SG-CA-Pilot";                Desc = "Pilot group for CA policy rollout.";                       Members = @("derek.nguyen", "sarah.kim") }
    @{ Name = "SG-Legacy-Auth-Exceptions";  Desc = "Exceptions for legacy authentication. Currently empty.";   Members = @() }
)

foreach ($g in $labGroups) {
    # Find or create the group
    $group = Get-MgGroup -Filter "displayName eq '$($g.Name)'" -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($group) {
        Write-Host "  SKIP    $($g.Name) (already exists)" -ForegroundColor Yellow
    }
    else {
        try {
            $group = New-MgGroup -DisplayName $g.Name `
                                 -Description $g.Desc `
                                 -MailEnabled:$false `
                                 -SecurityEnabled:$true `
                                 -MailNickname ($g.Name -replace '[^a-zA-Z0-9]', '') `
                                 -ErrorAction Stop
            Write-Host "  CREATED $($g.Name)" -ForegroundColor Green
        }
        catch {
            Write-Host "  FAILED  $($g.Name) : $($_.Exception.Message)" -ForegroundColor Red
            continue
        }
    }

    # Current members, so re-runs don't try to add someone twice
    $currentMemberIds = @(Get-MgGroupMember -GroupId $group.Id -All -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })

    foreach ($m in $g.Members) {
        $upn  = "$m@$domain"
        $user = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue

        if (-not $user) {
            Write-Host "    MISSING $upn (user not found)" -ForegroundColor Red
            continue
        }
        if ($currentMemberIds -contains $user.Id) {
            Write-Host "    SKIP    $upn (already a member)" -ForegroundColor Yellow
            continue
        }

        try {
            New-MgGroupMember -GroupId $group.Id -DirectoryObjectId $user.Id -ErrorAction Stop
            Write-Host "    ADDED   $upn" -ForegroundColor Green
        }
        catch {
            Write-Host "    FAILED  $upn : $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host "Done." -ForegroundColor Cyan