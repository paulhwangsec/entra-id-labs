#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Creates attribute-driven dynamic membership groups for the provisioning lab.

.DESCRIPTION
    Lab setup only. Two parts:

    1. Copies each user's employeeType into onPremisesExtensionAttributes.extensionAttribute1.
       employeeType is not a supported property in dynamic membership rules, so the
       rules use the extension attribute instead. This mirrors hybrid environments,
       where attributes like employee type are often synced from on-premises AD
       into an extension attribute.

    2. Creates four dynamic security groups, including one with a compound rule.

    Safe to re-run: attributes already set and groups that already exist are skipped.

    Requires: Connect-MgGraph with User.ReadWrite.All and Group.ReadWrite.All.

.NOTES
    Written with AI assistance (Anthropic Claude). Reviewed, tested, and run
    by Paul Hwang in a Microsoft 365 trial lab tenant. Lab work, not production.
#>

$context = Get-MgContext
if (-not $context) {
    Write-Error "Not connected to Microsoft Graph. Run Connect-MgGraph first."
    return
}
Write-Host "Provisioning lab setup in tenant: $($context.TenantId)" -ForegroundColor Cyan

#region Part 1: Copy employeeType into extensionAttribute1 -------------------------

Write-Host "`nPart 1: Setting extensionAttribute1 from employeeType" -ForegroundColor Cyan

try {
    $users = @(Get-MgUser -All -Property id, displayName, userPrincipalName, employeeType, onPremisesExtensionAttributes -ErrorAction Stop)
}
catch {
    Write-Error "Could not read users: $($_.Exception.Message)"
    return
}

foreach ($u in $users) {
    # Users without an employee type (admin and break-glass accounts) are left alone
    if (-not $u.EmployeeType) { continue }

    $current = $u.OnPremisesExtensionAttributes.ExtensionAttribute1
    if ($current -eq $u.EmployeeType) {
        Write-Host "  SKIP    $($u.UserPrincipalName) (already '$current')" -ForegroundColor Yellow
        continue
    }

    try {
        # Only writable this way for cloud-only users. For synced users it comes from on-premises AD.
        Update-MgUser -UserId $u.Id -BodyParameter @{
            onPremisesExtensionAttributes = @{ extensionAttribute1 = $u.EmployeeType }
        } -ErrorAction Stop
        Write-Host "  SET     $($u.UserPrincipalName) -> extensionAttribute1 = '$($u.EmployeeType)'" -ForegroundColor Green
    }
    catch {
        Write-Host "  FAILED  $($u.UserPrincipalName) : $($_.Exception.Message)" -ForegroundColor Red
    }
}

#endregion

#region Part 2: Create dynamic groups ----------------------------------------------

Write-Host "`nPart 2: Creating dynamic groups" -ForegroundColor Cyan

$dynamicGroups = @(
    @{
        Name = "DG-Dept-Plant-Operations"
        Desc = "All users in the Plant Operations department."
        Rule = '(user.department -eq "Plant Operations")'
    }
    @{
        Name = "DG-Location-Salt-Lake-City"
        Desc = "All users based in Salt Lake City."
        Rule = '(user.city -eq "Salt Lake City")'
    }
    @{
        Name = "DG-Contractors"
        Desc = "All contractors, by employee type in extensionAttribute1."
        Rule = '(user.extensionAttribute1 -eq "Contractor")'
    }
    @{
        # Compound rule. Used for group-based licensing: disabled accounts drop out automatically.
        Name = "DG-All-Employees-Licensed"
        Desc = "Enabled US employees. Receives the Microsoft 365 license through group-based licensing."
        Rule = '(user.extensionAttribute1 -eq "Employee") -and (user.usageLocation -eq "US") -and (user.accountEnabled -eq true)'
    }
)

foreach ($g in $dynamicGroups) {
    $existing = Get-MgGroup -Filter "displayName eq '$($g.Name)'" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existing) {
        Write-Host "  SKIP    $($g.Name) (already exists)" -ForegroundColor Yellow
        continue
    }

    try {
        New-MgGroup -DisplayName $g.Name `
                    -Description $g.Desc `
                    -MailEnabled:$false `
                    -SecurityEnabled:$true `
                    -MailNickname ($g.Name -replace '[^a-zA-Z0-9]', '') `
                    -GroupTypes @('DynamicMembership') `
                    -MembershipRule $g.Rule `
                    -MembershipRuleProcessingState 'On' `
                    -ErrorAction Stop | Out-Null
        Write-Host "  CREATED $($g.Name)" -ForegroundColor Green
        Write-Host "          Rule: $($g.Rule)"
    }
    catch {
        Write-Host "  FAILED  $($g.Name) : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`nDone. Dynamic membership can take several minutes to populate." -ForegroundColor Cyan

#endregion
