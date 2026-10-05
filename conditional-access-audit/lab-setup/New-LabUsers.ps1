<#
.SYNOPSIS
    Creates test users for the entra-ca-audit lab environment.

.DESCRIPTION
    Lab setup only. Creates 8 cloud-only users with realistic attributes
    (department, job title, location, employee type) so Conditional Access
    policies have meaningful targets. Safe to re-run: existing users are skipped.

    Requires: Connect-MgGraph with User.ReadWrite.All.
    This is NOT part of the audit tool. The audit tool is read-only.
.NOTES
    Written with AI assistance (Anthropic Claude). Reviewed, tested, and run
    by Paul Hwang in a Microsoft 365 trial lab tenant. Lab work, not production.
#>

# Confirm we're connected before doing anything
$context = Get-MgContext
if (-not $context) {
    Write-Error "Not connected to Microsoft Graph. Run Connect-MgGraph first."
    return
}

# Tenant domain is derived from the signed-in account, so nothing is hardcoded
$domain = ($context.Account -split '@')[1]
Write-Host "Creating lab users in tenant: $domain" -ForegroundColor Cyan

# One password for all lab users, entered at runtime so it never lives in the script
$securePassword = Read-Host "Enter a password for all lab users" -AsSecureString
$plainPassword  = ConvertFrom-SecureString -SecureString $securePassword -AsPlainText

# Test user definitions: a small manufacturing org
$labUsers = @(
    @{ First = "Maria";  Last = "Lopez";  Dept = "Plant Operations"; Title = "Production Supervisor";  City = "Portland";       Type = "Employee"   }
    @{ First = "James";  Last = "Carter"; Dept = "Plant Operations"; Title = "Machine Operator";       City = "Portland";       Type = "Employee"   }
    @{ First = "Aisha";  Last = "Khan";   Dept = "Finance";          Title = "Accountant";             City = "Salt Lake City"; Type = "Employee"   }
    @{ First = "Derek";  Last = "Nguyen"; Dept = "IT";               Title = "Systems Administrator";  City = "Salt Lake City"; Type = "Employee"   }
    @{ First = "Sarah";  Last = "Kim";    Dept = "Human Resources";  Title = "HR Generalist";          City = "Salt Lake City"; Type = "Employee"   }
    @{ First = "Tom";    Last = "Becker"; Dept = "Maintenance";      Title = "Maintenance Technician"; City = "Spokane";        Type = "Contractor" }
    @{ First = "Linda";  Last = "Park";   Dept = "Sales";            Title = "Account Manager";        City = "Spokane";        Type = "Employee"   }
    @{ First = "Raj";    Last = "Patel";  Dept = "Engineering";      Title = "Process Engineer";       City = "Portland";       Type = "Contractor" }
)

foreach ($u in $labUsers) {
    $alias = "$($u.First).$($u.Last)".ToLower()
    $upn   = "$alias@$domain"

    # Skip users that already exist so the script can be re-run safely
    $existing = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  SKIP    $upn (already exists)" -ForegroundColor Yellow
        continue
    }

    $params = @{
        AccountEnabled    = $true
        DisplayName       = "$($u.First) $($u.Last)"
        GivenName         = $u.First
        Surname           = $u.Last
        UserPrincipalName = $upn
        MailNickname      = $alias
        Department        = $u.Dept
        JobTitle          = $u.Title
        City              = $u.City
        Country           = "United States"
        UsageLocation     = "US"   # Required before any license can be assigned
        EmployeeType      = $u.Type
        CompanyName       = "Lab Manufacturing Co"
        PasswordProfile   = @{
            Password                      = $plainPassword
            ForceChangePasswordNextSignIn = $false   # Lab convenience only
        }
    }

    try {
        New-MgUser @params -ErrorAction Stop | Out-Null
        Write-Host "  CREATED $upn  [$($u.Dept) / $($u.Type)]" -ForegroundColor Green
    }
    catch {
        Write-Host "  FAILED  $upn : $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "Done." -ForegroundColor Cyan