# Conditional Access Audit

A read-only PowerShell tool that audits Microsoft Entra Conditional Access configuration and reports what is actually configured, who is excluded, and where the gaps are.

> **Lab work, not production.** This was built and tested in a Microsoft 365 trial tenant with Entra ID P2. It has not been run against a production tenant. The tenant, users, and policies shown here were created for testing.

## The problem

Conditional Access configurations are often built by one person and inherited by someone else. When the original administrator leaves without documentation, the next person has to answer basic questions before they can safely change anything:

- What policies exist, and which ones are actually enforcing?
- Who is excluded, and through which groups?
- Are the emergency access accounts excluded everywhere they need to be?
- Is anyone falling through the gaps with no MFA requirement?

The Entra admin center shows one policy at a time. The problems usually come from how policies interact: a user excluded from one policy and only partly caught by another, or a break-glass account excluded from five policies and forgotten in the sixth. Conditional Access is default-allow, so anything no policy targets is simply allowed.

This tool reads every policy, resolves IDs to names, expands group membership, and evaluates the configuration as a whole.

## What it checks

| # | Check | What it reports | Why it matters |
|---|---|---|---|
| 1 | Policy inventory | Name, state (On, Report-only, Off), created and modified dates | Baseline of what exists |
| 2 | Policy targeting | Users, groups, roles, guests, apps, platforms, locations, client apps, risk levels, grant controls, all resolved to readable names | The portal shows this one policy at a time; this shows all of it |
| 3 | Exclusions | Every exclusion on its own row, with excluded groups expanded to their members | Exclusions are where gaps hide; empty excluded groups are flagged as likely stale exceptions |
| 4 | Break-glass exclusions | Whether each emergency access account is excluded from every policy that targets it, directly or through group or role membership | A missed exclusion is how an organization locks itself out of its own tenant |
| 5 | MFA coverage | Every user classified as Covered, Partial, or Not covered by enabled MFA policies; app-scoped MFA policies and excluded apps | Default-allow means an untargeted user has no MFA requirement |
| 6 | Report-only and Off policies | Policies that enforce nothing, with days since last change | Report-only policies are often rollouts that stalled |
| 7 | Legacy authentication | Whether legacy auth is blocked, and whether the block is enforced and complete | Legacy protocols cannot do MFA and can be used to bypass it |

Every check adds findings to a single summary, rated High, Medium, Low, or Info.

## Sample output

From a run against the lab tenant. The lab was built with specific problems planted in it (see [The lab environment](#the-lab-environment)).

```
=== Findings summary ===
  High: 2   Medium: 3   Low: 2

Severity Check        Policy                         Finding
-------- -----        ------                         -------
High     Break-glass  CA004-Block-High-SignIn-Risk   bg-admin02@paulhwangsec.onmicrosoft.com is targeted and not excluded (All
                                                     users). This applies now.
High     Legacy auth  CA003-Block-Legacy-Auth        Legacy authentication block exists but is report-only, so legacy protocols are
                                                     still allowed.
Medium   MFA coverage                                2 user(s) have MFA only for specific apps or under conditions: Raj Patel via
                                                     CA006-MFA-Office365-Only [apps: Office 365 (app group)]; Tom Becker via
                                                     CA006-MFA-Office365-Only [apps: Office 365 (app group)].
Medium   Report-only  CA003-Block-Legacy-Auth        Policy is report-only and enforces nothing. Last changed 0 day(s) ago. Review
                                                     sign-in logs and decide whether to promote it.
Medium   Report-only  CA007-Block-Mobile-Outside-US  Policy is report-only and enforces nothing. Last changed 0 day(s) ago. Review
                                                     sign-in logs and decide whether to promote it.
Low      Exclusions   CA003-Block-Legacy-Auth        Excluded group 'SG-Legacy-Auth-Exceptions' is empty. Likely a stale exception;
                                                     confirm whether it is still needed.
Low      Report-only  CA005-Require-Compliant-Device Policy is Off. Last changed 0 day(s) ago. Confirm whether it is still needed
                                                     or should be removed.
```

Full exports from the same run are in [`sample-output/`](sample-output/). Screenshots of each check are in [`screenshots/`](screenshots/).

## The lab environment

The lab tenant was built to look like an environment someone else configured and left behind. Each policy has a specific problem so that every check has something real to find. The setup scripts are in [`lab-setup/`](lab-setup/) so the environment can be rebuilt.

| Policy | State | Planted problem | Detected by |
|---|---|---|---|
| CA001-Require-MFA-Admins | On | None (clean baseline) | Control case, no findings |
| CA002-Require-MFA-AllUsers | On | Excludes a vendor exemption group with real members | Check 5: two users have only partial MFA |
| CA003-Block-Legacy-Auth | Report-only | Never promoted; excludes an empty group | Checks 3, 6, 7 |
| CA004-Block-High-SignIn-Risk | On | Excludes one break-glass account and forgets the other | Check 4: High |
| CA005-Require-Compliant-Device | Off | Abandoned | Check 6 |
| CA006-MFA-Office365-Only | On | MFA for one app group only | Check 5: the exempt users are covered for Office 365 and nothing else |
| CA007-Block-Mobile-Outside-US | Report-only | Named location, platform, and client app conditions; pilot group only | Checks 2, 6; correctly reported as not targeting break-glass |

Break-glass accounts are excluded directly in some policies and through a group (`SG-Emergency-Access`) in others. The tool has to expand group membership to get Check 4 right, which is the case naive scripts tend to miss.

All 7 planted problems were detected, with no false positives. The break-glass accounts appear in Check 5 as "Not covered (break-glass, expected)" rather than as MFA gaps.

## Requirements

- PowerShell 7
- Microsoft Graph PowerShell SDK modules: `Microsoft.Graph.Authentication`, `Microsoft.Graph.Identity.SignIns`, `Microsoft.Graph.Users`, `Microsoft.Graph.Groups`, `Microsoft.Graph.Applications`, `Microsoft.Graph.Identity.DirectoryManagement`
- An account with a read-only role that can see Conditional Access, such as **Global Reader** or **Security Reader**

### Graph permissions

The script requests only these delegated, read-only scopes:

| Scope | Used for |
|---|---|
| `Policy.Read.All` | Conditional Access policies, named locations, Security Defaults status |
| `User.ReadBasic.All` | Resolving user IDs to names; listing users for coverage analysis |
| `GroupMember.Read.All` | Resolving group names and expanding group membership |
| `RoleManagement.Read.Directory` | Resolving role template IDs to role names and listing role members |
| `Application.Read.All` | Resolving application IDs to app names |

If a scope is missing, the script warns and continues. Anything it cannot resolve is shown as `[UNRESOLVED <type>] <id>` and raised as a finding, rather than crashing.

## Usage

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Applications, Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser

.\Invoke-CAAudit.ps1 -TenantId "contoso.onmicrosoft.com" -BreakGlassUpn "bg-admin01@contoso.onmicrosoft.com","bg-admin02@contoso.onmicrosoft.com"
```

| Parameter | Description |
|---|---|
| `-TenantId` | Tenant to audit. Recommended: without it, a cached account on the workstation can point the sign-in at the wrong tenant (this happened during testing). |
| `-BreakGlassUpn` | Emergency access accounts to verify. If omitted, the script lists users excluded from at least half of the active policies as likely candidates. |
| `-OutputPath` | Export folder. Defaults to `.\sample-output`. |
| `-UseExistingConnection` | Use the current Graph session instead of connecting. Scopes are still checked. |

### Output

Console output for each check and a findings summary, plus these files:

| File | Contents |
|---|---|
| `CAAudit-<timestamp>-findings.csv` | All findings, sorted by severity |
| `CAAudit-<timestamp>-policies.csv` | One row per policy, every condition resolved to names |
| `CAAudit-<timestamp>-exclusions.csv` | One row per exclusion |
| `CAAudit-<timestamp>-breakglass.csv` | Each break-glass account against each policy |
| `CAAudit-<timestamp>-mfa-coverage.csv` | Each user's MFA coverage status |
| `CAAudit-<timestamp>-report.json` | Everything above in one file |

## How it works

A few design decisions that affect the results:

- **Exclusions are evaluated before inclusions**, because that is how Conditional Access works. A user who is both included and excluded is excluded.
- **Group membership is transitive.** Nested groups are expanded. Groups that are members of directory roles are expanded too.
- **An empty group and an unreadable group are different results.** An empty excluded group is a finding. A group the script could not read is reported as Unknown, not guessed.
- **"Full" MFA coverage means** an enabled policy that requires MFA for all resources, with no platform, location, risk, or client app conditions, and where MFA cannot be bypassed by satisfying a different control. With an OR grant such as "MFA or compliant device," a user can skip MFA, so that counts as Partial.
- **Only enabled policies count toward coverage.** Report-only and Off policies enforce nothing.

### Things the Graph data does not make obvious

These came up during testing and are handled in the script:

- **"All client apps" is stored as a single value, `all`.** The portal shows it as "1 included," which reads like one specific client type.
- **The SDK returns an empty guest object even when no guest condition is set.** Checking whether the object exists is always true; the script checks whether it has content.
- **Timestamps are UTC.** The script labels them, so they are not compared against local-time logs by mistake.
- **Delegated consent accumulates.** A Graph PowerShell session can carry write scopes granted earlier for other work, even when the audit only requests read scopes. The script warns when this happens. During testing it fired because the lab setup scripts had previously been granted write access.

## Caveats and what it cannot see

- **It evaluates policy configuration, not sign-ins.** It does not simulate a specific sign-in. For that, use the What If tool in the Entra admin center or the sign-in logs.
- **"Covered" does not mean MFA is registered.** A user targeted by an MFA policy may not have registered a method yet. Registration status is not checked.
- **PIM-eligible role assignments are not counted.** Only active role members are evaluated. An eligible admin who activates a role becomes subject to role-targeted policies at that point.
- **Per-user MFA is not evaluated.** The legacy per-user MFA setting is outside Conditional Access.
- **User type is not read.** With `User.ReadBasic.All`, the script cannot tell guests from members, so guest coverage is not analyzed separately.
- **Report-only age is approximate.** Graph does not expose when a policy's state last changed, so the last-modified date is used. The audit log has the full history.
- **Not evaluated:** session controls, device filters, authentication contexts, workload identity policies, and insider risk conditions.
- **Not tested at scale.** The lab has 11 users and 7 policies. Lookups are cached per group and role, but per-user coverage evaluation has not been tested against thousands of users.
- **The break-glass candidate list is a hint.** Being excluded from many policies does not make an account a break-glass account.
- **For production use,** consent the read-only scopes on their own or use an identity that has only those scopes, so the session cannot carry write access.
- **Break-glass accounts in this lab use TOTP for MFA.** Microsoft recommends phishing-resistant methods such as FIDO2 keys for production emergency access accounts.

## Repository layout

```
conditional-access-audit/
  Invoke-CAAudit.ps1        The audit tool (read-only)
  lab-setup/
    New-LabUsers.ps1        Creates 8 test users with realistic attributes
    New-LabGroups.ps1       Creates 4 test groups, including an empty exception group
    New-LabPolicies.ps1     Creates CA002 to CA007 with planted problems
  sample-output/            Exports from a run against the lab tenant
  screenshots/              Tenant setup and audit output
```

The lab setup scripts need write scopes and are separate from the audit tool on purpose. The tool you would run against someone else's tenant never asks for write access.

## How this was built

The PowerShell in this repository was written with AI assistance (Anthropic's Claude), as were the test scenarios. I set up and configured the lab tenant, ran every script against it, checked the output against the planted configuration, and reported problems that were then fixed, such as empty guest objects showing up as guest conditions and timestamps appearing without a time zone. The code was not written from scratch by me.
