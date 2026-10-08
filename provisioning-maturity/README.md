# Provisioning Maturity

Moving from manual access assignment to attribute-driven provisioning in Microsoft Entra ID: dynamic groups, group-based licensing, an access package with approval and expiration, an access review, and a PowerShell check that compares each dynamic group's rule with its actual membership.

> **Lab work, not production.** This was built and tested in a Microsoft 365 trial tenant with Entra ID P2. It has not been run against a production tenant. The tenant, users, and groups shown here were created for testing.

## The problem

In many environments, access is granted by hand. Someone files a ticket, an admin adds the user to a group or assigns a license, and nothing ever takes it away. Over time:

- Users accumulate access from every role they have held.
- People end up in groups that do not fit their role, and nobody notices.
- Licenses stay assigned to accounts that no longer need them.
- No one can say who approved a given access grant, or whether it is still needed.

Attribute-driven provisioning ties access to attributes that already exist, such as department, location, and employee type. When an attribute changes, access follows. For access that cannot be derived from attributes, request-and-approve workflows with expiration replace open-ended manual grants.

## What was built

| # | Component | What it shows |
|---|---|---|
| 1 | Manually assigned group `SG-Contractor-ERP-Access` | The "before" state: access granted by request and never reviewed, including one employee who does not belong in a contractor group |
| 2 | Access review on that group | Owner-based review with auto-apply, where a reviewer who does not respond causes access to be removed |
| 3 | Four dynamic groups, including a compound rule | Membership driven entirely by user attributes |
| 4 | Group-based licensing on a dynamic group | Licenses follow group membership instead of being assigned per user |
| 5 | Access package `AP-Finance-Reporting` | Two resources bundled into one request, scoped to employees, with approval and a 1-hour expiration |
| 6 | `Test-DynamicGroupMembership.ps1` | Read-only check that evaluates each dynamic rule against current attributes and flags rule-versus-actual mismatches |

### Licensing used

Everything here runs on **Entra ID P2** (included in Microsoft 365 E5). Dynamic groups and group-based licensing need only P1. Entitlement management and access reviews, as used here, are covered by P2.

The portal confirmed four features that need **Entra ID Governance** rather than P2. None of them were needed for this build:

| Feature | Where the portal flagged it |
|---|---|
| User-to-Group Affiliation (machine-learning review recommendations) | Grayed out in the access review settings |
| On-behalf-of requests (for example, a manager requesting for a report) | Banner on the access package Requests tab |
| Requiring a Verified ID from requestors | Banner on the access package Requests tab |
| Automatic assignment of access packages based on attributes | Not configured; Microsoft lists it as a Governance feature |

## 1. The "before" state: a manually assigned group

`SG-Contractor-ERP-Access` is an assigned group for contractor access to an ERP reporting system. Its members are Tom Becker and Raj Patel (contractors) and Linda Park, a Sales employee who should not be in a contractor group. That third member is the kind of drift manual assignment produces: someone was added for a one-off reason and never removed.

## 2. Access review with no reviewer response

A one-time access review was created on the group:

| Setting | Value |
|---|---|
| Reviewers | Group owner (Derek Nguyen) |
| Duration | 1 day |
| Auto apply results to resource | Enabled |
| If reviewers don't respond | **Remove access** |
| Decision helper | No sign-in within 30 days |
| Justification required | Yes |

The owner was deliberately never signed in, so the review would end with no decisions.

**What "no response" does depends entirely on one setting.** The options are No change, Remove access, Approve access, and Take recommendations. The default is No change, which means an ignored review changes nothing at all. "Remove access" makes silence a decision: access that no one vouches for is removed.

**Result:** _see [Results](#results)._

**Why the review targets an assigned group:** an access review cannot remove members from a dynamic group, because the membership rule would add them straight back. Dynamic groups are governed by fixing the attributes that drive them, not by reviewing their members.

## 3. Dynamic groups

| Group | Rule | Members |
|---|---|---|
| `DG-Dept-Plant-Operations` | `(user.department -eq "Plant Operations")` | 2 |
| `DG-Location-Salt-Lake-City` | `(user.city -eq "Salt Lake City")` | 3 |
| `DG-Contractors` | `(user.extensionAttribute1 -eq "Contractor")` | 2 |
| `DG-All-Employees-Licensed` | `(user.extensionAttribute1 -eq "Employee") -and (user.usageLocation -eq "US") -and (user.accountEnabled -eq true)` | 6 |

The compound rule on `DG-All-Employees-Licensed` includes `accountEnabled -eq true`, so a disabled account drops out of the group and stops consuming a license without anyone touching it.

**`employeeType` is not a supported property in dynamic membership rules.** Department, city, job title, usage location, and the extension attributes are supported; employee type is not. The setup script copies each user's employee type into `extensionAttribute1`, and the rules use that. In hybrid environments this is a common pattern: employee type is synced from on-premises Active Directory into an extension attribute.

**Attribute write permissions matter.** A dynamic group used for access control is only as secure as the controls on who can change the attributes in its rule. For synced attributes, that includes write permissions in on-premises AD.

## 4. Group-based licensing

The Microsoft 365 E5 license was assigned to `DG-All-Employees-Licensed`, so every enabled US employee is licensed automatically and contractors are not.

Observations from the lab:

- **License assignment for groups has moved to the Microsoft 365 admin center.** The Entra admin center shows a group's licenses but states that adding, removing, and reprocessing them is only available in the M365 admin center.
- **Processing is asynchronous.** The group's license state sat at "Queued" in Entra for an extended period after assignment. Adding someone to a licensed group does not license them instantly, which matters on a new hire's first morning.
- **The license source was reported inconsistently.** The M365 admin center showed one group assignment and the license count rose from 1 to 7. At the same time, Graph's `licenseAssignmentStates` reported the six employees' licenses as direct assignments with no `assignedByGroup` value, while Entra still showed the group assignment as Queued.
- **The behavior was group-driven anyway.** Rather than rely on the label, the behavior was tested directly: when Sarah Kim's employee type changed and she dropped out of the group, her license was removed within about two minutes, with no manual action. A true direct assignment would have stayed. The lesson is to verify licensing by testing what happens on a change, not by trusting how the license source is labeled during processing.

Direct assignments are the main failure mode to watch for: a license assigned directly stays on the user no matter what happens to their attributes, which silently defeats attribute-driven licensing.

## 5. Access package

`AP-Finance-Reporting` in catalog `CAT-Finance`:

| Setting | Value |
|---|---|
| Resources | `SG-Finance-Reporting-Users` and `SG-Finance-Shared-Drive` (Member) |
| Who can get access | Members of `DG-All-Employees-Licensed` |
| Who can request | Self (and Admin) |
| Approval | Required, 1 stage, named approver, 3 days to decide |
| Justification | Required from both requestor and approver |
| Expiration | **1 hour** (lab value so expiration could be observed; production would typically use 90 to 180 days) |
| Extension | Allowed, with approval |

Scoping requests to a dynamic group means only current employees can see and request the package. Contractors never see it in My Access.

**Walkthrough:**

1. Linda Park signed in to My Access and requested the package with a justification. Status: Pending approval.
2. The approver approved it with a justification.
3. Linda was added to **both** resource groups from that one request.
4. After the expiration period, she should be removed from both. _See [Results](#results)._

The two resource groups have no other way in. Anyone in them got there through the package, with a recorded request, approval, and end date.

## 6. Rule-versus-actual membership check

[`scripts/Test-DynamicGroupMembership.ps1`](scripts/Test-DynamicGroupMembership.ps1) is read-only. For every dynamic group it:

1. Reads the membership rule and processing state.
2. Evaluates the rule itself against every user's current attributes to work out who should be a member.
3. Compares that with who actually is a member.
4. Reports missing members (match the rule but are not in the group) and unexpected members (in the group but no longer match).

It supports rules built from `user.<property>` with `-eq`, `-ne`, `-startsWith`, and `-in`, joined by `-and` and `-or`. Rules using other syntax are reported as "Not evaluated" rather than guessed.

**Test:** Sarah Kim's employee type was changed from Employee to Contractor, and the script was run immediately:

```
Group                      Processing Expected Actual Status
-----                      ---------- -------- ------ ------
DG-All-Employees-Licensed  On                5      6 MISMATCH
DG-Contractors             On                3      2 MISMATCH
DG-Dept-Plant-Operations   On                2      2 OK
DG-Location-Salt-Lake-City On                3      3 OK

--- DG-All-Employees-Licensed [MISMATCH]
  Unexpected: Sarah Kim    (in the group, do not match the rule)

--- DG-Contractors [MISMATCH]
  Missing:    Sarah Kim    (match the rule, not in the group)
```

For that window, Sarah's attributes said Contractor but she still held employee-scoped access, including the license.

About two minutes later the script reported all four groups OK (`DG-All-Employees-Licensed` 5/5, `DG-Contractors` 3/3), and Sarah's license count was 0. A short mismatch after an attribute change is normal. A mismatch that persists means processing is paused, stuck, or the rule does not do what was intended.

Required scopes (read-only): `User.Read.All`, `Group.Read.All`, `GroupMember.Read.All`.

```powershell
.\scripts\Test-DynamicGroupMembership.ps1 -TenantId "contoso.onmicrosoft.com"
```

## Before and after

| | Manual assignment | Attribute-driven |
|---|---|---|
| How access is granted | A ticket and an admin adding the user | The user's attributes match a rule, or they request a package and it is approved |
| When access is removed | When someone remembers | When the attribute changes, or when the package assignment expires |
| Role change | Old access stays; new access is added on request | Old groups drop away and new ones apply automatically |
| Leaver | Depends on the offboarding checklist | Disabling the account removes it from groups that require `accountEnabled -eq true`, freeing the license |
| Audit question "who approved this?" | Often unanswerable | Recorded request, justification, and approval |
| Licensing | Assigned per user, easy to forget | Follows group membership |

### What breaks in each

**Manual assignment:**
- Wrong people in the wrong groups (Linda in a contractor group).
- Access never expires, so it accumulates across role changes.
- Licenses stay on accounts that no longer need them.
- Reviews are the only cleanup mechanism, and if reviewers do not respond and the setting is "No change," nothing happens.

**Attribute-driven:**
- **Bad attributes mean bad access.** If HR data is wrong or late, access is wrong. The rules are only as accurate as the source data.
- **Attribute write access becomes a privilege.** Anyone who can change an attribute in a rule can change group membership.
- **Processing lag.** Changes are not instant. The membership check shows the gap.
- **Direct license assignments undermine it.** A license assigned directly stays even after the user leaves the group.
- **Not every property can be used.** `employeeType` cannot appear in a rule; an extension attribute is needed.
- **Access reviews do not apply to dynamic group members.** Governance moves to the attributes and the rules.

## Results

| Test | Result |
|---|---|
| Dynamic groups populated from attributes | All four matched expected membership |
| Rule-versus-actual check immediately after an attribute change | MISMATCH reported for Sarah Kim in both affected groups |
| Rule-versus-actual check after reprocessing | All four groups OK about two minutes after the change |
| Sarah Kim's license after leaving `DG-All-Employees-Licensed` | Removed automatically (0 licenses), even though Graph had labeled it a direct assignment |
| Access package request, approval, and delivery to both groups | Confirmed |
| Access package expiration after 1 hour | _To be confirmed_ |
| Access review with no reviewer response | _To be confirmed_ |

## Repository layout

```
provisioning-maturity/
  README.md
  scripts/
    New-LabDynamicGroups.ps1          Sets extensionAttribute1 and creates the four dynamic groups (lab setup, needs write scopes)
    Test-DynamicGroupMembership.ps1   Read-only rule-versus-actual membership check
  sample-output/                      CSV exports from the membership check
  screenshots/                        Portal and PowerShell evidence for each step
```

## Caveats

- **Lab scale.** 11 users, 4 dynamic groups. The membership check evaluates every user against every rule in memory, which is fine at this size but has not been tested against thousands of users.
- **The membership check supports a subset of rule syntax.** Unsupported rules are skipped and labeled, not guessed.
- **Lab timings.** The 1-day review and 1-hour package expiration were chosen so results could be observed during the build. They are not recommendations.
- **The approver is a named admin, not the requester's manager.** Manager attributes were not populated in the lab.
- **The licensing source discrepancy was observed, not explained.** Documentation did not settle why Graph reported group-driven licenses as direct during processing. The removal test showed the licenses behaved as group-assigned.

## How this was built

The PowerShell in this repository and the lab design were produced with AI assistance (Anthropic's Claude). I configured the tenant, built the groups, access review, and access package in the portal, ran every script against the tenant, performed the request and approval as the test users, and checked each result. Problems found along the way, such as the unsupported `employeeType` rule property and a parsing error in a verification command, were diagnosed and fixed with AI assistance. The code was not written from scratch by me.
