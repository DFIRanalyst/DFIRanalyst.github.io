---
title: "Detecting New AD User Account Creation Events"
date: 2024-11-04 20:15:00 +0000
categories: [Microsoft Defender]
tags: [T1136.002, Account Creation, KQL, Domain Account, Detection Engineering]
---

## Summary

New user accounts in Active Directory can be a routine part of operations but they're also a common persistence tactic used by attackers after initial access. Monitoring account creation events helps you catch unauthorized provisioning early, before those accounts are used to move laterally or escalate privileges.

This detection focuses on user account creations that fall outside normal automated workflows or privileged account management. Known service accounts, system-generated identities, and privileged access accounts are filtered out to reduce noise.

## MITRE Technique

- **T1136.002 – Create Account: Domain Account**

Adversaries may create domain accounts to maintain access to the environment. These accounts can be used directly or staged for future lateral movement.

## Detection Logic

The logic is simple: watch for User Account Created events, then exclude anything that matches known patterns used for legitimate service accounts, external identities or PAM-managed access. What’s left are accounts you should probably take a closer look at.

## KQL Query

Here's a sanitized version of the detection:

```kql
IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType contains "User Account Created"
| where not(toupper(AccountDisplayName) has_any("{SERVICE_ACCOUNT_1}", "{SERVICE_ACCOUNT_2}", "{SERVICE_ACCOUNT_3}"))
| where not(TargetAccountUpn contains "{EXTERNAL_ACCOUNT_IDENTIFIER}") // External accounts
| where not(TargetAccountDisplayName contains "{AUTOMATED_SYSTEM_ACCOUNT}") // System-generated accounts
| where not(AccountName endswith "{PAM_SUFFIX}") // Privileged access management
| project Timestamp, Application, ActionType, TargetAccountUpn, AccountName, AccountUpn, ReportId
```
Edit the detection to include or remove any accounts that you do not need to monitor.

## Notes on Blind Spots

This detection assumes that:

  - Directory event logging is active and working correctly

  - Account creation isn't happening at high volume due to automation

If either assumption breaks, the detection may generate noise or miss events entirely.

## What Could Trigger a False Positive

Legitimate account creations that don't match your exclusions will show up here. These may include:

  - Manual user provisioning by IT admins

  - IT test accounts that don’t follow naming standards

  - Untracked automation that wasn’t excluded

Always review the context of the account creation. If there's no matching change record, that's a red flag.

## Validation

This detection was tested against test environments with routine onboarding scripts and manually created accounts. It successfully filtered out expected service and system accounts.

## Response Tips

If a suspicious account creation is detected:

  - Investigate the initiating user and system

  - Check if the account was used to access resources

  - Validate whether the creation aligns with approved IT activity

If it's unauthorized:

  - Disable the account

  - Monitor for follow-up actions from the source host

  - Review group membership and permissions granted to the account

## Takeaways

New AD accounts are a valuable detection point for spotting early stage persistence. With a few filters in place, you can keep the alert volume manageable while still surfacing what matters. Just make sure your exclusions stay up to date as your environment changes.

## References

[MITRE ATT&CK T1136.002](https://attack.mitre.org/techniques/T1136/002/)

[IdentityDirectoryEvents Reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identitydirectoryevents-table)
