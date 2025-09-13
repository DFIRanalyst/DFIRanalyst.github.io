---
title: "Detecting Restricted Admin Mode Enablement"
date: 2024-09-02 19:00:00 +0000
categories: [Microsoft Defender]
tags: [T1078.003, Restricted Admin, RDP, KQL, Logon Events, Detection Engineering]
---

## Summary

Restricted Admin mode can be useful for remote desktop access in certain cases, but it also poses a significant security risk. It allows a user to initiate an RDP session without sending  credentials to the target machine. While helpful in limited, trusted scenarios, attackers can also abuse this to move laterally while avoiding credential theft.

This query monitors changes to the `DisableRestrictedAdmin` registry value under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`. If someone flips this setting, it could be an early indicator of misconfiguration, unauthorized access, or an attacker setting up credential-less RDP access.

Changes to this registry key aren’t common, so when they do happen, you’ll want to know.

## MITRE Technique

- **T1078.003 – Valid Accounts: Local Accounts**

Attackers often use local accounts for persistence or lateral movement, and enabling Restricted Admin mode can help them move without exposing stolen credentials.

## Hunting Logic

This query looks for:

- Registry modifications using the `DeviceRegistryEvents` table
- Target key: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
- Specific value: `DisableRestrictedAdmin`

## KQL Query

```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey == @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
| where RegistryValueName == "DisableRestrictedAdmin"
| extend DisableRestrictedAdminStatus = iff(RegistryValueData == "0", "Enabled", "Disabled")
| project Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RegistryValueName, RegistryValueData, DisableRestrictedAdminStatus, ReportId
| order by Timestamp desc
```

## Notes on Blind Spots

This query only works if Defender MDE agent is functioning and active. If is has been disabled or tampered with, you’re not going to catch this.

## What Could Trigger a False Positive

- Legitimate administrative changes

Always verify with the system owner before jumping to conclusions.

## Validation

Tested internally by flipping the value on a test endpoint. The detection flagged both the enable and disable changes correctly, showing which user and process triggered the change. V

## Response Tips

- Investigate the account and process that made the modification
- Confirm whether it was expected or part of authorized change
- If not:
  - Isolate the endpoint
  - Revert the registry change 
  - Review logs for other suspicious activity

## Takeaways

Restricted Admin mode isn’t something most users even know exists. If it gets enabled or disabled, it should be intentional and traceable. This query helps you catch those changes early and gives you visibility into what could otherwise be a quiet misconfiguration with security implications.

## References

[MITRE ATT&CK T1078.003](https://attack.mitre.org/techniques/T1078/003/)

[Restricted Admin Mode for RDP](https://www.redteaming.org/rdpkerberos.html)

