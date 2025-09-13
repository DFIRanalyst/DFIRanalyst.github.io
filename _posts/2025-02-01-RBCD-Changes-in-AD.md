---
title: "Detecting Unauthorized RBCD Changes in Active Directory to Prevent Lateral Movement"
date: 2025-02-01 17:30:00 +0000
categories: [Splunk]
tags: [RBCD, T1550, LDAP, SPL, Windows Event Logs, Detection Engineering, Active Directory]
---

## Summary

This detection was built to identify any modifications to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute in Active Directory. Changes to this attribute are used to configure Resource-Based Constrained Delegation (RBCD), which can be abused by attackers to impersonate accounts or gain elevated access across domains.

Monitoring this attribute is critical. Unauthorized changes can enable stealthy lateral movement and privilege escalation within an environment.

## MITRE Technique

- **T1550.002 – Use Alternate Authentication Material: Pass the Hash / Account Manipulation**

This technique covers abuse of authentication attributes and delegation mechanisms to gain unauthorized access.

## Detection Logic

The approach here is straightforward:

- Pull Windows Security Event Logs (Event ID 5136) that capture directory service changes.

- Extract and filter for modifications specifically targeting the msDS-AllowedToActOnBehalfOfOtherIdentity attribute.

- Alert when this attribute is touched, regardless of user or system.

## SPL Query

```spl
index=wineventlog source=WinEventLog:Security sourcetype=WinEventLog EventCode=5136
| rex field=_raw "LDAP Display Name:\s+(?<LDAPDisplayName>[^\r\n]+)"
| search LDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity"
| eval "Event Time" = strftime(_time, "%Y-%m-%d %H:%M:%S")
| rename ComputerName as "AD Server", Account_Name as "Modified By (User)", DN as "Target Object DN", LDAPDisplayName as "Modified LDAP Attribute"
| table "Event Time", "AD Server", "Modified By (User)", "Target Object DN", "Modified LDAP Attribute"
```

## Notes on Blind Spots

This detection depends on a few things working properly:

- Attribute change auditing must be enabled via Group Policy.

- Domain controllers must be forwarding these logs to the SIEM.

- The SIEM must be indexing these events without delay or drop.


If any of those steps fail, the detection won’t catch anything.


## What Could Trigger a False Positive

Legitimate changes by IT Admins or automation tools can show up here. 

To validate the alert, check your change control history, if you track that sort of things which most places don't LOL. Was it tied to a known change request? Is the account involved tied to IT operations? If not, dig deeper.

## Validation

This detection was tested during a red team engagement led by an external security firm. During the exercise, their operators used an account to perform RBCD. The detection query successfully flagged the unauthorized delegation attempt in historical logs.

## Response Tips

Treat these alerts seriously. If a change wasn’t planned, it could be part of a lateral movement play. Here’s what I recommend:

- Investigate the user and machine that made the change.

- Review associated command-line or PowerShell activity.

-  Check if the change is documented in the change management records.

-    If it wasn’t authorized:

      - Isolate the system involved.

      - Disable or reset affected accounts.

      - Check for additional signs of compromise tied to the same user or host.

## Takeaways

RBCD can be a powerful tool for attackers if left unmonitored. The msDS-AllowedToActOnBehalfOfOtherIdentity attribute is rarely touched under normal conditions, so any changes to it should be closely reviewed.

## References

[MITRE ATT&CK T1550.002](https://attack.mitre.org/techniques/T1550/)

[RBCD](https://www.semperis.com/blog/ad-security-101-resource-based-constraint-delegation/)
