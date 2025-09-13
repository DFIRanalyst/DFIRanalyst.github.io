---
title: "Detecting High-Volume SMB Enumeration (Again, but Smarter)"
date: 2025-09-10 10:00:00 -0400
categories: [Microsoft Defender]
tags: [SMB, Enumeration, KQL, T1135, Threat Hunting, Detection Engineering]
---

## Summary

This was a follow-up to my earlier detection on SMB enumeration. In this case, the goal was to flag incoming SMB activity from devices that touched a large number of unique remote IPs over ports 445 and 139.

After Microsoft made some changes to how DeviceNetworkEvents logs behave, that earlier logic stopped working the way I wanted. So I rebuilt the detection with a system-focused lens. Now I’m asking, which machines are reaching out to a lot of other devices over SMB? That flip in perspective still gets to the heart of the same question, but is more resilient with the updated schema.

## MITRE Technique

- **T1046 - Network Service Scanning** 

While this is often grouped with lateral movement prep, it’s just as common during the early recon phase, especially in internal engagements or targeted attacks where shared drives can hold real value.

## Detection Logic

The detection monitors devices initiating SMB connections to 900+ unique hosts. That number is just where I saw the line between normal activity and noisy recon behavior. Your number may be higher or lower depending on your environment.

Known good sources like patching servers or asset scanners were filtered out using a small suppression list.

## KQL Query

```kql
DeviceNetworkEvents
| where DeviceName !contains "sccmserver"
| where DeviceName !in (
    "knownhost01", "knownhost02", "securityscanner"
)
| where ActionType in (
    "ConnectionAcknowledged", "ConnectionSuccess",
    "NtlmAuthenticationInspected", "KerberosConnectionInspected"
)
| where RemotePort in (445, 139)
| summarize UniqueSMBTargets = dcount(RemoteIP), TargetIPs = make_set(RemoteIP), LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, LocalIP
| where UniqueSMBTargets > 900
| project LastSeen, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, LocalIP, UniqueSMBTargets, TargetIPs
```

## Notes on Blind Spots
Like the previous SMB enumeration post, this query only works if Defender MDE agent is functioning and active. If is has been disabled or tampered with, you’re not going to catch this. It also assumes that enumeration at this scale is unusual, which holds up most of the time, but not always. 

## What Could Trigger a False Positive

Legit tools like SCCM, patching tools, vulnerability scanners and  asset inventory scanners can light this up. That’s why I built the exclusion list directly into the query for known safe hosts.


## Response Tips

- If something pops:

  - Validate by reviewing the process name, device and account that kicked it off.

  -  Was it a known scanner? Something built-in like PowerShell? A third-party tool?

  - If it’s not an expected action, dig into the full process tree and check surrounding activity.

- If confirmed malicious:

  - Block network access for the device.

  - Lock and investigate the account tied to the scan.

  - Check for dropped payloads.

## Takeaways

This is one of those patterns that shows up after a foothold. It’s easy to overlook unless you're tracking SMB traffic at scale. Defender gives you what you need to start hunting, but just like the first post, having a parallel detection in your NDR tool would round out your visibility.


## References

[MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)

[A Little Guide to SMB Enumeration](https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/)
