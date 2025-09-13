---
title: "Detecting SMB Enumeration Activity with Microsoft Defender"
date: 2024-11-01 12:00:00 +0000
categories: [Microsoft Defender]
tags: [SMB, Enumeration, KQL, T1046, Threat Hunting, Detection Engineering]
---

## Summary ##

Following a red team simulation designed to test detection coverage, I built a detection to catch suspicious SMB enumeration across the network. This kind of activity can be an early indicator of lateral movement, especially when a single host starts touching a large number of systems over SMB.

Defender makes this pretty straightforward to pull network activity over ports 445 and 139 using  KQL.

## MITRE Technique

- **T1046 - Network Service Scanning**  

This technique is often used to discover shared folders, services, or user accounts across the network. It’s noisy if you’re looking in the right place.

## Detection Logic

The idea here is pretty straightforward: watch for systems making SMB connections to a high number of unique hosts. Legitimate SMB use usually targets a few specific devices, not the entire subnet.

In this case, I flagged any user initiating SMB connections to more than 1000 unique hosts within a 10 day window.

## KQL Query


```kql
DeviceNetworkEvents
| where Timestamp > ago(10d)
| where RemotePort in (445, 139)
| where ActionType in ("NtlmAuthenticationInspected", "NetworkSignatureInspected", "ConnectionAcknowledged")
| extend AdditionalData = parse_json(AdditionalFields)
| where AdditionalData.username != "{ServiceAccount}" or AdditionalData.hostname != "{ServiceAccountHostname}" or AdditionalData.server_dns_computer_name != ""
| extend SuspiciousUsername = tostring(AdditionalData.username),
         SuspiciousHostname = tostring(AdditionalData.hostname),
         PotentialVictim = tostring(AdditionalData.server_dns_computer_name),
         Suspicious_IP = tostring(LocalIP)
| summarize SMB_Enumeration_Count = dcount(PotentialVictim),
            Affected_Hosts = make_set(PotentialVictim),
            LocalIP = any(Suspicious_IP),
            Suspicious_Hostname = make_set(SuspiciousHostname),
            Timestamp = max(Timestamp),
            ReportId = any(ReportId),
            DeviceId = any(DeviceId)
by SuspiciousUsername
| where SMB_Enumeration_Count > 1000
| project Timestamp, Suspicious_Hostname, SuspiciousUsername,
          SMB_Enumeration_Count, Affected_Hosts, LocalIP, ReportId, DeviceId
```

## Notes on Blind Spots

This query only works if Defender MDE agent is functioning and active. If is has been disabled or tampered with, you’re not going to catch this. It also assumes that enumeration at this scale is unusual, which holds up most of the time, but not always. 

## What Could Trigger a False Positive

It’s possible to see alerts from tools doing legitimate scans or inventory, such as:

- Asset discovery

- Vulnerability  scans

- SCCM


To validate, check the command line and process tree. Look at who ran it, what triggered it, and whether the activity was expected.


## Response Tips
If it turns out to be malicious, here’s what I'd usually do:

- Investigate the device and user account involved.

- Confirm whether the activity was part of an approved process.

  - If not:

    - Isolate the system.

    - Revoke session and disable the account responsible for the activity.

    - Start checking for signs of follow-up activity like credential dumping or abnormal scripts being run, etc.

    - Look for other events that occurred prior to the identified activity to determine if it was part of a broader pattern or ongoing campaign.

## Takeaways

SMB enumeration is often the first move in many attacks, and while it’s a bit noisy and often blends in with legitimate activity, it’s also pretty common for staging cyber attacks. When Microsoft Defender is set up properly, it can give you good visibility into this kind of activity but ideally you'll want to make a similar detection using a Network Detection & Response (NDR) tool for ideal coverage. 

## References

[MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)

[A Little Guide to SMB Enumeration](https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/)
