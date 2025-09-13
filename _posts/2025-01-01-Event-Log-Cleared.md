---
title: "Detecting Event Log Clearing Activity"
date: 2025-01-01 21:30:00 +0000
categories: [Microsoft Defender]
tags: [T1070.001, Event Logs, Process Monitoring, KQL, Detection Engineering]
--- 

## Summary

One of the easiest ways to hide activity after a compromise is to wipe the logs. Whether it’s the red team or something real, clearing event logs is almost always an attempt to cover tracks. It’s not something users typically do, and when it shows up, it’s worth investigating.

This query has proven useful for catching commands that clear logs, like wevtutil cl, Clear-EventLog, and auditpol /clear. 

## MITRE Technique

- **T1070.001 – Indicator Removal on Host: Clear Windows Event Logs**

Attackers use this to delete logs and wipe evidence from the system after gaining access or covering their tracks.

## Detection Logic

The goal here is to catch the common log-clearing commands. It checks both ProcessCommandLine and AdditionalFields for keywords. It also filters out empty AdditionalFields entries to keep things efficient.

Commands it looks for:

  - wevtutil cl

  - Clear-EventLog

  - auditpol /clear

These tools are used to clear different log sources across Windows. If someone runs one of these, you should know about it.

## KQL Query

```kql
DeviceEvents
| where Timestamp > ago(3d)
| where isnotempty(AdditionalFields)
| where ProcessCommandLine has_any ("wevtutil cl", "Clear-EventLog", "auditpol /clear")
    or AdditionalFields contains "Clear-EventLog"
    or AdditionalFields contains "wevtutil cl" 
    or ProcessCommandLine has "wevtuil cl" 
    or AdditionalFields contains "auditpol /clear"
| project Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, AdditionalFields, ProcessCommandLine, ReportId
| order by Timestamp desc
```

## Notes on Blind Spots

This query only works if Defender MDE agent is functioning and active. If is has been disabled or tampered with, you’re not going to catch this.

It also assumes that event log clearing isn’t part of your routine workflows. If you have scripts that regularly wipe logs, those will need to be filtered out.

## What Could Trigger a False Positive

Here’s what might show up that isn’t malicious:

  - IT Admins doing cleanup or maintenance

  - Scheduled scripts that clear logs as part of a reset

If you get an alert, check who ran it and why. If there’s no justification, it’s time to dig deeper.

## Validation

This query was used during a red team exercise and picked up multiple test runs where event logs were cleared using standard tools. It correctly flagged the activity without requiring complex JSON parsing or heavy filtering.

## Response Tips

When this shows up:

  - Review the process and user that initiated the command

  - Check what else the account did before and after the command

If it wasn’t authorized:

  - Preserve what logs remain (grab a snapshot)

  - Isolate the system 

  - Start looking at lateral movement and persistence attempts

## Takeaways

Clearing logs is rarely random. Even if it’s an admin task, it should be documented and tracked. If you see someone clearing logs outside of expected activity, treat it seriously. This query gives you a low-noise way to surface it before it becomes a blind spot.

## References

[MITRE ATT&CK T1070.001](https://attack.mitre.org/techniques/T1070/001/)

[Microsoft Docs: wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)

[PowerShell Docs: Clear-EventLog](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/clear-eventlog?view=powershell-5.1)
