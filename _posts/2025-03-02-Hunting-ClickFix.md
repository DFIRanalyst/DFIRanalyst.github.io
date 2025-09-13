---
title: "Hunting Suspicious Commands in RunMRU Registry Keys"
date: 2025-03-02 21:00:00 +0000
categories: [Microsoft Defender]
tags: [RunMRU, LOLBins, Registry, Threat Hunting, KQL, Living Off the Land, Query, DFIR]
---

## Summary

The RunMRU registry key keeps a record of commands typed into the Windows Run dialog (Win + R). That makes it a useful place to look for one-off activity, especially when attackers are operating manually or trying to avoid dropping artifacts on disk.

This KQL query hunts for signs of suspicious or unusual usage by checking for known LOLBins or commandline tools often abused in post-exploitation. It’s not a full detection on its own, but it’s a solid starting point for deeper investigation.

## Query Logic

The query looks for:

  - Registry activity tied to the RunMRU key

  - Values that contain known LOLBins or built-in utilities commonly abused by attackers

These include stuff like cmd, powershell, mshta, and curl, all of which can be used for command execution, file download, or script injection.

## KQL Query

```kql
DeviceRegistryEvents
| where RegistryKey contains "RunMRU"
| where RegistryValueData has_any ("cmd /c", "powershell", "mshta", "wscript", "curl", "bitsadmin")
| project Timestamp, DeviceName, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
```

## Notes for Tuning

This isn’t a detection rule. It's meant for manual hunting, and the results will almost always need follow up, normal IT admin activity can show up here.

To improve fidelity:

  - Tailor the has_any list to include LOLBins or script engines you think maybe relevant

  - Add context by joining with process events or user session data

  - Watch for entries that are uncommon and coming from unexpected users

    - This is a great place to plug in any additional LOLBins you've seen abused in the wild. Tools like rundll32, mshta, certutil, or wmic with odd arguments can show up here. Just extend the has_any() clause as needed.

## Takeaways

RunMRU is often overlooked but can quietly surface signs of hands-on activity, tool testing, or post-exploitation exploration. It’s not noisy like process logs, and it sticks around longer in most cases. Queries like this are helpful when you're looking for low-volume indicators that fall outside normal telemetry.

## References

[LOLBAS Project](https://lolbas-project.github.io/#)

[RunMRU Registry Key](https://www.magnetforensics.com/blog/what-is-mru-most-recently-used/)
