---
title: "Click-Fix"
date: 2025-12-16 21:00:00 +0000
categories: [Microsoft Defender]
tags: [RunMRU, LOLBins, Registry, Threat Hunting, KQL, Living Off the Land, Detection Engineering, DFIR]
---

## Summary

The RunMRU registry key keeps a record of commands typed into the Windows Run dialog (Win + R). That makes it a useful place to look for one-off activity, especially when attackers are operating manually or trying to avoid dropping artifacts on disk.

This KQL detection hunts for signs of suspicious or unusual usage by checking for known LOLBins or commandline tools often abused in post-exploitation.


## MITRE Technique

- - **T1204.004  -  User Execution: Malicious Copy and Paste** 

An attacker might count on users copying and pasting commands without thinking. With a little social engineering, it's not hard to trick someone into dropping malicious code directly into PowerShell or Command Prompt.


## Detection Logic

The idea here is pretty straightforward. Watch for activity tied to the RunMRU registry key, then look at the values being written. If those values contain common LOLBins or built-in utilities that attackers like to abuse, it’s worth a closer look.

Things like cmd, powershell, mshta, and curl tend to show up since they’re already on the system and can be used for command execution, file downloads, or script injection.


## KQL Query

```kql
DeviceRegistryEvents
| where RegistryKey has "RunMRU"
| extend Cmd = tolower(RegistryValueData)
| where Cmd has_any (
    "powershell",
    "pwsh",
    "mshta",
    "cmd.exe",
    "bitsadmin",
    "certutil",
    "rundll32",
    "finger",
    "curl",
    "wget"
)
| where
    // PowerShell-specific ClickFix patterns
    (
        Cmd has "powershell"
        and Cmd has_any (
            "-enc",
            "-encodedcommand",
            "iex",
            "invoke-expression",
            "irm ",
            "iwr ",
            "-w hidden",
            "-windowstyle hidden"
        )
    )
    or
    // Non-PowerShell LOLBin download/exec patterns
    (
        Cmd !has "powershell"
        and Cmd has_any (
            "http://",
            "https://",
            "/transfer",
            "-urlcache",
            ".hta",
            ".js",
            ".vbs",
            "javascript:"
        )
    )
| project
    Timestamp,
    DeviceId,
    DeviceName,
    RegistryValueName,
    RegistryValueData,
    InitiatingProcessAccountName,
    ReportId
```

## Notes for on Blind Spots

To improve fidelity:

  - Tailor the has_any list to include LOLBins or script engines you think maybe relevant

  - Add context by joining with process events or user session data

  - Watch for entries that are uncommon and coming from unexpected users

    - This is a great place to plug in any additional LOLBins you've seen abused in the wild. Tools like rundll32, mshta, certutil, or wmic with odd arguments can show up here. Just extend the has_any() clause as needed.


## What Could Trigger a False Positive

Admins, power users, or IT support staff often use built-in tools like cmd, mshta, or certutil to do legit tasks. If they type or paste those into Run, you’ll see it logged. Doesn’t mean it’s malicious, but if it’s coming from a user who doesn’t normally do that kind of thing, it’s worth a closer look.

## Validation

(/assets/img/ClickFix.png)


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

RunMRU is often overlooked but can quietly surface signs of hands-on activity, tool testing, or post-exploitation exploration. It’s not noisy like process logs, and it sticks around longer in most cases. Queries like this are helpful when you're looking for low-volume indicators that fall outside normal telemetry.


## References

[LOLBAS Project](https://lolbas-project.github.io/#)

[RunMRU Registry Key](https://www.magnetforensics.com/blog/what-is-mru-most-recently-used/)

[MITRE ATT&CK](https://attack.mitre.org/techniques/T1204/004/)
