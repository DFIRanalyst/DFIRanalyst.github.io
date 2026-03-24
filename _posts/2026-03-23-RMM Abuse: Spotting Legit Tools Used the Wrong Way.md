---
title: "RMM Abuse: Spotting Legit Tools Used the Wrong way"
date: 2026-03-23 10:30:00 -0500
categories: [Microsoft Defender]
tags: [RMM, Remote Access, KQL, Defender, T1219, Threat Hunting, Detection Engineering, File Creation, XDR, RAT]
---


## Summary

Remote Monitoring and Management (RMM) tools are common in enterprise environments, but they’re also one of the easiest ways for attackers to maintain access once they’re inside.

Instead of dropping malware or relying on RDP, attackers can use tools like TeamViewer, AnyDesk, or RustDesk to blend in with normal IT activity. This detection looks for those tools running from **unusual locations**, which is often a sign they were manually dropped or executed outside of standard deployment methods.



## MITRE Technique

**T1219 – Remote Access Software**

Attackers often deploy legitimate remote access tools after initial access. These tools give them persistent, interactive control while blending in with normal administrative activity.


## Detection Logic

The idea here is pretty straightforward. Look for known RMM tools executing on endpoints, but filter out the common noise.

This detection focuses on:

* Executables running outside typical Windows or application directories
* Known RMM tools identified by folder path or naming patterns
* Process and file creation events that don’t match expected activity

RMM tools aren’t the problem by themselves. It’s when they show up in places they shouldn’t, or are used by accounts that normally wouldn’t use them.


## KQL Query

```kql
DeviceProcessEvents
| where FolderPath matches regex @'(?i)^[a-z]:\\\S+\.exe'
  and not ((FolderPath contains "c:\\windows"
  and FolderPath matches regex @'(?i)microsoft\.net|softwaredistribution|system32|syswow64|ccm|servicing|winsxs')
  or FolderPath matches regex @'(?i)^(d:\\apps|c:\\_datas\\)')
| extend RAT = case(
    FolderPath contains "teamviewer", "TeamViewer",
    FolderPath contains "anydesk", "AnyDesk",
    FolderPath contains "rustdesk", "RustDesk",
    FolderPath contains "vnc", "VNC",
    FolderPath contains "manageengine", "ManageEngine",
    FolderPath contains "fastclient", "FastClient",
    FolderPath contains "logmein", "LogMeIn",
    FolderPath contains "netviewer", "NetViewer",
    FolderPath contains "ultraviewer", "UltraViewer",
    FolderPath contains "dwrcs", "Dameware",
    FolderPath contains "splashtop", "Splashtop",
    FolderPath contains "zerotier", "ZeroTier",
    FolderPath contains "supremo", "Supremo",
    "Other"
)
| where RAT != "Other"
| distinct Timestamp, ReportId, DeviceId, DeviceName, AccountName, RAT, FileName, ActionType
```


## Notes for on Blind Spots

To improve fidelity:

* Tune the list of RMM tools based on what’s actually allowed in your environment
* Add context by joining with logon events or device inventory data
* Watch for tools running from temp folders, user directories, or unusual paths

Attackers can install these tools in normal-looking directories, so this detection works best when paired with user and device context.


## What Could Trigger a False Positive

IT support teams and vendors often use tools like TeamViewer or AnyDesk for legitimate access.

If these tools are deployed properly, they usually run from consistent locations. If you see them running from random folders or under unexpected users, that’s when it becomes interesting.


## Validation

![Found something bad!](/assets/img/rmm.png)
Look what I found executing from a non-standard directory.



## Response Tips

Treat these alerts seriously. If usage wasn’t expected, it could indicate unauthorized remote access. Here’s what I recommend:

* Investigate the user and device involved
* Check where the tool was executed from
* Review recent logon activity tied to the same account
* Confirm whether the tool is approved in your environment

  If it wasn’t authorized:

    * Isolate the system
    * Remove the tool and any persistence mechanisms
    * Reset credentials for the affected user
    * Check for additional indicators of compromise, remote access tools or lateral movement


## Takeaways

RMM tools are one of the easiest ways for attackers to stay inside an environment without raising alarms.

You don’t need to detect the tool itself. You need to detect when it shows up where it shouldn’t or is used in a way that doesn’t make sense.

That’s where this detection adds value.


## References

[Threat hunting case study: RMM software](https://www.intel471.com/blog/threat-hunting-case-study-rmm-software)
[Mitre ATT&CK](https://attack.mitre.org/techniques/T1219/)


---


