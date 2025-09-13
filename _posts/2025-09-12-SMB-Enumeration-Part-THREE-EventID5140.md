---
title: "Detecting Failed SMB Share Access Using Event ID 5140"
date: 2025-09-12 14:00:00 -0400
categories: [Splunk, Windows Event Logs]
tags: [SMB, EventID 5140, Splunk, T1135, Threat Hunting, Detection Engineering]
---

## Summary

This detection was built to catch repeated failed attempts to access shared folders over SMB. Instead of looking at network traffic or Defender logs, this one uses Security Event ID 5140 collected directly from File Share servers.

When you see the same account or IP failing to access multiple shares, it might be a sign of enumeration, a misconfiguration or something more suspicious. This is Especially useful in environments where EDR isn’t deployed everywhere or when you’re monitoring file servers directly.

## MITRE Technique

- **T1046 - Network Service Scanning**  

Attackers often hit shared folders first during internal recon. Even if they can’t access them, the attempts themselves can be a signal something is off.

## Detection Logic

The idea is simple: track Windows EventCode 5140 where the action was a failure. Then group by account and IP to find patterns where someone is repeatedly failing to access shares.

If you see more than 4 failed attempts from a single account, it’s worth a second look.

## Splunk Query
```spl
index=wineventlog source="WinEventLog:Security" sourcetype="WinEventLog" EventCode=5140 action=failure
| eval Source_Address=if(action="failure", Source_Address, null())
| stats count(eval(action="failure")) AS failed_access_attempts, latest(_time) AS last_access_time, values(Source_Address) AS failed_source_ips by Account_Name
| eval last_access_time = strftime(last_access_time, "%Y-%m-%d, %H:%M:%S")
| eval potential_enumeration=if(failed_access_attempts > 4, "Yes", "No")
| table last_access_time, failed_source_ips, Account_Name, failed_access_attempts, potential_enumeration
```
## Notes on Blind Spots

This depends entirely on Windows Security logs being forwarded from file servers. If logging is disabled or logs get tampered with, it won’t catch a thing. It also assumes that four failures from a single source are abnormal.

## What Could Trigger a False Positive

A few examples of legit activity that might show up here:

  - Sysadmin tools testing share access
  
  - Misconfigured login scripts 
  
  - Locked out PAM accounts

  - Vulnerability scanners 


## Response Tips

If something looks suspicious:

  - Check the source IP and user account involved.

  - See what other events surround the failed access.

  - Look for signs of follow-up actions like account lockouts, privilege escalation, or lateral movement.

If it turns out to be unauthorized:

  - Block the account.

  - Review past activity to understand the full scope.

## Takeaways

SMB share access failures don’t always mean trouble but when they start stacking up, it’s a sign you should dig deeper.

By pulling Event ID 5140 into your SIEM and correlating failed access patterns by user and IP, you can surface signs of enumeration before an attacker gets deeper into the environment. 

## References

[MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/)

[Windows Event ID 5140](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5140)
