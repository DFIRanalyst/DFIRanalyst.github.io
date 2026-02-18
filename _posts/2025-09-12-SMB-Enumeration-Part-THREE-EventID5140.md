---
title: "Catching SMB Share Crawling with Windows Event ID 5140"
date: 2025-09-12 14:00:00 -0400
categories: [Splunk, Windows Event Logs]
tags: [SMB, EventID 5140, Splunk, T1135, Threat Hunting, Detection Engineering]
---


## Summary

This detection was built to identify **Snaffler-like SMB crawling behavior** using Windows Security Event ID 5140 collected directly from file servers.

Snaffler and similar tools aggressively enumerate file shares looking for sensitive data like credentials, config files, and documents. Instead of looking for the tool itself, this detection focuses on the behavior: a single user or IP rapidly accessing a large number of shares and paths in a short period of time.

If someone is touching hundreds of folders across dozens of shares within minutes, that’s not normal user behavior.


## MITRE Technique

**T1039 – Data from Network Shared Drive**

Attackers often crawl file shares after gaining initial access. The goal is simple: find sensitive files fast. Enumeration of shared drives is a common post-exploitation step before staging data for exfiltration.


## Detection Logic

The logic focuses on Event ID 5140, which logs  access attempts to shared folders.

Instead of looking at individual events, the query groups activity into 10-minute windows and evaluates:

* Total share access events
* Number of unique shares accessed
* Number of unique relative paths touched

If a single user or source IP exceeds one of the following thresholds within 10 minutes:

* 15 or more unique shares
* 200 or more unique paths
* 500 or more total share access events

…it gets flagged for review.

Severity increases as those numbers climb.

This approach catches high-volume crawling without relying on process telemetry or EDR visibility.


## Splunk Query

```spl
index=wineventlog source="WinEventLog:Security" sourcetype="WinEventLog" EventCode=5140
| eval src_ip=coalesce(Source_Address, src_ip, IpAddress, ClientAddress)
| eval user=coalesce(Account_Name, user, SubjectUserName)
| where NOT user IN ("vulnerability-scanner", "DLP-tool")
| eval share=coalesce(ShareName, Share_Name)
| eval relpath=coalesce(RelativeTargetName, Relative_Target_Name)
| where isnotnull(src_ip) AND src_ip!="" AND src_ip!="-"
| where isnotnull(user) AND user!=""
| where isnotnull(share) AND share!=""

| bin _time span=10m
| stats
    count AS share_access_events
    dc(share) AS unique_shares
    dc(relpath) AS unique_paths
    values(share) AS shares
    earliest(_time) AS first_time
    latest(_time) AS last_time
  by src_ip, user, _time

| eval first_time=strftime(first_time,"%Y-%m-%d %H:%M:%S"),
       last_time=strftime(last_time,"%Y-%m-%d %H:%M:%S")

| where unique_shares>=15 OR unique_paths>=200 OR share_access_events>=500

| eval detection_name="Snaffler-like SMB crawling (5140)",
       severity=case(unique_shares>=30 OR unique_paths>=500,"high",
                     unique_shares>=20 OR unique_paths>=300,"medium",
                     true(),"low"),
       risk_score=case(severity="high",85, severity="medium",65, true(),45)

| fields _time, src_ip, user, share_access_events, unique_shares, unique_paths, first_time, last_time, shares, detection_name, severity, risk_score
| sort -unique_paths
```


## Notes on Blind Spots

This detection depends entirely on Windows Security logs being enabled and forwarded from file servers. If 5140 logging is disabled or logs are tampered with, this won’t catch anything.

It also assumes that high-volume share traversal within short time windows is abnormal. 


## What Could Trigger a False Positive

Some legitimate activities that might look similar:

* Vulnerability scanners
* Data loss prevention tools
* Backup software

Service accounts tied to scanning tools should be excluded where possible.


## Response Tips

If this fires:

* Identify the source IP and user account.
* Confirm whether the account is tied to a scanning tool or automation job.
* Look at authentication logs around the same time window. Do you notice any Remote Interactive logins?
* Check for on-going connections with the user/client responsible.

If it looks malicious:

* Isolate the source.
* Disable or reset the account.
* Scope other hosts accessed by the same user.
* Review for signs of staging or exfiltration.


## Takeaways

Snaffler doesn’t need to exploit anything. It just reads what’s already exposed.

High-volume share crawling is one of the clearest signals of internal reconnaissance. By grouping Event ID 5140 activity over short time windows and measuring share and path, you can catch data discovery behavior before it turns into exfiltration.

You don’t need the tool signature. You just need the behavior.


## References

[MITRE ATT&CK T1039](https://attack.mitre.org/techniques/T1039/)

[Windows Event ID 5140](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventid=5140)

[Snaffler](https://github.com/SnaffCon/Snaffler)
