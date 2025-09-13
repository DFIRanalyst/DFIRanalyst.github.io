---
title: "Detecting Password Spray Attempts on Citrix NetScaler"
date: 2024-12-15 18:15:00 +0000
categories: [Splunk]
tags: [T1110, Password Spray, Brute Force, NetScaler, SPL, Citrix, Detection Engineering]
---

## Summary

Password spraying continues to be one of the more effective and low-noise brute force techniques out there. Instead of hammering one account with many passwords, attackers flip the tactic and try a few common passwords across many accounts.

This detection focuses on identifying password spray attempts against Citrix NetScaler by monitoring failed login events and flagging abnormal patterns. It gives you early insight into brute force activity that may otherwise fly under the radar.

What made this one stand out is that shortly after I built and deployed the detection, Citrix released an advisory detailing mass ongoing password spray campaigns against NetScaler appliances. 

## MITRE Technique

- **T1110.003 – Brute Force: Password Spraying**
  
This technique involves attempting a small set of commonly used passwords across many user accounts, often targeting externally exposed services.

## Detection Logic

The idea is simple: look for multiple failed login attempts tied to a single user, coming from different IPs or within a short time frame. In this case, we focus on users who have more than 4 failed login attempts, which could suggest password spraying activity.

## SPL Query

```spl
index=NetScaler (citrix_netscaler_event_name=LOGIN_FAILED)
| eval Client_ip=if(citrix_netscaler_event_name="LOGIN_FAILED", Client_ip, null())
| stats count(eval(citrix_netscaler_event_name="LOGIN_FAILED")) AS failed_attempts, latest(_time) AS last_attempt_time, values(Client_ip) AS failed_login_ips by user
| eval last_attempt_time = strftime(last_attempt_time, "%Y-%m-%d, %H:%M:%S")
| eval potential_password_spray=if(failed_attempts > 4, "Yes", "No")
| table last_attempt_time, failed_login_ips, user, failed_attempts, potential_password_spray
```

## Notes on Blind Spots

This detection relies on clean and complete NetScaler logs. If event forwarding breaks, logging is disabled, or tampered with, the detection won’t fire. Also, this logic assumes that failed login attempts are infrequent during normal use. 

## What Could Trigger a False Positive

Common triggers for false positives:

  - Typing errors by end users

  - Vulnerability management tools


## Validation

This detection was built and tested internally, but its real value showed up once Citrix publicly disclosed that NetScaler appliances were being targeted by active password spraying campaigns. The patterns in the environment matched what was described, including low-and-slow attempts and scattered IPs targeting multiple user accounts.

## Response Tips

If the detection fires, start by checking the following:

  - Review the failed login timestamps and source IPs

  - Look at what usernames were targeted (are they targeting admin accounts?)

  - Check if the affected accounts were actually accessed

If it looks malicious:

  - Block the source IP (or IP range) 

  - Reset or temporarily disable affected user accounts

  - Notify impacted users and monitor for further login activity

  - Review firewall and VPN logs to check for related attempts else where in the environment

## Takeaways

Password spraying is subtle but powerful, especially against exposed login portals. This detection offers early visibility into those attacks, and it proved effective when similar real world activity hit the environment mirroring Citrix's advisory. Staying on top of vendor alerts and tuning detections to match evolving tactics can pay off fast.

## References

[MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/003/)

[Citrix Advisory: NetScaler Password Spray Attacks](https://www.bleepingcomputer.com/news/security/citrix-shares-mitigations-for-ongoing-netscaler-password-spray-attacks/)

[Citrix: NetScaler Logging Documentation](https://developer-docs.netscaler.com/en-us/netscaler-syslog-message-reference.html)
