---
title: "Leveling Up Visibility with Windows Event Forwarding"
date: 2025-11-24 10:00:00 -0500
categories: [Detection Engineering]
tags: [WEF, Windows Logging, Splunk, Detection Visibility, SIEM, PowerShell, Log Gap, TaskScheduler, Windows Event Forwarding]
---

## Summary ##

After weeks of configuring, tweaking, and troubleshooting, I finally got my **Windows Event Forwarding (WEF) project** working end-to-end in a test OU. Process Creation events (4688), Scheduled Task activity (201/129), and even Named Pipe IPC from PowerShell (53504) are now forwarding successfully to the central collector.

But getting WEF to work is just the beginning. The real value comes from deciding _what_ to forward, _why_ you're forwarding it, and _what detections you can build_ from the resulting data.

Below is a quick breakdown of what I tested and a tase of some events that are now flowing in.

<br>
<br>

## What Is Windows Event Forwarding? ##

Windows Event Forwarding lets you **collect logs from endpoints and servers without installing any agents**. It uses built-in services like WinRM and the Windows Event Collector (WEC) to forward logs to a central server.

What you can do is use WEF to:

- Collect high-value logs that Defender might miss or overwrite  
- Centralize logs from endpoints not enrolled in Defender  
- Build custom detection logic in Splunk or other SIEMs

<br>
<br>

## Why This Matters

Even if EDR/XDR is running on your endpoints, its native logging can fall short. A lot of key forensic artifacts either aren’t captured by default or are only stored for a limited time. That includes things like:

- 4104: PowerShell script block logs
- 4688: Process creation events
- 1102: Audit log cleared
- Task Scheduler and Service Control Manager events
- 5140: File share access attempts

Windows Event Forwarding (WEF) fills those gaps. It gives you the ability to centrally collect and retain these logs, which helps with detection, investigation, and correlation across multiple hosts during an incident. It’s not just about seeing that something happened, it’s about having enough context to understand how and why it happened.

<br>
<br>

## Not a Full Setup Guide

This post isn’t meant to walk through every step of configuring and deploying Windows Event Forwarding. There are already solid guides out there that cover GPOs, subscriptions, firewall rules, and WinRM. Instead, this is about why WEF matters, how it can close real-world gaps in logging, and an example of what events may be worth forwarding to your SIEM.

---

<br>
<br>

## GPO Configuration and Deployment ##

Getting logs off the endpoint starts with Group Policy. You use GPO to:

- Enable and configure **Windows Remote Management (WinRM)**, which WEF depends on for communication
- Push the **WEF subscription templates and server URI** to the target hosts so they know where to send logs and what logs to capture.
- Enable advanced audit settings like **process creation**, **logon events**, or **PowerShell activity** 
- Give the Event Forwarding service permission to read **the Security log** so they're accessible to the Event Forwarding service. 
  
It’s not just about collecting logs, it’s about making sure those logs exist in the first place and can be forwarded cleanly.

<br>
<br>

## Here are some examples of forwarded events from my deployment ##

Once forwarding is configured, logs show up under the `Forwarded Events` channel in Event Viewer on the collector.


### Process Creation - Event ID 4688

![WEF - Event ID 4688 Process Creation](/assets/img/wef_4688_proc.png)

This event is critical for detecting execution activity, especially when cross-referenced with Scriptblock logging.

### Scriptblock logging - Event ID 4104

![WEF - Event ID 4104 PowerShell scriptblock](/assets/img/wef_4104.png)

With 4688 you get every process launch and its parent-child chain, perfect for tracking how something started. Add 4104, and now you can see the PowerShell blocks that actually ran. Together, they give you both the how and the what of script execution.


<br>

---


### PowerShell Named Pipe IPC - Event ID 53504

![WEF - Event ID 53504 Named Pipe](/assets/img/wef_namedpipe.png)

This isn’t a default log, but a useful one if you're monitoring for behaviors like **remote PowerShell**, **lateral movement**, or **C2-like activity** using named pipes.

<br>

---

### Scheduled Task Activity - Event ID 201/129

![WEF - Event ID 201 Task Scheduler](/assets/img/wef_taskscheduler.png)

Scheduled Task logs can be used to detect persistence, staging activity, or even lateral movement.

<br>
<br>

## Validating WEF Collection ##

You can confirm events are flowing in several ways:

- Open **Event Viewer > Forwarded Events** on your collector
- Search for the event IDs you targeted (like 4688, 4103, 129, 201, etc.)

If you’re not seeing logs after confirming the source system is online and in-scope, check the subscription and network connectivity.

<br>
<br>

## Cleaner Results with Filtering

If you want to avoid noisy logs (like SYSTEM account chatter), suppress well-known SIDs like `S-1-5-18`. Helps highlight real user-driven activity.

<br>
<br>

## What to Do Next ##

Now that logs are coming in, here’s how you can take action:

- Forward to your SIEM for alerting and correlation. (In my case I chose to install Splunk's Universal Forwarder to get the logs into our Splunk SIEM)
- Start creating detections for **suspicious scheduled tasks**, **PowerShell behavior**, or **named pipe abuse**
- Build dashboards to track event frequency by device, time, or user

<br>
<br>

---

## Final Thoughts ##

WEF takes a bit of setup, but once it’s running, it gives you powerful visibility without adding agents to your systems. Whether you’re operating in a constrained environment or just want richer telemetry from servers, it’s worth the effort.

And the best part? It’s all native to Windows.

<br>
<br>

## References

[WEF for network for network defense](https://blog.palantir.com/windows-event-forwarding-for-network-defense-cb208d5ff86f)

[PowerShell](https://redcanary.com/threat-detection-report/techniques/powershell/)

[Guide to WEF and NTLMv1 monitoring](https://michaelwaterman.nl/2024/06/29/step-by-step-guide-to-windows-event-forwarding-and-ntlmv1-monitoring/)

[Use Windows Event Forwarding to help with intrusion detection](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
