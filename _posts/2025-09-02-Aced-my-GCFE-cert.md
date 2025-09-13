---
title: "Crushed the GCFE with a 93 but here’s what actually matters"
date: 2025-09-02 22:00:00 -0400
categories: [Certifications, DFIR]
tags: [GCFE, DFIR, Insider Threat, SRUM, Windows Forensics, Forensic Analysis]
---

## Summary

Just wrapped up the **GCFE** and passed with a 93%. The real win wasn’t the score though but it was how much I took away that I can actually use in the field.

This cert wasn’t just about learning where artifacts live. It was about learning how to piece them together to tell a full story about what happened on a system. Especially when you’re dealing with insider threats or potential misuse of local accounts, the real value comes from knowing how to build a behavioral profile from what's left behind.

## Profiling the Device and User

What stuck with me the most was how much emphasis GCFE puts on **understanding behavior**, not just events. You're not just hunting for single timestamps or events. You're stacking things like:

* What programs were run.
* What files were accessed. 
  - To understand what the user was working on or potentially exfiltrating.
* What external devices were plugged in. 
  - To catch activity like file transfers, portable media usage, or attempts to bypass network controls.
* What elements the user interacted with. 
  - To piece together user intent.

That kind of timeline building is exactly what’s needed during an insider threat investigation or any post-breach analysis. It gives you the ability to say, "Here's what the user did over this period and here’s why it matters."

## SRUM’s a Game Changer When Telemetry’s Gone

If you’ve ever dealt with an endpoint that didn’t have an EDR agent, or where logs were wiped, **SRUM (System Resource Usage Monitor)** might be your new best friend, well it's sure going to be mine!

SRUM can tell you:

* What apps were running
* When they were launched
* Whether they reached out to the internet (down to the bytes downloaded/uploaded)
* How long each program ran 

That’s a big step up from something like Prefetch, which only tells you that an application was executed but not whether it connected to the internet, not how long it ran, and definitely not how it behaved. In short, SRUM helps fill the gaps. The kind you run into all the time during an investigation, like realizing your security tools weren’t even deployed to a machine after an incident has already happened.

## Takeaways

GCFE gave me way more than I expected. The kind of skills that actually help when trying to answer “Was this activity normal?” or “Did this user actually launch this file?”

If you're in DFIR or doing any internal investigations, this cert is worth it!

