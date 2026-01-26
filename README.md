# NTLM-Must-Die

https://techcommunity.microsoft.com/blog/microsoftsentinelblog/azure-sentinel-insecure-protocols-workbook-implementation-guide/1197564

## 🚀 Quick Start: Practical Resources

**Ready to take action?** Check out the [`/resources`](./resources/) directory for practical tools and guides:

- **[KQL Queries](./resources/KQL/)** - Detection and monitoring queries for Microsoft Sentinel
- **[PowerShell Scripts](./resources/PowerShell/)** - Automation scripts for auditing and hardening
- **[Azure Arc Guides](./resources/AzureArc/)** - Setup guides for hybrid environment monitoring
- **[Checklists](./resources/Checklists/)** - Phase-by-phase implementation checklists
- **[Detection Rules](./resources/DetectionRules/)** - SIEM rules for NTLM attack detection
- **[Group Policies](./resources/Policies/)** - GPO templates for NTLM hardening

�� **Start here**: [Resources Overview](./resources/README.md)

---

## Overview

NTLM has long been a cornerstone of Windows authentication—but in today’s threat landscape, it’s become a liability. With its outdated cryptographic design and lack of mutual authentication, NTLM (especially NTLMv1) is a prime target for credential theft, relay attacks, and pass-the-hash techniques. Even NTLMv2, while more secure, remains vulnerable if not properly hardened.

In this article, we explore how we conducted a full NTLM usage assessment across the enterprise, identified active attack patterns, and implemented a hardening strategy using Microsoft Sentinel and MCP Server. From auditing and detection to risk mitigation and roadmap planning, this summary outlines the key findings, defensive measures, and actionable steps to phase out NTLM and strengthen identity security. 

Disabling NTLM in Enterprise Environments: Attacks, Defenses & Detection

Article content
NTLM Under Attack: How Adversaries Exploit It

NTLM’s design weaknesses make it a target for several well-known attacks:

Article content
Why NTLM is vulnerable: NTLM (notably v1) uses outdated cryptography and does not do mutual authentication. NTLMv1 relies on the DES cipher and MD4 hashing (“bad, bad, bad” by modern standards), making its responses easy to crack. It also lacks channel binding or server authentication, so a client will trust any server challenge – enabling the relay attacks. Microsoft openly warns that continued use of NTLMv1 poses a serious security risk, as it is a common avenue for credential theft and lateral movement in attacks. Even NTLMv2, while using HMAC-MD5 (far better than NTLMv1’s DES), is still susceptible to relay if additional protections (signing, encryption) aren’t enforced. In short, NTLM doesn’t verify who you’re talking to and can be tricked or cracked; Kerberos, by contrast, performs mutual authentication and uses stronger encryption, so it should be used wherever possible.

Defensive Measures: Protecting Against NTLM-Based Attacks

To secure your environment, the strategy is: reduce NTLM usage to the absolute minimum, eliminate NTLMv1 entirely, and harden everything against NTLM attacks. Microsoft’s recommended best practices include:

Article content
In addition to these steps, protect credential material to mitigate pass-the-hash:

Credential Guard (available in Windows Enterprise) virtualizes the LSASS process so that NTLM hashes aren’t stored in memory. Microsoft notes that Credential Guard automatically disables NTLMv1 and greatly reduces theft of NTLM hashes.
Use the Protected Users AD group for highly privileged accounts – members of this group cannot authenticate with NTLM at all, only Kerberos (among other restrictions).
Ensure strong, regularly changed passwords for accounts to make NTLM hash cracking impractical, and use multifactor authentication for remote access (to limit usefulness of stolen hashes).
Consider disabling NTLM for local accounts via Group Policy and using unique local admin passwords (with tools like LAPS) to prevent lateral movement with stolen local hashes.

These best practices, many of which are highlighted in Microsoft’s official guidance, will significantly reduce the attack surface. Ultimately, the goal is to reach a state where NTLM (especially NTLMv1) is rarely used or outright disabled, so attackers cannot leverage it. Any legacy systems that insist on NTLM should be isolated or updated – as one Microsoft article bluntly states, “Customers are strongly advised to phase out NTLMv1. Use of the NTLMv1 protocol has a definite, adverse effect on network security and may be compromised.”.

Auditing NTLM Usage and Distinguishing NTLMv1 vs NTLMv2

Before pulling the plug on NTLM, you need to identify where NTLM is still in use – and whether it’s NTLMv1 or v2 – so you can remediate or monitor those instances. Windows provides event logs and tools for this purpose:

Domain Controller Logs (4776): Every time a DC validates NTLM credentials, it logs an event ID 4776 (Audit Credential Validation) with the username and source workstation. By tracking 4776 events, you get a count of NTLM authentications hitting your DCs. This is great for measuring volume (baseline how often NTLM is used per day), but it doesn’t show NTLM version or target server.
Server Logs (4624): On the actual server or computer where an NTLM logon occurred, you’ll see an event ID 4624 (“Account successfully logged on”). In that event’s details is a field “Package Name (NTLM only)” which will show “NTLM V1” or “NTLM V2” when NTLM was used. This is the key to spotting NTLMv1 usage: collecting all 4624 events from servers and filtering for “NTLM V1”. Microsoft’s guidance suggests using a SIEM or Windows Event Forwarding to centralize these events, then search for any occurrence of NTLM V1. If none are found over your monitoring period, you can be confident NTLMv1 is truly gone. If you do find NTLMv1 events, you’ve pinpointed a legacy client or config that needs attention. (Common culprits include old printers, NAS devices, or outdated OS instances.)
NTLM Operational Log (8001-8004 events): By enabling detailed NTLM auditing in Group Policy, Windows will log events in the NTLM Operational log that trace NTLM authentication flows. For example, Event 8004 on a DC shows an NTLM logon and even which server it was for, while event 8001 on a client shows which process initiated the NTLM auth (e.g. a browser). These can be used to debug why NTLM happened (which application) and are helpful for cleanup. Newer Windows versions (Win11 24H2, Server 2025) even introduce enhanced events 4020/4032 that let a DC log NTLM version directly – making NTLMv1 detection easier.
SIEM/Sentinel: Feeding these logs into a SIEM like Microsoft Sentinel can greatly simplify analysis. Sentinel’s Insecure Protocols Workbook provides a dashboard view of legacy auth protocols – it highlights occurrences of NTLMv1, LM, etc., over time.

Article content
https://techcommunity.microsoft.com/blog/microsoftsentinelblog/azure-sentinel-insecure-protocols-workbook-implementation-guide/1197564

By auditing for a few weeks, you can compile a list of systems using NTLM and address them one by one. Pay particular attention to service accounts: if you find, for example, that a service account is always logging in via NTLM from Server X to Server Y, that’s a candidate to reconfigure for Kerberos (perhaps an SPN is missing). Microsoft Defender for Identity can help flag such patterns as well (identifying accounts that frequently use NTLM).

NTLMv1 vs NTLMv2 – Know the Difference: It’s crucial to identify NTLMv1 usage because of how much weaker it is. Here’s a quick comparison:

 

Article content
In summary, audit first, then act. Often organizations are surprised to discover a significant amount of NTLM traffic they weren’t aware of. Use the logs to drive remediation: disable NTLMv1 (you can do this relatively quickly once you prove no one needs it), then chip away at NTLMv2 usage by fixing the underlying causes (application config, old hardware, etc.). As you implement the protections from the previous section (policies to deny NTLM), keep auditing to verify nothing critical breaks and to track progress (you should see NTLM event counts plummeting!). This audit-and-remediate cycle is exactly what Microsoft recommends before flipping that switch to block NTLM domain-wide.

Microsoft Tools to Detect and Monitor NTLM Usage

Before you can eliminate NTLM, you need to see it. Visibility is everything — and Microsoft provides a powerful stack of tools to help you identify where NTLM is still in use, who’s using it, and how it’s being abused.

Here’s how we leveraged Microsoft’s ecosystem to get a full picture of NTLM activity across our environment:

🔍 Microsoft Sentinel

Microsoft Sentinel acts as the central nervous system for NTLM detection. By ingesting logs from domain controllers, endpoints, it allows us to:

Detect NTLM authentication attempts (successes and failures)
Correlate events across devices, users, and IPs
Visualize NTLMv1 vs NTLMv2 usage with the Insecure Protocols Workbook
Trigger alerts for brute-force, credential stuffing, and anomalous NTLM behavior

We used custom KQL queries to track NTLM usage by logon type, source IP, and account — and to detect high-volume failures, privileged account usage, and after-hours activity.

🛡️ Microsoft Defender for Identity (MDI)

MDI gave us deep visibility into NTLM usage at the domain controller level. It helped us:

Detect NTLM authentications from service accounts
Identify NTLM relay and pass-the-hash attempts
Monitor NTLM usage by privileged or sensitive accounts
Map authentication flows between source and target systems

MDI’s Service Account Discovery module was especially helpful in identifying non-human identities using NTLM — a common blind spot in many environments.

💻 Microsoft Defender for Endpoint (MDE)

MDE provided endpoint-level telemetry, helping us:

Detect NTLM authentication attempts initiated by local processes
Identify which applications or services were using NTLM
Surface password spray and brute-force patterns
Integrate NTLM-related risks into Secure Score for prioritization

This was key in identifying fallback behavior on user workstations and lab environments.

📁 Windows Event Logs

We also relied on native Windows logs to track NTLM activity:

Event ID 4624: Successful logons (includes NTLM version)
Event ID 4625: Failed logons
Event ID 4776: Credential validation on domain controllers
Event IDs 8001–8004: NTLM Operational logs (detailed NTLM flow)

These logs gave us granular insight into who was using NTLM, from where, and how often — and helped us distinguish between NTLMv1 and NTLMv2.

☁️ Azure AD Sign-In Logs

In hybrid environments, Azure AD Sign-In Logs helped us detect:

Legacy authentication attempts using NTLM
Conditional Access failures due to unsupported protocols
Risky sign-ins from unmanaged or legacy clients

🧠 By combining these tools, we built a layered detection strategy that gave us full-spectrum visibility — from endpoints to domain controllers to the cloud. This visibility was the foundation for our NTLM deprecation roadmap and allowed us to take action with confidence.

By leveraging these tools together, you get layered defense. For example, Sentinel can correlate an MDI alert (e.g., “NTLM Relay attack detected”) with an MDE alert (“Suspicious NTLM traffic on host X”) into a single incident, so you have full context to respond. Meanwhile, the Secure Score recommendations from MDE and MDI will keep nudging you towards the end goal: no NTLMv1 anywhere, and no unnecessary NTLMv2 either.

·       Microsoft Defender for Identity  includes a Service Account Discovery module that automatically identifies and classifies service accounts in Active Directory. This helps security teams see non-human identities such as service accounts — which often have elevated privileges but lack protections like MFA — that are commonly overlooked and targeted by attackers.

·       The new capability automatically discovers service accounts (including gMSA and sMSA, as well as user accounts acting as service identities) and inventories them within the Defender portal.

·       For each discovered account, teams get contextual details such as recent authentications, sources and destinations, privileges, and activity timelines.

·       A Connections tab shows how these accounts interact with machines and services, helping SOC teams spot unusual behavior.

·       The feature exposes service account tags into Advanced Hunting (IdentityInfo), enabling custom detections and automation.

·       Integration with privileged access management (PAM) tools adds privileged tagging and support for automated password rotation.

 

Article content
Article content
In conclusion, disabling NTLM is a journey that involves understanding the attack vectors, implementing technical controls to mitigate those attacks, and continuously monitoring to ensure old habits die out. The effort is well worth it: you remove a whole class of vulnerabilities (no more easy relay or hash-stealing attacks). Microsoft’s official guidance and tools are there to support this journey – from identifying where you are most exposed, to enforcing stronger settings, to catching attackers who try to exploit NTLM in the meantime. NTLM (especially v1) has to go. By adopting these best practices and using tools like Sentinel, Defender for Endpoint, and Defender for Identity, an enterprise can confidently hit “disable” on NTLM and close one of the oldest doors attackers still like to pry open. 

NTLM Under Attack: Usage Assessment and Hardening Strategy using Sentinel with MCP Server – This is a summary and not the complete report

Article content
Article content
 1. Top Accounts Using NTLM (Legitimate Use)

Despite the attack traffic, legitimate NTLM usage is minimal: only 66 successful NTLM network logons in the past 30 days. These were confined to a few known accounts:

Lab VM Users: Accounts like User1 and User3 on the lab machine vm-win11-1 used NTLM for local resource access (36 and 14 logons respectively). This suggests a test environment or fallback to NTLM for local authentication. Risk: Low (isolated lab), but we should monitor and eventually enforce Kerberos even in labs.
Service Account: svcadmin on ASHTravel-Apps (an application server) made 6 NTLM logons. This indicates an app or service authenticating with NTLM instead of Kerberos. Risk: Medium – service accounts using NTLM can be targeted by attackers. Recommendation: Register SPNs and migrate svcadmin to a Group Managed Service Account (gMSA) with Kerberos auth.
User Workstation: lydiab on lydiab-pc had 6 NTLM logons, likely an interactive login falling back to NTLM. Risk: Low – possibly due to a network configuration issue or remote access using NTLM. Ensure the PC can use Kerberos (e.g., correct DNS/SPN usage) to avoid NTLM fallback.

Key Takeaway: Only a handful of accounts are using NTLM legitimately (one service account and a couple of local users). This small set makes it feasible to eliminate NTLM by fixing those specific use cases (migrate the service account to Kerberos, adjust the lab and user environment settings). We’ve already identified each by name, so targeted remediation is possible.

2. Threat Detection: Active Attacks on NTLM

🚨 Active Brute-Force Campaign: The analysis shows an ongoing credential stuffing/password spraying attack against NTLM authentication. In the last 30 days, there were 843,905 failed NTLM logon attempts originating from 502 unique IP addresses. Virtually all were unsuccessful (99.99% failure rate) – a testament to strong passwords or the attackers not hitting a valid credential – but the sheer volume is critical.

Article content
Attack pattern: Virtually all attempts are targeting common administrative usernames: e.g., “Administrator” (and case variants), “Admin”, “USER”, etc. The default Administrator account (in various forms) was hit over 300k times combined across several hostname contexts. This clearly indicates the attackers are trying a broad set of likely privileged accounts with many password guesses (a classic password spray/credential-stuffing approach). The attack is distributed – over 500 source IPs from multiple countries (Russia, France, Germany, etc.) were involved, suggesting a botnet or network of compromised systems.

Failure rate: Importantly, none of these attempts have succeeded so far – all are recorded as failed logons (Event ID 4625). The attack success rate is effectively 0% (only 0.008% of NTLM attempts were successful, and those were the known legitimate ones). This means no confirmed breach yet, but the threat is real and persistent.

Attacker focus: The volume was fairly steady at ~25-30k attempts per day, spiking to 74k on Dec 21. Attacks continued into January, though by Jan 15 dropped to ~7k (possibly due to initial blocking actions or attacker tapering). The sustained nature (30 days straight) indicates the attackers are not deterred. They are likely rotating through password lists (“credential stuffing” suggests they could be trying passwords from leaked databases). This aligns with MITRE ATT&CK T1110.003 (Password Spraying) and T1110.004 (Credential Stuffing) – both observed at critical levels.

Article content
MITRE ATT&CK Mapping: This attack primarily maps to Brute Force techniques (Password Spraying T1110.003, Credential Stuffing T1110.004) – both assessed as 🔴 Critical due to the scale. The persistent targeting of admin accounts relates to Valid Accounts (Attempted) T1078. And while no lateral movement was successful, the presence of NTLM implies a risk of Pass-the-Hash T1550.002 if an account is compromised. The use of NTLM (network logon Type 3) suggests attempts over SMB, aligning with Remote Services T1021.002 (SMB/Windows Admin Shares).

3. NTLM Usage Trends

Despite the intense attack, overall NTLM authentication activity shows a slight downward trend in recent days, possibly due to initial mitigation steps:

Peak Attack – On Dec 21, 2025, the system logged 74,214 NTLM attempts (all failures), the highest in the period.
Steady State – Throughout late Dec and early Jan, daily NTLM attempts ranged between ~20,000–30,000 attempts per day.
Recent Decline – By Jan 15, 2026, daily attempts dropped to 6,936 (perhaps after blocking some attacker IPs or simply attacker fatigue). The failure rate remained 100% on that day as well.

Article content
The chart below illustrates the daily NTLM authentication attempts over the 30-day period, highlighting the attack’s peak and the subsequent decline:

Article content
 Daily NTLM Authentication Attempts (Success vs Failure). The red arrow marks the peak attack day on Dec 21, 2025.

The sustained attack and minor recent drop suggest that while some defensive actions may be helping, the threat actors are still active. We should remain vigilant and continue hardening (as detailed in subsequent sections) to drive that attack number to zero.

4. MITRE ATT&CK Mapping and Attack Chain

Threat Techniques Observed: The NTLM attack activity was mapped against the MITRE ATT&CK framework. Key techniques and their severities include:

T1110.003 – Password Spraying: Attackers tried a few passwords against many accounts (e.g., using common passwords on Administrator accounts), yielding 843k failed attempts. (Severity: Critical).
T1110.004 – Credential Stuffing: At least one IP was likely testing credentials from leaks (226k attempts from a single IP). (Severity: Critical).
T1078 – Valid Accounts (Attempted): Repeated login attempts to default admin accounts indicate attempts to use valid credentials illicitly. (Severity: Critical).
T1550.002 – Pass-the-Hash (Potential): NTLM’s design could allow Pass-the-Hash if a hash were obtained. No evidence of PtH occurred, but the risk exists with NTLM enabled. (Severity: Medium).
T1021.002 – Remote Services (SMB): The use of network logon (Type 3) and targeting of admin shares implies the attackers were attempting lateral movement via SMB or RPC if credentials were cracked. (Severity: Medium).

Attack Chain Recap: The likely attack chain starts with Initial Access attempts via password spray, moves to Credential Access by stuffing known passwords, and could lead to Lateral Movement via pass-the-hash if any account was compromised. Thankfully, in our case, the chain was interrupted at step 1/2 (no credential compromise occurred). However, it validates our defensive focus on those stages (preventing successful brute-force and detecting any abnormal credential use immediately).

5. Top 30 IPs to Block & Vulnerable Accounts

Blocking Attack Sources: We identified the Top 30 malicious IP addresses responsible for the bulk of NTLM attacks and have implemented blocks for them at our firewall. These include the Russian and European IPs mentioned earlier (91.238.181.134, 37.187.24.235, 88.214.25.169, etc.) as well as others from Asia and North America. By blocking these 30 IPs, we expect to cut off 80–90% of the malicious traffic. (We will continue to monitor in case the attackers rotate to new IPs.)

Securing Administrator Accounts: The brute-force attempts overwhelmingly targeted accounts named “Administrator” (in various forms and host contexts). As an immediate mitigation, we have:

Renamed default Admin accounts on critical systems to non-standard names.
Disabled unused built-in Administrators where possible.
Implemented Account Lockout policies (e.g., lock out after 5 bad attempts) to thwart unlimited password guessing. This ensures that even if some IPs aren’t blocked, they can’t hammer away at an account indefinitely without locking it.
Created decoy “Administrator” accounts with no privileges (honeypots) to alert us if someone tries to use them.

These steps address the fact that our environment had multiple systems with an account named “Administrator” that was being hammered (including “ALPINE-SRV1\Administrator” which saw ~129k attempts). Renaming and lockouts significantly reduce the chance of a successful guess.

Article content
Vulnerable Accounts Identified: Besides “Administrator,” we saw others like “ADMIN” and “user” being targeted (likely generic names). We’ll review if any actual accounts match those names and secure them accordingly. One service account (svcadmin) was using NTLM (as discussed in Section 1) – while it wasn’t targeted in this attack, we consider it a vulnerable account if attackers ever learn of it. Migrating it off NTLM will close that opportunity.

 6. Monitoring & Detection Rules

To stay ahead of these attacks, we have implemented and fine-tuned several SIEM detection rules in Microsoft Sentinel (and our on-premises logging):

Sentinel Detection Rules (KQL Queries)

Here’s a clean and visually engaging table summarizing the NTLM alert rules you described. This format is optimized for LinkedIn articles or Word documents:

🚨 NTLM Alert Rules Summary

Article content
 

Article content
 These detection rules leverage Windows Security Event logs (4624, 4625 events) and Identity logs, and are correlated in Sentinel. We have also integrated signals from Microsoft Defender for Endpoint and Defender for Identity for enhanced detection:

Defender for Endpoint alerts on NTLM password spray behavior at the host/network level (it uses its sensor to detect multiple failed authentications).
Defender for Identity will alert on things like pass-the-hash attempts or NTLM relays in real time, which Sentinel can consume and escalate.

7. Risk Register Highlights

We assessed and recorded the key risks related to NTLM in a Risk Register. Each risk is scored by likelihood and impact:

NTLM-001: Brute-Force Compromise – Likelihood: Medium, Impact: Critical. Risk: HIGH (🔴). This is the risk that an attacker eventually guesses a password via NTLM. Mitigations (account lockout, IP blocks) are In Progress and already reducing this risk.
NTLM-005: Credential Theft (Pass-the-Hash) – Likelihood: Medium, Impact: Critical. Risk: HIGH (🔴). If an attacker breaches a machine, NTLM hashes could be stolen from memory. We plan to mitigate this by deploying Credential Guard and enforcing Kerberos-only for admins (Protected Users group).
NTLM-003: NTLM Relay Attack – Likelihood: Medium, Impact: High. Risk: Medium (🟡). Although we haven’t seen this yet, an NTLM relay (e.g., via missing SMB signing) could allow an attacker to impersonate a server. We marked this as “Not Started” but will address by requiring signing on all SMB/LDAP (most of which is done; domain controllers already enforce LDAP/SMB signing).
NTLM-002: Lateral Movement via Pass-the-Hash – Likelihood: Low, Impact: Critical. Risk: Medium (🟡). This overlaps with NTLM-005 – basically, if a hash is stolen (005), the attacker using it to move laterally is 002. We have “Planned” mitigations (same as 005).
NTLM-004: Service Account NTLM Weakness – Likelihood: Low, Impact: High. Risk: Medium (🟡). This acknowledges that the service account svcadmin using NTLM could be compromised via NTLM. It’s “Planned” to be remediated by migrating that account to Kerberos (gMSA) – which will eliminate that risk entirely.

Each risk above corresponds to an item in our action plan. By the end of our 12-month roadmap, our goal is to have all these risks lowered to Low (🟢) by either removing NTLM or implementing compensating controls.

8. Target Metrics for 12-Month Hardening

We’ve set clear target metrics to measure success over the next year in eliminating NTLM and stopping attacks. Key performance indicators:

Article content
Planned progress checkpoints: Within 3 months, we aim to reduce NTLM events by 50% (through blocking and policy changes), and eliminate all privileged account NTLM usage. By 6 months, service accounts should be off NTLM and total events down to a trickle. By 12 months, NTLM should be virtually gone from the environment, aside from perhaps a few controlled exceptions, and any NTLM activity will be treated as an anomaly (or attack).

We will report on these metrics quarterly to track our progress. This not only improves security but also aligns with compliance best practices (e.g., NIST suggesting strong auth, PCI DSS requiring no legacy auth without MFA).

9. Kerberos vs. NTLM: Why This Matters

A quick comparison of NTLM vs. Kerberos helps illustrate why moving away from NTLM is critical:

Article content
In short, Kerberos is far superior for enterprise authentication: it’s more secure against MITM and credential theft, and more efficient. Our environment already heavily uses Kerberos (as seen by the low NTLM legit usage), which is good. The goal is to make NTLM a last-resort or nonexistent. By eliminating NTLM, we remove the possibility of pass-the-hash and greatly reduce the attack surface that the current brute-force campaign is abusing.

10. Conclusion and Next Steps

This assessment uncovered a high-volume NTLM attack in progress but also provided reassurance that our defenses (strong passwords, no NTLMv1, etc.) are holding the line so far. It also highlighted how close we are to operating without NTLM – only a handful of use cases remain.

Executive Summary of Actions:

🔴 Immediate (Done): Blocked the top attacker IPs, enabled strict account lockout policies, and secured default admin accounts (renamed/disabling and honeytokens). These steps should drastically curtail the ongoing attack in the short term.
🟡 Short-Term (In Progress, 1-3 months): Migrate the one NTLM-using service account to Kerberos (gMSA). Continue tuning SIEM alerts and monitoring. Roll out enhanced NTLM auditing to catch any other stragglers.
🟢 Mid-Term (3-6 months): Enforce NTLM restrictions via Group Policy in stages (audit then deny NTLM domain-wide). Implement Windows Defender Credential Guard on endpoints to protect credentials. Verify all critical apps use Kerberos or modern auth.
🔵 Long-Term (6-12 months): Complete the NTLM deprecation: disable NTLM on all servers and domain controllers (after verifying no impact). Any NTLM authentication after that point will be actively blocked. Deploy Microsoft Defender for Identity sensors on domain controllers for advanced detection (pass-the-hash, relay) as an extra safety net. Work towards a Zero Trust model where legacy auth like NTLM has no place.

Key Takeaways: Our environment withstood a month-long assault on NTLM without a breach – a testament to strong credentials and some luck. However, NTLM is clearly a magnet for attackers; they wouldn’t invest this effort if not for the chance of finding a weak link. The prudent course is to remove that weak link entirely by eliminating NTLM. Doing so will not only stop these current attacks cold (they can’t brute-force what isn’t available), but also strengthen our overall security posture against future threats (no more pass-the-hash, relays, etc.).

In summary, we are turning this incident into an opportunity: within the next year, NTLM will be phased out in favor of modern, secure authentication methods. This will close the door on a whole class of attacks and align us with security best practices. The ongoing monitoring and gradual enforcement will ensure this transition happens safely. By the end of the roadmap, any NTLM login attempt – if it happens at all – will be so unusual that it will raise an immediate red flag for investigation, if not blocked outright.

📊 NTLM Security Monitoring Workbook for Sentinel

🎯 Purpose

Real-time monitoring of NTLM authentication activity, detection of credential attacks (brute-force, credential stuffing), lateral movement analysis, and tracking NTLM deprecation progress.

🧭 Dashboard Capabilities

1️⃣ Overview Tab

Metrics: 🔢 Total NTLM Events – Success/failure counts (🔴 Critical if >90% failure rate) 🌐 Attack Sources – Unique IPs + failed attempts ✅ Legitimate NTLM Usage – For migration planning 📈 NTLM Activity Timeline – Hourly success vs failure 🧩 Logon Type Distribution – Interactive, Network, Service, etc. 💻 Top Devices Using NTLM – Migration candidates
Key Detection: 99.99% failure rate = under attack

Article content
Article content
2️⃣ Attack Detection Tab

Threat Hunting: 👤 Most Targeted Accounts – e.g., Administrator 🔴 >10K attempts | 🟠 >1K | 🟡 >100 🌍 Top Attacking IPs – Persistent attackers 🔒 Block Top 30 immediately ⏱️ High-Frequency Attack Windows – >100/hour 🚨 Automated: >2K/hour | High-Volume: >500 | Sustained: >100 🚨 Breach Indicators: Success after 5+ failures → Investigate immediately 🛡️ Privileged Account Monitoring – NTLM by admins = High Risk
MITRE ATT&CK: T1110.003 (Password Spraying) T1110.004 (Credential Stuffing)

Article content
Article content
Article content
 3️⃣ Identity & Device Analysis Tab

Cross-Platform Monitoring: 🏢 AD NTLM Usage (IdentityLogonEvents) Detect NTLMv1 (⚠️ Critical) 💻 Endpoint NTLM Activity (DeviceLogonEvents) High failure = endpoint attack
Lateral Movement Detection: 3+ devices in <15 min = 🛑 Pass-the-Hash
After-Hours Activity: Logons outside 7 AM–7 PM or weekends = 🟠 Insider threat
Service Account Analysis: svc*, app, sql accounts using NTLM 🎯 gMSA migration candidates
MITRE ATT&CK: T1550.002 (Pass-the-Hash) T1021.002 (Lateral Movement via SMB)

Article content
Article content
4️⃣ Threat Intelligence Tab

Advanced Analytics: 🧠 MITRE Technique Detection T1110.003, T1110.004, T1550.002 📊 Daily Trend Analysis – 30-day NTLM evolution 🔄 Cross-Table Correlation – SecurityEvent + IdentityLogonEvents + DeviceLogonEvents 📉 Deprecation Progress Tracking ✅ Reduction | 🔴 Increase | ➖ No Change

 

Article content
 

Article content
🔐 NTLM Authentication Analysis – Visual Query Summary

Article content
Article content
 

Article content
Article content
Article content
Article content
Article content
Article content
Article content
✅ Security Outcomes

🔍 Detects 843K+ brute-force attempts from 500+ IPs
🛡️ Flags 385K+ privileged account attacks
🚨 Alerts on successful logons after failures
🔄 Tracks NTLM deprecation and migration progress

 🚨 Recommended Alert Rules

Article content
🧱 Data Requirements

Data Sources: 
✅ SecurityEvent (4624, 4625) 
✅ IdentityLogonEvents (MDI)
 ✅ DeviceLogonEvents (MD
 
Prerequisites: 
Azure Monitor Agent or Log Analytics Agent.
 Advanced Audit Policy (Logon/Logoff, Account Logon).
 MDI sensors on DCs.
 MDE agents on endpoints.

 📌 Bonus KQL Queries for NTLM Monitoring

📘 1 — NTLM Usage Overview 

Purpose: Understand NTLM versions & logon types

Key Metrics: Total events • Success/Failure • Unique accounts/IPs

SecurityEvent

| where TimeGenerated > ago(30d)

| where EventID in (4624, 4625)

| where AuthenticationPackageName has "NTLM"

| extend Success = EventID == 4624

| extend NTLMVersion = case(

 AuthenticationPackageName has "NTLMv1","NTLMv1",

 AuthenticationPackageName has "NTLMv2","NTLMv2",

 "Other")

| summarize TotalEvents=count(), UniqueAccounts=dcount(Account),

 UniqueIPs=dcount(IpAddress)

 by NTLMVersion

| order by TotalEvents desc

 🔵 2 — Top Devices Using NTLM 

Purpose: Identify biggest NTLM consumers

Key Metrics: NTLM logons • Unique accounts • Devices

SecurityEvent

| where TimeGenerated > ago(30d)

| where EventID == 4624 and AuthenticationPackageName has "NTLM"

| summarize NTLMLogons=count(), UniqueAccounts=dcount(Account),

 SampleAccounts=make_set(Account,5)

 by Computer

| order by NTLMLogons desc

| take 20

 🟧  3 — NTLM Brute Force Attempts 

Purpose: Detect large NTLM failure spikes

Key Metrics: Failed attempts • IP spread • Accounts targeted

SecurityEvent

| where TimeGenerated > ago(30d)

| where EventID == 4625 and AuthenticationPackageName has "NTLM"

| summarize FailedAttempts=count(), UniqueIPs=dcount(IpAddress),

 FailureReasons=make_set(Status,5)

 by Computer

| order by FailedAttempts desc

 🟧  4 — Attack Source IP Analysis 

Purpose: Prioritize attacker IPs

Key Metrics: Failed attempts • Accounts hit • Destinations

SecurityEvent

| where TimeGenerated > ago(30d)

| where EventID == 4625 and AuthenticationPackageName has "NTLM"

| summarize FailedAttempts=count(), TargetAccounts=make_set(Account,10)

 by IpAddress

| where FailedAttempts >= 100

| order by FailedAttempts desc

 🟢  5 — NTLM Endpoint Monitoring 

Purpose: Measure NTLM across endpoints (DeviceLogonEvents)

Key Metrics: Success/Fail • Unique devices • Remote IPs

DeviceLogonEvents

| where TimeGenerated > ago(30d)

| where Protocol has "NTLM"

| summarize TotalEvents=count(), Failures=countif(ActionType=="LogonFailed"),

 UniqueDevices=dcount(DeviceName)

 by Protocol

 🟢  6 — Failed NTLM Attempts by Device 

Purpose: Detect repeated device‑level NTLM failures

Key Metrics: Failed attempts • Remote IPs • Accounts

DeviceLogonEvents

| where TimeGenerated > ago(30d)

| where Protocol has "NTLM" and ActionType=="LogonFailed"

| summarize FailedAttempts=count(), UniqueRemoteIPs=dcount(RemoteIP)

 by DeviceName

| where FailedAttempts > 10

 🟣 7 — NTLM Lateral Movement Burst 

Purpose: Detect multi‑device access in short windows

Key Metrics: Device count • Time span • Suspicion level

DeviceLogonEvents

| where TimeGenerated > ago(24h)

| where Protocol has "NTLM" and ActionType=="LogonSuccess"

| summarize DeviceCount=dcount(DeviceName),

 FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)

 by AccountName, bin(TimeGenerated, 30m)

| where DeviceCount >= 3

 🟢  8 — After‑Hours NTLM Activity 

Purpose: Spot abnormal NTLM behavior outside business hours

Key Metrics: Logons • Devices • Remote IPs

DeviceLogonEvents

| where TimeGenerated > ago(7d)

| where Protocol has "NTLM" and ActionType=="LogonSuccess"

| extend Hour = datetime_part("Hour", TimeGenerated)

| extend AfterHours = Hour < 8 or Hour >= 19

| summarize Logons=count(), Devices=dcount(DeviceName)

 by AfterHours, AccountName

 🔴  9 — NTLM Usage in AD / Identity 

Purpose: Monitor NTLM used in directory authentication

Key Metrics: Success/Fail • Accounts • Source & Destination devices

IdentityLogonEvents

| where TimeGenerated > ago(30d)

| where Protocol has "NTLM"

| summarize TotalEvents=count(), UniqueAccounts=dcount(AccountName)

 by LogonType

 🔴  10 — External / Unknown NTLM Sources 

Purpose: Identify suspicious external NTLM attempts

Key Metrics: Failed attempts • Destinations • Threat level

IdentityLogonEvents

| where TimeGenerated > ago(7d)

| where Protocol has "NTLM" and ActionType=="LogonFailed"

| summarize FailedAttempts=count(), Targets=make_set(AccountName,10)

 by IPAddress

| where FailedAttempts > 20

 🟣  11 — Service Account NTLM Usage 

Purpose: Detect service accounts using NTLM

Key Metrics: Logon count • Destinations • Risk level

let Svc = dynamic(["svc","service","automation"]);

IdentityLogonEvents

| where TimeGenerated > ago(30d)

| where Protocol has "NTLM"

| where AccountName has_any (Svc)

| summarize LogonCount=count(), Destinations=dcount(DestinationDeviceName)

 by AccountName

 🟢  12 — NTLM Timeline 

Purpose: Visualize NTLM trend daily

Key Metrics: Daily total • Success rate • Unique accounts

IdentityLogonEvents

| where TimeGenerated > ago(30d)

| where Protocol has "NTLM"

| extend Day = bin(TimeGenerated,1d)

| summarize TotalEvents=count(), Success=countif(ActionType=="LogonSuccess")

 by Day

 🟣  13 — Cross‑Source NTLM Correlation 

Purpose: Merge SecurityEvent + DeviceLogonEvents + IdentityLogonEvents

Key Metrics: Source count • Total NTLM events

// (Abbreviated here - full version available above)

union SecurityEvent, DeviceLogonEvents, IdentityLogonEvents

| where Protocol has "NTLM"

| summarize TotalEvents=count(), Sources=make_set(Source)

 by Account

| where dcount(Sources) >= 2

 🔵 Final Call to Action 

• Reduce NTLMv1

• Monitor NTLMv2 for anomalies

• Prioritize after‑hours + high‑failure IPs

• Move apps to Kerberos / modern auth

✅ Conclusion

Disabling NTLM is not just a configuration change—it’s a strategic shift toward modern, secure authentication. Our assessment revealed that while NTLM is still present, its legitimate use is minimal and manageable. With a clear roadmap, layered detection, and the right tools like Microsoft Sentinel, Defender for Endpoint, and Defender for Identity, we’re on track to eliminate NTLM entirely within 12 months.

This journey has already improved our security posture, reduced attack surface, and aligned us with Zero Trust principles. The key takeaway? NTLM—especially v1—has no place in a modern enterprise. By auditing, hardening, and replacing legacy protocols, we’re closing one of the oldest and most exploited doors in enterprise security.
