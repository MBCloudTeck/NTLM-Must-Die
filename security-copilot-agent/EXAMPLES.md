# NTLM Must Die Security Copilot Agent - Examples

This document provides detailed examples of how to use the NTLM Must Die Security Copilot Agent for various scenarios.

## Table of Contents
1. [Discovery and Assessment](#discovery-and-assessment)
2. [Threat Detection](#threat-detection)
3. [Incident Response](#incident-response)
4. [Remediation Planning](#remediation-planning)
5. [Compliance and Reporting](#compliance-and-reporting)

---

## Discovery and Assessment

### Example 1: Initial Environment Assessment

**Scenario**: You've just been assigned to reduce NTLM usage in your organization and need to understand the current state.

**Conversation with Agent**:

```
User: NTLM agent, I need to understand NTLM usage in my environment. 
      Can you analyze the last 30 days?

Agent: I'll analyze NTLM authentication patterns across your environment 
       for the past 30 days...

[Executes: detect_ntlm_authentication and analyze_ntlm_trends queries]

📊 NTLM Usage Analysis - Last 30 Days

Total NTLM Authentication Events: 1,247,832
├─ NTLMv1: 12,450 (1.0%) ⚠️ CRITICAL
└─ NTLMv2: 1,235,382 (99.0%) ⚠️ HIGH

Unique Systems Using NTLM: 3,421
Unique Accounts Using NTLM: 8,932

🔴 Risk Assessment: CRITICAL
Reason: Active NTLMv1 usage detected

📈 Trend Analysis:
Week 1: 345,221 events
Week 2: 318,445 events (-7.8%)
Week 3: 302,119 events (-5.1%)
Week 4: 282,047 events (-6.6%)

Top 5 Sources by Event Count:
1. PRINT-SERVER-01: 234,556 events (18.8%)
2. NAS-STORAGE-MAIN: 189,334 events (15.2%)
3. APP-LEGACY-WEB: 145,223 events (11.6%)
4. DC01.contoso.com: 98,776 events (7.9%)
5. SQL-PROD-CLUSTER: 87,654 events (7.0%)

Top 5 Accounts:
1. svc-backup: 456,789 events (36.6%)
2. svc-monitoring: 234,567 events (18.8%)
3. svc-sql: 123,456 events (9.9%)
4. SYSTEM: 98,765 events (7.9%)
5. admin-legacy: 87,654 events (7.0%)

🎯 Immediate Priorities:
1. Eliminate NTLMv1 usage (12,450 events)
2. Investigate high-volume service accounts
3. Address top 5 source systems (50.5% of traffic)
4. Review privileged account NTLM usage

Would you like me to:
- Deep dive into NTLMv1 sources?
- Create a remediation plan?
- Generate an executive report?

User: Yes, show me the NTLMv1 sources in detail.

Agent: Analyzing NTLMv1 authentication sources...

[Executes: detect_ntlmv1_usage with detailed breakdown]

🚨 NTLMv1 Sources - CRITICAL FINDING

Total NTLMv1 Events: 12,450
Affected Systems: 47
Time Range: Last 30 days

Breakdown by Source:

1. 🖨️ PRINT-LEGACY-FLOOR2 (192.168.10.45)
   - Events: 8,932 (71.7% of NTLMv1)
   - Account: SYSTEM
   - Pattern: Print spooler service authentication
   - Device: HP LaserJet 4250 (firmware v2.115 - 2009)
   - Recommendation: Update firmware or replace printer

2. 💾 NAS-BACKUP-OLD (192.168.20.100)
   - Events: 2,344 (18.8% of NTLMv1)
   - Account: svc-backup
   - Pattern: SMB share access for backups
   - Device: Synology DS212 (DSM 4.3 - EOL)
   - Recommendation: Upgrade NAS firmware to DSM 7.x

3. 🔒 SCANNER-LEGAL (192.168.30.78)
   - Events: 1,174 (9.4% of NTLMv1)
   - Account: DOMAIN\scanner-user
   - Pattern: Scan-to-folder authentication
   - Device: Canon imageRUNNER 2520 (2012 model)
   - Recommendation: Update scanner firmware or reconfigure

📋 Remediation Plan:
1. PRINT-LEGACY-FLOOR2: Replace with modern printer (est. cost: $800)
2. NAS-BACKUP-OLD: Upgrade to DSM 7.2 (free, 2 hours downtime)
3. SCANNER-LEGAL: Contact Canon support for firmware update

Estimated Time to Eliminate NTLMv1: 1-2 weeks
Risk if Not Fixed: CRITICAL - Trivial credential theft via NTLMv1 crack

Shall I generate the implementation plan with Group Policy settings?
```

### Example 2: Service Account Discovery

```
User: NTLM agent, show me which service accounts are using NTLM.

Agent: Analyzing service account NTLM usage...

[Executes: analyze_ntlm_by_account filtered for service accounts]

🔑 Service Account NTLM Usage

Total Service Accounts Using NTLM: 47
Total NTLM Events from Service Accounts: 892,345 (71.5% of all NTLM)

High-Risk Service Accounts (>10,000 events/month):

1. svc-backup@contoso.com ⚠️
   - Events: 456,789 (51.2%)
   - Systems: NAS-STORAGE-MAIN, BACKUP-SERVER-01, FILE-SRV-10 (+23 more)
   - Pattern: Daily backup jobs at 02:00 UTC
   - Issue: Missing SPN for backup service
   - Fix: setspn -S backupservice/backup-server-01.contoso.com contoso\svc-backup

2. svc-monitoring@contoso.com ⚠️
   - Events: 234,567 (26.3%)
   - Systems: All domain controllers (8), member servers (345)
   - Pattern: Continuous monitoring every 5 minutes
   - Issue: Monitoring tool configured for NTLM
   - Fix: Reconfigure monitoring tool for Kerberos authentication

3. svc-sql@contoso.com ⚠️
   - Events: 123,456 (13.8%)
   - Systems: SQL-PROD-CLUSTER, SQL-DEV-01, APP-WEB-01 (+12 more)
   - Pattern: Application database connections
   - Issue: Connection strings using NTLM
   - Fix: Update connection strings to use Integrated Security with Kerberos

4. svc-webapp@contoso.com
   - Events: 45,678 (5.1%)
   - Systems: IIS-WEB-01, IIS-WEB-02, IIS-WEB-03
   - Pattern: IIS application pool identity
   - Issue: App pool not configured for Kerberos
   - Fix: Configure SPNs for HTTP service

5. svc-sharepoint@contoso.com
   - Events: 31,855 (3.6%)
   - Systems: SP-APP-01, SP-APP-02, SP-WFE-01, SP-WFE-02
   - Pattern: SharePoint service connections
   - Issue: SharePoint not properly configured for Kerberos
   - Fix: Run SharePoint Kerberos configuration wizard

🎯 Remediation Priority:
1. svc-backup (highest volume, easiest fix - add SPN)
2. svc-monitoring (high volume, requires tool reconfiguration)
3. svc-sql (moderate volume, requires app changes)
4. svc-webapp (low volume, straightforward IIS config)
5. svc-sharepoint (low volume, complex but documented process)

💡 Best Practices:
- Consider migrating to Group Managed Service Accounts (gMSA)
- Enable "Account is sensitive and cannot be delegated" for privileged service accounts
- Add to Protected Users group if no NTLM requirement
- Implement regular SPN audits

Would you like detailed remediation steps for any of these accounts?
```

---

## Threat Detection

### Example 3: NTLM Relay Attack Detection

```
User: NTLM agent, are there any signs of NTLM relay attacks?

Agent: Scanning for NTLM relay attack patterns...

[Executes: detect_ntlm_relay_attack query]

🚨 ALERT: Potential NTLM Relay Attack Detected

Severity: HIGH
Confidence: 87%
Detection Time: 2026-01-26 14:35:22 UTC

Attack Pattern Identified:
├─ Source IP: 192.168.50.147
├─ Affected Account: svc-backup@contoso.com  
├─ Target Systems: 17 servers in 12 minutes
└─ Authentication Method: NTLMv2

Timeline:
14:23:15 - First authentication: DC01.contoso.com
14:24:03 - AUTH: DC02.contoso.com
14:24:45 - AUTH: FILE-SRV-01.contoso.com
14:25:12 - AUTH: FILE-SRV-02.contoso.com
14:26:34 - AUTH: SQL-PROD-01.contoso.com
14:27:19 - AUTH: EXCHANGE-MBX-01.contoso.com
... (11 more targets)
14:34:56 - Last observed: SHAREPOINT-APP-01.contoso.com

Indicators:
✓ Single source IP authenticating to multiple high-value targets
✓ Rapid succession of authentications (< 1 minute between attempts)
✓ Targets include domain controllers and critical infrastructure
✓ Account typically used for batch operations, not interactive logons
✓ No corresponding logon from legitimate source for this account

MITRE ATT&CK Mapping:
├─ Tactic: Credential Access (TA0006)
├─ Technique: LLMNR/NBT-NS Poisoning and SMB Relay (T1557.001)
└─ Tactic: Lateral Movement (TA0008)

🎯 Immediate Response Actions:

CRITICAL - Execute Immediately:
1. Isolate source IP 192.168.50.147
   Command: netsh advfirewall firewall add rule name="Block 192.168.50.147" dir=in action=block remoteip=192.168.50.147

2. Disable svc-backup account
   Command: Disable-ADAccount -Identity svc-backup

3. Reset svc-backup password
   Command: Set-ADAccountPassword -Identity svc-backup -Reset

HIGH Priority - Execute Within 1 Hour:
4. Review authentication logs for credential access on all 17 targets
5. Check for persistence mechanisms (scheduled tasks, services, WMI subscriptions)
6. Scan for lateral movement indicators from 192.168.50.147
7. Review security logs on source IP for malicious activity

Medium Priority - Execute Within 24 Hours:
8. Enable SMB signing on all targets (prevents future relay attacks)
   GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
   "Microsoft network server: Digitally sign communications (always)" = Enabled

9. Enable EPA (Extended Protection for Authentication)
10. Implement LDAP signing on domain controllers

🔍 Forensic Queries:
Want me to:
- Show detailed authentication flow?
- Identify what the attacker accessed on each system?
- Generate incident report for SOC?
- Check for similar patterns in last 7 days?
```

### Example 4: Pass-the-Hash Detection

```
User: NTLM agent, check for pass-the-hash attacks in the last 48 hours.

Agent: Analyzing authentication patterns for pass-the-hash indicators...

[Executes: detect_suspicious_ntlm_patterns with PTH signatures]

🔍 Pass-the-Hash Analysis - Last 48 Hours

Suspicious Patterns Found: 2

⚠️ Pattern 1: Anomalous Privileged Account Usage

Account: da-admin@contoso.com (Domain Admin)
Source IP: 192.168.75.234
Time Range: 2026-01-25 22:15:00 - 22:47:00 UTC
Authentication Type: NTLM (Network Logon Type 3)

Indicators:
✓ Domain Admin account authenticated via NTLM (should use Kerberos)
✓ Authentication from workstation (DA accounts should only use PAWs)
✓ After-hours activity (normal business hours: 08:00-18:00)
✓ Multiple failed attempts before success (possible stolen hash)
✓ No corresponding interactive logon from this IP

Failed Attempts:
22:15:12 - FAILED (Event 4625)
22:15:45 - FAILED (Event 4625)
22:16:23 - SUCCESS (Event 4624)

Target Systems:
├─ DC03.contoso.com (Domain Controller)
├─ EXCHSERV-01.contoso.com (Exchange Server)
└─ FILE-EXEC-01.contoso.com (Executive File Server)

Risk Score: 9.2/10 (CRITICAL)

Recommended Actions:
1. Immediately disable da-admin account
2. Reset password for da-admin
3. Investigate source IP 192.168.75.234
4. Review all activities performed by da-admin during this window
5. Check for golden ticket or skeleton key attacks

⚠️ Pattern 2: Service Account Lateral Movement

Account: svc-webapp@contoso.com
Source IPs: 192.168.80.56, 192.168.80.57, 192.168.80.58
Time Range: 2026-01-26 11:22:00 - 11:35:00 UTC
Authentication Type: NTLM (Network Logon Type 3)

Indicators:
✓ Service account used from multiple IPs simultaneously
✓ Service account accessing systems outside normal scope
✓ Unusual lateral movement pattern (web server → database → file server)

Normal Behavior: svc-webapp only accesses IIS-WEB-* servers
Observed Behavior: Accessed SQL-PROD-01, FILE-HR-01, DC02

Risk Score: 7.8/10 (HIGH)

Recommended Actions:
1. Reset password for svc-webapp
2. Review recent changes to svc-webapp permissions
3. Check for credential dumping on IIS-WEB servers (where svc-webapp runs)
4. Implement JIT (Just-In-Time) access for service accounts

🛡️ Prevention Recommendations:
1. Enable Windows Credential Guard (prevents hash theft from LSASS)
2. Add privileged accounts to Protected Users group (blocks NTLM)
3. Implement PAW (Privileged Access Workstations) for admin accounts
4. Deploy Microsoft Defender for Identity for real-time PTH detection
5. Enable LSASS protection (RunAsPPL)

Shall I generate the incident response playbook for these findings?
```

---

## Incident Response

### Example 5: Active Incident Investigation

```
User: NTLM agent, we have an active security incident. User reports suspicious 
      activity on their account (jsmith@contoso.com). Can you check for NTLM-related issues?

Agent: Analyzing authentication activity for jsmith@contoso.com...

[Executes: Multiple queries for account-specific analysis]

🚨 Incident Analysis: jsmith@contoso.com

Analysis Period: Last 24 hours
Incident Severity: HIGH
Recommendation: Immediate Action Required

🔴 Suspicious Activity Detected:

Timeline of Events:

13:45:23 - Normal Activity
├─ Source: LAPTOP-JSMITH (192.168.100.45)
├─ Auth: Kerberos (Expected)
└─ Location: Corporate Office

14:12:47 - ANOMALY BEGINS ⚠️
├─ Source: UNKNOWN-WORKSTATION (192.168.200.178)
├─ Auth: NTLM (Unexpected - user normally uses Kerberos)
├─ Location: Guest Network
└─ Failed Attempts: 3 before success

14:13:15 - Successful NTLM Authentication
├─ Accessed: FILE-FINANCE-01 (sensitive data)
├─ Actions: Multiple file reads (CFO financial reports)
└─ Duration: 23 minutes

14:36:42 - Lateral Movement Detected
├─ From: FILE-FINANCE-01
├─ To: SQL-HR-PROD (HR database server)
├─ Auth: NTLM using jsmith credentials
└─ Actions: Database queries (employee SSN, salary data)

15:02:19 - Data Exfiltration Suspected
├─ Large file transfer initiated
├─ Destination: External IP 203.0.113.45 (Russia)
├─ Volume: 1.2 GB
└─ Status: Blocked by firewall ✓

Simultaneously at 14:45:00 - Legitimate User Still Active
├─ Source: LAPTOP-JSMITH (192.168.100.45)
├─ Auth: Kerberos
├─ Activity: Email, Teams, normal business operations
└─ Confirmation: User was NOT at guest network location

🎯 Root Cause Analysis:

Credential Theft Mechanism: NTLM Relay Attack
├─ User visited malicious link in phishing email (13:58)
├─ Attacker captured NTLM challenge/response
├─ Relayed credentials to access corporate resources
└─ Used NTLM (not Kerberos) to avoid detection

Entry Point:
├─ Phishing email received: 13:50
├─ Link clicked: 13:58
├─ Attacker captured hash: 14:00
└─ First malicious authentication: 14:12

Attack Vector: LLMNR/NBT-NS Poisoning + SMB Relay
MITRE ATT&CK: T1557.001

💥 IMMEDIATE ACTIONS REQUIRED:

1. DISABLE ACCOUNT (Execute Now)
   ```powershell
   Disable-ADAccount -Identity jsmith
   ```

2. RESET PASSWORD (Execute Now)
   ```powershell
   Set-ADAccountPassword -Identity jsmith -Reset
   ```

3. REVOKE ALL ACTIVE SESSIONS (Execute Now)
   ```powershell
   Invoke-Command -ComputerName DC01 -ScriptBlock {
       klist purge -li 0x3e7
   }
   ```

4. ISOLATE COMPROMISED SYSTEMS (Execute Now)
   - UNKNOWN-WORKSTATION (192.168.200.178)
   - FILE-FINANCE-01 (potential malware implant)

5. BLOCK ATTACKER IP (Execute Now)
   ```powershell
   New-NetFirewallRule -DisplayName "Block Incident IP" -Direction Outbound -RemoteAddress 203.0.113.45 -Action Block
   ```

📋 INVESTIGATION TASKS (Next 4 Hours):

1. Forensic imaging of:
   - UNKNOWN-WORKSTATION (192.168.200.178)
   - FILE-FINANCE-01
   
2. Check for persistence mechanisms:
   - Scheduled tasks
   - Services
   - Registry Run keys
   - WMI event subscriptions

3. Review file access logs:
   - What files were accessed on FILE-FINANCE-01?
   - Were files modified or deleted?
   - Check for ransomware indicators

4. Database query analysis:
   - What queries were run on SQL-HR-PROD?
   - Was data exported or modified?
   - Check transaction logs

5. Identify other compromised accounts:
   - Scan for similar NTLM patterns from guest network
   - Check for concurrent authentications

🔧 REMEDIATION (Next 48 Hours):

1. Implement SMB Signing (Prevents relay attacks)
2. Disable LLMNR/NBT-NS via Group Policy
3. Deploy Microsoft Defender for Identity
4. Enable Credential Guard on endpoints
5. Security awareness training for jsmith and team

📊 IMPACT ASSESSMENT:

Confidentiality: HIGH
├─ Financial reports accessed (board-level sensitive)
├─ HR data queried (PII, SSNs, salaries)
└─ Data exfiltration attempted (blocked)

Integrity: MEDIUM
├─ No evidence of data modification
└─ File system timestamps unchanged

Availability: LOW
└─ No service disruption

Compliance Impact:
├─ GDPR: Personal data breach (HR access)
├─ SOX: Financial data unauthorized access
└─ Notification: Required within 72 hours

Would you like me to:
- Generate full incident report?
- Create timeline visualization?
- Draft compliance notification?
- Provide detailed forensic queries?
```

---

## Remediation Planning

### Example 6: Creating Comprehensive Remediation Plan

```
User: NTLM agent, create a complete remediation plan to eliminate all NTLM 
      from my environment. We have 90 days to complete this.

Agent: Creating comprehensive 90-day NTLM elimination plan...

[Analyzes current usage, dependencies, and creates phased approach]

📋 NTLM Elimination Project Plan - 90 Days

Project Overview:
├─ Current NTLM Events: 1,247,832/month
├─ Target: <1,000/month (>99.9% reduction)
├─ Timeline: 90 days (13 weeks)
├─ Risk Level: Current=CRITICAL, Target=LOW
└─ Estimated Effort: 320 person-hours

═══════════════════════════════════════════════════════════

PHASE 1: FOUNDATION (Weeks 1-2)
Goal: Establish monitoring and eliminate NTLMv1

Week 1: Monitoring Infrastructure
□ Day 1-2: Enable NTLM auditing via Group Policy
  ├─ Run: Enable-NTLMAuditing.ps1
  ├─ Deploy to all DCs and member servers
  └─ Verify event collection in Sentinel

□ Day 3-4: Deploy Sentinel detection rules
  ├─ Import: sentinel-ntlmv1-detection.yaml
  ├─ Import: sentinel-ntlm-relay-attack.yaml
  ├─ Import: sentinel-privileged-ntlm.yaml
  └─ Configure alert notifications

□ Day 5: Deploy Insecure Protocols Workbook
  └─ Baseline current NTLM usage metrics

Week 2: NTLMv1 Elimination (CRITICAL)
□ Day 8-9: Identify all NTLMv1 sources (47 systems found)
  ├─ PRINT-LEGACY-FLOOR2: Replace printer ($800)
  ├─ NAS-BACKUP-OLD: Firmware upgrade (free)
  └─ SCANNER-LEGAL: Firmware update or replace

□ Day 10-11: Execute NTLMv1 remediation
  └─ Deploy Disable-NTLMv1.ps1 via GPO

□ Day 12-14: Verify NTLMv1 elimination
  └─ Target: 0 NTLMv1 events for 3 consecutive days

Success Criteria:
✓ 0 NTLMv1 events
✓ All detection rules operational
✓ Baseline metrics documented

═══════════════════════════════════════════════════════════

PHASE 2: SERVICE ACCOUNT REMEDIATION (Weeks 3-6)
Goal: Migrate service accounts to Kerberos (71.5% of NTLM traffic)

Week 3-4: Top 5 Service Accounts
□ svc-backup (456,789 events/month)
  ├─ Day 15-16: Configure SPNs
  │   setspn -S backupservice/backup-server-01 contoso\svc-backup
  ├─ Day 17: Test backup jobs with Kerberos
  ├─ Day 18: Enable in production
  └─ Expected reduction: 36.6% of NTLM traffic

□ svc-monitoring (234,567 events/month)
  ├─ Day 19-21: Reconfigure monitoring tool
  ├─ Day 22: Configure Kerberos authentication
  ├─ Day 23: Test monitoring functionality
  └─ Expected reduction: 18.8% of NTLM traffic

□ svc-sql (123,456 events/month)
  ├─ Day 24-25: Update connection strings (45 applications)
  ├─ Day 26: Configure SQL SPNs
  ├─ Day 27-28: Deploy connection string updates
  └─ Expected reduction: 9.9% of NTLM traffic

Week 5-6: Remaining Service Accounts (42 accounts)
□ Day 29-35: Batch processing
  ├─ Group accounts by application/function
  ├─ Configure SPNs for each
  ├─ Test in dev/staging
  └─ Roll out to production

□ Day 36-42: Convert to Group Managed Service Accounts (gMSA)
  ├─ Identify candidates for gMSA conversion
  ├─ Create gMSAs
  ├─ Migrate applications
  └─ Decommission old service accounts

Success Criteria:
✓ 90% reduction in service account NTLM usage
✓ All critical service accounts on Kerberos
✓ gMSA implemented for new services

═══════════════════════════════════════════════════════════

PHASE 3: INFRASTRUCTURE & APPLICATIONS (Weeks 7-10)
Goal: Migrate infrastructure and applications to Kerberos

Week 7: File Servers & Print Servers
□ Day 43-45: Configure SPNs for file services
  └─ 23 file servers requiring configuration

□ Day 46-47: Test file access with Kerberos
□ Day 48-49: Deploy to production

Week 8: Web Applications
□ Day 50-52: IIS/Apache Kerberos configuration
  ├─ Configure HTTP SPNs
  ├─ Enable Kernel-mode authentication
  └─ Test application authentication

□ Day 53-56: Legacy web applications
  ├─ Update authentication modules
  ├─ Reconfigure for Windows Authentication
  └─ Test SSO functionality

Week 9-10: Database Servers & Specialized Applications
□ Day 57-63: SQL Server Kerberos
  ├─ Configure SQL SPNs for all instances
  ├─ Update connection strings
  └─ Test applications

□ Day 64-70: SharePoint, Exchange, specialized apps
  ├─ Run Kerberos configuration wizards
  ├─ Test all functionality
  └─ Document any NTLM requirements

Success Criteria:
✓ 95% reduction in NTLM traffic
✓ All critical infrastructure on Kerberos
✓ Known exceptions documented

═══════════════════════════════════════════════════════════

PHASE 4: HARDENING & ENFORCEMENT (Weeks 11-13)
Goal: Enforce Kerberos-only authentication and harden environment

Week 11: Security Hardening
□ Day 71-73: Deploy SMB Signing
  └─ GPO: Microsoft network server: Digitally sign communications (always)

□ Day 74-75: Enable LDAP Signing & Channel Binding
  └─ Prevents LDAP relay attacks

□ Day 76-77: Deploy Extended Protection for Authentication (EPA)

Week 12: Credential Guard & Protected Users
□ Day 78-80: Deploy Windows Credential Guard
  ├─ Requires: Windows 10/11 Enterprise, UEFI, TPM
  ├─ Automatically disables NTLMv1
  └─ Protects against credential theft

□ Day 81-82: Configure Protected Users Group
  ├─ Add Domain Admins
  ├─ Add privileged service accounts
  └─ Blocks NTLM authentication entirely

□ Day 83-84: Implement LAPS
  └─ Prevents lateral movement with local admin

Week 13: Final Enforcement
□ Day 85-87: Enable NTLM Restriction GPO (Audit Mode)
  └─ Log NTLM attempts without blocking

□ Day 88-89: Review audit logs
  └─ Address any remaining NTLM usage

□ Day 90: Enable NTLM Restriction (Enforcement Mode)
  ├─ GPO: Network security: Restrict NTLM: Incoming NTLM traffic = Deny all accounts
  ├─ GPO: Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers = Deny all
  └─ Document approved exceptions

Success Criteria:
✓ >99.9% reduction in NTLM usage
✓ NTLMv1 completely eliminated
✓ Credential Guard deployed to all supported endpoints
✓ Privileged accounts in Protected Users group
✓ NTLM restriction policies enforced

═══════════════════════════════════════════════════════════

RESOURCE ALLOCATION:

Personnel:
├─ Security Engineer (40 hours/week x 13 weeks = 520 hours)
├─ Systems Administrator (20 hours/week x 13 weeks = 260 hours)
├─ Application Teams (10 hours/week x 13 weeks = 130 hours)
└─ Total: 910 person-hours

Budget:
├─ Hardware replacement (printers/scanners): $5,000
├─ Firmware licenses (if needed): $2,000
├─ Training & certification: $3,000
├─ Contingency (10%): $1,000
└─ Total: $11,000

Tools:
├─ Microsoft Sentinel (existing)
├─ Microsoft Defender for Identity (recommended)
├─ PowerShell scripts (provided)
└─ Group Policy (existing)

═══════════════════════════════════════════════════════════

RISK MITIGATION:

Application Breakage Risk: MEDIUM
├─ Mitigation: Comprehensive testing in dev/staging
├─ Rollback plan: Disable GPO, revert SPNs
└─ Backup: Document all original configs

Service Disruption Risk: LOW-MEDIUM
├─ Mitigation: Phase rollouts, after-hours changes
└─ Communication: IT notification 48 hours advance

Legacy System Risk: MEDIUM
├─ Issue: Some systems cannot support Kerberos
├─ Mitigation: Network segmentation, isolate legacy
└─ Document exceptions with risk acceptance

═══════════════════════════════════════════════════════════

SUCCESS METRICS:

Week 0 (Baseline):
├─ NTLM Events: 1,247,832/month
├─ NTLMv1: 12,450/month
└─ Risk Score: 9.5/10 (CRITICAL)

Week 6 (Mid-Point):
├─ NTLM Events: ~375,000/month (70% reduction)
├─ NTLMv1: 0
└─ Risk Score: ~4.5/10 (MEDIUM)

Week 13 (Completion):
├─ NTLM Events: <1,000/month (99.9% reduction)
├─ NTLMv1: 0
└─ Risk Score: <2.0/10 (LOW)

═══════════════════════════════════════════════════════════

DELIVERABLES:

Documentation:
□ NTLM Baseline Assessment Report
□ Service Account Inventory
□ Application Authentication Matrix
□ SPN Configuration Guide
□ Exception Request Process
□ Incident Response Playbook
□ Post-Implementation Review

Technical:
□ Group Policy Objects (configured)
□ PowerShell Automation Scripts
□ Sentinel Detection Rules
□ Monitoring Dashboards
□ Configuration Change Records

═══════════════════════════════════════════════════════════

POST-IMPLEMENTATION:

Ongoing Monitoring:
├─ Weekly: Review Sentinel NTLM alerts
├─ Monthly: Generate usage trend reports
└─ Quarterly: Audit new applications for NTLM

Continuous Improvement:
├─ Monitor for new NTLM usage
├─ Update detection rules
├─ Refine exception process
└─ Share lessons learned

═══════════════════════════════════════════════════════════

Would you like me to:
- Generate detailed runbooks for each phase?
- Create Project Plan Gantt chart?
- Provide PowerShell scripts for automation?
- Generate executive presentation deck?
- Set up weekly progress tracking?
```

---

## Compliance and Reporting

### Example 7: Executive Report Generation

```
User: NTLM agent, generate an executive summary report for our CISO about NTLM 
      risk in our environment.

Agent: Creating executive summary report...

[Generates comprehensive executive-friendly report]

══════════════════════════════════════════════════════════
EXECUTIVE SUMMARY
NTLM Security Risk Assessment
══════════════════════════════════════════════════════════

Date: January 26, 2026
Prepared For: Chief Information Security Officer
Organization: Contoso Corporation
Classification: Confidential

══════════════════════════════════════════════════════════

📊 EXECUTIVE SUMMARY

Contoso Corporation currently faces CRITICAL security risk due to widespread use of NTLM authentication protocol across the enterprise. NTLM, particularly NTLMv1, is a legacy protocol with known cryptographic weaknesses that attackers actively exploit for credential theft, lateral movement, and privilege escalation.

Key Findings:
• 1.2M monthly NTLM authentications across 3,421 systems
• 12,450 monthly NTLMv1 authentications (cryptographically broken)
• 71.5% of NTLM traffic from service accounts (high-value targets)
• Active NTLM relay attack detected in last 30 days
• Privileged accounts using NTLM despite policy

Risk Level: 🔴 CRITICAL (9.5/10)

Recommendation: Immediate action required to eliminate NTLMv1 and systematically reduce NTLMv2 usage over 90 days.

══════════════════════════════════════════════════════════

🎯 BUSINESS IMPACT

Security Risks:
├─ Credential Theft: Attackers can intercept and crack NTLM hashes
├─ Lateral Movement: Compromised credentials enable network traversal
├─ Privilege Escalation: Administrative accounts vulnerable
└─ Data Breach: Unauthorized access to sensitive systems

Financial Impact:
├─ Potential breach cost: $4.2M (industry average)
├─ Regulatory fines: $2.5M (GDPR, SOX, HIPAA violations)
├─ Remediation cost: $11K (proactive, 90-day project)
└─ ROI: 400x return on preventive investment

Compliance Impact:
├─ GDPR: Personal data protection inadequate
├─ PCI-DSS: Payment systems using weak authentication
├─ SOX: Financial system access controls insufficient
└─ HIPAA: Healthcare data authentication vulnerabilities

Reputational Risk:
├─ Customer trust erosion if breach occurs
├─ Competitive disadvantage
└─ Regulatory scrutiny

══════════════════════════════════════════════════════════

📈 CURRENT STATE ANALYSIS

Authentication Landscape:
┌─────────────────────────────────────────────────┐
│ Monthly Authentication Events: 5,234,567        │
│ ├─ Kerberos: 3,986,735 (76.2%) ✓ Secure       │
│ ├─ NTLMv2: 1,235,382 (23.6%) ⚠️ Vulnerable    │
│ └─ NTLMv1: 12,450 (0.2%) 🔴 Critical Risk     │
└─────────────────────────────────────────────────┘

NTLM Usage by Category:
├─ Service Accounts: 71.5% (892K events)
├─ Infrastructure: 18.3% (228K events)
├─ User Accounts: 7.2% (90K events)
└─ Legacy Devices: 3.0% (37K events)

Top Risk Areas:
1. Backup Service (svc-backup): 456K events
   → Missing SPNs, easy fix, high impact

2. Monitoring Service (svc-monitoring): 234K events
   → Tool misconfiguration, moderate effort

3. Legacy Print Server: 234K events
   → Hardware replacement needed

4. NAS Storage: 189K events
   → Firmware upgrade required

5. Web Applications: 145K events
   → Application reconfiguration needed

══════════════════════════════════════════════════════════

🚨 SECURITY INCIDENTS (Last 30 Days)

Incident 1: NTLM Relay Attack (HIGH SEVERITY)
├─ Date: January 15, 2026
├─ Impact: 17 systems compromised
├─ Root Cause: Lack of SMB signing
├─ Cost: 45 hours incident response
└─ Status: Contained, remediation ongoing

Incident 2: Privilege Escalation (MEDIUM SEVERITY)
├─ Date: January 22, 2026
├─ Impact: Domain admin credentials stolen
├─ Root Cause: Pass-the-hash via NTLM
├─ Cost: 28 hours investigation
└─ Status: Account reset, monitoring enhanced

Near Misses:
├─ 3 suspected NTLM relay attempts (blocked)
├─ 12 anomalous NTLM patterns (investigated)
└─ 5 privileged account NTLM usage (alerted)

Annual Incident Trend:
├─ 2024: 8 NTLM-related incidents
├─ 2025: 15 NTLM-related incidents (+88%)
└─ 2026 (projected): 22 incidents if not addressed

══════════════════════════════════════════════════════════

💡 RECOMMENDED ACTIONS

Immediate (Week 1):
□ Eliminate all NTLMv1 usage (12,450 events)
  ├─ Risk Reduction: CRITICAL → HIGH
  ├─ Effort: 40 hours
  └─ Cost: $5,000

□ Deploy NTLM relay attack detection
  ├─ Enable Microsoft Defender for Identity
  ├─ Deploy Sentinel detection rules
  └─ Cost: $0 (included in existing licenses)

Short-Term (90 Days):
□ Execute NTLM Elimination Project
  ├─ Migrate service accounts to Kerberos
  ├─ Reconfigure applications and infrastructure
  ├─ Deploy security hardening measures
  ├─ Effort: 910 person-hours
  ├─ Cost: $11,000
  └─ Risk Reduction: CRITICAL → LOW

Long-Term (Ongoing):
□ Continuous monitoring and enforcement
□ New application Kerberos requirements
□ Quarterly security posture reviews
□ Annual NTLM audit

══════════════════════════════════════════════════════════

📊 PROJECTED OUTCOMES (Post-Remediation)

Security Improvements:
├─ Risk Score: 9.5/10 → 1.8/10 (81% improvement)
├─ Attack Surface: -99.9% NTLM exposure
├─ Incident Rate: -85% NTLM-related incidents
└─ Compliance: Full compliance with auth standards

Financial Benefits:
├─ Avoided breach cost: $4.2M (potential)
├─ Reduced incident response: -$250K/year
├─ Compliance fine avoidance: $2.5M (potential)
└─ Net Benefit: $6.95M over 3 years

Operational Improvements:
├─ Automated password rotation (gMSA)
├─ Reduced authentication failures
├─ Better audit trails (Kerberos)
└─ Simplified compliance reporting

══════════════════════════════════════════════════════════

🎯 SUCCESS CRITERIA

Technical Metrics:
✓ NTLMv1: 0 events per month
✓ NTLMv2: <1,000 events per month (<0.02%)
✓ Kerberos: >99.98% of all authentication
✓ Zero NTLM relay incidents

Business Metrics:
✓ Compliance: Full regulatory compliance
✓ Security Score: >95/100
✓ Incident Reduction: -85%
✓ Audit Findings: Zero critical

Timeline:
├─ Week 2: NTLMv1 eliminated
├─ Week 6: 70% NTLM reduction
├─ Week 13: 99.9% NTLM reduction
└─ Ongoing: Sustained low NTLM usage

══════════════════════════════════════════════════════════

💰 INVESTMENT SUMMARY

One-Time Costs:
├─ Hardware replacements: $5,000
├─ Software licenses: $2,000
├─ Training: $3,000
├─ Contingency: $1,000
└─ Total: $11,000

Ongoing Costs:
├─ Monitoring (Sentinel): $0 (existing)
├─ MDI license: $5/user/month
├─ Quarterly reviews: 16 hours/quarter
└─ Annual: ~$15,000

Return on Investment:
├─ Investment: $11,000
├─ Risk Reduction: $6.95M (3-year horizon)
└─ ROI: 400x

Payback Period: <1 month (if breach avoided)

══════════════════════════════════════════════════════════

🏁 NEXT STEPS

Board/Executive Committee:
□ Approve 90-day NTLM Elimination Project
□ Allocate $11,000 budget
□ Designate executive sponsor

IT Leadership:
□ Assign dedicated security engineer
□ Schedule project kickoff
□ Establish weekly status reporting

Security Team:
□ Week 1: Deploy monitoring and eliminate NTLMv1
□ Week 2-13: Execute remediation plan
□ Ongoing: Monitor and enforce

Communication:
□ IT Staff: Technical briefing (Week 1)
□ Business Units: Impact assessment (Week 1)
□ Executive: Monthly dashboard updates

══════════════════════════════════════════════════════════

RECOMMENDATION

The Security Team recommends IMMEDIATE APPROVAL of the NTLM Elimination Project. The current CRITICAL risk level, combined with recent security incidents and regulatory compliance requirements, necessitates urgent action.

The proposed 90-day project offers exceptional ROI (400x), addresses compliance gaps, and significantly reduces organizational risk exposure. Delaying this initiative increases the likelihood of a security breach with potential multi-million dollar impact.

Request: Executive approval to proceed with Phase 1 (NTLMv1 elimination) immediately, with full project commencement by end of week.

══════════════════════════════════════════════════════════

Report Generated By: NTLM Must Die Security Copilot Agent
Contact: security-team@contoso.com
Version: 1.0

══════════════════════════════════════════════════════════

Would you like me to:
- Generate PowerPoint presentation?
- Create detailed project charter?
- Draft board resolution?
- Provide compliance mapping document?
```

---

These examples demonstrate the comprehensive capabilities of the NTLM Must Die Security Copilot Agent across various security scenarios, from initial discovery through incident response to executive reporting.
