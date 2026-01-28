# Remediation & Migration Guide

## Overview

This guide provides a comprehensive, phased approach to eliminating legacy protocols from your environment. The methodology is based on industry best practices and real-world enterprise implementations.

## Core Principles

### 1. Visibility Before Action
**Never disable what you cannot see.**
- Establish comprehensive monitoring first
- Collect baseline data for 2-4 weeks minimum
- Document all dependencies before making changes

### 2. Phased Approach
**Gradual transition reduces risk.**
- Start with pilot groups
- Expand incrementally
- Always have rollback plans ready

### 3. Business Continuity First
**Security improvements should not break business.**
- Engage stakeholders early
- Test thoroughly in non-production
- Schedule changes during maintenance windows
- Monitor closely post-change

### 4. Defense in Depth
**Multiple layers of protection.**
- Don't rely on a single control
- Combine technical and administrative controls
- Monitor continuously even after remediation

## Phase 1: Discovery & Assessment

### Timeline: Weeks 1-4

### Objectives
- Complete inventory of legacy protocol usage
- Identify all dependencies
- Assess business impact
- Build stakeholder support

### Step 1: Enable Comprehensive Logging

#### A. Collect Logs from Multiple Sources

**Endpoints & Domain Controllers:**
```powershell
# Enable NTLM auditing domain-wide
# Via Group Policy:
# Network security: Restrict NTLM: Audit NTLM authentication in this domain
# Set to: Enable all

# Enable LDAP diagnostics on DCs
$DCs = (Get-ADDomainController -Filter *).Name
foreach ($DC in $DCs) {
    Invoke-Command -ComputerName $DC -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" `
            -Name "16 LDAP Interface Events" -Value 2
    }
}
```

**Network Devices:**
```bash
# Configure network IDS/IPS
# Zeek (Bro) - enable protocol detection
zeek -i eth0 -C local.zeek

# Suricata - enable legacy protocol rules
suricata -c /etc/suricata/suricata.yaml -i eth0
```

**Cloud Services:**
```powershell
# Enable Azure AD sign-in logs
# Prerequisites: Azure AD Premium P1 or P2
# Logs are automatically available in Azure Portal

# Export to Log Analytics for analysis
# Azure AD → Diagnostic settings → Add diagnostic setting
# Select: SigninLogs, AuditLogs
# Send to: Log Analytics workspace
```

### Step 2: Normalize & Analyze

#### B. Centralize to SIEM (Microsoft Sentinel)

**Push all logs to a central SIEM for correlation and analysis:**

```
Data Sources to Ingest:
┌─────────────────────────────────────────────────┐
│ Identity Layer                                  │
│  • AD Domain Controllers (Event Forwarding)     │
│  • Azure AD Sign-in Logs                        │
│  • LDAP Servers                                 │
├─────────────────────────────────────────────────┤
│ Server Layer                                    │
│  • Windows Servers (AMA Agent)                  │
│  • Linux Servers (Syslog)                       │
│  • Exchange Online                              │
│  • SharePoint Online                            │
├─────────────────────────────────────────────────┤
│ Network Layer                                   │
│  • Firewall Logs                                │
│  • IDS/IPS Alerts                               │
│  • NetFlow/IPFIX Data                          │
│  • DNS Logs                                     │
├─────────────────────────────────────────────────┤
│ Endpoint Layer                                  │
│  • Workstations (Security Events)               │
│  • EDR Telemetry (Defender for Endpoint)       │
│  • Configuration Data                           │
└─────────────────────────────────────────────────┘
```

**Recommended Architecture:**

```
                   ┌──────────────────┐
                   │   Sentinel /     │
                   │  Log Analytics   │
                   └────────┬─────────┘
                            │
          ┌─────────────────┼─────────────────┐
          │                 │                 │
    ┌─────▼─────┐     ┌────▼────┐     ┌─────▼─────┐
    │   Azure    │     │  Azure  │     │   Azure   │
    │ Monitor    │     │  Event  │     │ Diagnostic│
    │   Agent    │     │  Hubs   │     │  Settings │
    └─────┬─────┘     └────┬────┘     └─────┬─────┘
          │                 │                 │
    ┌─────▼─────────────────▼─────────────────▼─────┐
    │  Domain Controllers, Servers, Workstations,   │
    │  Cloud Services, Network Devices              │
    └────────────────────────────────────────────────┘
```

### Step 3: Create Analytics & Alerts

#### C. Alert on Risky Usage

**Create alert rules for immediate attention:**

**Critical Alerts (Security Team - Immediate Response):**
- NTLMv1 usage detected → Any occurrence
- SMBv1 enabled on new system → Any occurrence
- Telnet/FTP from external IP → Any occurrence
- LDAP simple bind from untrusted network → Any occurrence

**High Priority Alerts (Daily Review):**
- NTLM authentication spike (>50% over baseline)
- IMAP/POP/SMTP Auth sign-in to Exchange Online
- Multiple failed legacy auth attempts (potential attack)

**Medium Priority Alerts (Weekly Review):**
- New application using legacy protocols
- Geographic anomaly with legacy auth
- Legacy protocol usage after hours

### Step 4: Build Reporting Dashboards

#### D. Track Metrics Over Time

**Executive Dashboard Metrics:**
```kql
// Monthly trend of legacy protocol usage
let ProtocolUsageTrend = 
    union
        (SigninLogs | where ClientAppUsed == "Other clients" | extend Protocol = "Legacy Auth"),
        (SecurityEvent | where AuthenticationPackageName has "NTLM" | extend Protocol = "NTLM"),
        (WindowsEvent | where EventID == 2889 | extend Protocol = "LDAP Simple")
    | summarize Count=count() by Protocol, bin(TimeGenerated, 1d)
    | render timechart;

// Users/devices using legacy auth (Top 20)
let TopLegacyUsers = SigninLogs
    | where TimeGenerated > ago(30d)
    | where ClientAppUsed == "Other clients"
    | summarize Count=count() by UserPrincipalName
    | top 20 by Count desc;

// Geographic distribution
let LegacyAuthGeo = SigninLogs
    | where TimeGenerated > ago(30d)
    | where ClientAppUsed == "Other clients"
    | extend Country = tostring(LocationDetails.countryOrRegion)
    | summarize Count=count() by Country
    | render piechart;
```

**Operational Dashboard (Security Team):**
- Real-time legacy protocol attempts (last 24 hours)
- Failed authentication attempts by protocol
- New sources of legacy traffic (never seen before)
- Systems with legacy protocols enabled
- Remediation progress by OU/department

## Phase 2: Planning & Notification

### Timeline: Weeks 5-8

### Objectives
- Develop detailed remediation roadmap
- Obtain executive sponsorship and budget
- Communicate with affected teams
- Establish success criteria

### Step 1: Categorize Findings

**Risk-Based Prioritization:**

| Category | Risk Level | Action Timeline | Example |
|----------|-----------|-----------------|---------|
| **Critical** | ⛔ Immediate | 1-2 weeks | NTLMv1, Telnet, SMBv1 from internet |
| **High** | 🔴 Urgent | 1-3 months | NTLMv2 without signing, Basic auth cloud |
| **Medium** | 🟠 Important | 3-6 months | Kerberos RC4, SNMP v1/v2 internal |
| **Low** | 🟡 Planned | 6-12 months | Legacy protocols on isolated networks |

**Dependency Mapping:**
```
For each legacy protocol usage, document:

1. Source Information:
   - System/application name
   - Owner/responsible team
   - Business criticality (1-5)
   - Last known use date

2. Technical Details:
   - Protocol(s) used
   - Frequency of use
   - Authentication method
   - Encryption status

3. Dependencies:
   - Required for which business process?
   - Can it be migrated? (Yes/No/Unknown)
   - Estimated effort (Hours/Days/Weeks)
   - Required resources (People/Budget/Tools)

4. Risk Assessment:
   - Security risk (Critical/High/Medium/Low)
   - Compliance impact (Yes/No)
   - Data sensitivity (Public/Internal/Confidential/Restricted)
   - External accessibility (Yes/No)
```

### Step 2: Develop Remediation Roadmap

**Sample Timeline (6-Month Program):**

```
Month 1: Immediate Actions
Week 1-2:
  ✓ Disable NTLMv1 domain-wide
  ✓ Identify and isolate systems with Telnet/FTP enabled
  ✓ Block external access to legacy protocols at firewall

Week 3-4:
  ✓ Audit all SMBv1 systems, disable where possible
  ✓ Enable SMB signing domain-wide
  ✓ Deploy Conditional Access to block legacy auth (pilot)

Month 2-3: Core Remediation
  • Migrate applications from NTLM to Kerberos
  • Update network devices to modern protocols
  • Replace/upgrade legacy hardware
  • Disable Basic Auth in Microsoft 365

Month 4-5: Expanded Rollout
  • Block NTLM for pilot OUs
  • Migrate remaining applications
  • Disable legacy protocols in Exchange Online
  • Update remaining network equipment

Month 6: Enforcement & Validation
  • Block legacy protocols domain-wide
  • Continuous monitoring and alerting
  • Final validation and documentation
  • Establish ongoing governance
```

### Step 3: Communicate & Educate

**Notify & Educate Stakeholders:**

**Communication Plan:**
```
Audience: Executive Leadership
Message: Security risks, compliance, business case
Timing: Week 5 (before detailed planning)
Format: Executive briefing (15-minute presentation)
Follow-up: Monthly status updates

Audience: IT Management
Message: Technical approach, timeline, resource needs
Timing: Week 6
Format: Technical workshop (1-hour session)
Follow-up: Bi-weekly sync meetings

Audience: Application Owners
Message: Impact to their systems, required actions
Timing: Week 7 (after analysis complete)
Format: Email + office hours for questions
Follow-up: Individual meetings as needed

Audience: End Users
Message: What's changing, why, when, support contacts
Timing: 2 weeks before each phase
Format: Email, intranet article, Teams message
Follow-up: Helpdesk briefing, FAQ published
```

**Sample Communication Email:**
```
Subject: Important Security Update: Legacy Protocol Elimination

Dear [Team/User],

As part of our ongoing commitment to security and compliance, we are 
modernizing our authentication and communication protocols.

WHAT'S CHANGING:
Starting [DATE], we will be disabling legacy protocols including:
- NTLMv1 authentication
- SMBv1 file sharing
- Unencrypted email protocols (POP3, IMAP, SMTP)
- [Other relevant protocols]

WHY THIS MATTERS:
These legacy protocols have known security vulnerabilities and are 
actively exploited by attackers. Modern alternatives provide:
✓ Stronger encryption
✓ Better performance  
✓ Enhanced security
✓ Compliance with industry standards

WHAT YOU NEED TO DO:
[Specific actions required]

TIMELINE:
- [DATE]: Pilot deployment (IT department)
- [DATE]: Phase 1 (Department X, Y)
- [DATE]: Phase 2 (Remaining departments)

SUPPORT:
Questions? Contact:
- Email: security@company.com
- Teams: #legacy-protocol-migration
- Helpdesk: x1234

Thank you for your cooperation in keeping our environment secure.

[Security Team]
```

## Phase 3: Pilot Implementation

### Timeline: Weeks 9-12

### Objectives
- Test changes in controlled environment
- Validate monitoring and alerting
- Refine rollback procedures
- Build confidence for production deployment

### Step 1: Select Pilot Group

**Ideal Pilot Characteristics:**
- Small, manageable size (10-50 users)
- Technically savvy users (IT department ideal)
- Representative workload and applications
- Available for troubleshooting
- Executive sponsor awareness

**Sample Pilot OUs:**
```
Pilot Phase 1 (Week 9-10):
- IT Security Team (10 users)
- IT Infrastructure Team (15 users)

Pilot Phase 2 (Week 11-12):
- IT Help Desk (25 users)
- IT Development Team (20 users)
```

### Step 2: Apply Changes to Pilot

**Implementation Checklist:**

```powershell
# 1. Create pilot OU structure
New-ADOrganizationalUnit -Name "Pilot-Legacy-Remediation" -Path "DC=contoso,DC=com"

# 2. Move pilot systems to pilot OU
Get-ADComputer -Filter {Name -like "IT-*"} | Move-ADObject -TargetPath "OU=Pilot-Legacy-Remediation,DC=contoso,DC=com"

# 3. Create and link GPO for legacy protocol restrictions
New-GPO -Name "Pilot-Disable-Legacy-Protocols" | New-GPLink -Target "OU=Pilot-Legacy-Remediation,DC=contoso,DC=com"

# 4. Configure GPO settings
# - Disable NTLMv1
# - Disable SMBv1
# - Require SMB signing
# - Enable additional auditing

# 5. Force GPO update
Invoke-GPUpdate -Computer "PilotComputer1" -Force
```

### Step 3: Monitor Pilot

**Daily Monitoring (First Week):**
```kql
// Check for blocked legacy protocol attempts in pilot OU
WindowsEvent
| where TimeGenerated > ago(24h)
| where EventID == 8003  // NTLM blocked
| extend Computer = tostring(Computer)
| where Computer startswith "IT-"  // Pilot computers
| summarize Count=count() by Computer, tostring(EventData)
| order by Count desc
```

**Success Metrics:**
- Zero business process disruptions
- No increase in helpdesk tickets
- All applications functioning correctly
- Reduced legacy protocol usage to zero in pilot group

### Step 4: Gather Feedback & Iterate

**Pilot Feedback Form:**
```
Questions for Pilot Users:

1. Did you experience any issues accessing:
   - File shares? (Y/N - Details)
   - Email? (Y/N - Details)
   - Applications? (Y/N - Details)
   - Printers/scanners? (Y/N - Details)

2. Did you notice any performance changes?
   - Faster / Same / Slower
   - Details:

3. Did you receive adequate communication?
   - Yes / No / Partially
   - Suggestions:

4. Are you confident we can roll this out to the rest of the organization?
   - Yes / No / With changes
   - Concerns:
```

**Iterate Based on Feedback:**
- Fix any issues identified
- Update documentation
- Refine communication templates
- Adjust timeline if needed

## Phase 4: Production Rollout

### Timeline: Months 4-6

### Objectives
- Apply changes domain-wide in phases
- Minimize business disruption
- Maintain rollback capability
- Achieve zero legacy protocol usage

### Step 1: Phased Rollout Plan

**Example Rollout Schedule:**

```
Week 13-14: Administrative Users
- Domain Admins, Enterprise Admins
- IT management
- ~50 users
- Weekend deployment

Week 15-16: IT Department
- All IT staff excluding pilot (already done)
- ~200 users
- Weekend deployment

Week 17-20: Department by Department
- Week 17: Finance (100 users)
- Week 18: HR (75 users)
- Week 19: Sales (150 users)
- Week 20: Engineering (200 users)

Week 21-24: Remaining Users
- All other departments
- ~1000 users
- Phased by location/building

Week 25-26: Cleanup & Exceptions
- Handle remaining edge cases
- Address any outstanding issues
- Document permanent exceptions
```

### Step 2: Build Phase-Out and Block Gradually

**Gradual Enforcement Strategy:**

**Stage 1: Monitoring Only**
```
Duration: First 2 weeks of data collection
Action: Log only, no blocking
Purpose: Establish baseline
```

**Stage 2: Audit Mode**
```
Duration: Weeks 3-4
Action: Log with alerts, no blocking
Purpose: Identify all usage patterns
GPO: Network security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all
```

**Stage 3: Soft Block (Pilot)**
```
Duration: Weeks 9-12
Action: Block for pilot group, log exceptions
Purpose: Validate blocking works
GPO: Network security: Restrict NTLM: Incoming NTLM traffic = Deny all accounts (Pilot OU only)
```

**Stage 4: Hard Block (Production)**
```
Duration: Week 13+
Action: Block for all, log and alert on exceptions
Purpose: Full enforcement
GPO: Apply to all OUs in phases
```

### Step 3: Execute Production Changes

**Pre-Deployment Checklist:**
- [ ] Change request approved
- [ ] Communication sent (1 week prior)
- [ ] Monitoring dashboards confirmed working
- [ ] Rollback procedure documented and tested
- [ ] Support team briefed and ready
- [ ] Emergency contacts identified
- [ ] Maintenance window scheduled (if required)

**Deployment Day Procedure:**

```powershell
# Production deployment script
# Run during maintenance window

param(
    [Parameter(Mandatory=$true)]
    [string]$TargetOU,
    
    [switch]$WhatIf
)

# 1. Verify pre-requisites
Write-Host "Verifying pre-requisites..." -ForegroundColor Cyan
$gpo = Get-GPO -Name "Disable-Legacy-Protocols" -ErrorAction Stop
$ou = Get-ADOrganizationalUnit -Identity $TargetOU -ErrorAction Stop

# 2. Backup current GPO links
Write-Host "Backing up current GPO configuration..." -ForegroundColor Cyan
$backup = Get-GPLink -Target $TargetOU
$backup | Export-Clixml -Path "C:\Backups\GPO-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss').xml"

# 3. Link GPO to target OU
if ($WhatIf) {
    Write-Host "WHATIF: Would link GPO '$($gpo.DisplayName)' to OU '$TargetOU'" -ForegroundColor Yellow
} else {
    Write-Host "Linking GPO to production OU..." -ForegroundColor Cyan
    New-GPLink -Guid $gpo.Id -Target $TargetOU -LinkEnabled Yes -ErrorAction Stop
    Write-Host "GPO linked successfully" -ForegroundColor Green
}

# 4. Force GPO update on target systems
Write-Host "Forcing GPO update on target systems..." -ForegroundColor Cyan
$computers = Get-ADComputer -SearchBase $TargetOU -Filter *
foreach ($computer in $computers) {
    if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet) {
        if (!$WhatIf) {
            Invoke-GPUpdate -Computer $computer.Name -RandomDelayInMinutes 0 -Force
        }
    }
}

Write-Host "Deployment complete! Monitor dashboards for issues." -ForegroundColor Green
```

**Post-Deployment Monitoring (First 24 Hours):**
```kql
// Real-time monitoring query
// Run every 15 minutes first day
WindowsEvent
| where TimeGenerated > ago(15m)
| where EventID in (8003, 5447)  // Blocked NTLM, Error events
| summarize Count=count() by EventID, Computer, tostring(EventData)
| where Count > 0  // Any blocks should be investigated
```

### Step 4: Handle Exceptions

**Exception Handling Process:**

1. **User Reports Issue**
   - Log ticket with priority based on business impact
   - Collect detailed information (system, application, error message)

2. **Technical Investigation**
   - Reproduce issue in test environment
   - Identify root cause (missing SPN, legacy application, etc.)

3. **Resolution Options (in preference order):**
   a. **Fix Configuration** - Add SPN, update app settings (preferred)
   b. **Upgrade Application** - Update to version with modern auth
   c. **Isolate System** - Move to exception OU with restricted access
   d. **Temporary Exception** - Time-limited exemption with approval

4. **Document Exception**
   - Create exception record with justification
   - Set review date (3-6 months)
   - Notify security team
   - Add to exception tracking database

**Exception Tracking:**
```powershell
# Exception database schema (CSV/Database)
$exceptionTemplate = [PSCustomObject]@{
    ExceptionID = "EXC-2026-001"
    DateCreated = Get-Date
    RequestedBy = "john.doe@contoso.com"
    BusinessJustification = "Legacy ERP system cannot be upgraded until Q3"
    System = "ERP-SERVER-01"
    Protocol = "NTLMv2"
    Risk = "Medium"
    Mitigation = "System isolated on VLAN 100, monitored 24/7"
    ReviewDate = (Get-Date).AddMonths(3)
    ExpirationDate = (Get-Date).AddMonths(6)
    Approved By = "Jane Smith, CISO"
    Status = "Active"
}
```

## Phase 5: Monitoring & Enforcement

### Timeline: Ongoing (Month 7+)

### Objectives
- Maintain zero legacy protocol usage
- Detect and respond to violations quickly
- Continuously improve security posture
- Report progress to stakeholders

### Step 1: Continuous Monitoring

**Automated Daily Checks:**
```powershell
# Schedule this script to run daily
# Alert if any issues found

# Check 1: Verify no NTLMv1
$ntlmv1 = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624
    StartTime = (Get-Date).AddDays(-1)
} | Where-Object {$_.Properties[8].Value -match "NTLM V1"}

if ($ntlmv1) {
    Send-AlertEmail -Subject "ALERT: NTLMv1 Detected" -Body $ntlmv1
}

# Check 2: Verify no SMBv1 enabled
$computers = Get-ADComputer -Filter *
foreach ($computer in $computers | Select-Object -First 100) {
    if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet) {
        $smb1 = Invoke-Command -ComputerName $computer.Name -ScriptBlock {
            (Get-SmbServerConfiguration).EnableSMB1Protocol
        } -ErrorAction SilentlyContinue
        
        if ($smb1) {
            Send-AlertEmail -Subject "ALERT: SMBv1 Enabled" -Body "Computer: $($computer.Name)"
        }
    }
}

# Check 3: Review legacy auth attempts
# Query Sentinel/Log Analytics for any legacy auth in last 24h
```

### Step 2: Incident Response for Violations

**Automated Response Workflow:**

```
Legacy Protocol Detected
         ↓
    Log Incident
         ↓
    Assess Severity
         ↓
    ┌────┴─────────────────┐
    │                      │
Critical Path      Non-Critical Path
    │                      │
Block Immediately    Investigate First
    │                      │
Notify SOC          Schedule Remediation
    │                      │
Investigate         Apply Fix
    │                      │
Root Cause          Verify Resolution
    │                      │
Apply Fix           Close Ticket
    │
Verify
    │
Close Ticket
```

**Response Runbook for Common Scenarios:**

**Scenario 1: New System with SMBv1 Enabled**
```
1. Identify system and owner
2. Check if system is in exception list (No? Continue)
3. Remotely disable SMBv1
4. Notify system owner
5. Update configuration management to prevent recurrence
```

**Scenario 2: Application Using NTLM**
```
1. Identify application and business owner
2. Check if Kerberos SPNs are missing → Add SPNs
3. Test application functionality
4. If issue persists, create temporary exception
5. Schedule application upgrade/fix
```

### Step 3: Regular Reporting

**Weekly Report (Security Team):**
```kql
// Weekly legacy protocol summary
let StartTime = startofweek(now());
let EndTime = now();

union
    (SigninLogs | where TimeGenerated between(StartTime..EndTime) | where ClientAppUsed == "Other clients" | extend Protocol = "Legacy Auth"),
    (SecurityEvent | where TimeGenerated between(StartTime..EndTime) | where AuthenticationPackageName has "NTLM" | extend Protocol = "NTLM")
| summarize Count=count(), UniqueUsers=dcount(UserPrincipalName) by Protocol
| extend WeekOf = StartTime
```

**Monthly Report (Executive Leadership):**
```
Executive Summary: Legacy Protocol Elimination

Period: [Month Year]

METRICS:
✓ Legacy protocol usage: [X]% reduction vs last month
✓ NTLMv1 usage: 0 (target achieved)
✓ SMBv1 enabled systems: [X] (down from [Y])
✓ Compliance: [X]% compliant with security baseline

HIGHLIGHTS:
• Successfully migrated [Application Name] to Kerberos
• Decommissioned [X] legacy devices
• Completed phase [N] of deployment

CHALLENGES:
• [List any ongoing issues and mitigation plans]

NEXT MONTH:
• Phase [N+1] deployment to [Department]
• Legacy device replacement procurement
• Quarterly security assessment
```

**Quarterly Review (Governance):**
- Review all active exceptions
- Assess if exceptions can be closed
- Update risk register
- Review and update policies
- Plan next phase of improvements

## Remediation Playbooks by Protocol

### NTLM → Kerberos Migration
See: [NTLM to Kerberos Migration Guide](./NTLM-to-Kerberos.md)

Key steps:
1. Verify DNS is working correctly
2. Register Service Principal Names (SPNs)
3. Configure delegation if needed
4. Test Kerberos authentication
5. Block NTLM for pilot, then production

### SMBv1 → SMBv3 Migration
See: [SMBv1 to SMBv3 Migration Guide](./SMBv1-to-SMBv3.md)

Key steps:
1. Audit SMBv1 usage (2-4 weeks)
2. Update or replace legacy devices
3. Disable SMBv1 on clients
4. Disable SMBv1 on servers
5. Remove SMBv1 feature completely

### Legacy Mail → Modern Auth
See: [Legacy Mail to Modern Auth Guide](./Legacy-Mail-to-Modern.md)

Key steps:
1. Identify applications using POP/IMAP/SMTP Auth
2. Update applications to OAuth 2.0
3. Deploy Conditional Access policies
4. Disable basic auth in Exchange Online
5. Block legacy protocols at tenant level

### Telnet → SSH
See: [Telnet to SSH Migration Guide](./Telnet-to-SSH.md)

Key steps:
1. Identify systems with Telnet enabled
2. Install and configure SSH server
3. Migrate scripts and processes to SSH
4. Disable Telnet service
5. Block Telnet at firewall

## Rollback Procedures

### When to Rollback

**Immediate Rollback Triggers:**
- Critical business process failure
- Multiple reports of inability to work
- Security incident caused by changes
- Major compliance violation

**Investigate First (Don't Rollback):**
- Individual user issues (likely configuration)
- Expected changes (non-modern apps)
- Performance questions (gather metrics first)

### Rollback Steps

**GPO-Based Changes:**
```powershell
# Remove GPO link
Remove-GPLink -Name "Disable-Legacy-Protocols" -Target "OU=Department,DC=contoso,DC=com"

# Force update
Invoke-GPUpdate -Computer "TargetComputer" -Force

# Verify rollback
gpresult /h gpresult.html
```

**Registry-Based Changes:**
```powershell
# Re-enable NTLM (emergency only)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 3

# Re-enable SMBv1 (emergency only - requires reboot)
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

Restart-Computer
```

**Post-Rollback:**
1. Document what failed and why
2. Communicate status to stakeholders
3. Fix root cause in test environment
4. Re-test before attempting again
5. Update runbook with lessons learned

## Success Criteria & KPIs

### Technical Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| NTLMv1 Usage | 0 | Daily automated check |
| NTLMv2 Usage | <5% of auth events | Weekly trend report |
| SMBv1 Enabled Systems | 0 | Daily automated check |
| Legacy Auth Sign-ins (Cloud) | 0 | Daily Azure AD report |
| Telnet/FTP Services | 0 | Weekly network scan |
| Unencrypted LDAP | 0 | Weekly DC audit |

### Business Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Business Process Disruption | 0 critical incidents | Incident tracking |
| User Satisfaction | >85% positive | Post-deployment survey |
| Helpdesk Ticket Increase | <10% temporary spike | Ticket system |
| Time to Resolve Issues | <4 hours | Incident metrics |
| Project Delivery | On time, on budget | Project tracking |

### Security Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Vulnerability Scan Results | 0 critical legacy protocol vulns | Monthly scan |
| Security Incidents | 0 related to legacy protocols | SIEM analysis |
| Compliance Gaps | 0 related to legacy protocols | Quarterly audit |
| Pen Test Results | No legacy protocol exploits | Annual test |

## Common Pitfalls & How to Avoid Them

### Pitfall 1: Insufficient Monitoring
**Problem:** Disabling protocols without understanding usage
**Solution:** Always collect 2-4 weeks of baseline data first

### Pitfall 2: No Rollback Plan
**Problem:** Critical issue with no way to quickly recover
**Solution:** Document and test rollback before production

### Pitfall 3: Poor Communication
**Problem:** Users surprised by changes, helpdesk overwhelmed
**Solution:** Communicate early, often, and clearly

### Pitfall 4: Ignoring Legacy Hardware
**Problem:** Business-critical printer/scanner stops working
**Solution:** Identify all hardware dependencies upfront

### Pitfall 5: All-at-Once Approach
**Problem:** Too many changes, can't isolate issues
**Solution:** Phased rollout with pilot testing

### Pitfall 6: No Executive Support
**Problem:** Project stalls when budget or approvals needed
**Solution:** Secure executive sponsorship before starting

## Templates & Checklists

### Pre-Deployment Checklist
- [ ] Monitoring enabled and collecting data (2+ weeks)
- [ ] All dependencies documented
- [ ] Stakeholders informed and supportive
- [ ] Pilot completed successfully
- [ ] Rollback procedure documented and tested
- [ ] Support team trained
- [ ] Communication sent to affected users
- [ ] Change request approved
- [ ] Maintenance window scheduled (if needed)

### Post-Deployment Checklist
- [ ] Confirm services are running normally
- [ ] Review monitoring dashboards (no critical alerts)
- [ ] Verify zero legacy protocol usage in target group
- [ ] Check helpdesk queue for related issues
- [ ] Send confirmation email to stakeholders
- [ ] Update project tracker
- [ ] Document lessons learned
- [ ] Plan next phase

### Exception Request Template
See: [Exception Request Form](./Exception-Request-Template.md)

## Additional Resources

### Microsoft Documentation
- [Eliminating NTLM from your environment](https://techcommunity.microsoft.com/t5/itops-talk-blog/beyond-the-edge-of-ntlm/ba-p/1422348)
- [Transition away from SMBv1](https://aka.ms/stopusingsmb1)
- [Blocking legacy authentication in Azure AD](https://docs.microsoft.com/azure/active-directory/conditional-access/block-legacy-authentication)

### Community Resources
- [NTLM-Must-Die GitHub Repository](https://github.com/MBCloudTeck/NTLM-Must-Die)
- [Microsoft Security Community](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/ct-p/MicrosoftSecurityandCompliance)

---

**[← Back to Legacy Protocols](../README.md)** | **[Detection & Monitoring →](../Detection-Monitoring/)**
