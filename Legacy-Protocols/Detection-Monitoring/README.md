# Detection & Monitoring: Legacy Protocols

## Overview

Effective detection and monitoring is the foundation of any legacy protocol elimination program. This guide provides comprehensive strategies, tools, and queries for identifying legacy protocol usage across on-premises and cloud environments.

## Detection Strategy Framework

### 1. Multi-Layer Approach

```
┌─────────────────────────────────────────────────────┐
│               Cloud Layer (Azure AD)                 │
│  • Sign-in logs • Conditional Access • MDCA         │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────┴──────────────────────────────────┐
│            Identity Layer (AD, LDAP)                 │
│  • DC logs • NTLM audit • Kerberos events           │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────┴──────────────────────────────────┐
│          Application Layer (Services)                │
│  • IIS logs • Exchange • SQL • SharePoint           │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────┴──────────────────────────────────┐
│           Network Layer (Traffic)                    │
│  • Firewall logs • IDS/IPS • NetFlow               │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────┴──────────────────────────────────┐
│           Endpoint Layer (Devices)                   │
│  • Event logs • EDR • Configuration state           │
└─────────────────────────────────────────────────────┘
```

### 2. Detection Phases

| Phase | Duration | Focus | Success Criteria |
|-------|----------|-------|-----------------|
| **Baseline** | 2-4 weeks | Normal usage patterns | Complete visibility established |
| **Analysis** | 1-2 weeks | Identify dependencies | All use cases documented |
| **Monitoring** | Ongoing | Track changes, detect anomalies | Alerts firing correctly |
| **Enforcement** | Phased | Block legacy, alert on violations | Zero legacy protocol usage |

## On-Premises Detection

### Active Directory / Domain Controllers

#### Enable NTLM Auditing

**Via Group Policy:**
```
Computer Configuration
 → Policies
  → Windows Settings
   → Security Settings
    → Local Policies
     → Security Options
      → Network security: Restrict NTLM: Audit NTLM authentication in this domain
         Set to: Enable all
```

**Via PowerShell:**
```powershell
# Enable NTLM auditing on all DCs
$DCs = (Get-ADDomainController -Filter *).Name

foreach ($DC in $DCs) {
    Invoke-Command -ComputerName $DC -ScriptBlock {
        # Enable NTLM Operational logging
        wevtutil sl Microsoft-Windows-NTLM/Operational /e:true
        wevtutil sl Microsoft-Windows-NTLM/Operational /ms:104857600  # 100MB
        
        # Enable advanced audit policy
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable
        auditpol /set /subcategory:"Credential Validation" /success:enable
    }
}
```

#### Enable LDAP Auditing

**Registry Configuration:**
```powershell
# Enable LDAP diagnostics on DCs
$DCs = (Get-ADDomainController -Filter *).Name

foreach ($DC in $DCs) {
    Invoke-Command -ComputerName $DC -ScriptBlock {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" `
            -Name "16 LDAP Interface Events" -Value 2
    }
}
```

**Event to Monitor:**
- Event ID 2889 → LDAP simple bind / cleartext bind detected

#### Key Event IDs Reference

| Event ID | Log | Description | Priority |
|----------|-----|-------------|----------|
| 4624 | Security | Account logon | High |
| 4625 | Security | Logon failure | High |
| 4776 | Security | DC credential validation | High |
| 8001 | NTLM Operational | Outbound NTLM auth | Medium |
| 8002 | NTLM Operational | Inbound NTLM auth | Medium |
| 8003 | NTLM Operational | NTLM blocked | Critical |
| 8004 | NTLM Operational | DC NTLM request | Medium |
| 2889 | Directory Service | LDAP simple bind | High |
| 5136 | Security | Directory object modified | Low |

### Windows Event Log Queries

#### PowerShell: Find NTLMv1 Usage
```powershell
# Search for NTLMv1 in last 7 days across all DCs
$StartTime = (Get-Date).AddDays(-7)
$DCs = (Get-ADDomainController -Filter *).Name

$results = @()
foreach ($DC in $DCs) {
    Write-Host "Checking $DC..." -ForegroundColor Cyan
    
    $events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
        LogName = 'Security'
        Id = 4624
        StartTime = $StartTime
    } -ErrorAction SilentlyContinue | Where-Object {
        $_.Properties[8].Value -match "NTLM V1"
    }
    
    foreach ($event in $events) {
        $results += [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            DomainController = $DC
            UserName = $event.Properties[5].Value
            Workstation = $event.Properties[11].Value
            SourceIP = $event.Properties[18].Value
            AuthPackage = $event.Properties[8].Value
        }
    }
}

$results | Export-Csv -Path "C:\Reports\NTLMv1-Detections.csv" -NoTypeInformation
$results | Format-Table -AutoSize
```

#### PowerShell: LDAP Simple Bind Detection
```powershell
# Find LDAP simple binds (Event 2889)
$DCs = (Get-ADDomainController -Filter *).Name
$results = @()

foreach ($DC in $DCs) {
    $events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
        LogName = 'Directory Service'
        Id = 2889
        StartTime = (Get-Date).AddDays(-7)
    } -ErrorAction SilentlyContinue
    
    foreach ($event in $events) {
        $results += [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            DomainController = $DC
            ClientIP = $event.Properties[0].Value
            BindingType = $event.Properties[1].Value
        }
    }
}

$results | Group-Object ClientIP | Sort-Object Count -Descending | 
    Select-Object Count, Name | Format-Table -AutoSize
```

### Network-Level Detection

#### Network IDS/IPS Rules

**Zeek (formerly Bro) Script:**
```zeek
# Detect legacy protocols
event protocol_confirmation(c: connection, atype: Analyzer::Tag, aid: count)
{
    if ( atype == Analyzer::ANALYZER_SMB1 ) {
        NOTICE([$note=SMBv1_Usage,
                $msg=fmt("SMBv1 detected from %s to %s", c$id$orig_h, c$id$resp_h),
                $conn=c]);
    }
    
    if ( atype == Analyzer::ANALYZER_TELNET ) {
        NOTICE([$note=Telnet_Usage,
                $msg=fmt("Telnet connection from %s to %s", c$id$orig_h, c$id$resp_h),
                $conn=c]);
    }
}
```

**Suricata Rules:**
```
# Detect SMBv1
alert smb any any -> any any (msg:"SMBv1 Protocol Detected"; smb.version:1; sid:2000001;)

# Detect Telnet
alert tcp any any -> any 23 (msg:"Telnet Connection Attempt"; sid:2000002;)

# Detect unencrypted FTP
alert tcp any any -> any 21 (msg:"FTP Control Connection"; sid:2000003;)

# Detect POP3
alert tcp any any -> any 110 (msg:"Unencrypted POP3 Connection"; sid:2000004;)

# Detect IMAP
alert tcp any any -> any 143 (msg:"Unencrypted IMAP Connection"; sid:2000005;)
```

**Snort Rules:**
```
# Basic legacy protocol detection
alert tcp any any -> any 23 (msg:"TELNET Traffic Detected"; flow:to_server,established; content:"|FF|"; depth:1; sid:1000001;)
alert tcp any any -> any 21 (msg:"FTP Traffic Detected"; flow:to_server,established; content:"USER "; sid:1000002;)
alert tcp any any -> any 110 (msg:"POP3 Traffic Detected"; flow:to_server,established; content:"USER "; sid:1000003;)
alert tcp any any -> any 445 (msg:"SMB Traffic Detected"; flow:to_server,established; content:"|FF|SMB"; depth:8; sid:1000004;)
```

#### NetFlow Analysis

**Typical Legacy Protocol Ports:**
```
Protocol    | TCP Port | UDP Port | Detection Method
------------|----------|----------|------------------
Telnet      | 23       | -        | Any traffic to TCP/23
FTP         | 20, 21   | -        | Traffic to TCP/21 (control)
TFTP        | -        | 69       | Traffic to UDP/69
SMTP (clear)| 25       | -        | Traffic to TCP/25 without STARTTLS
POP3 (clear)| 110      | -        | Traffic to TCP/110
IMAP (clear)| 143      | -        | Traffic to TCP/143
SNMP v1/v2  | -        | 161, 162 | SNMP community string in cleartext
NetBIOS     | 137-139  | 137, 138 | Legacy name resolution
SMB/CIFS    | 445      | -        | Check for SMBv1 signature
LDAP (clear)| 389      | -        | Traffic to TCP/389 without TLS
```

**Sample NetFlow Query (Cisco Stealthwatch):**
```sql
-- Find systems using legacy ports
SELECT 
    source_ip,
    destination_ip,
    destination_port,
    COUNT(*) as connection_count,
    SUM(bytes) as total_bytes
FROM netflow_data
WHERE destination_port IN (21, 23, 110, 143, 389)
    AND timestamp > NOW() - INTERVAL '7 days'
GROUP BY source_ip, destination_ip, destination_port
ORDER BY connection_count DESC;
```

## Cloud Detection (Microsoft 365 / Azure)

### Azure AD Sign-in Logs

#### Legacy Authentication Detection

**Azure Portal:**
```
Azure Active Directory
 → Sign-ins
  → Add filters:
   • Client App: Filter = "Other clients"
   • Status: All
   • Date: Last 30 days
```

**PowerShell:**
```powershell
# Connect to Azure AD
Connect-AzureAD
Connect-AzAccount

# Get legacy auth sign-ins
$startDate = (Get-Date).AddDays(-30)
$endDate = Get-Date

# Note: This requires Azure AD Premium P1 or P2
$signIns = Get-AzureADAuditSignInLogs -Filter "createdDateTime ge $($startDate.ToString('yyyy-MM-dd')) and clientAppUsed eq 'Other clients'"

$legacyAuth = $signIns | Select-Object `
    createdDateTime,
    userPrincipalName,
    clientAppUsed,
    @{N='App';E={$_.resourceDisplayName}},
    @{N='Location';E={$_.location.city}},
    @{N='Status';E={$_.status.errorCode}}

$legacyAuth | Export-Csv -Path "C:\Reports\Legacy-Auth-SignIns.csv" -NoTypeInformation

# Summary by user
$legacyAuth | Group-Object userPrincipalName | 
    Select-Object Count, Name | Sort-Object Count -Descending | 
    Format-Table -AutoSize
```

### Exchange Online Monitoring

#### Check Mailbox Protocol Status
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Get all mailboxes with legacy protocols enabled
$mailboxes = Get-EXOMailbox -ResultSize Unlimited | Get-EXOCASMailbox | 
    Select-Object DisplayName, UserPrincipalName, ImapEnabled, PopEnabled, 
                  ActiveSyncEnabled, MAPIEnabled, OWAEnabled

# Filter to those with legacy protocols enabled
$legacyEnabled = $mailboxes | Where-Object {
    $_.ImapEnabled -eq $true -or 
    $_.PopEnabled -eq $true -or 
    $_.ActiveSyncEnabled -eq $true
}

$legacyEnabled | Export-Csv -Path "C:\Reports\Mailboxes-Legacy-Protocols.csv" -NoTypeInformation

Write-Host "`nMailboxes with legacy protocols enabled: $($legacyEnabled.Count)" -ForegroundColor Yellow
```

#### Check Actual Usage
```powershell
# Get mailbox statistics to see actual protocol usage
$startDate = (Get-Date).AddDays(-30)
$endDate = Get-Date

$usage = Get-MessageTrace -StartDate $startDate -EndDate $endDate |
    Where-Object {$_.FromIP -match "^(\d{1,3}\.){3}\d{1,3}$"} |
    Select-Object Received, SenderAddress, RecipientAddress, FromIP, MessageTraceId

# Export for analysis
$usage | Export-Csv -Path "C:\Reports\Mail-Protocol-Usage.csv" -NoTypeInformation
```

## Microsoft Sentinel Integration

### Workspace Setup

**Enable Required Data Connectors:**
1. Azure Active Directory (Sign-in logs)
2. Azure Active Directory Identity Protection
3. Windows Security Events (via AMA)
4. Windows Forwarded Events
5. DNS (optional)
6. Office 365 (Exchange logs)

### KQL Detection Queries

#### Comprehensive Legacy Protocol Detection
```kql
// Master query for all legacy protocol detections
union
    // Azure AD legacy authentication
    (SigninLogs
    | where TimeGenerated > ago(30d)
    | where ClientAppUsed == "Other clients"
    | extend Protocol = "Azure AD Legacy Auth"
    | project TimeGenerated, Protocol, UserPrincipalName, IPAddress, AppDisplayName, ResultType),
    
    // NTLM authentication
    (SecurityEvent
    | where TimeGenerated > ago(30d)
    | where EventID in (4624, 4776)
    | where AuthenticationPackageName has "NTLM"
    | extend Protocol = "NTLM"
    | project TimeGenerated, Protocol, Account, Computer, IpAddress, EventID),
    
    // NTLMv1 specific
    (WindowsEvent
    | where TimeGenerated > ago(30d)
    | where EventID == 4624
    | extend LmPackage = tostring(EventData["LmPackageName"])
    | where LmPackage == "NTLM V1"
    | extend Protocol = "NTLMv1"
    | project TimeGenerated, Protocol, Computer, tostring(EventData["TargetUserName"]), tostring(EventData["IpAddress"])),
    
    // LDAP simple bind
    (WindowsEvent
    | where TimeGenerated > ago(30d)
    | where Channel == "Directory Service" and EventID == 2889
    | extend Protocol = "LDAP Simple Bind"
    | project TimeGenerated, Protocol, Computer, tostring(EventData["Client IP Address"])),
    
    // SMBv1 (if logged)
    (Event
    | where TimeGenerated > ago(30d)
    | where EventLog == "Microsoft-Windows-SmbServer/Security"
    | where EventID == 1009
    | extend Protocol = "SMBv1"
    | project TimeGenerated, Protocol, Computer, tostring(EventData))
| summarize Count=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) 
    by Protocol, bin(TimeGenerated, 1d)
| render timechart
```

#### High-Risk Legacy Authentication Patterns
```kql
// Detect risky legacy authentication patterns
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed == "Other clients"
| extend RiskFactors = pack_array(
    iff(RiskLevelDuringSignIn == "high", "High Risk User", ""),
    iff(RiskLevelAggregated == "high", "High Aggregate Risk", ""),
    iff(ipv4_is_private(IPAddress) == false, "External IP", ""),
    iff(LocationDetails.countryOrRegion !in ("US", "CA", "UK"), "Unusual Location", "")
)
| where array_length(RiskFactors) > 1
| project TimeGenerated, UserPrincipalName, AppDisplayName, ClientAppUsed, IPAddress, 
          Location=tostring(LocationDetails.city), RiskFactors, ResultType
| order by TimeGenerated desc
```

#### Failed Legacy Authentication Attempts
```kql
// Potential brute force via legacy protocols
SigninLogs
| where TimeGenerated > ago(24h)
| where ClientAppUsed == "Other clients"
| where ResultType != "0"  // Failed sign-ins
| summarize 
    FailedAttempts = count(),
    DistinctIPs = dcount(IPAddress),
    Apps = make_set(AppDisplayName),
    Errors = make_set(ResultDescription)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where FailedAttempts > 5
| order by FailedAttempts desc
```

### Custom Workbook for Legacy Protocols

The main repository includes a comprehensive workbook. Deploy it to Sentinel:

**Steps:**
1. Navigate to Sentinel → Workbooks → Add workbook
2. Click Edit → Advanced Editor
3. Paste the JSON from `Legacy Protocols` file (lines 297-368)
4. Click Apply → Save
5. Name: "Legacy Protocol Monitoring"

### Analytics Rules

#### Create Alert: NTLMv1 Detected
```kql
// Alert on ANY NTLMv1 usage (should be zero)
WindowsEvent
| where TimeGenerated > ago(5m)
| where Provider == "Microsoft-Windows-Security-Auditing"
| where EventID == 4624
| extend LmPackageName = tostring(EventData["LmPackageName"])
| where LmPackageName == "NTLM V1"
| extend TargetUser = tostring(EventData["TargetUserName"])
| extend IpAddress = tostring(EventData["IpAddress"])
| project TimeGenerated, Computer, TargetUser, IpAddress, LmPackageName
```

**Alert Configuration:**
- Severity: High
- Frequency: Every 5 minutes
- Lookup: Last 5 minutes
- Alert threshold: Greater than 0 results
- Action: Email security team, create incident

#### Create Alert: Spike in Legacy Auth
```kql
// Alert on unusual increase in legacy authentication
let baseline = SigninLogs
| where TimeGenerated between(ago(14d)..ago(7d))
| where ClientAppUsed == "Other clients"
| summarize BaselineCount = count() by bin(TimeGenerated, 1d)
| summarize AvgBaseline = avg(BaselineCount);

SigninLogs
| where TimeGenerated > ago(1h)
| where ClientAppUsed == "Other clients"
| summarize CurrentCount = count()
| extend Baseline = toscalar(baseline)
| extend PercentIncrease = round((CurrentCount - Baseline) * 100.0 / Baseline, 1)
| where PercentIncrease > 50  // 50% increase over baseline
| project CurrentCount, Baseline, PercentIncrease
```

## Automated Detection Scripts

### PowerShell: Comprehensive Audit Script

```powershell
<#
.SYNOPSIS
    Comprehensive legacy protocol detection and reporting
.DESCRIPTION
    Scans on-premises and cloud environments for legacy protocol usage
.EXAMPLE
    .\Detect-LegacyProtocols.ps1 -Domain "contoso.com" -ReportPath "C:\Reports"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Domain,
    
    [Parameter(Mandatory=$true)]
    [string]$ReportPath,
    
    [int]$DaysBack = 7,
    
    [switch]$IncludeCloud
)

# Create report directory
New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null

Write-Host "=== Legacy Protocol Detection Started ===" -ForegroundColor Cyan
Write-Host "Domain: $Domain" -ForegroundColor White
Write-Host "Looking back: $DaysBack days" -ForegroundColor White
Write-Host ""

# 1. Check NTLM usage
Write-Host "[1/6] Checking NTLM usage..." -ForegroundColor Yellow
$startTime = (Get-Date).AddDays(-$DaysBack)
$DCs = (Get-ADDomainController -Filter *).Name

$ntlmResults = @()
foreach ($DC in $DCs) {
    $events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
        LogName = 'Security'
        Id = 4776
        StartTime = $startTime
    } -ErrorAction SilentlyContinue
    
    $ntlmResults += [PSCustomObject]@{
        DomainController = $DC
        NTLMCount = $events.Count
    }
}
$ntlmResults | Export-Csv -Path "$ReportPath\NTLM-Usage.csv" -NoTypeInformation

# 2. Check for SMBv1
Write-Host "[2/6] Checking SMBv1 status..." -ForegroundColor Yellow
$computers = Get-ADComputer -Filter * -SearchBase "OU=Workstations,DC=$($Domain.Split('.')[0]),DC=$($Domain.Split('.')[1])"

$smbResults = @()
foreach ($computer in $computers | Select-Object -First 100) {
    if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet) {
        try {
            $smb = Invoke-Command -ComputerName $computer.Name -ScriptBlock {
                (Get-SmbServerConfiguration).EnableSMB1Protocol
            } -ErrorAction Stop
            
            $smbResults += [PSCustomObject]@{
                ComputerName = $computer.Name
                SMBv1Enabled = $smb
            }
        } catch {}
    }
}
$smbResults | Export-Csv -Path "$ReportPath\SMBv1-Status.csv" -NoTypeInformation

# 3. Check for Telnet service
Write-Host "[3/6] Checking for Telnet service..." -ForegroundColor Yellow
# Implementation similar to above

# 4. Cloud checks (if enabled)
if ($IncludeCloud) {
    Write-Host "[4/6] Checking Azure AD legacy auth..." -ForegroundColor Yellow
    Connect-AzureAD -ErrorAction SilentlyContinue
    # Add cloud checks here
}

Write-Host ""
Write-Host "=== Detection Complete ===" -ForegroundColor Green
Write-Host "Reports saved to: $ReportPath" -ForegroundColor White
```

## Continuous Monitoring Best Practices

### 1. Establish Baselines
- Collect 2-4 weeks of normal usage data
- Document expected legacy protocol usage
- Identify business-critical dependencies

### 2. Set Up Automated Alerts
- NTLMv1: Alert on ANY usage (zero tolerance)
- SMBv1: Alert on ANY enabled systems
- Legacy auth: Alert on 50%+ increase over baseline
- Failed auth: Alert on 10+ failures in 1 hour

### 3. Regular Review Cadence
- Daily: Review critical alerts (NTLMv1, SMBv1)
- Weekly: Review trend reports, new legacy usage
- Monthly: Executive summary, progress metrics

### 4. Dashboard Metrics
- Total legacy protocol authentications (trend)
- Systems with legacy protocols enabled (count)
- Top users of legacy protocols
- Top applications using legacy protocols
- Geographic distribution of legacy usage

## Troubleshooting Detection

### Common Issues

**Issue: No events being logged**
```powershell
# Verify auditing is enabled
auditpol /get /subcategory:"Credential Validation"
auditpol /get /subcategory:"Logon"

# Check event log configuration
wevtutil gl Security
wevtutil gl Microsoft-Windows-NTLM/Operational
```

**Issue: Too many events, log filling up**
```powershell
# Increase log size
wevtutil sl Security /ms:1073741824  # 1GB
wevtutil sl Microsoft-Windows-NTLM/Operational /ms:209715200  # 200MB

# Configure log retention
wevtutil sl Security /rt:false  # Don't overwrite
```

**Issue: Events not forwarding to SIEM**
```powershell
# Check WEF subscription status
wecutil gs <SubscriptionName>

# Verify event log reader service
Get-Service Wecsvc
```

## Additional Resources

- [Sentinel Data Connectors](https://docs.microsoft.com/azure/sentinel/connect-data-sources)
- [Azure Monitor Agent](https://docs.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-overview)
- [Windows Event Forwarding](https://docs.microsoft.com/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection)

---

**[← Back to Legacy Protocols](../README.md)** | **[Resources →](../../NTLM%20resources/)**
