# NTLMv1 & NTLMv2: Legacy Windows Authentication

## Overview

NTLM (NT LAN Manager) is a challenge-response authentication protocol that has been the default Windows authentication method since Windows NT. Despite being superseded by Kerberos, NTLM remains widely deployed and poses significant security risks.

## Protocol Versions

### NTLMv1 (1993)
- **Status**: ⛔ **CRITICALLY INSECURE** - Must be disabled immediately
- **Cryptography**: DES encryption, MD4 hashing
- **Key Length**: 56-bit effective (DES)
- **Known Attacks**: Rainbow tables, GPU cracking, relay attacks
- **Crack Time**: Minutes to hours with modern hardware

### NTLMv2 (1998)
- **Status**: ⚠️ **HIGH RISK** - Plan migration to Kerberos
- **Cryptography**: HMAC-MD5
- **Key Length**: 128-bit
- **Known Attacks**: Relay attacks (without SMB signing), pass-the-hash
- **Crack Time**: Days to months (strong passwords), minutes (weak passwords)

## Security Vulnerabilities

### 1. NTLMv1 Specific Vulnerabilities

#### DES Encryption Weakness
```
Problem: Uses 56-bit DES encryption (effectively 56-bit security)
Impact: Can be brute-forced with modern hardware
Attack: Rainbow tables, GPU cracking (< 1 day with consumer hardware)
```

#### MD4 Hashing
```
Problem: MD4 is cryptographically broken
Impact: Password hashes can be cracked offline
Attack: Pre-computed hash tables, collision attacks
```

#### No Server Authentication
```
Problem: Client cannot verify server identity
Impact: Man-in-the-middle attacks possible
Attack: Fake server can capture credentials
```

### 2. NTLMv2 Vulnerabilities

#### NTLM Relay Attacks
```
Problem: No mutual authentication, tokens can be relayed
Impact: Attacker can impersonate users without knowing password
Attack: Tools like Responder, ntlmrelayx, Inveigh
```

#### Pass-the-Hash (PTH)
```
Problem: NTLM hash itself can authenticate (no salt)
Impact: Stolen hash works indefinitely until password changed
Attack: Mimikatz, Pass-the-Hash Toolkit
```

#### No Channel Binding
```
Problem: Cannot bind authentication to secure channel
Impact: NTLM authentication can be replayed on different connections
Attack: Session hijacking, credential forwarding attacks
```

#### No Mutual Authentication
```
Problem: Server identity not verified by default
Impact: Client may authenticate to rogue server
Attack: Evil Twin, Man-in-the-Middle
```

## Common Attack Scenarios

### Scenario 1: NTLM Relay Attack

**Attack Chain:**
1. Attacker runs Responder/ntlmrelayx on network
2. Victim attempts to access attacker-controlled SMB share
3. Attacker relays NTLM authentication to target server
4. Attacker gains access as victim user

**Prerequisites:**
- SMB signing not required on target
- NTLM authentication enabled
- Network access to victim and target

**Impact:**
- Administrative access to target systems
- Lateral movement across domain
- Data exfiltration

**Real-World Example:**
```bash
# Attacker runs relay attack
python ntlmrelayx.py -tf targets.txt -smb2support

# Meanwhile, runs responder to poison network
responder -I eth0 -w -v

# Victim unknowingly triggers authentication
# Attacker gains admin access to target servers
```

### Scenario 2: Pass-the-Hash Attack

**Attack Chain:**
1. Attacker compromises workstation
2. Extracts NTLM hash from memory (Mimikatz)
3. Uses hash to authenticate to other systems
4. Lateral movement without knowing password

**Detection:**
```kql
// Detect Pass-the-Hash in Azure Sentinel
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where LogonType == 9  // NewCredentials
| where AuthenticationPackageName == "NTLM"
| project TimeGenerated, Computer, Account, LogonProcessName, IpAddress
```

### Scenario 3: NTLMv1 Downgrade Attack

**Attack Chain:**
1. Attacker forces client to use NTLMv1 (protocol downgrade)
2. Captures NTLMv1 challenge-response
3. Cracks credentials offline using rainbow tables
4. Uses credentials for further attacks

**Prevention:**
```powershell
# Disable NTLMv1 via Group Policy
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 5
```

## Detection & Monitoring

### Windows Event Logs

#### Key Event IDs

| Event ID | Log Source | Description | Use Case |
|----------|-----------|-------------|----------|
| 4624 | Security | Successful logon | Identify NTLM usage, detect NTLMv1 |
| 4625 | Security | Failed logon | Detect brute-force, spray attacks |
| 4776 | Security | DC credential validation | Track NTLM authentications at DC |
| 8001 | NTLM Operational | Outgoing NTLM auth | Identify source applications |
| 8002 | NTLM Operational | Incoming NTLM auth | Identify server NTLM usage |
| 8003 | NTLM Operational | NTLM blocked | Audit denial policies |
| 8004 | NTLM Operational | DC NTLM audit | Track DC NTLM processing |

### Enable NTLM Auditing

#### Step 1: Enable Advanced Audit Policy
```powershell
# Via PowerShell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

# Via Group Policy
# Computer Configuration → Policies → Windows Settings → Security Settings
# → Advanced Audit Policy Configuration → Account Logon
# → Audit Credential Validation: Success, Failure
```

#### Step 2: Enable NTLM Operational Logging
```powershell
# Enable NTLM Operational channel
wevtutil sl Microsoft-Windows-NTLM/Operational /e:true

# Via Group Policy
# Computer Configuration → Policies → Windows Settings → Security Settings
# → Local Policies → Security Options
# Network security: Restrict NTLM: Audit NTLM authentication in this domain
# Set to: Enable all
```

#### Step 3: Increase Log Size
```powershell
# Increase NTLM Operational log size to 100MB
wevtutil sl Microsoft-Windows-NTLM/Operational /ms:104857600
```

### Detection Queries

#### Microsoft Sentinel / Azure Monitor

**Detect NTLMv1 Usage (CRITICAL)**
```kql
// Parse Windows Events for NTLMv1
WindowsEvent
| where TimeGenerated > ago(30d)
| where Provider == "Microsoft-Windows-Security-Auditing"
| where EventID == 4624
| extend LmPackageName = tostring(EventData["LmPackageName"])
| where isnotempty(LmPackageName) and LmPackageName == "NTLM V1"
| extend TargetUser = tostring(EventData["TargetUserName"])
| extend IpAddress = tostring(EventData["IpAddress"])
| extend Workstation = tostring(EventData["WorkstationName"])
| project TimeGenerated, Computer, TargetUser, IpAddress, Workstation, LmPackageName
| summarize Count=count(), LastSeen=max(TimeGenerated) by Computer, TargetUser, IpAddress, Workstation
| order by Count desc
```

**NTLM Authentication Summary**
```kql
// Overall NTLM usage patterns
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4624, 4625)
| where AuthenticationPackageName has "NTLM"
| summarize 
    SuccessCount = countif(EventID == 4624),
    FailureCount = countif(EventID == 4625)
    by Computer, Account, IpAddress
| extend FailureRate = round((FailureCount * 100.0) / (SuccessCount + FailureCount), 2)
| where FailureRate > 10 or FailureCount > 50  // Potential attack indicators
| order by FailureCount desc
```

**NTLM Relay Attack Indicators**
```kql
// Detect potential NTLM relay attacks
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where AuthenticationPackageName == "NTLM"
| where LogonType in (3, 9)  // Network logon, NewCredentials
| summarize 
    DistinctComputers = dcount(Computer),
    DistinctIPs = dcount(IpAddress),
    Count = count()
    by Account
| where DistinctComputers > 10 or DistinctIPs > 10  // Same account, many targets
| order by DistinctComputers desc
```

**Geographic Anomalies with NTLM**
```kql
// Detect impossible travel with NTLM
SigninLogs
| where TimeGenerated > ago(24h)
| where AuthenticationProtocol has "NTLM"
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| project TimeGenerated, UserPrincipalName, Country, City, IPAddress
| order by UserPrincipalName, TimeGenerated asc
| serialize
| extend PrevCountry = prev(Country, 1)
| extend PrevTime = prev(TimeGenerated, 1)
| extend TimeDiffMinutes = datetime_diff('minute', TimeGenerated, PrevTime)
| where Country != PrevCountry and TimeDiffMinutes < 60  // Different country within 1 hour
| project TimeGenerated, UserPrincipalName, Country, PrevCountry, TimeDiffMinutes, IPAddress
```

### PowerShell Detection Scripts

**Audit NTLM Configuration**
```powershell
# Check NTLM level
$ntlmLevel = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel

$levels = @{
    0 = "Send LM and NTLM - no NTLMv2 session security"
    1 = "Use NTLMv2 session security if negotiated"
    2 = "Send NTLM only"
    3 = "Send NTLMv2 only"
    4 = "DC refuses LM"
    5 = "DC refuses LM and NTLM (accepts only NTLMv2)"
}

Write-Host "Current NTLM Level: $ntlmLevel - $($levels[$ntlmLevel])" -ForegroundColor $(if($ntlmLevel -ge 5){"Green"}else{"Red"})
```

**Find Systems Using NTLM**
```powershell
# Query domain controllers for NTLM usage
$DCs = (Get-ADDomainController -Filter *).Name

foreach ($DC in $DCs) {
    Write-Host "Checking $DC..." -ForegroundColor Cyan
    
    $events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
        LogName = 'Security'
        Id = 4776
        StartTime = (Get-Date).AddDays(-7)
    } -MaxEvents 1000 -ErrorAction SilentlyContinue
    
    $ntlmCount = $events.Count
    Write-Host "  NTLM authentications: $ntlmCount" -ForegroundColor Yellow
}
```

## Remediation Strategies

### Phase 1: Immediate Actions (Week 1)

#### Disable NTLMv1 Immediately
```powershell
# Set LM Compatibility Level to 5 (DC refuses LM and NTLM v1)
# Domain-wide via Group Policy
```

**Group Policy Path:**
```
Computer Configuration
 └─ Windows Settings
     └─ Security Settings
         └─ Local Policies
             └─ Security Options
                 └─ Network security: LAN Manager authentication level
                     └─ Send NTLMv2 response only. Refuse LM & NTLM
```

#### Enable NTLM Auditing
```powershell
# Audit all NTLM authentication attempts
# Group Policy: Network security: Restrict NTLM: Audit NTLM authentication in this domain
# Set to: Enable all
```

### Phase 2: Assessment (Weeks 2-4)

#### Identify NTLM Sources
```powershell
# Collect 2-4 weeks of NTLM usage data
# Analyze event logs to identify:
# 1. Which systems use NTLM
# 2. Which accounts use NTLM
# 3. Which applications require NTLM
# 4. Business impact of blocking NTLM
```

#### Document Dependencies
```
Create inventory of:
- Legacy applications requiring NTLM
- Network devices (printers, NAS) using NTLM
- Service accounts authenticating via NTLM
- Third-party integrations using NTLM
```

### Phase 3: Remediation (Months 2-6)

#### Configure Kerberos SPNs
```powershell
# For services still using NTLM, configure Service Principal Names
setspn -A HTTP/webapp.contoso.com ServiceAccount
setspn -A HTTP/webapp ServiceAccount

# Verify
setspn -L ServiceAccount
```

#### Enable Kerberos Delegation
```powershell
# Configure constrained delegation where needed
Set-ADUser -Identity "ServiceAccount" -TrustedForDelegation $false
Set-ADUser -Identity "ServiceAccount" -TrustedToAuthForDelegation $true
```

#### Require SMB Signing
```powershell
# Prevent NTLM relay attacks via Group Policy
# Microsoft network client: Digitally sign communications (always)
# Microsoft network server: Digitally sign communications (always)
```

### Phase 4: Enforcement (Month 6+)

#### Block NTLM in Pilot Groups
```powershell
# Create pilot OU with NTLM blocked
# Group Policy: Network security: Restrict NTLM: Incoming NTLM traffic
# Set to: Deny all accounts
```

#### Monitor for Issues
```powershell
# Check Event ID 8003 for blocked NTLM attempts
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-NTLM/Operational'
    Id = 8003
    StartTime = (Get-Date).AddDays(-1)
} | Select-Object TimeCreated, Message | Format-Table -AutoSize
```

#### Gradual Rollout
```
Week 1-2: IT department OUs
Week 3-4: Administrative OUs
Week 5-8: General user OUs (phased by location/department)
Week 9+: Complete domain-wide enforcement
```

## Migration to Kerberos

### Why Kerberos is Better

| Feature | NTLMv2 | Kerberos |
|---------|--------|----------|
| Mutual Authentication | ❌ No | ✅ Yes |
| Encryption | HMAC-MD5 | AES-128/256 |
| Performance | Slower | Faster (ticket caching) |
| Delegation | Limited | Full constrained/resource-based |
| Pass-the-Hash | ❌ Vulnerable | ✅ Resistant |
| Offline Attacks | ❌ Vulnerable | ✅ Resistant |
| Cross-forest | Limited | Full support |

### Prerequisites for Kerberos

1. **DNS must be working correctly**
   - Forward and reverse lookup zones
   - Service records (SRV) for domain controllers
   - Client DNS configuration pointing to internal DNS

2. **SPNs must be registered**
   - HTTP, CIFS, HOST, etc. for services
   - No duplicate SPNs
   - Proper service account configuration

3. **Time synchronization**
   - Time skew < 5 minutes (default)
   - NTP configured correctly
   - All systems sync from domain hierarchy

4. **Proper DNS naming**
   - Systems use FQDN, not just hostname
   - DNS suffix search list configured
   - No WINS fallback

### Common Issues Preventing Kerberos

| Issue | Symptom | Solution |
|-------|---------|----------|
| Missing SPN | NTLM fallback | Register SPN with `setspn` |
| DNS mismatch | "Cannot find domain" | Fix forward/reverse DNS |
| Time skew | "Clock skew too great" | Sync time with `w32tm` |
| Wrong DNS suffix | Name resolution fails | Configure DNS suffix in DHCP/GPO |
| Firewall blocking | Timeout, fallback to NTLM | Open UDP 88, TCP 88 |
| Duplicate SPN | Authentication fails | Find and remove with `setspn -X` |

### Testing Kerberos

```powershell
# Test Kerberos authentication
klist purge
Test-NetConnection -ComputerName server.contoso.com -Port 445
klist

# Verify Kerberos ticket obtained
# Should show ticket for CIFS/server.contoso.com
```

## Monitoring After Migration

### Success Metrics

1. **NTLM Authentication Count**: Should trend to zero
2. **Kerberos Authentication Count**: Should increase proportionally
3. **Authentication Failures**: Should remain stable or decrease
4. **Application Availability**: Should remain at 100%

### Alert Rules

```kql
// Alert on any NTLMv1 usage
WindowsEvent
| where EventID == 4624
| extend LmPackageName = tostring(EventData["LmPackageName"])
| where LmPackageName == "NTLM V1"
// Generate alert - this should never happen after phase 1

// Alert on unexpected NTLM spike
SecurityEvent
| where EventID == 4624
| where AuthenticationPackageName == "NTLM"
| summarize Count=count() by bin(TimeGenerated, 1h)
| where Count > 1000  // Adjust threshold based on baseline
// Generate alert - possible attack or misconfiguration
```

## Additional Resources

### Microsoft Documentation
- [NTLM Overview](https://docs.microsoft.com/windows-server/security/kerberos/ntlm-overview)
- [Limiting NTLM Use](https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain)
- [Kerberos Authentication](https://docs.microsoft.com/windows-server/security/kerberos/kerberos-authentication-overview)

### Tools
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) - Understand attacks (security research only)
- [Responder](https://github.com/lgandx/Responder) - Test NTLM relay vulnerability
- [PingCastle](https://www.pingcastle.com/) - AD security audit including NTLM usage
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Attack path analysis

### Further Reading
- [Farewell NTLMv1 (Microsoft)](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/ntlm-blocking-and-you-application-analysis-and-auditing/ba-p/397191)
- [NTLM Relay Attacks](https://en.hackndo.com/ntlm-relay/)
- [Kerberos Explained](https://ldapwiki.com/wiki/Kerberos)

---

**[← Back to Legacy Protocols](../README.md)** | **[Next: Kerberos RC4 →](./Kerberos-RC4.md)**
