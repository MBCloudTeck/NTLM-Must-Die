# Quick Reference: Legacy Protocols

## Critical Actions (First 24 Hours)

### 1. Disable NTLMv1 Immediately
```powershell
# Domain-wide GPO
# Network security: LAN Manager authentication level
# Set to: Send NTLMv2 response only. Refuse LM & NTLM
```
**Why:** NTLMv1 can be cracked in minutes. Zero tolerance.

### 2. Identify SMBv1 Systems
```powershell
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```
**Why:** WannaCry, NotPetya vector. Must be eliminated.

### 3. Check for Telnet Services
```powershell
Get-Service | Where-Object {$_.Name -like "*telnet*"}
```
**Why:** Transmits passwords in cleartext. Critical vulnerability.

## Risk Matrix

| Protocol | Severity | Can Wait? | Action |
|----------|----------|-----------|--------|
| NTLMv1 | 🔴 Critical | NO | Disable today |
| Telnet | 🔴 Critical | NO | Disable today |
| FTP (clear) | 🔴 Critical | NO | Block at firewall |
| SMBv1 | 🔴 Critical | 2 weeks max | Audit then disable |
| NTLMv2 (no signing) | 🟠 High | 1-3 months | Plan Kerberos migration |
| Basic Auth (Cloud) | 🟠 High | 1-3 months | Deploy Conditional Access |
| SNMP v1/v2 | 🟡 Medium | 3-6 months | Upgrade to v3 |
| POP3/IMAP (clear) | 🟡 Medium | 3-6 months | Enforce TLS |

## One-Liner Detection Commands

### Windows (PowerShell)

```powershell
# Check NTLMv1 usage (last 24 hours)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddDays(-1)} | 
  Where-Object {$_.Properties[8].Value -match "NTLM V1"} | 
  Select-Object TimeCreated,@{N='User';E={$_.Properties[5].Value}}

# Check SMBv1 status
(Get-SmbServerConfiguration).EnableSMB1Protocol

# Check for Telnet
Get-WindowsOptionalFeature -Online -FeatureName TelnetServer

# Check LDAP binds (last week)
Get-WinEvent -FilterHashtable @{LogName='Directory Service';Id=2889;StartTime=(Get-Date).AddDays(-7)} |
  Select-Object TimeCreated,Message
```

### Linux (Bash)

```bash
# Scan for legacy services
nmap -p 21,23,110,143,389,445 -sV localhost

# Check SSH config strength
ssh-audit localhost

# Find Telnet processes
ps aux | grep telnet

# Check for FTP service
systemctl status vsftpd
```

### Cloud (Azure AD)

```powershell
# Legacy auth sign-ins (last 7 days)
Get-AzureADAuditSignInLogs -Filter "createdDateTime ge $(Get-Date).AddDays(-7).ToString('yyyy-MM-dd') and clientAppUsed eq 'Other clients'" |
  Select-Object createdDateTime,userPrincipalName,clientAppUsed
```

## Quick KQL Queries for Sentinel

### All Legacy Protocols (Dashboard)
```kql
union
  (SigninLogs | where ClientAppUsed == "Other clients" | extend Protocol = "Legacy Auth"),
  (SecurityEvent | where AuthenticationPackageName has "NTLM" | extend Protocol = "NTLM"),
  (WindowsEvent | where EventID == 4624 and tostring(EventData["LmPackageName"]) == "NTLM V1" | extend Protocol = "NTLMv1"),
  (WindowsEvent | where EventID == 2889 | extend Protocol = "LDAP Simple Bind")
| summarize Count=count() by Protocol, bin(TimeGenerated, 1h)
| render timechart
```

### Critical: NTLMv1 Detection
```kql
WindowsEvent
| where EventID == 4624
| extend LmPackageName = tostring(EventData["LmPackageName"])
| where LmPackageName == "NTLM V1"
| project TimeGenerated, Computer, tostring(EventData["TargetUserName"])
```

### High: Legacy Auth from External IPs
```kql
SigninLogs
| where ClientAppUsed == "Other clients"
| extend IsExternal = ipv4_is_private(IPAddress) == false
| where IsExternal
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName
```

## Common Fixes (Copy-Paste Ready)

### Disable NTLMv1 (GPO)
```
Computer Configuration
 → Policies
  → Windows Settings
   → Security Settings
    → Local Policies
     → Security Options
      → Network security: LAN Manager authentication level
       → Send NTLMv2 response only. Refuse LM & NTLM
```

### Disable SMBv1 (PowerShell)
```powershell
# Windows 10/11/Server 2016+
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Set via GPO for entire domain
# Computer Configuration → Administrative Templates → MS Security Guide
# → Configure SMBv1 server → Disabled
```

### Disable Telnet (PowerShell)
```powershell
# Stop and disable Telnet service
Stop-Service TlntSvr -ErrorAction SilentlyContinue
Set-Service -Name TlntSvr -StartupType Disabled -ErrorAction SilentlyContinue

# Remove Telnet feature
Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer
```

### Enable SSH Instead (PowerShell - Windows)
```powershell
# Install OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start and enable
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Configure firewall
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

### Block Legacy Auth (Azure AD Conditional Access)
```
Azure AD → Security → Conditional Access → New Policy
Name: Block Legacy Authentication
Users: All users (exclude emergency accounts)
Cloud apps: All cloud apps
Conditions: Client apps → Exchange ActiveSync clients, Other clients
Grant: Block access
Enable policy: On
```

## Emergency Rollback Commands

### Re-enable NTLMv2 (Emergency Only)
```powershell
# If business critical service fails
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
  -Name "LmCompatibilityLevel" -Value 3
```

### Re-enable SMBv1 (Emergency Only - Requires Reboot)
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Restart-Computer
```

### Remove Conditional Access Block (Emergency Only)
```
Azure AD → Conditional Access → [Policy Name] → Enable policy → Off
```

## Monitoring Checklist

### Daily Checks
- [ ] Zero NTLMv1 events
- [ ] Zero Telnet connections
- [ ] Zero SMBv1 enabled systems
- [ ] Review critical alerts

### Weekly Checks
- [ ] NTLM usage trending down
- [ ] Legacy auth attempts decreasing
- [ ] No new legacy protocol sources
- [ ] Exception list reviewed

### Monthly Checks
- [ ] Executive dashboard updated
- [ ] All exceptions have review dates
- [ ] Compliance posture improved
- [ ] Plan next phase rollout

## Common Error Messages & Fixes

### "Access Denied" After Disabling NTLM
**Cause:** Application needs Kerberos SPN
**Fix:**
```powershell
setspn -A HTTP/webapp.contoso.com ServiceAccount
```

### "Cannot Connect" After Disabling SMBv1
**Cause:** Client still using SMBv1
**Fix:** Update client OS or firmware

### "Authentication Failed" After Blocking Legacy Auth
**Cause:** Application using basic auth
**Fix:** Update application to use OAuth 2.0 or deploy app proxy

## Resource Links (By Protocol)

- **NTLM:** [Full Guide](./Authentication/NTLM.md) | [Detection](./Detection-Monitoring/README.md) | [Remediation](./Remediation/README.md)
- **SMBv1:** [Full Guide](./Authentication/SMBv1.md)
- **Telnet:** [Full Guide](./Network-Protocols/Telnet.md)
- **Detection:** [Monitoring Guide](./Detection-Monitoring/README.md)
- **Remediation:** [Phase-by-Phase Guide](./Remediation/README.md)

## Support Contacts

**Internal:**
- Security Team: [security@company.com](mailto:security@company.com)
- Infrastructure Team: [infrastructure@company.com](mailto:infrastructure@company.com)
- Helpdesk: x1234

**External:**
- Microsoft Support: https://support.microsoft.com
- Security Community: https://techcommunity.microsoft.com

## Next Steps

1. ✅ Run detection scripts (today)
2. ✅ Disable NTLMv1 (this week)
3. ✅ Audit SMBv1 usage (this week)
4. ✅ Plan Kerberos migration (next month)
5. ✅ Deploy monitoring (ongoing)

---

**[← Back to Legacy Protocols](./README.md)** | **[Main Repository →](../README.md)**
