# SMBv1: Legacy File Sharing Protocol

## Overview

SMB (Server Message Block) version 1 is a network file sharing protocol developed in the 1980s. Despite being superseded by SMBv2 (2006) and SMBv3 (2012), SMBv1 remains enabled in many environments, creating critical security vulnerabilities.

## Why SMBv1 is Dangerous

### Critical Vulnerabilities

1. **EternalBlue (MS17-010)** - Used in WannaCry, NotPetya ransomware
2. **EternalRomance / EternalSynergy** - Additional NSA-developed exploits
3. **No Encryption** - All data transmitted in cleartext
4. **No Integrity Checking** - Data can be tampered without detection
5. **Weak Authentication** - Relies on NTLM, vulnerable to relay attacks
6. **Poor Performance** - Inefficient protocol design

### Real-World Impact

| Attack | Year | Impact | SMBv1 Role |
|--------|------|---------|------------|
| WannaCry | 2017 | 200,000+ computers, $4B+ damage | Primary infection vector |
| NotPetya | 2017 | $10B+ damage, critical infrastructure | Lateral movement |
| Bad Rabbit | 2017 | Media, infrastructure across Europe | Propagation method |
| EternalBlue exploits | Ongoing | Cryptominers, ransomware, APTs | Initial access, spreading |

## Technical Details

### SMB Version Comparison

| Feature | SMBv1 | SMBv2 | SMBv3 |
|---------|-------|-------|-------|
| **Windows Support** | All versions | Vista+ | 8+ / 2012+ |
| **Encryption** | ❌ None | ❌ None | ✅ AES-128/256 |
| **Signing** | Optional | Optional | Mandatory (on encryption) |
| **Performance** | Poor | Good | Excellent |
| **Integrity** | ❌ None | ✅ SHA-256 | ✅ SHA-256 + AES-CMAC |
| **Message Size** | 64KB | 1MB | 1MB+ |
| **Resilient Handles** | ❌ No | ❌ No | ✅ Yes |
| **Scale-out** | ❌ No | ❌ No | ✅ Yes |
| **Oplocks** | Basic | Enhanced | Leasing |

### Known Vulnerabilities

#### MS17-010 (EternalBlue)
```
CVE: CVE-2017-0144
CVSS: 9.3 (Critical)
Affected: Windows XP through Windows 10, Server 2003-2016
Impact: Remote Code Execution, SYSTEM privileges
Exploit: Publicly available, widely used in ransomware
```

**Attack Mechanism:**
1. Attacker sends specially crafted SMBv1 packets
2. Buffer overflow in SMBv1 handling code
3. Remote code execution with SYSTEM privileges
4. Typically installs backdoor (DoublePulsar) or ransomware

**Detection:**
```kql
// Detect EternalBlue exploitation attempts
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 5145  // Network share accessed
| where RelativeTargetName contains "\\IPC$" or RelativeTargetName contains "\\ADMIN$"
| where AccessMask == "0x100181"  // Suspicious access mask
| summarize Count=count() by Computer, IpAddress, ShareName
| where Count > 10
```

#### MS17-010 Exploit Variations
- **EternalBlue** - Primary exploit for Windows 7, Server 2008
- **EternalChampion** - Windows 8, 10, Server 2012+
- **EternalRomance** - Alternative exploitation method
- **EternalSynergy** - Used with EternalRomance

### Protocol Weaknesses

#### No Encryption
```
Problem: All data (including credentials) sent in cleartext
Impact: Network sniffing can capture sensitive information
Tools: Wireshark, tcpdump, Network Monitor
```

#### Weak Signing
```
Problem: Signing optional and can be downgraded
Impact: Man-in-the-middle attacks possible
Attack: Responder, MITM6, ARP poisoning
```

#### NTLM Dependency
```
Problem: Primarily uses NTLM authentication
Impact: Subject to NTLM relay, pass-the-hash attacks
See: Authentication/NTLM.md for details
```

## Common Use Cases (Why it Persists)

### Legacy Devices

| Device Type | Examples | Typical Reason |
|-------------|----------|----------------|
| **Network Storage** | Old NAS, SAN controllers | Firmware limitations, vendor abandonment |
| **Printers/Scanners** | Multi-function devices | Outdated embedded software |
| **Copiers** | Commercial copy machines | Scan-to-folder requires SMBv1 |
| **Industrial Equipment** | Manufacturing, HVAC controls | Safety certification prevents updates |
| **Medical Devices** | Imaging equipment, patient monitors | FDA certification, vendor support ended |
| **Security Systems** | Cameras, access control | Proprietary software requirements |

### Legacy Applications

```
Application Scenarios:
- Old database applications using UNC paths
- Legacy backup software expecting SMBv1
- Custom in-house apps built on old frameworks
- Third-party vendor software without updates
```

### Legacy Operating Systems

```
Unsupported OS still requiring SMBv1:
- Windows XP / Server 2003 (End of support 2014)
- Windows Server 2003 R2
- Windows Embedded POSReady 2009
- Very old Linux distributions (pre-2010)
```

## Detection & Monitoring

### Check if SMBv1 is Enabled

#### Windows Client (8+, 10, 11)
```powershell
# Check if SMBv1 feature is enabled
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Check SMBv1 server component
Get-SmbServerConfiguration | Select EnableSMB1Protocol

# Check SMBv1 client component  
Get-SmbServerConfiguration | Select EnableSMB1Client
```

#### Windows Server (2012+)
```powershell
# Check feature installation status
Get-WindowsFeature FS-SMB1

# Check runtime configuration
Get-SmbServerConfiguration | Select EnableSMB1Protocol
```

#### PowerShell for Older Systems
```powershell
# Windows 7 / Server 2008 R2
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$smb1 = Get-ItemProperty -Path $regPath -Name "SMB1" -ErrorAction SilentlyContinue
if ($smb1.SMB1 -eq 0) {
    Write-Host "SMBv1 is disabled" -ForegroundColor Green
} else {
    Write-Host "SMBv1 is enabled" -ForegroundColor Red
}
```

### Network Detection

#### Identify SMBv1 Traffic
```bash
# Wireshark / tshark filter
smb.protocol_version == 0x00

# Tcpdump capture SMBv1
tcpdump -i eth0 'tcp port 445' -w smb_capture.pcap

# Analyze with tshark
tshark -r smb_capture.pcap -Y "smb.protocol_version == 0x00" -T fields -e ip.src -e ip.dst -e smb.cmd
```

#### Network IDS/IPS Signatures

**Snort Rule for SMBv1:**
```
alert tcp any any -> any 445 (msg:"SMBv1 Protocol Detected"; content:"|FF|SMB"; depth:4; sid:1000001;)
```

**Suricata Rule:**
```
alert smb any any -> any any (msg:"SMBv1 negotiation detected"; smb.protocol:1; sid:2000001;)
```

### Active Directory Monitoring

#### Audit SMBv1 Usage Domain-Wide
```powershell
# Script to check all domain computers
$computers = Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate | 
    Where-Object {$_.LastLogonDate -gt (Get-Date).AddDays(-90)}

$results = @()
foreach ($computer in $computers) {
    Write-Progress -Activity "Checking SMBv1 status" -Status $computer.Name
    
    if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet) {
        try {
            $smb1Status = Invoke-Command -ComputerName $computer.Name -ScriptBlock {
                (Get-SmbServerConfiguration).EnableSMB1Protocol
            } -ErrorAction Stop
            
            $results += [PSCustomObject]@{
                ComputerName = $computer.Name
                OperatingSystem = $computer.OperatingSystem
                SMBv1Enabled = $smb1Status
                LastLogon = $computer.LastLogonDate
            }
        } catch {
            $results += [PSCustomObject]@{
                ComputerName = $computer.Name
                OperatingSystem = $computer.OperatingSystem
                SMBv1Enabled = "Check Failed"
                LastLogon = $computer.LastLogonDate
            }
        }
    }
}

# Export results
$results | Export-Csv -Path "C:\Reports\SMBv1-Audit-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Summary
$enabledCount = ($results | Where-Object {$_.SMBv1Enabled -eq $true}).Count
$totalCount = $results.Count
Write-Host "`nSMBv1 Enabled on $enabledCount of $totalCount systems" -ForegroundColor $(if($enabledCount -gt 0){"Red"}else{"Green"})
```

### Microsoft Sentinel Detection

```kql
// Detect SMBv1 connections
Event
| where TimeGenerated > ago(30d)
| where EventLog == "Microsoft-Windows-SmbServer/Security"
| where EventID == 1009  // SMBv1 access attempt
| extend ClientIP = tostring(EventData["ClientName"])
| extend ServerName = Computer
| summarize Count=count(), LastSeen=max(TimeGenerated) by ServerName, ClientIP
| order by Count desc
```

```kql
// Detect SMBv1 access from external IPs (potential attack)
Event
| where TimeGenerated > ago(7d)
| where EventLog == "Microsoft-Windows-SmbServer/Security"  
| where EventID == 1009
| extend ClientIP = tostring(EventData["ClientName"])
| where ipv4_is_private(ClientIP) == false  // External IP
| project TimeGenerated, Computer, ClientIP, EventData
```

## Remediation Strategies

### Phase 1: Assessment (Weeks 1-2)

#### Step 1: Inventory SMBv1 Usage
```powershell
# Enable SMBv1 auditing (Server 2016+)
Set-SmbServerConfiguration -AuditSmb1Access $true

# Wait 1-2 weeks for audit data

# Check audit events
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-SmbServer/Audit'
    Id = 3000
} | Select-Object TimeCreated, Message
```

#### Step 2: Identify Dependencies
```
Document:
1. Which clients connect using SMBv1?
2. Which shares are accessed via SMBv1?
3. What applications/services require SMBv1?
4. What business processes would be affected?
```

#### Step 3: Categorize Systems
```
Risk Categories:
- Critical: Can be disabled immediately (no dependencies)
- High: Can disable after client upgrades (1-2 months)
- Medium: Requires application updates (3-6 months)
- Low: Legacy device replacement needed (6-12 months)
```

### Phase 2: Client Upgrades (Months 1-2)

#### Upgrade Old Clients
```
Priority Actions:
1. Update Windows 7 → Windows 10/11
2. Update Server 2008 R2 → Server 2019/2022
3. Update Linux Samba → 4.x+ with SMBv2/3 support
4. Update network storage firmware
```

#### Configure Modern SMB
```powershell
# Enable SMBv2/v3 (should be default on modern systems)
Set-SmbServerConfiguration -EnableSMB2Protocol $true
Set-SmbClientConfiguration -EnableSMB2Protocol $true

# Verify
Get-SmbServerConfiguration | Select EnableSMB1Protocol, EnableSMB2Protocol
```

### Phase 3: Disable SMBv1 (Month 3+)

#### Windows 10 / 11 / Server 2016+
```powershell
# Disable SMBv1 completely
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Or via PowerShell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Remove SMBv1 feature entirely (recommended)
Remove-WindowsFeature FS-SMB1
```

#### Windows 7 / Server 2008 R2
```powershell
# Disable via registry
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Type DWord

# Disable client
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" -Name "DependOnService" -Value @("Bowser","MRxSmb20","NSI")

# Restart required
Restart-Computer
```

#### Group Policy Deployment
```
Create GPO: Disable SMBv1 Domain-Wide

Computer Configuration
  → Administrative Templates
    → MS Security Guide
      → Configure SMBv1 server
        → Disabled

Computer Configuration
  → Administrative Templates
    → MS Security Guide  
      → Configure SMBv1 client
        → Disabled

Link to target OUs, enforce, reboot systems
```

### Phase 4: Legacy Device Handling

#### Option 1: Firmware Update
```
1. Check vendor website for latest firmware
2. Test firmware update in lab environment
3. Schedule maintenance window
4. Update firmware to version with SMBv2/3 support
5. Disable SMBv1 and verify functionality
```

#### Option 2: Network Isolation
```
1. Move legacy devices to isolated VLAN
2. Implement strict firewall rules:
   - Allow only required ports
   - Restrict source IP addresses
   - Log all connections
3. Use jump box/bastion host for management
4. Monitor aggressively for anomalies
```

#### Option 3: SMB Gateway/Proxy
```
1. Deploy modern Linux system with Samba
2. Configure Samba to accept SMBv3 from clients
3. Configure Samba to proxy to SMBv1 device (on isolated network)
4. Restrict access to gateway only
5. Monitor and log all translations
```

#### Option 4: Device Replacement
```
For devices that cannot be updated or isolated:
1. Identify modern alternatives
2. Get budget approval for replacement
3. Plan migration timeline
4. Replace during maintenance windows
5. Decommission old devices securely
```

### Phase 5: Verification (Ongoing)

#### Continuous Monitoring
```powershell
# Schedule this script to run weekly
$computers = Get-ADComputer -Filter * -Properties LastLogonDate | 
    Where-Object {$_.LastLogonDate -gt (Get-Date).AddDays(-30)}

foreach ($computer in $computers) {
    if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet) {
        $smb1 = Invoke-Command -ComputerName $computer.Name -ScriptBlock {
            (Get-SmbServerConfiguration).EnableSMB1Protocol
        } -ErrorAction SilentlyContinue
        
        if ($smb1 -eq $true) {
            Write-Warning "SMBv1 enabled on $($computer.Name)"
            # Send alert email to security team
        }
    }
}
```

#### Automated Compliance Checks
```kql
// Azure Policy / Sentinel alert
// Alert if any system re-enables SMBv1
ConfigurationData
| where TimeGenerated > ago(1h)
| where ConfigDataType == "WindowsFeatures"
| where SvcName == "FS-SMB1" and SvcState == "Running"
| project Computer, TimeGenerated, SvcState
// Trigger alert - SMBv1 should never be enabled
```

## Alternative Solutions

### For Legacy Applications

#### App-V (Application Virtualization)
```
Isolate legacy applications in virtualized environment:
1. Package legacy app with App-V
2. Include Windows 7 with SMBv1 in container
3. Restrict network access from container
4. Users access via Remote App
```

#### Containers (Docker/Windows Containers)
```dockerfile
# Example: Windows Server Core with SMBv1 for legacy app
FROM mcr.microsoft.com/windows/servercore:ltsc2019
RUN dism /online /enable-feature /featurename:SMB1Protocol
COPY legacy-app C:\\app
ENTRYPOINT ["C:\\app\\legacy.exe"]
```

### For Legacy Devices

#### Protocol Translation Gateway
```
Tools:
- Samba 4.x+ (Linux) - Translate SMBv3 → SMBv1
- FreeNAS/TrueNAS - Built-in SMB translation
- Windows Server 2019+ - SMB gateway role
```

## Testing Before Deployment

### Test Plan Template

```
1. Test Environment Setup
   - Clone production environment in lab
   - Include representative devices and applications
   
2. Disable SMBv1 in Test
   - Follow remediation steps
   - Document any issues
   
3. Functional Testing
   - Test all known SMB share access
   - Test legacy applications
   - Test device scanner/copier functions
   - Test backup operations
   
4. Performance Testing
   - Measure file copy speeds before/after
   - Should improve with SMBv2/3
   
5. Security Testing
   - Verify SMBv1 truly disabled
   - Scan for vulnerabilities
   - Test from external perspective
   
6. Rollback Testing
   - Verify you can re-enable if critical issue found
   - Document rollback procedure
   - Test rollback in lab
```

### Pre-Production Checklist

- [ ] SMBv1 usage audited for 2+ weeks
- [ ] All dependencies documented
- [ ] Alternative solutions identified for legacy devices
- [ ] Change request approved
- [ ] Communication sent to affected users
- [ ] Rollback plan documented and tested
- [ ] Monitoring and alerting configured
- [ ] Support team briefed on potential issues
- [ ] Emergency contacts identified
- [ ] Maintenance window scheduled

## Success Metrics

### Key Performance Indicators

1. **SMBv1 Enabled Systems**: Target = 0
2. **SMBv1 Connection Attempts**: Target = 0
3. **Business Process Disruption**: Target = 0
4. **Vulnerability Scan Results**: No critical SMB vulns
5. **File Transfer Performance**: Should improve 20-40%

### Reporting Dashboard

```kql
// Executive dashboard for SMBv1 elimination project
let EnabledSystems = ConfigurationData
    | where ConfigDataType == "WindowsFeatures"
    | where SvcName == "FS-SMB1" and SvcState == "Running"
    | summarize EnabledCount = dcount(Computer);

let TotalSystems = Heartbeat
    | where TimeGenerated > ago(24h)
    | summarize TotalCount = dcount(Computer);

EnabledSystems
| extend Total = toscalar(TotalSystems)
| extend PercentageDisabled = round((Total - EnabledCount) * 100.0 / Total, 1)
| project EnabledCount, TotalSystems=Total, PercentageDisabled
```

## Additional Resources

### Microsoft Official Guidance
- [Stop using SMB1](https://aka.ms/stopusingsmb1)
- [SMBv1 Not Installed by Default](https://techcommunity.microsoft.com/t5/storage-at-microsoft/smb1-product-clearinghouse/ba-p/426008)
- [Detect, Enable and Disable SMBv1](https://docs.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)

### Vulnerability Information
- [MS17-010](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144)
- [WannaCry Analysis](https://www.us-cert.gov/ncas/alerts/TA17-132A)
- [NotPetya Technical Analysis](https://www.welivesecurity.com/2017/06/27/notpetya-isnt-ransomware/)

### Tools
- [SMBv1 Product Clearinghouse](https://aka.ms/stillneedssmb1) - Report products requiring SMBv1
- [SMB Security Best Practices](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn551363(v=ws.11))

---

**[← Back to Legacy Protocols](../README.md)** | **[Next: LDAP →](./LDAP.md)**
