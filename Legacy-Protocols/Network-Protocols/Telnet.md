# Telnet: Legacy Terminal Protocol

## Overview

Telnet (Telecommunication Network Protocol) is a text-based network protocol developed in 1969 for remote terminal access. Despite being obsolete for decades, it remains one of the most dangerous legacy protocols still in use due to its complete lack of security features.

## Why Telnet is Critically Insecure

### No Encryption
- **All data transmitted in cleartext** including usernames and passwords
- Network sniffing can capture complete sessions
- Trivial to intercept credentials with Wireshark, tcpdump, or even browser extensions

### No Authentication
- Basic username/password only
- No multi-factor authentication support
- No certificate-based authentication
- No protection against man-in-the-middle attacks

### No Integrity Checking
- Data can be modified in transit without detection
- Session hijacking possible
- Command injection attacks feasible

## Real-World Impact

### Common Attack Scenarios

**1. Credential Harvesting**
```bash
# Attacker passively sniffs network traffic
tcpdump -i eth0 -A 'port 23'

# Credentials appear in cleartext:
# login: admin
# password: P@ssw0rd123
```

**2. IoT Device Exploitation**
- Telnet enabled by default on many IoT devices
- Weak or default credentials
- Mirai botnet (2016) exploited Telnet to compromise 600,000+ devices
- Used for DDoS attacks, cryptocurrency mining, spam

**3. Man-in-the-Middle (MITM)**
```
Attacker intercepts Telnet session → Modifies commands in flight →
Server executes attacker's commands → Victim sees normal response
```

## Detection

### Network Detection

**Check for Active Telnet Services**
```bash
# Nmap scan for Telnet
nmap -p 23 -sV --open <network-range>

# Example output showing Telnet:
# 23/tcp open  telnet  Linux telnetd
```

**Monitor Telnet Traffic**
```bash
# Detect Telnet connections
tcpdump -i any 'tcp port 23' -n

# Suricata rule
alert tcp any any -> any 23 (msg:"Telnet Connection Detected"; flow:to_server,established; sid:2000010;)
```

### Windows Detection

**Check if Telnet Client/Server is Installed**
```powershell
# Check Telnet Client
Get-WindowsOptionalFeature -Online -FeatureName TelnetClient

# Check Telnet Server
Get-WindowsOptionalFeature -Online -FeatureName TelnetServer

# Verify Telnet service status
Get-Service -Name TlntSvr -ErrorAction SilentlyContinue
```

**Audit Domain-Wide**
```powershell
$computers = Get-ADComputer -Filter * -Properties OperatingSystem
$results = @()

foreach ($computer in $computers) {
    if (Test-Connection -ComputerName $computer.Name -Count 1 -Quiet) {
        try {
            $telnetServer = Invoke-Command -ComputerName $computer.Name -ScriptBlock {
                Get-Service -Name TlntSvr -ErrorAction SilentlyContinue
            }
            
            if ($telnetServer) {
                $results += [PSCustomObject]@{
                    ComputerName = $computer.Name
                    ServiceStatus = $telnetServer.Status
                    OperatingSystem = $computer.OperatingSystem
                }
            }
        } catch {}
    }
}

$results | Export-Csv -Path "C:\Reports\Telnet-Audit.csv" -NoTypeInformation
```

### Microsoft Sentinel Detection

```kql
// Detect Telnet connections from firewall logs
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DestinationPort == 23
| extend Protocol = "Telnet"
| summarize Count=count() by SourceIP, DestinationIP, DestinationPort
| order by Count desc
```

## Common Use Cases (Why it Persists)

| Device Type | Reason | Risk Level |
|-------------|--------|-----------|
| Network Switches | Management interface, legacy firmware | Critical |
| Routers | Default management protocol | Critical |
| Industrial Controllers | No SSH support, certification issues | Critical |
| Environmental Sensors | Embedded systems, no updates | High |
| Serial Console Servers | Legacy compatibility | High |
| Old Unix/Linux Systems | Pre-configured, never updated | High |
| Test Equipment | Vendor locked-in, proprietary | Medium |

## Migration to SSH

### Why SSH is Better

| Feature | Telnet | SSH |
|---------|--------|-----|
| **Encryption** | ❌ None | ✅ Strong (AES-256, ChaCha20) |
| **Authentication** | Password only | Keys, passwords, certificates, MFA |
| **Integrity** | ❌ None | ✅ HMAC validation |
| **Port Forwarding** | ❌ No | ✅ Yes (tunneling) |
| **File Transfer** | ❌ No | ✅ SCP, SFTP |
| **Session Security** | ❌ Vulnerable | ✅ Protected |

### Migration Steps

#### Step 1: Install SSH Server

**Linux/Unix:**
```bash
# Install OpenSSH Server (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install openssh-server

# Install OpenSSH Server (RHEL/CentOS)
sudo yum install openssh-server

# Enable and start SSH service
sudo systemctl enable sshd
sudo systemctl start sshd

# Verify SSH is running
sudo systemctl status sshd
```

**Windows:**
```powershell
# Install OpenSSH Server (Windows 10/11, Server 2019+)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start SSH service
Start-Service sshd

# Set to start automatically
Set-Service -Name sshd -StartupType 'Automatic'

# Verify
Get-Service sshd
```

#### Step 2: Configure SSH Securely

**Linux SSH Hardening (`/etc/ssh/sshd_config`):**
```bash
# Use SSH Protocol 2 only
Protocol 2

# Disable root login
PermitRootLogin no

# Disable password authentication (after key setup)
PasswordAuthentication no
PubkeyAuthentication yes

# Disable empty passwords
PermitEmptyPasswords no

# Use strong ciphers only
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Restrict to specific users/groups
AllowUsers admin sysadmin
# or AllowGroups ssh-users

# Enable logging
SyslogFacility AUTH
LogLevel INFO

# Set idle timeout
ClientAliveInterval 300
ClientAliveCountMax 2

# Restart SSH after config changes
sudo systemctl restart sshd
```

**Windows SSH Configuration:**
```powershell
# Edit: C:\ProgramData\ssh\sshd_config
# Apply similar hardening as Linux

# Restart SSH service
Restart-Service sshd
```

#### Step 3: Set Up Key-Based Authentication

**Generate SSH Key Pair (Client):**
```bash
# Generate ED25519 key (recommended)
ssh-keygen -t ed25519 -C "user@example.com"

# Or RSA 4096-bit if ED25519 not supported
ssh-keygen -t rsa -b 4096 -C "user@example.com"

# Keys saved to:
# Private: ~/.ssh/id_ed25519 (keep secret!)
# Public: ~/.ssh/id_ed25519.pub
```

**Deploy Public Key to Server:**
```bash
# Method 1: Using ssh-copy-id (easiest)
ssh-copy-id -i ~/.ssh/id_ed25519.pub user@server

# Method 2: Manual
cat ~/.ssh/id_ed25519.pub | ssh user@server "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"

# Method 3: Direct copy
scp ~/.ssh/id_ed25519.pub user@server:~/.ssh/authorized_keys
```

**Set Correct Permissions:**
```bash
# On server
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

#### Step 4: Test SSH Connection

```bash
# Test SSH connection
ssh -i ~/.ssh/id_ed25519 user@server

# If successful, try without specifying key (uses default)
ssh user@server

# Verbose output for troubleshooting
ssh -vvv user@server
```

#### Step 5: Migrate Scripts and Tools

**Before (Telnet):**
```bash
#!/bin/bash
# Legacy script using Telnet
telnet router.example.com 23 << EOF
admin
password
show version
exit
EOF
```

**After (SSH):**
```bash
#!/bin/bash
# Modern script using SSH with key auth
ssh -i ~/.ssh/automation_key automation@router.example.com << EOF
show version
EOF
```

**For Bulk Operations:**
```bash
# Using Ansible for automation (recommended)
ansible network-devices -m command -a "show version"

# Or parallel SSH
parallel-ssh -h hosts.txt -l admin -A "show version"
```

#### Step 6: Disable Telnet

**Linux:**
```bash
# Stop Telnet service
sudo systemctl stop telnet.socket
sudo systemctl disable telnet.socket

# Remove Telnet package
sudo apt-get remove telnetd  # Debian/Ubuntu
sudo yum remove telnet-server  # RHEL/CentOS

# Verify Telnet is not running
sudo netstat -tlnp | grep :23
```

**Windows:**
```powershell
# Disable Telnet Server
Stop-Service TlntSvr
Set-Service -Name TlntSvr -StartupType Disabled

# Remove Telnet Server feature
Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer

# Verify
Get-Service TlntSvr
```

**Network Devices:**
```cisco
# Cisco IOS example
Router(config)# no service telnet
Router(config)# line vty 0 4
Router(config-line)# transport input ssh
Router(config-line)# no transport input telnet
Router(config)# exit
Router# write memory
```

#### Step 7: Block Telnet at Firewall

**Linux iptables:**
```bash
# Block incoming Telnet
sudo iptables -A INPUT -p tcp --dport 23 -j DROP

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

**Cisco ASA:**
```cisco
access-list OUTSIDE_IN deny tcp any any eq 23 log
```

**Cloud (Azure NSG):**
```powershell
# Create rule to block Telnet
New-AzNetworkSecurityRuleConfig -Name "Deny-Telnet" `
    -Description "Block Telnet protocol" `
    -Access Deny `
    -Protocol Tcp `
    -Direction Inbound `
    -Priority 100 `
    -SourceAddressPrefix Internet `
    -SourcePortRange * `
    -DestinationAddressPrefix * `
    -DestinationPortRange 23
```

## Handling Legacy Devices That Require Telnet

### Option 1: Firmware Update
1. Check vendor website for latest firmware
2. Look for SSH support in newer versions
3. Test update in lab environment
4. Schedule maintenance window
5. Update firmware and migrate to SSH

### Option 2: Replace Device
- For critical systems, consider replacement
- Modern alternatives support SSH by default
- Budget for device lifecycle management

### Option 3: Network Isolation (Temporary)
```
Internet
    ↓ (blocked)
[Firewall] → Block Telnet from internet
    ↓
[Management VLAN] → Isolated network for legacy devices
    ↓
[Legacy Device] → Telnet only accessible from management VLAN
    ↓
[Jump Box/Bastion] → SSH to jump box, then Telnet to device
```

**Implementation:**
1. Create dedicated management VLAN
2. Move legacy devices to management VLAN
3. Implement strict ACLs
4. Require VPN + jump box for access
5. Log all connections
6. Monitor aggressively

### Option 4: Protocol Gateway/Proxy

**Using SSH to Telnet Gateway:**
```bash
# Install and configure shellinabox or similar
sudo apt-get install shellinabox

# Configure to proxy SSH → Telnet
# Users connect via SSH, gateway translates to Telnet
# All external communication encrypted

# Or use a custom script
#!/bin/bash
# ssh-to-telnet-proxy.sh
DEVICE=$1
ssh -o ProxyCommand="nc $DEVICE 23" user@localhost
```

## Monitoring After Remediation

### Continuous Verification

```kql
// Alert on any Telnet traffic (should be zero)
CommonSecurityLog
| where TimeGenerated > ago(5m)
| where DestinationPort == 23
| project TimeGenerated, SourceIP, DestinationIP, Action, DeviceVendor
// Alert if Count > 0
```

```bash
# Daily scan for Telnet services
#!/bin/bash
nmap -p 23 -sV --open <network-range> -oG - | grep "23/open" | \
    mail -s "ALERT: Telnet Detected" security@company.com
```

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Telnet Services Running | 0 | Daily automated scan |
| Telnet Network Connections | 0 | Continuous IDS monitoring |
| SSH Adoption Rate | 100% | Quarterly audit |
| SSH Key-Based Auth | >90% | SSH server logs |

## Additional Resources

### Documentation
- [OpenSSH Documentation](https://www.openssh.com/)
- [SSH Best Practices (Mozilla)](https://infosec.mozilla.org/guidelines/openssh)
- [NIST SSH Guidelines](https://nvlpubs.nist.gov/nistpubs/ir/2015/NIST.IR.7966.pdf)

### Tools
- [OpenSSH](https://www.openssh.com/) - Standard SSH implementation
- [PuTTY](https://www.putty.org/) - Windows SSH client
- [Ansible](https://www.ansible.com/) - Automation with SSH
- [ssh-audit](https://github.com/jtesta/ssh-audit) - SSH configuration scanner

---

**[← Back to Legacy Protocols](../README.md)** | **[Next: FTP →](../File-Transfer/FTP.md)**
