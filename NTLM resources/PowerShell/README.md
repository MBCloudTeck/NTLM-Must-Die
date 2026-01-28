# PowerShell Scripts for NTLM Auditing and Hardening

This folder contains PowerShell scripts to help audit, monitor, and harden your environment against NTLM-based attacks.

## Scripts Overview

### Auditing Scripts
- `Audit-NTLMUsage.ps1` - Comprehensive NTLM usage audit across domain
- `Get-NTLMEvents.ps1` - Collect and analyze NTLM events from servers
- `Export-NTLMReport.ps1` - Generate detailed NTLM usage reports

### Configuration Scripts
- `Enable-NTLMAuditing.ps1` - Enable NTLM auditing via Group Policy
- `Configure-NTLMRestrictions.ps1` - Apply NTLM restrictions and hardening
- `Disable-NTLMv1.ps1` - Disable NTLMv1 across domain

### Monitoring Scripts
- `Monitor-NTLMEvents.ps1` - Real-time NTLM event monitoring
- `Test-NTLMConfiguration.ps1` - Validate NTLM hardening settings

### Remediation Scripts
- `Fix-ServiceAccountSPN.ps1` - Configure SPNs for service accounts to use Kerberos
- `Update-LegacySystems.ps1` - Identify and remediate legacy systems using NTLM

## Usage

### Prerequisites
- PowerShell 5.1 or later (7.x recommended)
- Active Directory module (for domain-related scripts)
- Administrative privileges
- Remote Server Administration Tools (RSAT) for some scripts

### Running Scripts

```powershell
# Audit NTLM usage
.\Audit-NTLMUsage.ps1 -Domain "contoso.com" -OutputPath "C:\Reports"

# Enable NTLM auditing
.\Enable-NTLMAuditing.ps1 -TargetOU "OU=Servers,DC=contoso,DC=com"

# Disable NTLMv1
.\Disable-NTLMv1.ps1 -WhatIf  # Test mode
.\Disable-NTLMv1.ps1 -Apply    # Apply changes
```

## Best Practices

1. **Test First** - Always test in a non-production environment
2. **Use -WhatIf** - Use the -WhatIf parameter when available to preview changes
3. **Backup** - Backup Group Policy settings before making changes
4. **Monitor** - Monitor event logs after running configuration scripts
5. **Document** - Document all changes and exceptions

## Common Workflows

### Initial Assessment
```powershell
# 1. Audit current NTLM usage
.\Audit-NTLMUsage.ps1

# 2. Generate baseline report
.\Export-NTLMReport.ps1 -TimeRange 7
```

### Hardening Implementation
```powershell
# 1. Enable auditing
.\Enable-NTLMAuditing.ps1

# 2. Monitor for 2 weeks
.\Monitor-NTLMEvents.ps1 -Duration 14

# 3. Disable NTLMv1
.\Disable-NTLMv1.ps1 -Apply

# 4. Apply restrictions
.\Configure-NTLMRestrictions.ps1 -Level Medium
```

### Ongoing Monitoring
```powershell
# Schedule monitoring script
.\Monitor-NTLMEvents.ps1 -Schedule -Frequency Daily
```

## Troubleshooting

### Script Execution Policy
```powershell
# Check current policy
Get-ExecutionPolicy

# Set policy for current session
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### Module Dependencies
```powershell
# Install required modules
Install-Module -Name ActiveDirectory
Install-Module -Name PSWindowsUpdate
```

## Support

For issues or questions:
1. Check script comments for detailed usage
2. Review Prerequisites section
3. Check event logs for errors
4. Refer to main repository documentation

## Security Considerations

- Scripts require administrative privileges
- Use secure credential management (avoid hardcoded passwords)
- Review scripts before execution
- Maintain audit logs of script execution
- Use source control for custom modifications
