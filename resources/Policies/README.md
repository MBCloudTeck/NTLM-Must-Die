# Group Policy Templates and Configurations

This folder contains Group Policy Object (GPO) templates and configurations for NTLM hardening and auditing.

## Available Policies

### Auditing Policies
- `NTLM-Auditing-Policy/` - Comprehensive NTLM auditing configuration
  - Enables all NTLM-related event logging
  - Configures NTLM Operational log
  - Sets appropriate audit levels

### Hardening Policies
- `Disable-NTLMv1-Policy/` - Completely disables NTLMv1
- `NTLM-Restrictions-Policy/` - Restricts NTLM usage (allow Kerberos)
- `Enhanced-Authentication-Policy/` - Comprehensive authentication hardening

### Credential Protection Policies
- `Credential-Guard-Policy/` - Enables Windows Credential Guard
- `Protected-Users-Policy/` - Configures Protected Users group restrictions

## How to Use These Policies

### Option 1: Import Using Group Policy Management Console

1. Open Group Policy Management Console (GPMC)
2. Right-click on the target OU or domain
3. Select "Import Settings"
4. Browse to the policy folder
5. Follow the import wizard

### Option 2: Use PowerShell Scripts

The PowerShell scripts in `../PowerShell/` directory can create and configure these policies automatically:
- `Enable-NTLMAuditing.ps1` - Creates auditing policy
- `Disable-NTLMv1.ps1` - Creates NTLMv1 restriction policy

### Option 3: Manual Configuration

Each policy folder contains:
- `README.md` - Detailed configuration steps
- `Settings.txt` - List of all settings and values
- `GPO-Backup/` - GPO backup for import

## Policy Application Order

**Recommended deployment sequence**:

1. **Phase 1: Enable Auditing** (Low Risk)
   - Apply `NTLM-Auditing-Policy`
   - Wait 2-4 weeks for data collection
   - Analyze results

2. **Phase 2: Credential Protection** (Medium Risk)
   - Apply `Credential-Guard-Policy` to compatible systems
   - Configure `Protected-Users-Policy` for privileged accounts
   - Monitor for issues

3. **Phase 3: Disable NTLMv1** (High Impact)
   - Apply `Disable-NTLMv1-Policy`
   - Monitor event logs closely
   - Be prepared to rollback if needed

4. **Phase 4: Restrict NTLM** (Highest Impact)
   - Apply `NTLM-Restrictions-Policy` incrementally
   - Start with non-critical systems
   - Gradually expand to production

## Testing Recommendations

### Before Applying in Production

1. **Create Test OU**
   ```powershell
   New-ADOrganizationalUnit -Name "NTLM-Testing" -Path "DC=contoso,DC=com"
   ```

2. **Apply Policy to Test OU**
   ```powershell
   New-GPLink -Name "Disable NTLMv1 Policy" -Target "OU=NTLM-Testing,DC=contoso,DC=com"
   ```

3. **Move Test Systems to Test OU**
   ```powershell
   Move-ADObject -Identity "CN=TestServer01,CN=Computers,DC=contoso,DC=com" `
                 -TargetPath "OU=NTLM-Testing,DC=contoso,DC=com"
   ```

4. **Update Group Policy on Test Systems**
   ```powershell
   Invoke-Command -ComputerName "TestServer01" -ScriptBlock { gpupdate /force }
   ```

5. **Verify Settings Applied**
   ```powershell
   Invoke-Command -ComputerName "TestServer01" -ScriptBlock { gpresult /r }
   ```

6. **Test Applications**
   - Test all critical applications
   - Verify authentication still works
   - Check event logs for errors

## Policy Settings Reference

### NTLM Auditing Policy Settings

**Location**: Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options

| Setting | Value | Purpose |
|---------|-------|---------|
| Network security: Restrict NTLM: Audit NTLM authentication in this domain | Enable all | Audit all NTLM auth in domain |
| Network security: Restrict NTLM: Audit Incoming NTLM Traffic | Enable auditing for all accounts | Audit incoming NTLM |

**Location**: Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration

| Setting | Value | Purpose |
|---------|-------|---------|
| Audit Logon | Success and Failure | Capture logon events |
| Audit Account Logon | Success and Failure | Capture credential validation |

### Disable NTLMv1 Policy Settings

**Location**: Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options

| Setting | Value | Purpose |
|---------|-------|---------|
| Network security: LAN Manager authentication level | Send NTLMv2 response only. Refuse LM & NTLM | Disable NTLMv1 and LM |
| Network security: Restrict NTLM: Incoming NTLM traffic | Deny all accounts | Block NTLMv1 incoming |
| Network security: Restrict NTLM: NTLM authentication in this domain | Deny all | Block NTLMv1 in domain |

## Rollback Procedures

If a policy causes issues:

### Quick Disable (Does not remove policy)
```powershell
# Disable the GPO link
Set-GPLink -Name "Policy-Name" -Target "OU=Target,DC=contoso,DC=com" -LinkEnabled No
```

### Remove Link
```powershell
# Remove the GPO link
Remove-GPLink -Name "Policy-Name" -Target "OU=Target,DC=contoso,DC=com"
```

### Force Update After Rollback
```powershell
# Update group policy on affected systems
Invoke-Command -ComputerName "AffectedServer" -ScriptBlock { gpupdate /force }
```

## Monitoring After Policy Application

### Check Event Logs
```powershell
# Check for NTLM blocks (Event ID 4776)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4776} -MaxEvents 50

# Check for NTLM operational events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-NTLM/Operational'} -MaxEvents 50
```

### Monitor for Authentication Failures
```kql
// In Microsoft Sentinel
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID in (4625, 4776)  // Failed logon attempts
| where EventData contains "NTLM"
| summarize Count=count() by Computer, Account
```

## Policy Documentation

Each policy folder should contain:
- `README.md` - Detailed description and instructions
- `Settings.txt` - Complete list of settings
- `Prerequisites.txt` - System requirements
- `Testing-Checklist.md` - Testing steps
- `Rollback-Plan.md` - Rollback procedures

## Compliance and Auditing

These policies help meet requirements for:
- CIS Windows Benchmarks
- NIST Cybersecurity Framework
- PCI DSS (if applicable)
- SOC 2 security controls
- GDPR security requirements

## Support Matrix

| Policy | Windows 10/11 | Server 2016 | Server 2019 | Server 2022 |
|--------|---------------|-------------|-------------|-------------|
| NTLM Auditing | ✅ | ✅ | ✅ | ✅ |
| Disable NTLMv1 | ✅ | ✅ | ✅ | ✅ |
| Credential Guard | ✅ (Enterprise) | ❌ | ✅ | ✅ |
| Protected Users | ✅ | ✅ | ✅ | ✅ |

## Additional Resources

- [Microsoft Group Policy Documentation](https://docs.microsoft.com/group-policy/)
- [NTLM Security Settings Reference](https://docs.microsoft.com/windows/security/threat-protection/security-policy-settings/)
- [CIS Windows Benchmarks](https://www.cisecurity.org/benchmark/microsoft_windows_server)

## Best Practices

1. **Always test in non-production first**
2. **Document all policy changes**
3. **Maintain backup of working GPOs**
4. **Use WMI filters for targeted application**
5. **Monitor event logs after deployment**
6. **Have rollback plan ready**
7. **Communicate with stakeholders**
8. **Schedule changes during maintenance windows**

## Troubleshooting

### Policy Not Applying
```powershell
# Check GPO link
Get-GPInheritance -Target "OU=Target,DC=contoso,DC=com"

# Check for blocking
Get-GPO -Name "Policy-Name" | Select-Object DisplayName, GpoStatus

# Force update
gpupdate /force /target:computer
```

### Settings Not Taking Effect
```powershell
# Check RSoP (Resultant Set of Policy)
gpresult /h C:\Temp\gpresult.html

# Check for conflicts
gpresult /r
```

## Contact and Support

For questions or issues with these policies:
1. Review the policy-specific README
2. Check event logs for errors
3. Consult Microsoft documentation
4. Test in isolated environment

---

**Remember**: These are powerful security settings. Always test thoroughly before production deployment.
