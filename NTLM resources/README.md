# NTLM-Must-Die Resources

This directory contains practical resources, scripts, queries, and documentation to help you detect, monitor, and eliminate NTLM authentication in your environment.

## Directory Structure

### 📊 KQL Queries (`KQL/`)
Kusto Query Language queries for Microsoft Sentinel and Azure Monitor:
- Detection queries for NTLMv1 and NTLMv2 usage
- Analysis queries for identifying NTLM sources and patterns
- Suspicious activity detection
- Trend analysis and reporting queries

**Start here**: `KQL/README.md`

### ☁️ Azure Arc Documentation (`AzureArc/`)
Comprehensive guides for using Azure Arc to monitor and manage hybrid environments:
- Setup and configuration guides
- Microsoft Sentinel integration
- Security policy enforcement
- Best practices for hybrid NTLM monitoring

**Start here**: `AzureArc/README.md`

### 💻 PowerShell Scripts (`PowerShell/`)
Automation scripts for NTLM auditing and hardening:
- `Audit-NTLMUsage.ps1` - Comprehensive NTLM usage audit
- `Enable-NTLMAuditing.ps1` - Enable NTLM event logging
- `Disable-NTLMv1.ps1` - Safely disable NTLMv1 across domain
- Additional monitoring and remediation scripts

**Start here**: `PowerShell/README.md`

### 📋 Checklists (`Checklists/`)
Phase-by-phase checklists to guide your NTLM deprecation journey:
- Phase 1: Assessment
- Phase 2: Planning
- Phase 3: Hardening
- Phase 4: Monitoring
- Role-specific checklists for security, infrastructure, and application teams

**Start here**: `Checklists/README.md`

### 🚨 Detection Rules (`DetectionRules/`)
SIEM detection rules for identifying NTLM-based attacks:
- Microsoft Sentinel analytics rules
- Splunk queries
- Generic SIEM detection logic
- MITRE ATT&CK mappings

**Start here**: `DetectionRules/README.md`

### 📜 Group Policies (`Policies/`)
Group Policy templates and configurations:
- NTLM restriction policies
- Auditing configurations
- Security hardening templates
- Import/export instructions

**Start here**: `Policies/README.md`

## Quick Start Guide

### 1. Assessment Phase
```powershell
# Enable auditing
.\PowerShell\Enable-NTLMAuditing.ps1

# Wait 7-14 days for data collection

# Run audit
.\PowerShell\Audit-NTLMUsage.ps1 -Domain "contoso.com" -Days 7 -OutputPath "C:\Reports"
```

### 2. Analysis Phase
Use KQL queries to analyze collected data:
```kql
// Detect any NTLMv1 usage (critical)
// See: KQL/detect-ntlmv1-usage.kql

// Analyze NTLM by source
// See: KQL/analyze-ntlm-by-source.kql

// Generate executive summary
// See: KQL/report-ntlm-summary.kql
```

### 3. Hardening Phase
```powershell
# Test changes first
.\PowerShell\Disable-NTLMv1.ps1 -WhatIf

# Apply when ready
.\PowerShell\Disable-NTLMv1.ps1 -Apply
```

### 4. Monitoring Phase
- Deploy Sentinel detection rules from `DetectionRules/`
- Set up continuous monitoring with KQL queries
- Follow ongoing monitoring checklist

## Recommended Workflow

1. **Read the Main README** (`../README.md`) - Understand NTLM security issues
2. **Start with Assessment** (`Checklists/phase1-assessment.md`)
3. **Enable Auditing** (`PowerShell/Enable-NTLMAuditing.ps1`)
4. **Set up Azure Arc** (Optional but recommended: `AzureArc/setup-guide.md`)
5. **Collect Baseline Data** (7-14 days)
6. **Run Analysis** (`PowerShell/Audit-NTLMUsage.ps1` and KQL queries)
7. **Plan Remediation** (`Checklists/phase2-planning.md`)
8. **Implement Hardening** (`PowerShell/Disable-NTLMv1.ps1` and policies)
9. **Deploy Detection Rules** (`DetectionRules/`)
10. **Monitor and Iterate** (`Checklists/phase4-monitoring.md`)

## Prerequisites

### General Requirements
- Windows Server 2016 or later (2019+ recommended)
- Active Directory environment
- PowerShell 5.1 or later (7.x recommended)
- Administrative privileges

### For Azure Integration (Optional)
- Azure subscription
- Microsoft Sentinel (recommended)
- Azure Arc-enabled servers

### For SIEM Integration
- Existing SIEM platform (Sentinel, Splunk, QRadar, etc.)
- Event log forwarding configured
- Sufficient log storage

## Key Resources by Role

### Security Operations Team
- `DetectionRules/` - Deploy detection rules
- `KQL/detect-suspicious-ntlm-patterns.kql` - Hunt for attacks
- `Checklists/security-team-checklist.md` - Security team tasks

### Infrastructure/AD Team
- `PowerShell/` - Automation scripts
- `Policies/` - Group Policy templates
- `Checklists/infrastructure-team-checklist.md` - Infrastructure tasks

### Application Teams
- `Checklists/application-team-checklist.md` - Application remediation
- `AzureArc/` - Monitoring application authentication

### Executives/Management
- `KQL/report-ntlm-summary.kql` - Executive summary reports
- `Checklists/executive-readiness.md` - Briefing materials

## Support and Contributions

### Getting Help
- Review documentation in each folder
- Check README files for detailed instructions
- Refer to Microsoft documentation links provided

### Contributing
Contributions welcome! If you have:
- Additional KQL queries
- PowerShell scripts
- Detection rules
- Best practices
- Lessons learned

Please consider contributing back to help others.

## Security Considerations

⚠️ **Important Security Notes**:
- Always test in non-production first
- Have rollback plans ready
- Document all changes
- Monitor logs after changes
- Keep executive stakeholders informed
- Use secure credential management
- Avoid hardcoding credentials in scripts

## Related Microsoft Documentation

- [Microsoft Security: NTLM Overview](https://docs.microsoft.com/windows-server/security/kerberos/ntlm-overview)
- [Microsoft Sentinel Documentation](https://docs.microsoft.com/azure/sentinel/)
- [Azure Arc Documentation](https://docs.microsoft.com/azure/azure-arc/)
- [Credential Guard](https://docs.microsoft.com/windows/security/identity-protection/credential-guard/)
- [Protected Users Security Group](https://docs.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group)

## License

This resource repository is part of the NTLM-Must-Die project. See main repository for license information.

## Acknowledgments

These resources are based on:
- Microsoft security best practices
- Real-world enterprise implementations
- Community contributions
- Security research and threat intelligence

---

**Remember**: NTLM is a legacy protocol that poses significant security risks. The goal is to completely eliminate it from your environment, starting with the critically insecure NTLMv1.
