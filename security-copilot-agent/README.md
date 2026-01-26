# NTLM Must Die - Security Copilot Agent

## Overview

The **NTLM Must Die Security Copilot Agent** is a specialized plugin for Microsoft Security Copilot that helps security teams analyze, detect, and eliminate insecure NTLM authentication in enterprise environments.

This agent provides:
- **Real-time NTLM analysis** using KQL queries for Microsoft Sentinel
- **Attack detection** for NTLM relay, pass-the-hash, and credential theft
- **Risk assessment** with vulnerability scoring and prioritization
- **Remediation guidance** with step-by-step implementation plans
- **Comprehensive reporting** for tracking NTLM reduction progress

## What is Microsoft Security Copilot?

Microsoft Security Copilot is an AI-powered security analysis platform that combines large language models with security-specific capabilities. It helps security professionals analyze threats, investigate incidents, and respond to security events using natural language.

Custom agents extend Security Copilot with specialized knowledge and capabilities for specific security domains.

## Why This Agent?

NTLM (NT LAN Manager) is a legacy authentication protocol with serious security vulnerabilities:

- **NTLMv1** uses broken cryptography (DES, MD4) and is trivially crackable
- **NTLMv2** lacks mutual authentication, enabling relay attacks
- Both are targets for pass-the-hash, credential theft, and lateral movement

This agent helps organizations:
1. **Discover** where NTLM is still being used
2. **Detect** NTLM-based attacks in real-time
3. **Remediate** by migrating to Kerberos
4. **Monitor** progress toward NTLM elimination

## Capabilities

### 1. Analyze NTLM Usage
Ask the agent questions like:
- "Show me all NTLMv1 usage in my environment"
- "What accounts are using NTLM authentication?"
- "Which systems are generating the most NTLM traffic?"
- "Analyze NTLM usage trends over the past 30 days"

The agent will query Microsoft Sentinel using KQL and provide detailed analysis including:
- NTLMv1 vs NTLMv2 breakdown
- Top sources and accounts
- Authentication patterns and trends
- Risk classification

### 2. Detect NTLM Attacks
Identify active threats:
- "Are there any NTLM relay attacks in my environment?"
- "Detect pass-the-hash attempts using NTLM"
- "Show me suspicious NTLM authentication patterns"
- "Alert me if privileged accounts use NTLM"

The agent provides:
- Real-time detection using Microsoft Sentinel rules
- MITRE ATT&CK framework mapping
- Incident correlation across multiple data sources
- Recommended response actions

### 3. Provide Remediation Guidance
Get actionable remediation steps:
- "How do I disable NTLMv1?"
- "What are the steps to eliminate NTLM in my environment?"
- "How can I configure Kerberos instead of NTLM?"
- "Give me a Group Policy template to harden NTLM"

The agent offers:
- Phase-by-phase implementation checklists
- PowerShell automation scripts
- Group Policy configuration templates
- Best practices from Microsoft security guidance

### 4. Generate Reports
Create comprehensive reports:
- "Generate an NTLM usage summary report"
- "Show me a risk assessment for NTLM in my environment"
- "Create a remediation progress report"
- "Give me an executive summary of legacy protocol usage"

Report types include:
- Executive summaries with risk scoring
- Technical detail reports with metrics
- Trend analysis for tracking progress
- Compliance and audit reports

### 5. Assess Risk
Understand your security posture:
- "What is my NTLM risk score?"
- "Assess the security risk of NTLM in my environment"
- "What vulnerabilities does NTLM expose us to?"
- "Prioritize NTLM remediation based on risk"

Risk assessment includes:
- CVSS vulnerability scoring
- Attack surface analysis
- Prioritized remediation recommendations
- Compliance impact assessment

### 6. Deploy Detection Rules
Implement security monitoring:
- "Give me Sentinel detection rules for NTLM attacks"
- "How do I configure alerts for NTLMv1?"
- "What SIEM rules should I deploy for NTLM monitoring?"

The agent provides:
- Pre-built Microsoft Sentinel rules (YAML format)
- KQL queries for custom detections
- Alert tuning recommendations
- Integration with Microsoft Defender for Identity

## Installation

### Prerequisites
- Microsoft Security Copilot license
- Microsoft Sentinel workspace (for detection queries)
- Windows Security Event log collection enabled
- NTLM auditing configured via Group Policy

### Steps

1. **Download the agent manifest**
   ```bash
   wget https://raw.githubusercontent.com/MBCloudTeck/NTLM-Must-Die/main/security-copilot-agent/manifest.json
   ```

2. **Import into Security Copilot**
   - Open Microsoft Security Copilot portal
   - Navigate to **Settings** > **Plugins**
   - Click **Add Plugin** > **Custom Agent**
   - Upload `manifest.json`
   - Enable the agent

3. **Configure permissions**
   - Grant the agent access to your Microsoft Sentinel workspace
   - Ensure it has read permissions for SecurityEvent tables
   - Configure any required API connections

4. **Verify installation**
   Ask Security Copilot: "NTLM agent, can you analyze my environment?"

## Usage Examples

### Example 1: Initial NTLM Assessment
```
User: "NTLM agent, analyze NTLM usage in my environment over the last 7 days"

Agent: I'll analyze NTLM authentication patterns in your environment...
[Executes detect_ntlm_authentication KQL query]

Summary:
- Total NTLM Events: 45,832
- NTLMv1 Events: 234 (CRITICAL)
- NTLMv2 Events: 45,598
- Unique Accounts: 1,247
- Unique Systems: 892

Risk Level: CRITICAL - NTLMv1 detected

Top Sources:
1. LEGACY-PRINT-01: 12,450 events
2. NAS-STORAGE-05: 8,932 events
3. APP-SERVER-23: 6,721 events

Recommendations:
1. Immediately disable NTLMv1 on legacy systems
2. Investigate printer and NAS device configurations
3. Work with app team to migrate APP-SERVER-23 to Kerberos
```

### Example 2: Detecting NTLM Relay Attack
```
User: "Are there any NTLM relay attacks happening right now?"

Agent: Analyzing authentication patterns for NTLM relay indicators...
[Executes detect_ntlm_relay_attack KQL query]

ALERT: Potential NTLM Relay Attack Detected

Source IP: 192.168.10.45
Target Systems: DC01, DC02, FILE-SRV-10, SQL-PROD-02 (13 total)
Affected Account: svc-backup@contoso.com
Timeline: Started 14:23 UTC, ongoing

Pattern: Single source IP authenticating to multiple high-value targets in rapid succession using NTLM v2.

MITRE ATT&CK: T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay

Recommended Actions:
1. Isolate source IP 192.168.10.45 immediately
2. Reset credentials for svc-backup@contoso.com
3. Enable SMB signing on all target systems
4. Review authentication logs for credential access
5. Check for persistence mechanisms on compromised systems
```

### Example 3: Remediation Planning
```
User: "How do I eliminate NTLMv1 from my environment?"

Agent: Here's a step-by-step plan to eliminate NTLMv1:

Phase 1: Assessment (Week 1)
✓ Enable NTLM auditing via Group Policy
✓ Run Audit-NTLMUsage.ps1 to identify all NTLMv1 sources
✓ Document affected systems, applications, and devices
✓ Estimate remediation timeline

Phase 2: Remediation (Weeks 2-4)
✓ Update/replace legacy devices (printers, NAS, scanners)
✓ Patch or reconfigure applications
✓ Test Kerberos authentication on affected systems
✓ Create exemptions for systems that cannot be updated

Phase 3: Enforcement (Week 5)
✓ Apply Group Policy: Network security: LAN Manager authentication level = "Send NTLMv2 response only. Refuse LM & NTLM"
✓ Deploy policy to pilot OU first
✓ Monitor for breakage and address issues
✓ Roll out domain-wide

Phase 4: Verification (Week 6+)
✓ Confirm no NTLMv1 events in logs
✓ Enable Windows Credential Guard (disables NTLMv1)
✓ Continuous monitoring via Sentinel

PowerShell Scripts Available:
- Audit-NTLMUsage.ps1: Comprehensive audit across domain
- Disable-NTLMv1.ps1: Apply Group Policy settings
- Enable-NTLMAuditing.ps1: Configure NTLM auditing

Would you like me to generate the Group Policy template?
```

## Integration with Microsoft Products

### Microsoft Sentinel
- Pre-built KQL queries for NTLM detection
- Custom workbook: Insecure Protocols Workbook
- Alert rules for NTLMv1, relay attacks, anomalies
- Incident correlation and response automation

### Microsoft Defender for Identity
- NTLM relay attack detection
- Pass-the-hash detection
- Service account discovery
- Privileged account monitoring

### Microsoft Defender for Endpoint
- Endpoint-level NTLM telemetry
- Application-level NTLM usage tracking
- Credential Guard status monitoring
- Integration with Secure Score

### Azure AD / Entra ID
- Hybrid authentication monitoring
- Legacy authentication blocking
- Conditional Access policies
- Sign-in log analysis

## KQL Query Reference

All KQL queries are available in the `/resources/KQL/` directory:

| Query | Purpose | Severity |
|-------|---------|----------|
| `detect-ntlmv1-usage.kql` | Identify all NTLMv1 attempts | Critical |
| `detect-ntlm-authentication.kql` | Monitor all NTLM events | High |
| `detect-suspicious-ntlm-patterns.kql` | Detect anomalous patterns | Medium |
| `analyze-ntlm-by-source.kql` | Break down by source system | Info |
| `analyze-ntlm-by-account.kql` | Break down by account | Info |
| `analyze-ntlm-trends.kql` | Track usage over time | Info |
| `report-ntlm-summary.kql` | Executive summary | Info |
| `report-legacy-protocol-usage.kql` | All legacy protocols | Info |

## PowerShell Script Reference

Automation scripts are available in `/resources/PowerShell/`:

| Script | Purpose |
|--------|---------|
| `Audit-NTLMUsage.ps1` | Comprehensive NTLM audit across domain |
| `Enable-NTLMAuditing.ps1` | Configure NTLM auditing via Group Policy |
| `Disable-NTLMv1.ps1` | Disable NTLMv1 and configure secure settings |

## Detection Rules

SIEM detection rules are available in `/resources/DetectionRules/`:

- **Microsoft Sentinel Rules** (YAML format)
  - `sentinel-ntlmv1-detection.yaml`
  - `sentinel-ntlm-relay-attack.yaml`
  - `sentinel-privileged-ntlm.yaml`
  - `sentinel-anomalous-ntlm.yaml`

## MITRE ATT&CK Mapping

This agent addresses the following MITRE ATT&CK tactics and techniques:

### Credential Access (TA0006)
- **T1557.001** - LLMNR/NBT-NS Poisoning and SMB Relay
- **T1187** - Forced Authentication

### Lateral Movement (TA0008)
- **T1021** - Remote Services

### Defense Evasion (TA0005)
- **T1550.002** - Pass the Hash

## Security Best Practices

### Immediate Actions (Critical Priority)
1. **Eliminate NTLMv1**: Disable via Group Policy immediately
2. **Enable Windows Credential Guard**: Automatically disables NTLMv1
3. **Protected Users Group**: Add privileged accounts (blocks NTLM entirely)
4. **Enable SMB Signing**: Prevents NTLM relay attacks

### Progressive Hardening
1. **Enable NTLM Auditing**: Track usage via Event IDs 4624, 4776, 8001-8004
2. **Configure Service Principal Names (SPNs)**: Enable Kerberos for services
3. **Enable LDAP Signing**: Prevent LDAP relay attacks
4. **Extended Protection for Authentication (EPA)**: Additional layer of protection

### Monitoring and Detection
1. **Microsoft Sentinel**: Deploy NTLM detection rules
2. **Microsoft Defender for Identity**: Enable NTLM attack detections
3. **Windows Event Forwarding**: Centralize security logs
4. **Regular Audits**: Weekly review of NTLM usage trends

## Troubleshooting

### Agent Not Responding
- Verify agent is enabled in Security Copilot settings
- Check permissions to Sentinel workspace
- Ensure SecurityEvent table has data

### No NTLM Events Detected
- Verify NTLM auditing is enabled via Group Policy
- Check Windows Security Event log collection
- Confirm data connector is working in Sentinel

### False Positives
- Tune detection rules based on your environment
- Add known-good systems to exclusion lists
- Adjust thresholds for anomaly detection

## Support and Contributions

### Resources
- **Repository**: https://github.com/MBCloudTeck/NTLM-Must-Die
- **Documentation**: See `/resources/` directory for guides and checklists
- **Microsoft Guidance**: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level

### Contributing
Contributions are welcome! Please submit pull requests for:
- New KQL queries
- Enhanced detection rules
- Additional PowerShell scripts
- Documentation improvements

### Credits
Original research and content by [David Alonso Dominguez](https://www.linkedin.com/in/david-alonso-dominguez/)

## License

This project is provided as-is for educational and security improvement purposes.

## Version History

- **v1.0.0** (Initial Release)
  - Core NTLM analysis capabilities
  - Attack detection rules
  - Remediation guidance
  - Risk assessment features
  - Integration with Microsoft Sentinel and Defender

## Roadmap

Future enhancements planned:
- [ ] Automated remediation workflows
- [ ] Integration with Azure Policy for compliance enforcement
- [ ] Machine learning-based anomaly detection
- [ ] Cross-tenant NTLM analysis for MSPs
- [ ] Mobile device NTLM usage tracking
- [ ] Extended support for hybrid and cloud-only environments
