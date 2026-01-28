# Detection Rules and SIEM Content

This folder contains detection rules and SIEM content for identifying NTLM-based attacks and suspicious authentication patterns.

## Contents

### Microsoft Sentinel Rules
- `sentinel-ntlmv1-detection.yaml` - Alert on any NTLMv1 usage
- `sentinel-ntlm-relay-attack.yaml` - Detect potential NTLM relay attacks
- `sentinel-privileged-ntlm.yaml` - Alert on privileged accounts using NTLM
- `sentinel-anomalous-ntlm.yaml` - Detect unusual NTLM patterns

### Splunk Rules
- `splunk-ntlm-detections.spl` - Splunk queries for NTLM monitoring

### Generic SIEM Rules
- `siem-generic-ntlm-rules.md` - Platform-agnostic detection logic

### Threat Hunting Queries
- `threat-hunting-ntlm.md` - Proactive threat hunting queries

## Rule Categories

### Critical Severity
- NTLMv1 usage detection
- NTLM relay attack patterns
- Pass-the-hash indicators

### High Severity
- Privileged account NTLM usage
- Unusual NTLM volume
- NTLM from untrusted sources

### Medium Severity
- Service account NTLM usage
- Legacy system NTLM authentication
- Anomalous time-based patterns

## Integration

These rules are designed to work with:
- Microsoft Sentinel (KQL-based)
- Splunk
- QRadar
- ArcSight
- ELK Stack
- Generic SIEM platforms

## Customization

Each rule includes:
- Detection logic
- Severity classification
- MITRE ATT&CK mapping
- Recommended response actions
- False positive guidance
- Tuning recommendations

## Usage

1. Review rule logic and customize for your environment
2. Test rules in a non-production SIEM instance
3. Tune thresholds based on baseline data
4. Deploy to production with appropriate alerting
5. Create response playbooks for each rule

## MITRE ATT&CK Mapping

These rules map to the following tactics and techniques:
- **TA0006** - Credential Access
  - T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay
  - T1187 - Forced Authentication
- **TA0008** - Lateral Movement
  - T1021 - Remote Services
- **TA0005** - Defense Evasion
  - T1550.002 - Pass the Hash

## Response Playbooks

Each detection rule should be paired with an incident response playbook:
1. Alert validation
2. Scope assessment
3. Containment actions
4. Eradication steps
5. Recovery procedures
6. Lessons learned

## Maintenance

- Review rules monthly
- Update based on new attack patterns
- Tune thresholds as environment changes
- Document false positives and exclusions
- Share improvements with community
