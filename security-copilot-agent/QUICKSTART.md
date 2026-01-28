# Quick Start Guide - NTLM Must Die Security Copilot Agent

## 5-Minute Setup

This guide gets you up and running with the NTLM Must Die Security Copilot Agent in 5 minutes.

### Step 1: Verify Prerequisites (1 minute)

✅ Check you have:
- Microsoft Security Copilot access
- Microsoft Sentinel workspace with Security Events data

Test Sentinel access with this query:
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| take 5
```

### Step 2: Install the Agent (2 minutes)

1. Download manifest:
   ```bash
   wget https://raw.githubusercontent.com/MBCloudTeck/NTLM-Must-Die/main/security-copilot-agent/manifest.json
   ```

2. In Security Copilot portal:
   - Settings → Plugins → Add Plugin
   - Upload `manifest.json`
   - Enable the agent

### Step 3: First Query (2 minutes)

Try these starter queries:

```
NTLM agent, analyze NTLM usage in my environment
```

```
NTLM agent, are there any NTLMv1 authentications?
```

```
NTLM agent, show me the top 5 systems using NTLM
```

## Common Use Cases

### Use Case 1: Initial NTLM Assessment

**Goal**: Understand current NTLM usage in your environment

**Queries to run**:
```
1. "NTLM agent, analyze NTLM usage over the last 7 days"
2. "NTLM agent, how many NTLMv1 vs NTLMv2 events occurred?"
3. "NTLM agent, what is my NTLM risk score?"
4. "NTLM agent, show me the top 10 sources of NTLM traffic"
```

**What you'll learn**:
- Total NTLM authentication count
- NTLMv1 vs NTLMv2 breakdown (critical for risk assessment)
- Top systems and accounts using NTLM
- Overall risk level and priority recommendations

### Use Case 2: Detect Active Attacks

**Goal**: Identify NTLM-based attacks happening now

**Queries to run**:
```
1. "NTLM agent, are there any NTLM relay attacks?"
2. "NTLM agent, detect pass-the-hash attempts"
3. "NTLM agent, show suspicious NTLM patterns in the last hour"
4. "NTLM agent, are privileged accounts using NTLM?"
```

**What you'll learn**:
- Active NTLM relay attack indicators
- Suspicious authentication patterns
- Privileged account exposure
- Recommended response actions

### Use Case 3: Plan Remediation

**Goal**: Create action plan to eliminate NTLM

**Queries to run**:
```
1. "NTLM agent, how do I disable NTLMv1?"
2. "NTLM agent, create a remediation plan for my environment"
3. "NTLM agent, what Group Policy settings should I configure?"
4. "NTLM agent, give me PowerShell scripts for NTLM auditing"
```

**What you'll get**:
- Step-by-step remediation plan
- Group Policy configuration templates
- PowerShell automation scripts
- Timeline and resource estimates

### Use Case 4: Generate Reports

**Goal**: Create executive summary for management

**Queries to run**:
```
1. "NTLM agent, generate an executive summary report"
2. "NTLM agent, show NTLM usage trends over 30 days"
3. "NTLM agent, create a risk assessment report"
4. "NTLM agent, what's our remediation progress?"
```

**What you'll get**:
- Executive-friendly summaries
- Trend visualizations
- Risk scoring with CVSS
- Progress tracking metrics

### Use Case 5: Deploy Monitoring

**Goal**: Set up continuous NTLM monitoring

**Queries to run**:
```
1. "NTLM agent, give me Sentinel detection rules for NTLM"
2. "NTLM agent, how do I configure alerts for NTLMv1?"
3. "NTLM agent, what KQL queries should I use for monitoring?"
4. "NTLM agent, integrate with Microsoft Defender for Identity"
```

**What you'll get**:
- Sentinel analytics rules (YAML)
- KQL queries for dashboards
- Alert configuration guidance
- Integration instructions for MDI

## Example Workflows

### Workflow 1: Emergency Response - NTLMv1 Detected

**Scenario**: You discover NTLMv1 usage (critical risk)

**Steps**:
1. Assess impact:
   ```
   NTLM agent, show all NTLMv1 authentication sources
   ```

2. Identify systems:
   ```
   NTLM agent, which systems are using NTLMv1?
   ```

3. Get remediation steps:
   ```
   NTLM agent, how do I immediately disable NTLMv1?
   ```

4. Deploy fix:
   - Run PowerShell script: `Disable-NTLMv1.ps1`
   - Apply Group Policy to domain

5. Verify elimination:
   ```
   NTLM agent, confirm no NTLMv1 events in last 24 hours
   ```

**Time to remediate**: 1-2 days

### Workflow 2: Systematic NTLM Reduction

**Scenario**: Phased approach to eliminate all NTLM

**Phase 1 - Week 1: Baseline**
```
NTLM agent, analyze NTLM usage over the last 30 days
NTLM agent, identify all accounts using NTLM
NTLM agent, list systems by NTLM event count
```

**Phase 2 - Weeks 2-3: Quick Wins**
```
NTLM agent, which systems can easily migrate to Kerberos?
NTLM agent, how do I configure SPNs for service accounts?
```
- Target systems with highest NTLM count
- Fix missing SPNs
- Update application configurations

**Phase 3 - Weeks 4-6: Legacy Systems**
```
NTLM agent, how do I handle legacy devices that require NTLM?
```
- Upgrade/replace old printers, NAS, scanners
- Isolate systems that cannot be updated
- Apply network segmentation

**Phase 4 - Week 7+: Hardening**
```
NTLM agent, give me all hardening recommendations
```
- Enable SMB signing
- Configure Protected Users group
- Deploy Credential Guard
- Continuous monitoring

### Workflow 3: Incident Investigation

**Scenario**: Suspicious NTLM activity detected

**Investigation steps**:

1. **Initial triage**:
   ```
   NTLM agent, show me all NTLM events in the last hour from IP 192.168.1.100
   ```

2. **Identify attack pattern**:
   ```
   NTLM agent, is this an NTLM relay attack?
   ```

3. **Assess scope**:
   ```
   NTLM agent, which systems and accounts are affected?
   ```

4. **Get response actions**:
   ```
   NTLM agent, what should I do to contain this attack?
   ```

5. **Document for compliance**:
   ```
   NTLM agent, generate an incident report for this event
   ```

## Tips and Best Practices

### Query Tips

**Be Specific with Time Ranges**:
```
✅ "analyze NTLM usage in the last 24 hours"
✅ "show NTLM events from yesterday"
❌ "analyze all NTLM usage" (may timeout on large datasets)
```

**Use Follow-Up Questions**:
```
1. "analyze NTLM usage"
2. "show more details on the top source"
3. "how do I remediate that system?"
```

**Combine Multiple Intents**:
```
✅ "analyze NTLM usage and create a remediation plan"
✅ "detect relay attacks and recommend response actions"
```

### Best Practices

1. **Start with Assessment**: Always understand your baseline before making changes

2. **Test in Pilot**: Deploy NTLM restrictions to a pilot OU first

3. **Monitor Continuously**: Set up Sentinel alerts before disabling NTLM

4. **Document Exceptions**: Track systems that legitimately need NTLM

5. **Review Weekly**: Check NTLM trends to measure progress

### Common Mistakes to Avoid

❌ **Don't disable NTLM domain-wide without testing**
   - Could break legacy applications
   - Test in pilot environment first

❌ **Don't ignore NTLMv2**
   - While less critical than NTLMv1, still a risk
   - Plan to eliminate eventually

❌ **Don't skip auditing**
   - Enable NTLM auditing before making changes
   - You need visibility for troubleshooting

❌ **Don't forget service accounts**
   - Often overlooked but common NTLM users
   - Configure SPNs for Kerberos support

## Quick Reference - KQL Queries

If you want to run queries directly in Sentinel:

### Detect NTLMv1 (Critical)
```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (3, 9, 10)
| extend PackageName = tostring(parse_json(EventData).PackageName)
| where PackageName contains "NTLM V1"
| summarize Count = count() by Computer, Account
| order by Count desc
```

### Monitor All NTLM
```kql
SecurityEvent
| where EventID in (4624, 4776)
| extend PackageName = tostring(parse_json(EventData).PackageName)
| where PackageName contains "NTLM"
| summarize Count = count() by bin(TimeGenerated, 1h)
| render timechart
```

### Top NTLM Sources
```kql
SecurityEvent
| where EventID == 4624
| extend PackageName = tostring(parse_json(EventData).PackageName)
| where PackageName contains "NTLM"
| summarize NTLMCount = count() by Computer
| top 10 by NTLMCount
```

## Troubleshooting

### Agent Not Responding

**Check**:
1. Is the agent enabled? (Settings → Plugins)
2. Do you have Sentinel data? (Run test query)
3. Are you addressing the agent? (Must say "NTLM agent" in query)

### No Results Returned

**Check**:
1. Is NTLM auditing enabled? (Group Policy)
2. Is log collection working? (Sentinel data connector)
3. Are you looking at the right time range? (Try "last 24 hours")

### Query Timeout

**Solutions**:
1. Reduce time range: "last 24 hours" instead of "last 30 days"
2. Be more specific: Add filters like "from system X"
3. Ask for summary: "summary report" instead of "all events"

## Next Steps

Now that you're up and running:

1. **Complete Initial Assessment**
   - Run the Use Case 1 queries
   - Document current NTLM usage

2. **Deploy Detection Rules**
   - See `INSTALLATION.md` for deployment steps
   - Set up alerts for NTLMv1 and relay attacks

3. **Create Remediation Plan**
   - Use Workflow 2 for systematic approach
   - Estimate timeline and resources

4. **Schedule Regular Reviews**
   - Weekly: Check NTLM trends
   - Monthly: Generate executive report
   - Quarterly: Reassess risk posture

## Additional Resources

- **Full Documentation**: See `README.md`
- **Installation Guide**: See `INSTALLATION.md`
- **KQL Queries**: `/NTLM resources/KQL/` directory
- **PowerShell Scripts**: `/NTLM resources/PowerShell/` directory
- **Detection Rules**: `/NTLM resources/DetectionRules/` directory

## Feedback

Found this quick start helpful? Have suggestions?
- Open an issue: https://github.com/MBCloudTeck/NTLM-Must-Die/issues
- Contribute improvements: Submit a pull request

---

**Ready to eliminate NTLM? Let's get started! 🚀**
