# Microsoft Sentinel Integration for NTLM Monitoring

This guide explains how to integrate Azure Arc-enabled servers with Microsoft Sentinel for advanced NTLM threat detection and monitoring.

## Overview

Microsoft Sentinel is a cloud-native SIEM (Security Information and Event Management) solution that provides:
- Intelligent threat detection for NTLM-based attacks
- Automated incident response
- Built-in workbooks for legacy protocol monitoring
- Integration with Azure Arc for hybrid environments

## Prerequisites

- Azure Arc-enabled servers with Log Analytics agent
- Log Analytics workspace
- Microsoft Sentinel enabled on the workspace
- NTLM auditing configured (see `setup-guide.md`)

## Step 1: Enable Microsoft Sentinel

### Via Azure Portal
1. Navigate to your Log Analytics workspace
2. Search for "Microsoft Sentinel" in the Azure Portal
3. Click "Add" and select your Log Analytics workspace
4. Click "Add Microsoft Sentinel"

### Via Azure CLI
```bash
az sentinel onboard create \
  --resource-group "rg-arc-ntlm-monitoring" \
  --workspace-name "law-ntlm-monitoring"
```

## Step 2: Configure Data Connectors

### Windows Security Events Connector

1. In Microsoft Sentinel, navigate to **Data connectors**
2. Search for "Security Events via Legacy Agent"
3. Click "Open connector page"
4. Select event collection level:
   - **Recommended**: Common events (includes 4624, 4776)
   - **Custom**: Select specific events for NTLM monitoring

For NTLM-specific monitoring, use **Custom** and configure:

```xml
<QueryList>
  <Query Id="0">
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4625 or EventID=4776)]]
    </Select>
    <Select Path="Microsoft-Windows-NTLM/Operational">
      *[System[(EventID=8001 or EventID=8002 or EventID=8003 or EventID=8004)]]
    </Select>
  </Query>
</QueryList>
```

### Azure Arc Connector

1. Navigate to **Data connectors** → "Windows Security Events via AMA"
2. This uses Azure Monitor Agent (AMA) with Data Collection Rules
3. Associate your Arc-enabled servers with the Data Collection Rule created in setup

## Step 3: Deploy Insecure Protocols Workbook

Microsoft provides a built-in workbook for legacy protocol monitoring:

1. Navigate to **Workbooks** in Microsoft Sentinel
2. Click **Templates**
3. Search for "Insecure Protocols"
4. Click "Save" to deploy to your workspace
5. Open the workbook to view:
   - NTLMv1 usage trends
   - Top sources of legacy authentication
   - Protocol distribution
   - Risk timeline

## Step 4: Configure Analytics Rules

### Create NTLM Attack Detection Rules

#### Rule 1: NTLMv1 Usage Detection

```kql
// Alert on any NTLMv1 usage (should be disabled)
SecurityEvent
| where TimeGenerated > ago(5m)
| where EventID == 4624
| extend PackageName = tostring(parse_json(EventData).PackageName)
| where PackageName contains "NTLM V1"
| extend 
    Account = tostring(parse_json(EventData).TargetUserName),
    SourceIP = IpAddress,
    TargetSystem = Computer
| summarize 
    Count = count(),
    FirstDetected = min(TimeGenerated),
    LastDetected = max(TimeGenerated),
    Systems = make_set(TargetSystem)
    by Account, SourceIP
| where Count > 0
| extend Severity = "High"
| project 
    FirstDetected,
    LastDetected,
    Account,
    SourceIP,
    Count,
    AffectedSystems = Systems,
    Severity,
    AlertDescription = "NTLMv1 authentication detected - immediate action required"
```

**Analytics Rule Configuration:**
- Name: "NTLMv1 Authentication Detected"
- Severity: High
- Tactics: Credential Access
- Run every: 5 minutes
- Lookup data from: Last 5 minutes

#### Rule 2: Potential NTLM Relay Attack

```kql
// Detect potential NTLM relay attacks (rapid authentications)
let threshold = 20;
let timeframe = 5m;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4624
| extend PackageName = tostring(parse_json(EventData).PackageName)
| where PackageName contains "NTLM"
| extend SourceIP = IpAddress
| summarize 
    AuthCount = count(),
    UniqueTargets = dcount(Computer),
    UniqueAccounts = dcount(Account),
    TargetSystems = make_set(Computer),
    Accounts = make_set(Account)
    by SourceIP, bin(TimeGenerated, 1m)
| where AuthCount > threshold
| extend Severity = case(
    AuthCount > 100, "Critical",
    AuthCount > 50, "High",
    "Medium"
)
| project 
    TimeGenerated,
    SourceIP,
    AuthCount,
    UniqueTargets,
    UniqueAccounts,
    TargetSystems,
    Accounts,
    Severity,
    AlertDescription = strcat("Potential NTLM relay attack: ", AuthCount, " authentications in 1 minute from ", SourceIP)
```

**Analytics Rule Configuration:**
- Name: "Potential NTLM Relay Attack"
- Severity: High
- Tactics: Lateral Movement, Credential Access
- Run every: 5 minutes
- Lookup data from: Last 5 minutes

#### Rule 3: Anomalous NTLM Usage from Privileged Accounts

```kql
// Detect unusual NTLM usage from privileged accounts
let PrivilegedGroups = dynamic(["Domain Admins", "Enterprise Admins", "Administrators"]);
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| extend PackageName = tostring(parse_json(EventData).PackageName)
| where PackageName contains "NTLM"
| extend 
    Account = tostring(parse_json(EventData).TargetUserName),
    SourceIP = IpAddress,
    LogonType = toint(parse_json(EventData).LogonType)
| where Account contains "admin" or Account contains "svc"
| summarize 
    AuthCount = count(),
    LogonTypes = make_set(LogonType),
    SourceIPs = make_set(SourceIP),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by Account, Computer
| extend Severity = "Medium"
| project 
    FirstSeen,
    LastSeen,
    Account,
    Computer,
    AuthCount,
    SourceIPs,
    LogonTypes,
    Severity,
    AlertDescription = "Privileged account using NTLM authentication - should use Kerberos"
```

**Analytics Rule Configuration:**
- Name: "Privileged Account Using NTLM"
- Severity: Medium
- Tactics: Credential Access
- Run every: 1 hour
- Lookup data from: Last 1 hour

## Step 5: Create Custom Workbook for NTLM Monitoring

Create a custom workbook for comprehensive NTLM visibility:

```json
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 1,
      "content": {
        "json": "## NTLM Authentication Monitoring Dashboard\nThis workbook provides comprehensive visibility into NTLM usage across your hybrid environment."
      }
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityEvent\n| where TimeGenerated > {TimeRange}\n| where EventID in (4624, 4776)\n| extend PackageName = tostring(parse_json(EventData).PackageName)\n| where PackageName contains \"NTLM\"\n| summarize Count = count() by bin(TimeGenerated, {TimeGranularity}), PackageName\n| render timechart",
        "size": 0,
        "title": "NTLM Authentication Trends"
      }
    }
  ]
}
```

## Step 6: Configure Automated Response

### Create Automation Rule

Set up automated response for NTLMv1 detections:

1. Navigate to **Automation** in Microsoft Sentinel
2. Click **Create** → **Automation rule**
3. Configure:
   - **Trigger**: When incident is created
   - **Conditions**: Analytics rule name contains "NTLMv1"
   - **Actions**: 
     - Add tag "NTLM-Critical"
     - Assign to security team
     - Run playbook "Block-Source-IP" (optional)

### Create Logic App Playbook (Optional)

For advanced response, create a Logic App to:
- Send email notifications
- Create ServiceNow ticket
- Post to Teams channel
- Execute remediation scripts

Example playbook trigger:
```json
{
  "type": "Microsoft.Logic/workflows",
  "properties": {
    "triggers": {
      "Microsoft_Sentinel_incident": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['azuresentinel']['connectionId']"
            }
          }
        }
      }
    }
  }
}
```

## Step 7: Set Up Watchlists

Create watchlists for exclusions and priority systems:

### Approved NTLM Systems Watchlist
```csv
SystemName,Reason,ExpirationDate
LEGACY-APP-01,Legacy application - scheduled for migration,2026-06-30
PRINTER-FLOOR3,Printer firmware doesn't support Kerberos,2026-12-31
```

### VIP Accounts Watchlist
```csv
AccountName,Priority,NotificationEmail
serviceaccount1,High,security-team@company.com
admin-backup,Critical,soc@company.com
```

Use in queries:
```kql
let ApprovedSystems = _GetWatchlist('ApprovedNTLMSystems');
SecurityEvent
| where EventID == 4624
| extend PackageName = tostring(parse_json(EventData).PackageName)
| where PackageName contains "NTLM"
| join kind=leftanti ApprovedSystems on $left.Computer == $right.SystemName
| // Alert only for non-approved systems
```

## Step 8: Configure Threat Intelligence Integration

Enable threat intelligence connector for enrichment:

1. Navigate to **Data connectors**
2. Enable "Threat Intelligence - TAXII"
3. Configure Microsoft Threat Intelligence feed
4. Correlate NTLM events with known malicious IPs

## Monitoring and Maintenance

### Daily Tasks
- Review NTLM incidents in Sentinel
- Check workbook for trend analysis
- Investigate any NTLMv1 alerts

### Weekly Tasks
- Review and update watchlists
- Analyze top NTLM sources
- Report progress to stakeholders

### Monthly Tasks
- Review and tune analytics rules
- Update automation playbooks
- Validate data collection coverage

## Best Practices

1. **Start with Monitoring** - Don't block immediately; understand your baseline
2. **Use Staging** - Test rules in a dev/test environment first
3. **Document Exceptions** - Maintain clear documentation for approved NTLM usage
4. **Regular Reviews** - Schedule monthly reviews of NTLM usage trends
5. **Gradual Hardening** - Progressively restrict NTLM as you remediate systems

## Troubleshooting

### No Events in Sentinel
- Verify Log Analytics agent is connected
- Check Data Collection Rule configuration
- Ensure NTLM auditing is enabled in Group Policy
- Verify firewall allows traffic to Azure

### High False Positive Rate
- Refine analytics rules with additional filters
- Update watchlists with known legitimate systems
- Adjust thresholds based on environment

### Performance Issues
- Optimize KQL queries with materialized views
- Adjust query time ranges
- Use summary tables for historical data

## Resources

- [Microsoft Sentinel Documentation](https://docs.microsoft.com/azure/sentinel/)
- [Insecure Protocols Workbook Guide](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/azure-sentinel-insecure-protocols-workbook-implementation-guide/1197564)
- [Analytics Rules Best Practices](https://docs.microsoft.com/azure/sentinel/best-practices-analytics-rules)
