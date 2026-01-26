# KQL Queries for NTLM Detection and Monitoring

This folder contains Kusto Query Language (KQL) queries for detecting and monitoring NTLM usage in your environment using Microsoft Sentinel, Azure Monitor, and other Azure services.

## Query Categories

### Detection Queries
- `detect-ntlmv1-usage.kql` - Identify NTLMv1 authentication attempts
- `detect-ntlm-authentication.kql` - Monitor all NTLM authentication events
- `detect-suspicious-ntlm-patterns.kql` - Identify anomalous NTLM usage patterns

### Analysis Queries
- `analyze-ntlm-by-source.kql` - Break down NTLM usage by source system
- `analyze-ntlm-by-account.kql` - Identify accounts using NTLM
- `analyze-ntlm-trends.kql` - Track NTLM usage over time

### Reporting Queries
- `report-ntlm-summary.kql` - Generate executive summary of NTLM usage
- `report-legacy-protocol-usage.kql` - Comprehensive legacy protocol report

## Usage

These queries are designed to work with:
- Microsoft Sentinel
- Azure Monitor Logs
- Log Analytics Workspaces

To use these queries:
1. Open your Log Analytics workspace or Microsoft Sentinel
2. Navigate to Logs
3. Copy and paste the query content
4. Adjust the time range as needed
5. Run the query

## Prerequisites

Ensure you have:
- Windows Security Event logs forwarded to your workspace
- NTLM auditing enabled via Group Policy
- Appropriate RBAC permissions to query the workspace

## Event IDs Referenced

- **4776** - Credential Validation (Domain Controller)
- **4624** - Account Logon (Shows NTLM version)
- **8001-8004** - NTLM Operational Events
- **4020/4032** - Enhanced NTLM events (Windows 11 24H2, Server 2025+)
