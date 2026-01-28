# Azure Arc Setup Guide

This guide walks you through setting up Azure Arc for monitoring and managing NTLM authentication across hybrid environments.

## Overview

Azure Arc enables centralized management and monitoring of servers regardless of where they're hosted. For NTLM monitoring, Azure Arc provides:
- Centralized log collection
- Policy enforcement
- Security monitoring via Microsoft Defender and Sentinel
- Compliance tracking

## Prerequisites

Before you begin, ensure you have:
- **Azure subscription** with appropriate permissions
- **Resource Group** where Arc resources will be created
- **Log Analytics workspace** for log collection
- **Admin access** to servers you want to onboard
- **Network connectivity** - Servers must reach Azure endpoints (*.azure-automation.net, *.guestconfiguration.azure.com, etc.)

## Step 1: Prepare Your Azure Environment

### Create a Resource Group
```bash
az group create --name "rg-arc-ntlm-monitoring" --location "eastus"
```

### Create Log Analytics Workspace
```bash
az monitor log-analytics workspace create \
  --resource-group "rg-arc-ntlm-monitoring" \
  --workspace-name "law-ntlm-monitoring" \
  --location "eastus"
```

### Get Workspace ID and Key
```bash
# Get Workspace ID
az monitor log-analytics workspace show \
  --resource-group "rg-arc-ntlm-monitoring" \
  --workspace-name "law-ntlm-monitoring" \
  --query customerId -o tsv

# Get Workspace Key
az monitor log-analytics workspace get-shared-keys \
  --resource-group "rg-arc-ntlm-monitoring" \
  --workspace-name "law-ntlm-monitoring" \
  --query primarySharedKey -o tsv
```

## Step 2: Install Azure Arc on Servers

### Windows Servers

Download and run the onboarding script:

```powershell
# Download the installation script
Invoke-WebRequest -Uri "https://aka.ms/azcmagent-windows" -OutFile "AzureConnectedMachineAgent.msi"

# Install the agent
msiexec /i AzureConnectedMachineAgent.msi /quiet

# Connect to Azure Arc
azcmagent connect `
  --resource-group "rg-arc-ntlm-monitoring" `
  --tenant-id "<YOUR_TENANT_ID>" `
  --location "eastus" `
  --subscription-id "<YOUR_SUBSCRIPTION_ID>" `
  --cloud "AzureCloud"
```

### Linux Servers

```bash
# Download and install the agent
wget https://aka.ms/azcmagent-linux -O ~/install_linux_azcmagent.sh
bash ~/install_linux_azcmagent.sh

# Connect to Azure Arc
azcmagent connect \
  --resource-group "rg-arc-ntlm-monitoring" \
  --tenant-id "<YOUR_TENANT_ID>" \
  --location "eastus" \
  --subscription-id "<YOUR_SUBSCRIPTION_ID>" \
  --cloud "AzureCloud"
```

### Bulk Onboarding

For onboarding multiple servers, create a service principal:

```bash
az ad sp create-for-rbac \
  --name "Arc-Onboarding-SP" \
  --role "Azure Connected Machine Onboarding" \
  --scopes "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/rg-arc-ntlm-monitoring"
```

Then use the service principal credentials in your onboarding scripts.

## Step 3: Configure NTLM Auditing

### Enable NTLM Auditing via Group Policy

On your domain controllers and member servers, enable NTLM auditing:

1. **Domain Controller Configuration**:
   - Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options
   - Enable "Network security: Restrict NTLM: Audit NTLM authentication in this domain" → "Enable all"
   - Enable "Network security: Restrict NTLM: Audit Incoming NTLM Traffic" → "Enable auditing for all accounts"

2. **Member Server Configuration**:
   - Same path as above
   - Enable "Network security: Restrict NTLM: Audit Incoming NTLM Traffic" → "Enable auditing for all accounts"

3. **Advanced Audit Policy**:
   - Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration
   - Enable "Audit Logon" → Success and Failure
   - Enable "Audit Account Logon" → Success and Failure

### Enable NTLM Operational Logging

```powershell
# Enable NTLM Operational Event Log
wevtutil sl Microsoft-Windows-NTLM/Operational /e:true

# Increase log size
wevtutil sl Microsoft-Windows-NTLM/Operational /ms:104857600
```

## Step 4: Install Log Analytics Agent

### Via Azure Portal
1. Navigate to your Arc-enabled server in Azure Portal
2. Click "Extensions" → "Add"
3. Select "Log Analytics Agent for Windows/Linux"
4. Provide your Log Analytics Workspace ID and Key
5. Click "Create"

### Via PowerShell (Windows)
```powershell
# Define parameters
$workspaceId = "<YOUR_WORKSPACE_ID>"
$workspaceKey = "<YOUR_WORKSPACE_KEY>"

# Install extension
az connectedmachine extension create `
  --name "MicrosoftMonitoringAgent" `
  --machine-name "<SERVER_NAME>" `
  --resource-group "rg-arc-ntlm-monitoring" `
  --type "MicrosoftMonitoringAgent" `
  --publisher "Microsoft.EnterpriseCloud.Monitoring" `
  --settings "{'workspaceId':'$workspaceId'}" `
  --protected-settings "{'workspaceKey':'$workspaceKey'}"
```

### Via Bash (Linux)
```bash
az connectedmachine extension create \
  --name "OmsAgentForLinux" \
  --machine-name "<SERVER_NAME>" \
  --resource-group "rg-arc-ntlm-monitoring" \
  --type "OmsAgentForLinux" \
  --publisher "Microsoft.EnterpriseCloud.Monitoring" \
  --settings "{'workspaceId':'$WORKSPACE_ID'}" \
  --protected-settings "{'workspaceKey':'$WORKSPACE_KEY'}"
```

## Step 5: Configure Data Collection

### Create Data Collection Rule

```bash
az monitor data-collection rule create \
  --name "dcr-ntlm-events" \
  --resource-group "rg-arc-ntlm-monitoring" \
  --location "eastus" \
  --data-flows "[{\"streams\":[\"Microsoft-SecurityEvent\"],\"destinations\":[\"law-ntlm-monitoring\"]}]" \
  --data-sources "{\"windowsEventLogs\":[{\"name\":\"security-events\",\"streams\":[\"Microsoft-SecurityEvent\"],\"xPathQueries\":[\"Security!*[System[(EventID=4624 or EventID=4776)]]\",\"Microsoft-Windows-NTLM/Operational!*\"]}]}"
```

## Step 6: Verify Setup

### Check Agent Status
```powershell
# Windows
azcmagent show

# Check if events are being collected
Get-WinEvent -LogName "Microsoft-Windows-NTLM/Operational" -MaxEvents 10
```

### Query Logs in Azure
```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID in (4624, 4776)
| take 10
```

## Next Steps

- Configure Microsoft Sentinel integration: See `sentinel-integration.md`
- Apply Azure Policies for NTLM hardening: See `security-policies.md`
- Set up alerts: See `configure-monitoring.md`

## Troubleshooting

### Agent Connection Issues
```powershell
# Check agent connectivity
azcmagent check

# View agent logs
Get-Content "C:\ProgramData\AzureConnectedMachineAgent\Log\himds.log" -Tail 50
```

### Log Collection Issues
- Verify Log Analytics workspace connection
- Check Data Collection Rule association
- Ensure NTLM auditing is enabled in Group Policy
- Verify firewall rules allow outbound HTTPS to Azure endpoints

## Resources

- [Azure Arc Documentation](https://docs.microsoft.com/azure/azure-arc/)
- [Connected Machine Agent Overview](https://docs.microsoft.com/azure/azure-arc/servers/agent-overview)
- [Log Analytics Agent](https://docs.microsoft.com/azure/azure-monitor/agents/log-analytics-agent)
