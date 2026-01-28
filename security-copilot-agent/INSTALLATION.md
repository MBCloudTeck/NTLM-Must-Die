# Installation Guide - NTLM Must Die Security Copilot Agent

## Prerequisites

Before installing the NTLM Must Die Security Copilot Agent, ensure you have:

### Required
- ✅ Microsoft Security Copilot license (required for custom agents)
- ✅ Microsoft Sentinel workspace with data ingestion configured
- ✅ Windows Security Event logs forwarded to Sentinel
- ✅ Appropriate RBAC permissions:
  - Security Copilot Administrator or Contributor
  - Sentinel Reader or Contributor
  - Log Analytics Reader

### Recommended
- ✅ Microsoft Defender for Identity configured
- ✅ Microsoft Defender for Endpoint deployed
- ✅ NTLM auditing enabled via Group Policy
- ✅ Windows Event Forwarding configured for centralized logging

## Step-by-Step Installation

### Step 1: Enable NTLM Auditing

Before using the agent, enable NTLM auditing to generate the necessary logs:

#### Using Group Policy (Recommended)
1. Open Group Policy Management Console (GPMC)
2. Create or edit a GPO linked to your domain
3. Navigate to:
   ```
   Computer Configuration > 
   Windows Settings > 
   Security Settings > 
   Local Policies > 
   Security Options
   ```
4. Configure the following policies:
   - **Network security: Restrict NTLM: Audit NTLM authentication in this domain**
     - Set to: `Enable all`
   - **Network security: Restrict NTLM: Audit Incoming NTLM Traffic**
     - Set to: `Enable auditing for all accounts`
   - **Audit Logon Events**
     - Set to: `Success and Failure`

5. Force Group Policy update on domain controllers:
   ```powershell
   gpupdate /force
   ```

#### Using PowerShell Script
Alternatively, use the provided automation script:

```powershell
# Download and run the NTLM auditing script
cd /path/to/NTLM-Must-Die/NTLM resources/PowerShell
.\Enable-NTLMAuditing.ps1
```

### Step 2: Configure Log Collection

#### Configure Windows Security Events in Sentinel

1. **Open Microsoft Sentinel**
   - Navigate to your Azure Portal
   - Go to Microsoft Sentinel
   - Select your workspace

2. **Configure Data Connector**
   - Go to **Configuration** > **Data connectors**
   - Search for "Security Events via AMA" or "Windows Security Events"
   - Click **Open connector page**
   - Follow the wizard to:
     - Install Azure Monitor Agent (AMA) on domain controllers
     - Create Data Collection Rule (DCR)
     - Select event types to collect (select "All Events" or at minimum "Common")

3. **Verify Data Ingestion**
   Run this KQL query in Sentinel Logs:
   ```kql
   SecurityEvent
   | where TimeGenerated > ago(1h)
   | where EventID in (4624, 4776)
   | take 10
   ```
   
   If you see results, data collection is working.

### Step 3: Download the Agent Manifest

#### Option A: Clone the Repository
```bash
git clone https://github.com/MBCloudTeck/NTLM-Must-Die.git
cd NTLM-Must-Die/security-copilot-agent
```

#### Option B: Download Directly
```bash
wget https://raw.githubusercontent.com/MBCloudTeck/NTLM-Must-Die/main/security-copilot-agent/manifest.json
```

#### Option C: Manual Download
1. Visit: https://github.com/MBCloudTeck/NTLM-Must-Die
2. Navigate to `security-copilot-agent/manifest.json`
3. Click "Raw" and save the file

### Step 4: Install the Agent in Security Copilot

> **Note**: Custom agent installation in Security Copilot is done through the Security Copilot portal. The exact steps may vary based on your Security Copilot version.

#### General Process:

1. **Open Security Copilot Portal**
   - Navigate to https://securitycopilot.microsoft.com
   - Sign in with your credentials

2. **Access Plugin Management**
   - Click on **Settings** (gear icon)
   - Select **Plugins** or **Custom Agents**
   - Click **Add Plugin** or **Import Agent**

3. **Upload Manifest**
   - Click **Upload** or **Browse**
   - Select the `manifest.json` file
   - Review agent capabilities and permissions
   - Click **Import** or **Add**

4. **Configure Permissions**
   - Grant the agent access to your Microsoft Sentinel workspace
   - Ensure it has read permissions for Log Analytics
   - Configure any API connections if prompted

5. **Enable the Agent**
   - Toggle the agent to **Enabled** status
   - The agent should now appear in your available plugins list

### Step 5: Verify Installation

Test the agent with simple queries:

1. **Test Basic Connectivity**
   ```
   NTLM agent, are you available?
   ```
   Expected response: Agent introduction and capabilities summary

2. **Test Sentinel Integration**
   ```
   NTLM agent, how many NTLM events occurred in the last 24 hours?
   ```
   Expected response: Query results from your Sentinel workspace

3. **Test Analysis Capability**
   ```
   NTLM agent, analyze my NTLM usage
   ```
   Expected response: Analysis summary with NTLMv1 and NTLMv2 breakdown

## Post-Installation Configuration

### Configure Alert Rules

Deploy the included detection rules to Microsoft Sentinel:

1. **Navigate to Analytics Rules**
   - Go to Microsoft Sentinel
   - Select **Analytics** > **Rule templates**
   - Click **Create** > **Scheduled query rule**

2. **Import NTLMv1 Detection Rule**
   ```bash
   # Upload the YAML file
   cd /path/to/NTLM-Must-Die/NTLM resources/DetectionRules
   # Import sentinel-ntlmv1-detection.yaml via Sentinel portal
   ```

3. **Import Other Rules**
   - `sentinel-ntlm-relay-attack.yaml`
   - `sentinel-privileged-ntlm.yaml`
   - `sentinel-anomalous-ntlm.yaml`

### Deploy Insecure Protocols Workbook

1. **Open Microsoft Sentinel**
2. Go to **Workbooks** > **Templates**
3. Search for "Insecure Protocols"
4. Click **Save** to deploy to your workspace
5. View the workbook to see NTLM usage visualizations

### Configure Microsoft Defender for Identity

1. **Enable NTLM Detection**
   - Open Microsoft Defender for Identity portal
   - Go to **Settings** > **Detection**
   - Enable NTLM-related detections:
     - NTLM Relay Attack
     - Suspicious NTLM Authentication
     - Account Enumeration

2. **Configure Service Account Discovery**
   - Enable **Service Account Discovery** module
   - This helps identify service accounts using NTLM

## Troubleshooting Installation

### Issue: Agent Not Appearing in Security Copilot

**Possible Causes:**
- Insufficient permissions
- Manifest file format error
- Security Copilot license not active

**Solutions:**
1. Verify your Security Copilot license:
   ```powershell
   # Check in Azure Portal > Licenses
   ```
2. Validate manifest JSON format:
   ```bash
   cat manifest.json | jq .
   ```
3. Check permissions: Ensure you have Copilot Administrator role

### Issue: Agent Can't Query Sentinel

**Possible Causes:**
- Missing Sentinel workspace connection
- Insufficient Log Analytics permissions
- Data connector not configured

**Solutions:**
1. Verify Sentinel data connector:
   ```kql
   SecurityEvent
   | where TimeGenerated > ago(1h)
   | summarize count() by EventID
   ```
2. Check agent permissions in Sentinel workspace
3. Ensure Azure Monitor Agent (AMA) is installed on DCs

### Issue: No NTLM Events Found

**Possible Causes:**
- NTLM auditing not enabled
- Log collection delay
- No actual NTLM traffic

**Solutions:**
1. Verify NTLM auditing is enabled:
   ```powershell
   # Check Group Policy settings
   gpresult /H gpreport.html
   # Open gpreport.html and search for "NTLM"
   ```
2. Check Event Viewer on a domain controller:
   ```
   Event Viewer > Windows Logs > Security
   Filter by Event IDs: 4624, 4776
   ```
3. Allow 5-10 minutes for log ingestion into Sentinel

### Issue: Query Timeouts

**Possible Causes:**
- Large data volume
- Insufficient workspace capacity
- Query optimization needed

**Solutions:**
1. Limit query time range:
   ```kql
   | where TimeGenerated > ago(1h)
   ```
2. Increase Sentinel workspace tier if needed
3. Use summary tables for historical analysis

## Upgrade Instructions

To upgrade to a newer version of the agent:

1. **Download New Manifest**
   ```bash
   wget https://raw.githubusercontent.com/MBCloudTeck/NTLM-Must-Die/main/security-copilot-agent/manifest.json -O manifest-new.json
   ```

2. **Remove Old Agent**
   - Go to Security Copilot > Settings > Plugins
   - Select "NTLM Must Die Agent"
   - Click **Remove** or **Disable**

3. **Import New Manifest**
   - Follow Step 4 installation instructions
   - Upload the new `manifest-new.json`

4. **Verify Upgrade**
   - Test agent with a simple query
   - Check version: `NTLM agent, what is your version?`

## Uninstallation

To remove the agent:

1. **Open Security Copilot**
2. Go to **Settings** > **Plugins**
3. Find "NTLM Must Die Agent"
4. Click **Remove** or **Disable**
5. Confirm removal

**Note**: Uninstalling the agent does not affect:
- Sentinel detection rules (must be removed separately)
- Log collection configuration
- NTLM auditing Group Policy settings

## Next Steps

After successful installation:

1. **Run Initial Assessment**
   ```
   NTLM agent, analyze NTLM usage in my environment over the last 7 days
   ```

2. **Review Quick Start Guide**
   - See `QUICKSTART.md` for common usage scenarios

3. **Deploy Detection Rules**
   - Follow detection rule deployment in Post-Installation section

4. **Create Remediation Plan**
   ```
   NTLM agent, create a remediation plan for eliminating NTLMv1
   ```

5. **Schedule Regular Audits**
   - Weekly: Review NTLM usage trends
   - Monthly: Generate executive summary report

## Support

If you encounter issues during installation:

1. **Check Documentation**
   - Review `README.md` for capabilities and usage
   - See `TROUBLESHOOTING.md` for common issues

2. **Community Support**
   - GitHub Issues: https://github.com/MBCloudTeck/NTLM-Must-Die/issues
   - Discussions: https://github.com/MBCloudTeck/NTLM-Must-Die/discussions

3. **Microsoft Resources**
   - Security Copilot Documentation: https://learn.microsoft.com/en-us/copilot/security/
   - Sentinel Documentation: https://learn.microsoft.com/en-us/azure/sentinel/

## Additional Resources

- **Microsoft Learn**: [Agent Manifest Documentation](https://learn.microsoft.com/en-us/copilot/security/developer/agent-manifest)
- **NTLM Security Guidance**: [Microsoft NTLM Overview](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)
- **Sentinel Workbook**: [Insecure Protocols Implementation Guide](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/azure-sentinel-insecure-protocols-workbook-implementation-guide/1197564)
