# Azure Arc Documentation and Resources

This folder contains documentation and resources for using Azure Arc to manage and secure hybrid environments, with a specific focus on NTLM monitoring and authentication hardening.

## What is Azure Arc?

Azure Arc extends Azure management and services to any infrastructure, including on-premises, multi-cloud, and edge environments. It enables:
- Centralized management of servers, Kubernetes clusters, and data services
- Azure Policy enforcement across hybrid environments
- Azure Monitor integration for comprehensive logging
- Microsoft Defender for Cloud security insights

## Contents

### Setup and Configuration
- `setup-guide.md` - Step-by-step guide to set up Azure Arc
- `onboard-servers.md` - How to onboard Windows/Linux servers to Azure Arc
- `configure-monitoring.md` - Configure monitoring and log collection

### Security and Compliance
- `security-policies.md` - Azure Policy configurations for NTLM hardening
- `compliance-tracking.md` - Track NTLM deprecation compliance across hybrid infrastructure

### Integration Guides
- `sentinel-integration.md` - Integrate Azure Arc with Microsoft Sentinel
- `defender-integration.md` - Enable Microsoft Defender for hybrid servers
- `log-analytics.md` - Configure Log Analytics for NTLM auditing

### Best Practices
- `best-practices.md` - Azure Arc best practices for authentication security
- `troubleshooting.md` - Common issues and solutions

## Why Use Azure Arc for NTLM Monitoring?

Azure Arc enables you to:
1. **Centralize Monitoring** - Collect NTLM audit logs from on-premises servers in Azure
2. **Enforce Policies** - Deploy NTLM hardening policies across all environments
3. **Track Compliance** - Monitor NTLM deprecation progress in a unified dashboard
4. **Respond to Threats** - Use Microsoft Sentinel for NTLM-based attack detection

## Prerequisites

- Azure subscription
- Azure Arc-enabled servers (requires Azure Connected Machine agent)
- Log Analytics workspace
- Appropriate Azure RBAC permissions

## Getting Started

1. Start with `setup-guide.md` to configure Azure Arc
2. Follow `onboard-servers.md` to connect your infrastructure
3. Configure monitoring using `configure-monitoring.md`
4. Apply security policies from `security-policies.md`
5. Integrate with Sentinel using `sentinel-integration.md`
