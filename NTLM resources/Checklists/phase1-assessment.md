# Phase 1: NTLM Usage Assessment Checklist

**Objective**: Understand current NTLM usage across your environment before making changes.

**Duration**: 2-4 weeks

**Risk Level**: Low (read-only assessment)

---

## Prerequisites

- [ ] Executive sponsorship secured
- [ ] Budget allocated for project
- [ ] Team members identified and available
- [ ] Access to domain controllers and member servers
- [ ] SIEM/logging infrastructure in place (or plan to set up)

---

## 1. Environment Documentation

- [ ] Document current Active Directory structure
  - [ ] List all domains and domain controllers
  - [ ] Identify forest functional level
  - [ ] Document trust relationships
- [ ] Inventory Windows systems
  - [ ] Count Windows servers by OS version
  - [ ] Count Windows workstations by OS version
  - [ ] Identify end-of-life systems
- [ ] Identify critical applications
  - [ ] List line-of-business applications
  - [ ] Document authentication requirements
  - [ ] Identify legacy applications

---

## 2. Enable NTLM Auditing

- [ ] Configure Group Policy for NTLM auditing
  - [ ] Enable "Network security: Restrict NTLM: Audit NTLM authentication in this domain"
  - [ ] Enable "Network security: Restrict NTLM: Audit Incoming NTLM Traffic"
  - [ ] Configure Advanced Audit Policy for Logon/Account Logon events
- [ ] Enable NTLM Operational log
  - [ ] On domain controllers
  - [ ] On member servers
  - [ ] On workstations (sample set)
- [ ] Verify Group Policy application
  - [ ] Run gpupdate /force on test systems
  - [ ] Check Group Policy Results
  - [ ] Verify events are being logged

**Script**: `../PowerShell/Enable-NTLMAuditing.ps1`

---

## 3. Configure Log Collection

### If Using Azure Arc + Sentinel
- [ ] Set up Azure Arc (see `../AzureArc/setup-guide.md`)
- [ ] Configure Log Analytics workspace
- [ ] Deploy Log Analytics agent to servers
- [ ] Configure Data Collection Rules for Security events
- [ ] Enable Microsoft Sentinel
- [ ] Deploy Insecure Protocols Workbook

### If Using On-Premises SIEM
- [ ] Configure Windows Event Forwarding (WEF)
- [ ] Set up event collector servers
- [ ] Configure SIEM to ingest Windows Security events
- [ ] Create NTLM-specific dashboards

### If Using Basic Collection
- [ ] Increase Security event log size (at least 100 MB)
- [ ] Configure event log forwarding to central server
- [ ] Set up basic PowerShell monitoring scripts

---

## 4. Baseline Collection Period

- [ ] Wait 7-14 days for representative data
- [ ] Ensure collection covers:
  - [ ] Normal business hours
  - [ ] After-hours/batch processing
  - [ ] Weekend activity
  - [ ] Month-end processing (if applicable)
- [ ] Verify data is being collected
  - [ ] Check domain controllers for event 4776
  - [ ] Check member servers for event 4624
  - [ ] Check NTLM Operational logs

---

## 5. Run Initial Analysis

- [ ] Execute NTLM usage audit script
  - Script: `../PowerShell/Audit-NTLMUsage.ps1`
- [ ] Run KQL queries (if using Sentinel)
  - [ ] NTLMv1 detection: `../KQL/detect-ntlmv1-usage.kql`
  - [ ] Overall NTLM usage: `../KQL/detect-ntlm-authentication.kql`
  - [ ] By source: `../KQL/analyze-ntlm-by-source.kql`
  - [ ] By account: `../KQL/analyze-ntlm-by-account.kql`
- [ ] Generate executive summary
  - Query: `../KQL/report-ntlm-summary.kql`

---

## 6. Identify NTLM Sources

### Systems
- [ ] List top 20 systems generating NTLM traffic
- [ ] Categorize by:
  - [ ] Domain controllers
  - [ ] Application servers
  - [ ] File servers
  - [ ] Workstations
  - [ ] Network devices (printers, NAS, etc.)
  - [ ] Legacy systems
- [ ] For each top source:
  - [ ] Document owner/contact
  - [ ] Document business purpose
  - [ ] Identify OS version
  - [ ] Note any constraints (vendor support, legacy app, etc.)

### Accounts
- [ ] List top 20 accounts using NTLM
- [ ] Categorize by:
  - [ ] Service accounts
  - [ ] User accounts
  - [ ] Computer accounts
  - [ ] Administrative accounts
- [ ] For each account:
  - [ ] Document purpose
  - [ ] Identify owner
  - [ ] Note if privileged
  - [ ] Check if in Protected Users group (shouldn't be using NTLM)

---

## 7. NTLMv1 Analysis (Critical)

- [ ] Identify ALL NTLMv1 usage (zero tolerance)
- [ ] For each NTLMv1 source:
  - [ ] Document system name
  - [ ] Identify OS version
  - [ ] Identify application/service
  - [ ] Contact owner
  - [ ] Create remediation plan
  - [ ] Set deadline (should be immediate)
- [ ] Verify NTLMv1 sources:
  - [ ] Confirm with system owners
  - [ ] Test if system can use NTLMv2
  - [ ] Check for firmware/software updates

---

## 8. Application Assessment

For each critical application:
- [ ] Document authentication method
- [ ] Check with vendor about Kerberos support
- [ ] Review application documentation
- [ ] Test Kerberos authentication in dev/test
- [ ] Document any NTLM dependencies
- [ ] Create migration plan if needed

---

## 9. Risk Assessment

- [ ] Calculate NTLMv1 risk score
  - Critical if any NTLMv1 found
- [ ] Calculate NTLMv2 risk score
  - Based on volume and exposed systems
- [ ] Identify high-risk patterns:
  - [ ] NTLM from privileged accounts
  - [ ] NTLM to/from DMZ
  - [ ] NTLM from internet-facing systems
  - [ ] Service accounts using NTLM
- [ ] Document vulnerable systems
- [ ] Assess attack surface

---

## 10. Documentation and Reporting

- [ ] Create assessment report including:
  - [ ] Executive summary
  - [ ] Current state analysis
  - [ ] NTLMv1 findings (critical section)
  - [ ] NTLMv2 usage patterns
  - [ ] Risk assessment
  - [ ] Top 20 NTLM sources
  - [ ] Top 20 NTLM accounts
  - [ ] Application dependencies
  - [ ] Recommendations
- [ ] Create remediation roadmap
  - [ ] Quick wins (0-30 days)
  - [ ] Medium-term (30-90 days)
  - [ ] Long-term (90+ days)
- [ ] Identify required resources
  - [ ] People
  - [ ] Budget
  - [ ] Tools

---

## 11. Stakeholder Communication

- [ ] Brief executive leadership
  - [ ] Present risk assessment
  - [ ] Request continued support
  - [ ] Identify any concerns
- [ ] Meet with application owners
  - [ ] Share findings
  - [ ] Discuss remediation plans
  - [ ] Set expectations
- [ ] Coordinate with infrastructure teams
  - [ ] Share technical findings
  - [ ] Discuss implementation approach
  - [ ] Identify potential issues

---

## Success Criteria

- [ ] Comprehensive inventory of NTLM usage completed
- [ ] All NTLMv1 sources identified and owners contacted
- [ ] Risk assessment completed and accepted
- [ ] Remediation roadmap created and approved
- [ ] Stakeholders informed and aligned
- [ ] Ready to proceed to Phase 2 (Planning)

---

## Next Steps

Once this checklist is complete:
1. Review findings with leadership
2. Get approval to proceed
3. Move to Phase 2: Planning (`phase2-planning.md`)

---

## Estimated Effort

- Initial setup: 8-16 hours
- Data collection period: 2-4 weeks (passive)
- Analysis: 16-40 hours
- Reporting: 8-16 hours
- **Total active effort**: 32-72 hours over 2-4 weeks

---

## Notes

_Use this section to document environment-specific findings, decisions, or issues_
