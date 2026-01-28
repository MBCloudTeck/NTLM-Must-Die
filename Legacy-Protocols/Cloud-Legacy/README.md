# Cloud Legacy Authentication

## Overview

Cloud legacy authentication refers to older authentication methods that don't support modern security features like multi-factor authentication (MFA), Conditional Access, and risk-based authentication. In Microsoft 365 and Azure AD, these protocols pose significant security risks.

## Types of Cloud Legacy Authentication

### 1. Basic Authentication

**What it is:**
- Simple username/password sent with each request
- Base64 encoded (NOT encrypted)
- No token caching or modern auth flow

**Used by:**
- Exchange ActiveSync
- POP3/IMAP for email
- Exchange Web Services (EWS)
- Remote PowerShell
- SMTP AUTH

**Risk Level:** 🔴 Critical

### 2. Legacy OAuth Flows

**Examples:**
- Resource Owner Password Credentials (ROPC) flow
- Implicit grant flow (for SPAs)
- Device code flow (without modern controls)

**Risk Level:** 🟠 High

### 3. Legacy Protocol Clients

**Client App Types (Azure AD):**
- "Other clients" - Legacy email clients
- "Exchange ActiveSync" - Old mobile email
- "Authenticated SMTP" - Direct SMTP submission
- "Autodiscover" - Legacy Exchange discovery

## Why Cloud Legacy Auth is Dangerous

### No MFA Support
```
User → Basic Auth → Service
        ↓
   Just username/password
   No second factor possible
   Stolen creds = full access
```

### No Conditional Access
- Cannot enforce location-based policies
- Cannot enforce device compliance
- Cannot enforce risk-based sign-in policies
- Cannot enforce session controls

### No Modern Security Features
- No risk detection
- No sign-in frequency controls
- No persistent browser sessions
- Limited audit logging

### Common Attack Pattern
```
1. Attacker obtains credentials (phishing, breach, etc.)
2. Attacker uses legacy protocol (bypasses MFA)
3. Automated access to mailbox/data
4. Data exfiltration or BEC attack
5. Often goes undetected for months
```

## Real-World Impact

### Business Email Compromise (BEC)
```
Scenario: Attacker uses stolen credentials with IMAP

Step 1: Access mailbox via IMAP (no MFA)
Step 2: Create inbox rule to hide emails
Step 3: Monitor for financial transactions
Step 4: Send fraudulent payment requests
Step 5: Delete sent items and rules
Impact: Average loss $50,000-$2M per incident
```

### Data Exfiltration
```
Scenario: Insider threat uses SMTP AUTH

Step 1: Configure mail client with SMTP AUTH
Step 2: Bulk export sensitive emails
Step 3: Forward to external email
Step 4: Delete mailbox audit logs
Impact: Compliance violation, data breach
```

## Detection

### Azure AD Sign-in Logs

**View Legacy Auth in Azure Portal:**
```
Azure Active Directory
 → Sign-ins
  → Add filters:
   • Client App: "Other clients", "Exchange ActiveSync", etc.
   • Status: All
   • Date: Last 30 days
```

**Common Client App Values:**
- `Authenticated SMTP` - Direct SMTP authentication
- `Autodiscover` - Legacy Exchange autodiscover
- `Exchange ActiveSync` - Mobile email (legacy)
- `Exchange Web Services` - EWS clients
- `IMAP4` - IMAP email access
- `Offline Address Book` - Legacy OAB download
- `Other clients` - Catch-all for other legacy protocols
- `POP3` - POP3 email access
- `Reporting Web Services` - Legacy SSRS
- `SMTP` - SMTP submission

### PowerShell Detection

```powershell
# Connect to Azure AD
Connect-AzureAD

# Get legacy auth sign-ins (last 30 days)
$startDate = (Get-Date).AddDays(-30).ToString('yyyy-MM-dd')
$signIns = Get-AzureADAuditSignInLogs -Filter "createdDateTime ge $startDate and clientAppUsed eq 'Other clients'"

# Group by user
$legacyUsers = $signIns | 
  Group-Object userPrincipalName | 
  Select-Object Count, Name | 
  Sort-Object Count -Descending

$legacyUsers | Export-Csv -Path "LegacyAuthUsers.csv" -NoTypeInformation
Write-Host "Found $($legacyUsers.Count) users using legacy auth" -ForegroundColor Yellow

# Group by client app
$legacyApps = $signIns | 
  Group-Object clientAppUsed | 
  Select-Object Count, Name | 
  Sort-Object Count -Descending

$legacyApps | Format-Table -AutoSize
```

### Microsoft Sentinel Detection

```kql
// Legacy authentication summary (last 30 days)
SigninLogs
| where TimeGenerated > ago(30d)
| where ClientAppUsed in ("Other clients", "Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "Authenticated SMTP")
| summarize 
    SignInCount = count(),
    UniqueUsers = dcount(UserPrincipalName),
    LastSeen = max(TimeGenerated)
    by ClientAppUsed, AppDisplayName
| order by SignInCount desc
```

```kql
// High-risk legacy auth patterns
SigninLogs
| where TimeGenerated > ago(7d)
| where ClientAppUsed == "Other clients" or ClientAppUsed has "Exchange ActiveSync"
| extend RiskScore = case(
    RiskLevelDuringSignIn == "high", 100,
    RiskLevelDuringSignIn == "medium", 50,
    ipv4_is_private(IPAddress) == false, 75,  // External IP
    LocationDetails.countryOrRegion !in ("US", "CA", "UK"), 60,  // Unusual location
    0
)
| where RiskScore > 50
| project TimeGenerated, UserPrincipalName, ClientAppUsed, IPAddress, 
          Location=LocationDetails.city, RiskScore, ResultType
| order by RiskScore desc, TimeGenerated desc
```

### Exchange Online Mailbox Status

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Check all mailboxes for legacy protocol settings
$mailboxes = Get-EXOMailbox -ResultSize Unlimited | 
  Get-EXOCASMailbox | 
  Where-Object {
    $_.ImapEnabled -eq $true -or 
    $_.PopEnabled -eq $true -or 
    $_.ActiveSyncEnabled -eq $true
  } | 
  Select-Object DisplayName, UserPrincipalName, 
                @{N='LegacyProtocols';E={
                  $protocols = @()
                  if ($_.ImapEnabled) { $protocols += 'IMAP' }
                  if ($_.PopEnabled) { $protocols += 'POP3' }
                  if ($_.ActiveSyncEnabled) { $protocols += 'ActiveSync' }
                  $protocols -join ', '
                }}

$mailboxes | Export-Csv -Path "MailboxesWithLegacy.csv" -NoTypeInformation
Write-Host "Found $($mailboxes.Count) mailboxes with legacy protocols enabled" -ForegroundColor Yellow
```

## Remediation Strategy

### Phase 1: Assessment (Weeks 1-2)

#### Step 1: Identify Legacy Auth Usage
```powershell
# Run this script to generate comprehensive report
$startDate = (Get-Date).AddDays(-30)
$report = @()

# Get all legacy auth sign-ins
$signIns = Get-AzureADAuditSignInLogs -Filter "createdDateTime ge $($startDate.ToString('yyyy-MM-dd'))"
$legacySignIns = $signIns | Where-Object {$_.clientAppUsed -ne "Mobile Apps and Desktop clients" -and $_.clientAppUsed -ne "Browser"}

foreach ($signIn in $legacySignIns) {
    $report += [PSCustomObject]@{
        Date = $signIn.createdDateTime
        User = $signIn.userPrincipalName
        ClientApp = $signIn.clientAppUsed
        App = $signIn.resourceDisplayName
        Location = $signIn.location.city
        IPAddress = $signIn.ipAddress
        Status = $signIn.status.errorCode
    }
}

$report | Export-Csv -Path "LegacyAuthReport-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation

# Summary statistics
Write-Host "`n=== Legacy Auth Summary ===" -ForegroundColor Cyan
Write-Host "Total legacy auth sign-ins: $($report.Count)" -ForegroundColor Yellow
Write-Host "Unique users: $(($report | Select-Object -Unique User).Count)" -ForegroundColor Yellow
Write-Host "Most common client app: $(($report | Group-Object ClientApp | Sort-Object Count -Descending | Select-Object -First 1).Name)" -ForegroundColor Yellow
```

#### Step 2: Identify Applications
```powershell
# Find which applications users are accessing with legacy auth
$apps = Get-AzureADAuditSignInLogs -Filter "createdDateTime ge $($startDate.ToString('yyyy-MM-dd'))" |
  Where-Object {$_.clientAppUsed -eq "Other clients"} |
  Group-Object resourceDisplayName |
  Select-Object Count, Name |
  Sort-Object Count -Descending

Write-Host "`n=== Applications Using Legacy Auth ===" -ForegroundColor Cyan
$apps | Format-Table -AutoSize

# Check if these apps support modern auth
# Update or configure apps to use OAuth 2.0
```

### Phase 2: Communication & Planning (Weeks 3-4)

#### Communicate with Users
```
Email Template:

Subject: Important: Email Client Update Required

Dear [User],

Our records show you're using an older email client that doesn't support 
modern security features like multi-factor authentication.

WHAT'S CHANGING:
Starting [DATE], basic authentication will be disabled for email access.

WHAT YOU NEED TO DO:
1. Update your email client to the latest version, OR
2. Use Outlook on the web (https://outlook.office365.com), OR
3. Contact IT for assistance: support@company.com

AFFECTED PROTOCOLS:
- POP3 and IMAP (older mail clients)
- Exchange ActiveSync (older mobile devices)

DEADLINE: [DATE]

Questions? Contact: support@company.com
```

#### Identify and Update Applications
```
For each application using legacy auth:

1. Check vendor documentation for OAuth 2.0 support
2. Update application to latest version
3. Reconfigure authentication settings
4. Test in non-production
5. Deploy to production
6. Verify modern auth is working
7. Remove from exception list
```

### Phase 3: Pilot Deployment (Weeks 5-8)

#### Deploy Conditional Access - Pilot Group
```
Azure AD → Security → Conditional Access → New Policy

Name: Block Legacy Auth - Pilot
Assignments:
  Users: [Pilot Group - e.g., IT Department]
  Cloud apps: All cloud apps
Conditions:
  Client apps: 
    ☑ Exchange ActiveSync clients
    ☑ Other clients
Grant:
  Block access
Session: (none)
Enable policy: On (after testing in Report-only mode)
```

#### Monitor Pilot Carefully
```kql
// Check if pilot users are blocked
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName in ("pilot-user1@contoso.com", "pilot-user2@contoso.com")  // List pilot users
| where ClientAppUsed in ("Other clients", "Exchange ActiveSync")
| where ResultType != 0  // Failed sign-ins
| project TimeGenerated, UserPrincipalName, ClientAppUsed, AppDisplayName, ResultType, ResultDescription
| order by TimeGenerated desc
```

### Phase 4: Production Deployment (Months 3-4)

#### Disable Basic Auth in Exchange Online
```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Disable basic auth for all protocols (organization-wide)
Get-OrganizationConfig | Set-OrganizationConfig -OAuth2ClientProfileEnabled $true

# Disable per protocol
Set-OrganizationConfig -SmtpClientAuthenticationDisabled $true

# Check status
Get-OrganizationConfig | Select-Object SmtpClientAuthenticationDisabled, OAuth2ClientProfileEnabled
```

#### Disable Legacy Protocols Per Mailbox (if needed)
```powershell
# Disable for specific users who haven't migrated yet
$users = Import-Csv "LegacyAuthUsers.csv"

foreach ($user in $users) {
    Set-CASMailbox -Identity $user.UserPrincipalName `
        -ImapEnabled $false `
        -PopEnabled $false `
        -ActiveSyncEnabled $false
    
    Write-Host "Disabled legacy protocols for $($user.UserPrincipalName)" -ForegroundColor Green
}
```

#### Deploy Conditional Access - All Users
```
Azure AD → Security → Conditional Access → New Policy

Name: Block Legacy Authentication - All Users
Assignments:
  Users: All users
  Exclude: 
    - Emergency access accounts (break glass)
    - Service accounts (temporary, review monthly)
  Cloud apps: All cloud apps
Conditions:
  Client apps:
    ☑ Exchange ActiveSync clients
    ☑ Other clients
Grant:
  Block access
Session: (none)
Enable policy: On
```

### Phase 5: Monitoring & Enforcement (Ongoing)

#### Daily Monitoring
```kql
// Alert on any legacy auth (should be zero)
SigninLogs
| where TimeGenerated > ago(1h)
| where ClientAppUsed in ("Other clients", "Exchange ActiveSync", "IMAP4", "POP3", "SMTP")
| where UserPrincipalName !in ("service-account@contoso.com")  // Exclude known exceptions
| project TimeGenerated, UserPrincipalName, ClientAppUsed, AppDisplayName, IPAddress
// Generate alert if Count > 0
```

#### Weekly Review
```powershell
# Generate weekly summary report
$weeklyReport = Get-AzureADAuditSignInLogs -Filter "createdDateTime ge $((Get-Date).AddDays(-7).ToString('yyyy-MM-dd'))" |
  Where-Object {$_.clientAppUsed -eq "Other clients"} |
  Group-Object userPrincipalName |
  Select-Object Count, Name |
  Sort-Object Count -Descending

if ($weeklyReport.Count -gt 0) {
    $weeklyReport | Format-Table -AutoSize
    # Send to security team for investigation
} else {
    Write-Host "No legacy auth detected this week!" -ForegroundColor Green
}
```

## Handling Exceptions

### Temporary Exception Process

**When Exception is Needed:**
- Legacy application cannot be updated immediately
- Third-party service requires basic auth
- Business-critical process during migration

**Exception Request Form:**
```
Requestor: [Name and email]
Business Justification: [Why exception is needed]
System/Application: [What needs exception]
Users Affected: [List of users]
Duration Requested: [Number of months]
Mitigation Measures: [How are you reducing risk?]
Migration Plan: [When will you remove this exception?]
Approval Required: Manager + CISO
```

**Implementing Exception:**
```
1. Create a group for exception users
   New-AzureADGroup -DisplayName "LegacyAuth-Exception-App1" -MailEnabled $false -SecurityEnabled $true

2. Add users to the group
   Add-AzureADGroupMember -ObjectId [GroupId] -RefObjectId [UserId]

3. Exclude group from Conditional Access policy
   Conditional Access → [Policy] → Assignments → Users → Exclude → [Group]

4. Set review date (3-6 months)
   
5. Monitor exception group usage
   
6. Review and remove when migration complete
```

## Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Legacy Auth Sign-ins | 0 (excluding exceptions) | Daily Sentinel query |
| Exception Count | <5% of users | Weekly review |
| Time to Remediate | <90 days | Project tracking |
| User Impact Incidents | 0 critical | Helpdesk tickets |
| MFA Adoption | 100% | Azure AD report |

## Common Issues & Solutions

### Issue: "App Password Required"
**Solution:** Update app to support OAuth 2.0 or use Microsoft Authenticator

### Issue: "Cannot Connect to Exchange"
**Solution:** Reconfigure Outlook profile to use modern authentication

### Issue: "ActiveSync Blocked on Mobile"
**Solution:** 
- Remove old account from mobile device
- Re-add account (will use OAuth 2.0)
- Or install Outlook mobile app

### Issue: "Third-Party App Doesn't Support OAuth"
**Solution:**
- Contact vendor for OAuth support
- Use app proxy/connector
- Create temporary exception with strict monitoring

## Additional Resources

### Microsoft Documentation
- [Deprecation of Basic Auth in Exchange Online](https://aka.ms/BasicAuthDeprecation)
- [Blocking Legacy Authentication](https://docs.microsoft.com/azure/active-directory/conditional-access/block-legacy-authentication)
- [Common Conditional Access Policies](https://docs.microsoft.com/azure/active-directory/conditional-access/concept-conditional-access-policy-common)

### Migration Guides
- [Outlook Configuration](https://support.microsoft.com/office/outlook-email-setup-6e27792a-9267-4aa4-8bb6-c84ef146101b)
- [Mobile Device Setup](https://support.microsoft.com/office/set-up-email-in-the-outlook-for-ios-mobile-app-b2de2161-cc1d-49ef-9ef9-81acd1c8e234)

---

**[← Back to Legacy Protocols](../README.md)** | **[Detection Guide →](../Detection-Monitoring/README.md)**
