<#
.SYNOPSIS
    Enables NTLM auditing via Group Policy.

.DESCRIPTION
    This script enables comprehensive NTLM auditing across your environment
    by configuring Group Policy settings for NTLM event logging.

.PARAMETER TargetOU
    The Organizational Unit to apply the policy. If not specified, applies to domain level.

.PARAMETER PolicyName
    Name for the Group Policy Object. Default is "NTLM Auditing Policy".

.PARAMETER WhatIf
    Shows what would be changed without making actual changes.

.EXAMPLE
    .\Enable-NTLMAuditing.ps1 -TargetOU "OU=Servers,DC=contoso,DC=com"

.EXAMPLE
    .\Enable-NTLMAuditing.ps1 -WhatIf

.NOTES
    Requires:
    - PowerShell 5.1 or later
    - Group Policy module
    - Domain Admin privileges
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [string]$TargetOU,
    
    [Parameter(Mandatory=$false)]
    [string]$PolicyName = "NTLM Auditing Policy",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

#Requires -Modules GroupPolicy, ActiveDirectory
#Requires -RunAsAdministrator

Import-Module GroupPolicy
Import-Module ActiveDirectory

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NTLM Auditing Configuration Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($WhatIf -or $PSCmdlet.ShouldProcess("NTLM Auditing", "Enable")) {
    
    Write-Host "[*] Configuring NTLM Auditing..." -ForegroundColor Yellow
    
    # Get or Create GPO
    try {
        $GPO = Get-GPO -Name $PolicyName -ErrorAction Stop
        Write-Host "[+] Using existing GPO: $PolicyName" -ForegroundColor Green
    } catch {
        if (-not $WhatIf) {
            $GPO = New-GPO -Name $PolicyName
            Write-Host "[+] Created new GPO: $PolicyName" -ForegroundColor Green
        } else {
            Write-Host "[WhatIf] Would create GPO: $PolicyName" -ForegroundColor Yellow
        }
    }
    
    if (-not $WhatIf) {
        # Configure Security Options for NTLM Auditing
        Write-Host "[*] Configuring Security Options..." -ForegroundColor Yellow
        
        # Network security: Restrict NTLM: Audit NTLM authentication in this domain
        Set-GPRegistryValue -Name $PolicyName -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
            -ValueName "AuditNTLMInDomain" -Type DWord -Value 7 | Out-Null
        
        # Network security: Restrict NTLM: Audit Incoming NTLM Traffic
        Set-GPRegistryValue -Name $PolicyName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
            -ValueName "AuditReceivingNTLMTraffic" -Type DWord -Value 2 | Out-Null
        
        # Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers
        Set-GPRegistryValue -Name $PolicyName -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
            -ValueName "RestrictSendingNTLMTraffic" -Type DWord -Value 1 | Out-Null
        
        Write-Host "[+] Security Options configured" -ForegroundColor Green
        
        # Enable Advanced Audit Policy
        Write-Host "[*] Configuring Advanced Audit Policies..." -ForegroundColor Yellow
        
        $AuditSettings = @"
Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
,$env:COMPUTERNAME,Logon/Logoff,Logon,{0cce9215-69ae-11d9-bed3-505054503030},Success and Failure,No Auditing
,$env:COMPUTERNAME,Account Logon,Credential Validation,{0cce923f-69ae-11d9-bed3-505054503030},Success and Failure,No Auditing
"@
        
        # Link GPO to OU or Domain
        Write-Host "[*] Linking GPO..." -ForegroundColor Yellow
        
        if ($TargetOU) {
            $LinkPath = $TargetOU
        } else {
            $Domain = Get-ADDomain
            $LinkPath = $Domain.DistinguishedName
        }
        
        try {
            New-GPLink -Name $PolicyName -Target $LinkPath -LinkEnabled Yes -ErrorAction Stop | Out-Null
            Write-Host "[+] GPO linked to: $LinkPath" -ForegroundColor Green
        } catch {
            if ($_.Exception.Message -like "*already linked*") {
                Write-Host "[+] GPO already linked to: $LinkPath" -ForegroundColor Green
            } else {
                throw $_
            }
        }
        
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Configuration Complete!" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next Steps:" -ForegroundColor Cyan
        Write-Host "1. Run 'gpupdate /force' on target systems" -ForegroundColor White
        Write-Host "2. Wait for events to populate (may take 1-2 hours)" -ForegroundColor White
        Write-Host "3. Check Event Viewer: Security Log (Event IDs 4624, 4776)" -ForegroundColor White
        Write-Host "4. Check Event Viewer: NTLM Operational Log" -ForegroundColor White
        Write-Host ""
        
    } else {
        Write-Host ""
        Write-Host "[WhatIf] Would configure the following:" -ForegroundColor Yellow
        Write-Host "  - Create/Update GPO: $PolicyName" -ForegroundColor White
        Write-Host "  - Enable NTLM domain auditing (Level: All)" -ForegroundColor White
        Write-Host "  - Enable NTLM incoming traffic auditing" -ForegroundColor White
        Write-Host "  - Configure NTLM restrictions (Audit mode)" -ForegroundColor White
        Write-Host "  - Link GPO to: $(if($TargetOU){$TargetOU}else{'Domain Root'})" -ForegroundColor White
        Write-Host ""
    }
    
} else {
    Write-Host "[*] Operation cancelled" -ForegroundColor Yellow
}

Write-Host "Script execution completed." -ForegroundColor Green
