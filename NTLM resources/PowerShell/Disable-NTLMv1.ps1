<#
.SYNOPSIS
    Disables NTLMv1 across the domain.

.DESCRIPTION
    This script creates and applies Group Policy to disable NTLMv1 authentication
    across your Active Directory domain. This is a critical security hardening step.

.PARAMETER WhatIf
    Shows what would be changed without making actual changes.

.PARAMETER Apply
    Apply the changes (required for actual execution).

.PARAMETER PolicyName
    Name for the Group Policy Object. Default is "Disable NTLMv1 Policy".

.PARAMETER TargetOU
    Organizational Unit to apply policy. If not specified, applies to domain level.

.EXAMPLE
    .\Disable-NTLMv1.ps1 -WhatIf

.EXAMPLE
    .\Disable-NTLMv1.ps1 -Apply

.EXAMPLE
    .\Disable-NTLMv1.ps1 -Apply -TargetOU "OU=Workstations,DC=contoso,DC=com"

.NOTES
    Requires:
    - PowerShell 5.1 or later
    - Group Policy module
    - Domain Admin privileges
    
    WARNING: This will disable NTLMv1. Ensure you have audited your environment
    and verified no systems require NTLMv1 before applying.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [switch]$Apply,
    
    [Parameter(Mandatory=$false)]
    [string]$PolicyName = "Disable NTLMv1 Policy",
    
    [Parameter(Mandatory=$false)]
    [string]$TargetOU
)

#Requires -Modules GroupPolicy, ActiveDirectory
#Requires -RunAsAdministrator

Import-Module GroupPolicy
Import-Module ActiveDirectory

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Disable NTLMv1 Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Safety check
if (-not $Apply -and -not $WhatIf) {
    Write-Host "[!] You must specify either -Apply or -WhatIf" -ForegroundColor Red
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\Disable-NTLMv1.ps1 -WhatIf    # Preview changes" -ForegroundColor White
    Write-Host "  .\Disable-NTLMv1.ps1 -Apply     # Apply changes" -ForegroundColor White
    Write-Host ""
    exit 1
}

if ($Apply) {
    Write-Host "[!] WARNING: This will disable NTLMv1 authentication!" -ForegroundColor Red
    Write-Host "[!] Ensure you have completed NTLM auditing first!" -ForegroundColor Red
    Write-Host ""
    
    $Confirmation = Read-Host "Type 'DISABLE-NTLMV1' to confirm"
    
    if ($Confirmation -ne "DISABLE-NTLMV1") {
        Write-Host "[*] Operation cancelled" -ForegroundColor Yellow
        exit 0
    }
}

if ($WhatIf -or $Apply) {
    Write-Host "[*] Configuring NTLMv1 Restrictions..." -ForegroundColor Yellow
    Write-Host ""
    
    if ($WhatIf) {
        Write-Host "[WhatIf Mode - No changes will be made]" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Would create/update GPO: $PolicyName" -ForegroundColor White
        Write-Host "Would configure:" -ForegroundColor White
        Write-Host "  - LmCompatibilityLevel = 5 (Deny LM and NTLMv1)" -ForegroundColor White
        Write-Host "  - Restrict NTLM: Incoming NTLM traffic = Deny all accounts" -ForegroundColor White
        Write-Host "  - Restrict NTLM: Outgoing NTLM traffic = Deny all" -ForegroundColor White
        Write-Host "  - Restrict NTLM: NTLM authentication in this domain = Deny all" -ForegroundColor White
        Write-Host ""
        
        if ($TargetOU) {
            Write-Host "Would link to: $TargetOU" -ForegroundColor White
        } else {
            $Domain = Get-ADDomain
            Write-Host "Would link to: $($Domain.DistinguishedName) (Domain Root)" -ForegroundColor White
        }
        Write-Host ""
        
        Write-Host "Next Steps (when ready to apply):" -ForegroundColor Cyan
        Write-Host "1. Complete NTLM usage audit" -ForegroundColor White
        Write-Host "2. Verify no systems require NTLMv1" -ForegroundColor White
        Write-Host "3. Test in dev/test environment" -ForegroundColor White
        Write-Host "4. Run script with -Apply parameter" -ForegroundColor White
        Write-Host ""
        
    } else {
        # Actually apply the configuration
        try {
            # Get or Create GPO
            try {
                $GPO = Get-GPO -Name $PolicyName -ErrorAction Stop
                Write-Host "[+] Using existing GPO: $PolicyName" -ForegroundColor Green
            } catch {
                $GPO = New-GPO -Name $PolicyName
                Write-Host "[+] Created new GPO: $PolicyName" -ForegroundColor Green
            }
            
            Write-Host "[*] Configuring registry settings..." -ForegroundColor Yellow
            
            # Set LM Compatibility Level to 5 (Deny LM and NTLMv1)
            Set-GPRegistryValue -Name $PolicyName `
                -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
                -ValueName "LmCompatibilityLevel" `
                -Type DWord -Value 5 | Out-Null
            
            Write-Host "[+] LmCompatibilityLevel set to 5 (Deny LM and NTLMv1)" -ForegroundColor Green
            
            # Restrict NTLM: Incoming NTLM traffic - Deny all accounts
            Set-GPRegistryValue -Name $PolicyName `
                -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                -ValueName "RestrictReceivingNTLMTraffic" `
                -Type DWord -Value 2 | Out-Null
            
            Write-Host "[+] Incoming NTLM traffic restricted" -ForegroundColor Green
            
            # Restrict NTLM: Outgoing NTLM traffic - Deny all
            Set-GPRegistryValue -Name $PolicyName `
                -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
                -ValueName "RestrictSendingNTLMTraffic" `
                -Type DWord -Value 2 | Out-Null
            
            Write-Host "[+] Outgoing NTLM traffic restricted" -ForegroundColor Green
            
            # Restrict NTLM in domain - Deny all
            Set-GPRegistryValue -Name $PolicyName `
                -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" `
                -ValueName "RestrictNTLMInDomain" `
                -Type DWord -Value 7 | Out-Null
            
            Write-Host "[+] NTLM restricted in domain" -ForegroundColor Green
            
            # Link GPO
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
            Write-Host "NTLMv1 Disabled Successfully!" -ForegroundColor Green
            Write-Host "========================================" -ForegroundColor Green
            Write-Host ""
            Write-Host "Important Next Steps:" -ForegroundColor Cyan
            Write-Host "1. Run 'gpupdate /force' on target systems" -ForegroundColor White
            Write-Host "2. Monitor event logs for NTLM failures" -ForegroundColor White
            Write-Host "3. Be prepared to rollback if critical systems fail" -ForegroundColor White
            Write-Host "4. Document any exceptions that need to be made" -ForegroundColor White
            Write-Host ""
            Write-Host "Rollback Instructions:" -ForegroundColor Yellow
            Write-Host "  Remove-GPLink -Name '$PolicyName' -Target '$LinkPath'" -ForegroundColor White
            Write-Host "  or disable the GPO link in Group Policy Management" -ForegroundColor White
            Write-Host ""
            
        } catch {
            Write-Host ""
            Write-Host "[-] Error occurred: $_" -ForegroundColor Red
            Write-Host ""
            exit 1
        }
    }
}

Write-Host "Script execution completed." -ForegroundColor Green
