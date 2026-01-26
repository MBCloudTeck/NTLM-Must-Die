<#
.SYNOPSIS
    Audits NTLM usage across Active Directory domain.

.DESCRIPTION
    This script performs a comprehensive audit of NTLM authentication usage across
    your Active Directory domain. It collects events from domain controllers and
    member servers, identifies NTLMv1 vs NTLMv2 usage, and generates detailed reports.

.PARAMETER Domain
    The Active Directory domain to audit. Defaults to current domain.

.PARAMETER DomainControllers
    Specific domain controllers to query. If not specified, queries all DCs in domain.

.PARAMETER Days
    Number of days to look back for events. Default is 7 days.

.PARAMETER OutputPath
    Path where reports will be saved. Default is current directory.

.PARAMETER IncludeServers
    Include member servers in the audit (slower but more comprehensive).

.EXAMPLE
    .\Audit-NTLMUsage.ps1 -Domain "contoso.com" -Days 7 -OutputPath "C:\Reports"

.EXAMPLE
    .\Audit-NTLMUsage.ps1 -DomainControllers "DC01","DC02" -IncludeServers

.NOTES
    Requires:
    - PowerShell 5.1 or later
    - Active Directory module
    - Administrative privileges
    - Remote Event Log access to DCs and servers
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain = $env:USERDNSDOMAIN,
    
    [Parameter(Mandatory=$false)]
    [string[]]$DomainControllers,
    
    [Parameter(Mandatory=$false)]
    [int]$Days = 7,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = (Get-Location).Path,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeServers
)

#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

# Import required modules
Import-Module ActiveDirectory

# Set error action
$ErrorActionPreference = "Continue"

# Initialize results
$Results = @()
$NTLMv1Count = 0
$NTLMv2Count = 0

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "NTLM Usage Audit Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Domain: $Domain" -ForegroundColor White
Write-Host "Lookback Period: $Days days" -ForegroundColor White
Write-Host "Output Path: $OutputPath" -ForegroundColor White
Write-Host ""

# Get Domain Controllers if not specified
if (-not $DomainControllers) {
    Write-Host "[*] Discovering Domain Controllers..." -ForegroundColor Yellow
    $DomainControllers = (Get-ADDomainController -Filter * -Server $Domain).HostName
    Write-Host "[+] Found $($DomainControllers.Count) Domain Controllers" -ForegroundColor Green
}

# Calculate start time
$StartTime = (Get-Date).AddDays(-$Days)

# Function to query NTLM events from a server
function Get-NTLMEventsFromServer {
    param(
        [string]$ComputerName,
        [datetime]$StartTime
    )
    
    Write-Host "[*] Querying $ComputerName..." -ForegroundColor Yellow
    
    $Events = @()
    
    try {
        # Query Event ID 4624 (Account Logon) with NTLM
        $FilterHashTable = @{
            LogName = 'Security'
            ID = 4624, 4776
            StartTime = $StartTime
        }
        
        $RawEvents = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $FilterHashTable -ErrorAction Stop
        
        foreach ($Event in $RawEvents) {
            $EventXML = [xml]$Event.ToXml()
            $EventData = @{}
            
            foreach ($Data in $EventXML.Event.EventData.Data) {
                $EventData[$Data.Name] = $Data.'#text'
            }
            
            # Check if it's NTLM
            if ($EventData.ContainsKey('AuthenticationPackageName')) {
                $PackageName = $EventData['AuthenticationPackageName']
                
                if ($PackageName -like "*NTLM*") {
                    $NTLMVersion = if ($PackageName -like "*V1*" -or $PackageName -eq "NTLM V1") {
                        "NTLMv1"
                    } elseif ($PackageName -like "*V2*" -or $PackageName -eq "NTLM V2") {
                        "NTLMv2"
                    } else {
                        "NTLM (Unknown Version)"
                    }
                    
                    $Events += [PSCustomObject]@{
                        TimeCreated = $Event.TimeCreated
                        Computer = $ComputerName
                        EventID = $Event.Id
                        NTLMVersion = $NTLMVersion
                        TargetUserName = $EventData['TargetUserName']
                        WorkstationName = $EventData['WorkstationName']
                        IpAddress = $EventData['IpAddress']
                        LogonType = $EventData['LogonType']
                    }
                }
            }
        }
        
        Write-Host "[+] Found $($Events.Count) NTLM events on $ComputerName" -ForegroundColor Green
        
    } catch {
        Write-Host "[-] Error querying $ComputerName : $_" -ForegroundColor Red
    }
    
    return $Events
}

# Query Domain Controllers
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Querying Domain Controllers" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

foreach ($DC in $DomainControllers) {
    $DCEvents = Get-NTLMEventsFromServer -ComputerName $DC -StartTime $StartTime
    $Results += $DCEvents
}

# Query Member Servers if requested
if ($IncludeServers) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Querying Member Servers" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    $Servers = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Server $Domain | 
               Where-Object {$DomainControllers -notcontains $_.DNSHostName} |
               Select-Object -First 50  # Limit to first 50 for performance
    
    Write-Host "[*] Found $($Servers.Count) member servers to query" -ForegroundColor Yellow
    
    foreach ($Server in $Servers) {
        $ServerEvents = Get-NTLMEventsFromServer -ComputerName $Server.DNSHostName -StartTime $StartTime
        $Results += $ServerEvents
    }
}

# Analyze Results
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Analysis Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$TotalEvents = $Results.Count
$NTLMv1Count = ($Results | Where-Object {$_.NTLMVersion -eq "NTLMv1"}).Count
$NTLMv2Count = ($Results | Where-Object {$_.NTLMVersion -eq "NTLMv2"}).Count

Write-Host ""
Write-Host "Total NTLM Events: $TotalEvents" -ForegroundColor White
Write-Host "NTLMv1 Events: $NTLMv1Count" -ForegroundColor $(if($NTLMv1Count -gt 0){"Red"}else{"Green"})
Write-Host "NTLMv2 Events: $NTLMv2Count" -ForegroundColor Yellow
Write-Host ""

# Top Sources
$TopSources = $Results | Group-Object WorkstationName | 
              Sort-Object Count -Descending | 
              Select-Object -First 10 Name, Count

Write-Host "Top 10 NTLM Sources:" -ForegroundColor Cyan
$TopSources | Format-Table -AutoSize

# Top Accounts
$TopAccounts = $Results | Group-Object TargetUserName | 
               Sort-Object Count -Descending | 
               Select-Object -First 10 Name, Count

Write-Host "Top 10 NTLM Accounts:" -ForegroundColor Cyan
$TopAccounts | Format-Table -AutoSize

# Export Results
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$ReportPath = Join-Path $OutputPath "NTLM-Audit-$Timestamp"

# Export detailed results
$CsvPath = "$ReportPath-Details.csv"
$Results | Export-Csv -Path $CsvPath -NoTypeInformation
Write-Host "[+] Detailed results exported to: $CsvPath" -ForegroundColor Green

# Export summary report
$SummaryPath = "$ReportPath-Summary.txt"
$SummaryContent = @"
NTLM Usage Audit Summary
========================
Domain: $Domain
Report Date: $(Get-Date)
Lookback Period: $Days days

Summary Statistics
==================
Total NTLM Events: $TotalEvents
NTLMv1 Events: $NTLMv1Count $(if($NTLMv1Count -gt 0){"[CRITICAL]"}else{""})
NTLMv2 Events: $NTLMv2Count

Risk Assessment
===============
$(if($NTLMv1Count -gt 0){"CRITICAL: NTLMv1 usage detected. Immediate action required."}
elseif($NTLMv2Count -gt 1000){"HIGH: Heavy NTLM usage detected. Plan remediation."}
elseif($NTLMv2Count -gt 100){"MEDIUM: Moderate NTLM usage. Continue monitoring."}
else{"LOW: Minimal NTLM usage."})

Recommendations
===============
1. $(if($NTLMv1Count -gt 0){"Immediately disable NTLMv1 using Group Policy"}else{"Continue monitoring for NTLMv1"})
2. Identify top NTLM sources and remediate
3. Configure Kerberos for service accounts
4. Enable Credential Guard on Windows 10/11 endpoints
5. Use Protected Users group for privileged accounts

Top Sources
===========
$($TopSources | Format-Table -AutoSize | Out-String)

Top Accounts
============
$($TopAccounts | Format-Table -AutoSize | Out-String)

Next Steps
==========
1. Review detailed CSV report
2. Investigate NTLMv1 sources (if any)
3. Work with application teams to remediate top sources
4. Schedule follow-up audit in 2 weeks
"@

$SummaryContent | Out-File -FilePath $SummaryPath -Encoding UTF8
Write-Host "[+] Summary report exported to: $SummaryPath" -ForegroundColor Green

# Alert on NTLMv1
if ($NTLMv1Count -gt 0) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "!!! CRITICAL ALERT !!!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "NTLMv1 usage detected in your environment!" -ForegroundColor Red
    Write-Host "NTLMv1 is highly insecure and must be disabled immediately." -ForegroundColor Red
    Write-Host ""
    Write-Host "NTLMv1 Sources:" -ForegroundColor Red
    $Results | Where-Object {$_.NTLMVersion -eq "NTLMv1"} | 
        Select-Object WorkstationName, TargetUserName, TimeCreated | 
        Format-Table -AutoSize
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Audit Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
