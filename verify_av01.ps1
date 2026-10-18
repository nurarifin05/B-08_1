#requires -Version 5.1
[CmdletBinding()]
param([string]$BasePath='C:\CTF-Lab')
$ErrorActionPreference='Stop'
$ticket=Join-Path $BasePath 'Case\incident_ticket.txt'
$inventory=Join-Path $BasePath 'Evidence\file_inventory.csv'
$shared=Join-Path $BasePath 'SharedFiles'
Write-Host '=== WEB/AV CTF AV-01 READ-ONLY INSPECTION ==='
Write-Host ('Incident ticket exists: '+(Test-Path $ticket))
Write-Host ('Inventory exists: '+(Test-Path $inventory))
Write-Host ('Shared folder exists: '+(Test-Path $shared))
if(Test-Path $inventory) { Import-Csv $inventory | Select-Object file,type,path,sha256 | Format-Table -AutoSize }
Get-WinEvent -ListLog '*Sentinel*' -ErrorAction SilentlyContinue | Select-Object LogName,RecordCount | Format-Table -AutoSize
Write-Host 'For actual detection/action proof, use the installed SentinelOne management console and policy-specific event view.'
Write-Host 'No evidence of quarantine is inferred from an absent test file.'
