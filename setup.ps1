#requires -Version 5.1
<#
AV-01 - Windows Server 2016 Desktop Experience (PowerShell 5.1)
Usage:
  .\setup.ps1 -Action Install
  .\setup.ps1 -Action Status
  .\setup.ps1 -Action TriggerEicar   # default local evidence folder
  .\setup.ps1 -Action ExportEvidence # or set an external UNC path
  .\setup.ps1 -Action Reset
No EDR software installation is attempted. No security controls are disabled.
#>
[CmdletBinding()]
param(
 [ValidateSet('Install','Status','Preflight','TriggerEicar','ExportEvidence','Reset')][string]$Action='Install',
 [string]$EvidenceExportPath='C:\CTF-Instructor\AV01-Evidence',
 [ValidateSet('SentinelOne','ESET','Other')][string]$EDRVendor='SentinelOne',
 [string]$BasePath='C:\CTF-Lab'
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$case=Join-Path $BasePath 'Case'
$share=Join-Path $BasePath 'SharedFiles'
$evidence=Join-Path $BasePath 'Evidence'
$logFile=Join-Path $evidence 'setup_events.log'
$target=Join-Path $share 'suspicious_attachment.com'
$sourceLabel='EICAR standard antivirus test string (harmless test pattern)'
$caseId='AV01-2026-001'
function Say([string]$s) { Write-Host "[AV01] $s" }
function Add-Log([string]$s) { if(Test-Path $evidence) { Add-Content -LiteralPath $logFile -Value ("{0:o} | {1}" -f (Get-Date),$s) -Encoding UTF8 } }
function Check-Admin {
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 $principal=New-Object Security.Principal.WindowsPrincipal($identity)
 if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run PowerShell as Administrator.' }
}
function OS-Check {
 $os=Get-CimInstance Win32_OperatingSystem
 Say ("OS: {0}" -f $os.Caption)
 if($os.Version -notlike '10.0*') { Write-Warning 'Expected Windows Server 2016 (NT 10.0). Check OS version.' }
}
function Init-Folders {
 foreach($folder in @($BasePath,$case,$share,$evidence)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
}
function Make-ByteArray {
 # 68-character official EICAR pattern constructed in memory; not printed or stored in logs
 $prefix='X5O!P%@AP[4\PZX54(P^)7CC)7}'
 $suffix='$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
 $full=$prefix+$suffix
 $bytes=[Text.Encoding]::ASCII.GetBytes($full)
 if($bytes.Length -ne 68) { throw ('EICAR pattern has unexpected length: '+$bytes.Length) }
 return ,$bytes
}
function SHA256-Bytes([byte[]]$bytes) {
 $sha=[Security.Cryptography.SHA256]::Create()
 try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
}
function Expected-Metadata {
 $b=Make-ByteArray
 return [ordered]@{ case_id=$caseId; filename='suspicious_attachment.com'; first_path=$target; sha256= (SHA256-Bytes $b); size_bytes=$b.Length; type=$sourceLabel; observed_detection='UNVERIFIED'; observed_action='UNVERIFIED'; observation_time_utc=''; product=$EDRVendor; analyst_notes='' }
}
function Write-TextUnlessExists($path,$content) {
 if(-not (Test-Path -LiteralPath $path)) { [IO.File]::WriteAllText($path,$content,[Text.UTF8Encoding]::new($false)) }
}
function Install-Lab {
 Check-Admin; OS-Check; Init-Folders
 Write-TextUnlessExists (Join-Path $case 'incident_ticket.txt') @'
INCIDENT AV01-2026-001 / INTERNAL USE / LAB
Asset: CTF-AV01-SRV2016 | Windows Server 2016 | Internal file server
Location: C:\CTF-Lab\SharedFiles
Report: Staff reported an unexpected .com attachment in the shared folder.
SOC task: Correlate filename, first observed path, SHA-256, and actual AV/EDR response.
Important: AV detection or quarantine has NOT been assumed; verify in console and policy.
Evidence may contain only dummy non-sensitive training files.
Four flag checkpoints are awarded by instructor after evidence validation.
'@
 Write-TextUnlessExists (Join-Path $share 'financial_report.txt') "Dummy financial report for AV-01 lab only.`r`nNo sensitive data.`r`n"
 Write-TextUnlessExists (Join-Path $share 'staff_data.csv') "staff_id,name,department`r`nT001,Dummy User,Training`r`nT002,Example User,IT`r`n"
 $meta=Expected-Metadata
 $csv=Join-Path $evidence 'file_inventory.csv'
 if(-not (Test-Path $csv)) {
  @([pscustomobject]@{file='financial_report.txt';type='benign';path=(Join-Path $share 'financial_report.txt');sha256=(Get-FileHash (Join-Path $share 'financial_report.txt') -Algorithm SHA256).Hash.ToLowerInvariant()},
    [pscustomobject]@{file='staff_data.csv';type='benign';path=(Join-Path $share 'staff_data.csv');sha256=(Get-FileHash (Join-Path $share 'staff_data.csv') -Algorithm SHA256).Hash.ToLowerInvariant()},
    [pscustomobject]@{file=$meta.filename;type='EICAR_TEST_EXPECTED';path=$meta.first_path;sha256=$meta.sha256}) |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
 }
 Add-Log 'Install baseline complete; EICAR was not triggered by Install action.'
 Say 'Baseline created. No real malware and no EICAR test pattern written yet.'
 Say 'Next: activate EDR agent, run Preflight, then TriggerEicar (default evidence: C:\CTF-Instructor\AV01-Evidence).'
 Status-Lab
}
function Test-Export([string]$p) {
 if([string]::IsNullOrWhiteSpace($p)) { throw 'EvidenceExportPath cannot be empty.' }
 # Accept absolute drive paths (development) and UNC shares (instructor/exam).
 $isLocal = $p -match '^[A-Za-z]:\\'
 $isUnc = $p -match '^\\\\[^\\]+\\[^\\]+'
 if(-not ($isLocal -or $isUnc)) { throw 'Use an absolute path such as C:\CTF-Instructor\AV01-Evidence or a UNC share.' }
 if($isLocal) {
  $full=[IO.Path]::GetFullPath($p).TrimEnd('\\')
  $lab=[IO.Path]::GetFullPath($BasePath).TrimEnd('\\')
  if($full -ieq $lab -or $full.StartsWith($lab+'\',[StringComparison]::OrdinalIgnoreCase)) {
   throw 'Instructor evidence must not be stored in the student CTF-Lab directory.'
  }
 }
 if(-not (Test-Path -LiteralPath $p -PathType Container)) {
  New-Item -ItemType Directory -Path $p -Force -ErrorAction Stop | Out-Null
 }
 $probe=Join-Path $p ('av01_write_test_'+[guid]::NewGuid().ToString('N')+'.txt')
 try { Set-Content -LiteralPath $probe -Value 'write-check' -Encoding ASCII -ErrorAction Stop; Remove-Item -LiteralPath $probe -Force -ErrorAction Stop }
 catch { throw ('Evidence folder not writable: '+$_.Exception.Message) }
 if($isLocal) { Write-Warning 'LOCAL evidence mode: development only. Administrators/participants with VM access can read or alter these records. Export evidence off-VM before a formal examination.' }
}
function Export-External([string]$p) {
 Test-Export $p
 $meta=Expected-Metadata
 $folder=Join-Path $p ('AV01_'+$env:COMPUTERNAME)
 if(-not (Test-Path $folder)) { New-Item -Path $folder -ItemType Directory -Force | Out-Null }
 $m=Join-Path $folder 'instructor_expected_metadata.json'
 $meta | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $m -Encoding UTF8
 Copy-Item -LiteralPath (Join-Path $evidence 'file_inventory.csv') -Destination (Join-Path $folder 'file_inventory.csv') -Force
 $instructions=@'
INSTRUCTOR ONLY. Preserve this off the participant VM.
Four flags must be issued from an INDEPENDENT grader upon validation of:
F1 file name, F2 original path, F3 SHA-256, F4 actual protection response.
Never mark a file quarantined solely because it is absent on disk.
Save console alert/export with timestamp, detection name, policy and action here.
Expected hashes are computed from the official 68-byte EICAR test pattern before attempted writing.
'@
 Set-Content -LiteralPath (Join-Path $folder 'instructor_instructions.txt') -Encoding UTF8 -Value $instructions
 Say ('Instructor evidence saved: '+$folder)
 Add-Log 'Expected metadata saved to selected evidence directory; local storage is not isolated.'
 return $folder
}
function Trigger-Test {
 Check-Admin
 if(-not (Test-Path (Join-Path $case 'incident_ticket.txt'))) { Install-Lab }
 $folder=Export-External $EvidenceExportPath
 Say 'WARNING: TriggerEicar assumes instructor has checked agent, console connectivity and policy. Trigger is not a test of live EDR readiness.'
 Say 'About to create standard EICAR antivirus test pattern. Antivirus may block or quarantine it.'
 if(Test-Path -LiteralPath $target) { throw 'Target already exists. No duplicate trigger; inspect it first.' }
 $bytes=Make-ByteArray
 $result='WRITE_NOT_ATTEMPTED'
 try {
  [IO.File]::WriteAllBytes($target,$bytes)
  $result= if(Test-Path -LiteralPath $target) {'WRITE_COMPLETED_FILE_PRESENT'} else {'WRITE_RETURNED_FILE_NOT_PRESENT'}
 } catch {
  $result='WRITE_BLOCKED_OR_FAILED: '+$_.Exception.GetType().Name+' '+$_.Exception.Message
  Write-Warning $result
 }
 $time=[DateTime]::UtcNow.ToString('o')
 $record=[ordered]@{case_id=$caseId; utc=$time; endpoint=$env:COMPUTERNAME; vendor=$EDRVendor; target=$target; expected_sha256=(Expected-Metadata).sha256; write_result=$result; av_alert_verified=$false; av_action_verified=$false}
 $record | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'trigger_attempt.json') -Encoding UTF8
 Add-Log ('EICAR write attempt: '+$result+' (not evidence of quarantine)')
 Say ('Trigger result: '+$result)
 Say 'Instructor must verify the EDR alert/action in the actual console; archive evidence externally for exams.'
}
function Status-Lab {
 Say ('Computer: '+$env:COMPUTERNAME)
 foreach($x in @($case,$share,$evidence)) { Say ("Exists {0}: {1}" -f $x,(Test-Path $x)) }
 Say ('EICAR target present: '+(Test-Path -LiteralPath $target))
 Say ('Expected SHA256 from in-memory standard test bytes: '+(Expected-Metadata).sha256)
 Say 'File absent does NOT prove quarantine; consult SentinelOne threat/event record.'
 $svc=Get-Service | Where-Object { $_.DisplayName -match 'Sentinel|ESET|Defender' -or $_.Name -match 'Sentinel|ESET|WinDefend' }
 if($svc) { $svc | Select-Object Name,DisplayName,Status | Format-Table -AutoSize | Out-Host } else { Say 'No candidate EDR service discovered by name (verify product and console manually).' }
}

function Preflight-EDR {
 Check-Admin
 OS-Check
 if(-not (Test-Path -LiteralPath (Join-Path $case 'incident_ticket.txt'))) { throw 'Run -Action Install first.' }
 Say ('Selected EDR vendor: '+$EDRVendor)
 $patterns=if($EDRVendor -eq 'SentinelOne') { @('Sentinel') } elseif($EDRVendor -eq 'ESET') { @('ESET','ekrn','ERAAgent') } else { @('Sentinel','ESET','Defender') }
 $found=@(Get-Service | Where-Object { $combined=$_.Name+' '+$_.DisplayName; $matched=$false; foreach($pattern in $patterns) { if($combined -match $pattern) { $matched=$true } }; $matched })
 if($found.Count -eq 0) { Write-Warning 'No candidate service detected locally. This is NOT definitive proof agent is missing.' }
 else { $found | Select-Object Name,DisplayName,Status | Format-Table -AutoSize | Out-Host }
 Say 'MANUAL CHECK REQUIRED: open EDR console, confirm exact endpoint, agent ONLINE, current policy, real-time protection, and authorization to perform EICAR test.'
 Say 'Do not trigger until all conditions above have been verified; local service status does not prove console connectivity or policy.'
 Add-Log ('Preflight inspected local EDR services: vendor='+$EDRVendor+' candidates='+$found.Count)
}

function Reset-Lab {
 Check-Admin
 Say 'Reset removes only benign training files and locally generated lab records, NOT SentinelOne alerts/quarantine.'
 if(Test-Path -LiteralPath $BasePath) { Remove-Item -LiteralPath $BasePath -Recurse -Force }
 Install-Lab
}
try {
 switch($Action) {
 'Install' { Install-Lab }
 'Status' { Status-Lab }
 'Preflight' { Preflight-EDR }
 'ExportEvidence' { Check-Admin; if(-not (Test-Path $evidence)) { throw 'Install baseline first' }; [void](Export-External $EvidenceExportPath) }
 'TriggerEicar' { Trigger-Test }
 'Reset' { Reset-Lab }
 }
} catch { Write-Error ('[AV01] '+$_.Exception.Message); exit 1 }
