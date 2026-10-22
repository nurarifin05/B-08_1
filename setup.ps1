#requires -Version 5.1
<# AV01 ESET HOME Essential - final LMS edition.
   Only EICAR (safe standardized antivirus test pattern) is used. No ESET settings are modified.
   No LMS flags, answers or instructor secrets are stored here.
#>
[CmdletBinding()]
param(
 [ValidateSet('Install','Status','Preflight','Trigger','RunScenario','Verify','Reset')][string]$Action='Status',
 [ValidateSet('All','Malware','HIPS','Scan','Webcam','Web')][string]$Module='All',
 [switch]$ConfirmTest,
 [switch]$LaunchInteractiveTests
)
$ErrorActionPreference='Stop'
$Lab='C:\CTF-Lab-AV01'
$Ev=Join-Path $Lab 'Evidence'
$Incident='INC-ADM-041'
function Info([string]$x){Write-Host "[AV01] $x"}
function Dir([string]$p){if(!(Test-Path -LiteralPath $p)){New-Item -ItemType Directory -Path $p -Force | Out-Null}}
function J([string]$name,$data){Dir $Ev; $data|ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $Ev $name) -Encoding UTF8}
function Event([string]$module,[string]$kind,[string]$message){
 Dir $Ev
 [pscustomobject]@{timestamp_utc=(Get-Date).ToUniversalTime().ToString('o');incident=$Incident;module=$module;event=$kind;details=$message} |
 ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $Ev 'lab_activity.jsonl') -Encoding UTF8
}
function EicarBytes {
 $chunks=@('X5O!P%@AP[4\PZX54(P^)7CC)7}', '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!', '$H+H*')
 [Text.Encoding]::ASCII.GetBytes(($chunks -join ''))
}
function Metadata([string]$module,[string]$path){
 $bytes=EicarBytes; $sha=[Security.Cryptography.SHA256]::Create()
 try{$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')}finally{$sha.Dispose()}
 $v=[pscustomobject]@{incident=$Incident;module=$module;filename=[IO.Path]::GetFileName($path);path=$path;size_bytes=$bytes.Length;sha256=$hash;timestamp_utc=(Get-Date).ToUniversalTime().ToString('o');description='Metadata reference, not proof of ESET detection'}
 J "reference_$($module.ToLowerInvariant()).json" $v
 return $bytes
}
function InstallLab {
 foreach($d in @('Case','SharedFiles','Documents','Intake','Evidence','Training')){Dir (Join-Path $Lab $d)}
 $ticket=Join-Path $Lab 'Case\incident_ticket.txt'
 if(!(Test-Path $ticket)){
 @"
Ticket: $Incident
Case: Compromised Administration Workstation
Akun dummy; hanya mesin laboratorium.
Tugas: audit real-time detection, HIPS, on-demand scanning, webcam control dan web protection.
File uji EICAR dibuat oleh Trigger SETELAH ESET siap.
"@ | Set-Content -LiteralPath $ticket -Encoding UTF8
 }
 foreach($item in @('student_registry.csv','meeting_minutes.txt')){
  $p=Join-Path $Lab "Documents\$item"
  if(!(Test-Path $p)){"Dokumen latihan AV01: $item"|Set-Content -LiteralPath $p -Encoding UTF8}
 }
 $baseline=Join-Path $Ev 'baseline_hashes.csv'
 if(!(Test-Path $baseline)){
  Get-ChildItem (Join-Path $Lab 'Documents') -File | ForEach-Object {
   [pscustomobject]@{Name=$_.Name;Path=$_.FullName;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
  } | Export-Csv -LiteralPath $baseline -NoTypeInformation -Encoding UTF8
 }
 Info "Installed lab baseline in $Lab; EICAR not created."
}
function Preflight {
 Info "Host: $env:COMPUTERNAME | Windows: $([Environment]::OSVersion.VersionString)"
 $svc=@(Get-Service -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -match 'ESET' -or $_.Name -match '^ekrn$'})
 if($svc.Count){$svc|Select-Object Name,Status,DisplayName|Format-Table -AutoSize|Out-Host}else{Info 'ESET service not identified; confirm ESET installation in GUI.'}
 $camera=@(Get-PnpDevice -Class Camera,Image -ErrorAction SilentlyContinue)
 if($camera.Count){$camera|Select-Object FriendlyName,Status|Format-Table -AutoSize|Out-Host}else{Info 'No camera detected. Real webcam checkpoint cannot be accepted without compatible camera.'}
 Info 'In ESET GUI verify: active license, current modules, real-time, HIPS, webcam and web protection.'
}
function MakeEicar([string]$module,[string]$path){
 $bytes=Metadata $module $path # evidence before write
 try {
  [IO.File]::WriteAllBytes($path,$bytes)
  Event $module 'WRITE_RETURNED' "Path=$path; verify ESET Detection Log"
  Info "$module: file write returned; inspect ESET logs and current file state."
 } catch {
  Event $module 'WRITE_FAILED_OR_BLOCKED' $_.Exception.Message
  Info "$module: file write did not complete ($($_.Exception.Message)); check ESET event for cause."
 }
}
function TriggerOne([string]$m){
 if(!$ConfirmTest){throw 'Add -ConfirmTest only after ESET installed and instructor-approved test.'}
 if(!(Test-Path $Lab)){throw 'Run -Action Install first.'}
 switch($m){
  'Malware' {MakeEicar 'Malware' (Join-Path $Lab 'SharedFiles\admission_attachment.com')}
  'Scan' {MakeEicar 'Scan' (Join-Path $Lab 'Intake\old_document_review.com');Info 'Run ESET custom scan on C:\CTF-Lab-AV01\Intake; file may already be blocked by real-time.'}
  'HIPS' {
   $key='HKCU:\Software\CTF-Lab-AV01';Dir $Ev
   if(!(Test-Path $key)){New-Item -Path $key -Force|Out-Null}
   New-ItemProperty -Path $key -Name 'AdminSyncHelper' -Value 'BENIGN_TRAINING_MARKER' -PropertyType String -Force | Out-Null
   & "$env:windir\System32\cmd.exe" /c whoami | Out-Null
   Event 'HIPS' 'BENIGN_REGISTRY_AND_PROCESS' "Registry $key\AdminSyncHelper; cmd.exe whoami"
   Info 'HIPS: benign registry marker + cmd.exe launched. No ESET block claimed. Review actual HIPS rule/log.'
  }
  'Webcam' {
   J 'webcam_test_plan.json' ([pscustomobject]@{candidate='AdminSyncHelper';requires='camera + approved test app + ESET Webcam Protection rule';simulation_only=$true;observed_block=$null})
   Event 'Webcam' 'PLAN_ONLY' 'No camera is accessed by PowerShell.'
   Info 'Webcam: test plan created only. For real validation, use webcam and test application with ESET rule.'
   if($LaunchInteractiveTests){try{Start-Process 'ms-camera:'}catch{Info 'Camera app unavailable.'}}
  }
  'Web' {
   J 'web_test_plan.json' ([pscustomobject]@{official_url='https://www.amtso.org/security-features-check/';simulation_only=$true;observed_block=$null})
   Event 'Web' 'PLAN_ONLY' 'No automatic anti-phishing alert asserted.'
   Info 'Web: official AMTSO test instructions prepared; browser and ESET log required.'
   if($LaunchInteractiveTests){Start-Process 'https://www.amtso.org/security-features-check/'}
  }
 }
}
function Verify {
 $ref=Join-Path $Ev 'baseline_hashes.csv'; if(!(Test-Path $ref)){throw 'Baseline missing.'}
 $errors=@()
 foreach($row in @(Import-Csv -LiteralPath $ref)){
  if(!(Test-Path -LiteralPath $row.Path)){$errors+="Missing $($row.Name)";continue}
  if((Get-FileHash -LiteralPath $row.Path -Algorithm SHA256).Hash -ne $row.SHA256){$errors+="Changed $($row.Name)"}
 }
 if($errors.Count){$errors|ForEach-Object{Info "FAIL $_"};throw 'Normal document integrity failed.'}
 Info 'PASS: normal documents match baseline.'
 Info 'ESET verdicts must be independently inspected in application Logs, Quarantine, HIPS/Webcam/Web pages.'
}
function Reset {
 $key='HKCU:\Software\CTF-Lab-AV01'
 if(Test-Path $key){Remove-Item -Path $key -Recurse -Force}
 Info 'HIPS training marker removed. ESET logs/quarantine NOT cleared. Restore VM snapshot to repeat cleanly.'
}
switch($Action){
 'Install'{InstallLab}
 'Status'{Info "Case $Incident | Baseline: $(Test-Path $Lab)";Preflight}
 'Preflight'{Preflight}
 'Trigger'{if($Module -eq 'All'){@('Malware','HIPS','Scan','Webcam','Web')|ForEach-Object{TriggerOne $_}}else{TriggerOne $Module}}
 'RunScenario'{@('Malware','HIPS','Scan','Webcam','Web')|ForEach-Object{TriggerOne $_}}
 'Verify'{Verify}
 'Reset'{Reset}
}
