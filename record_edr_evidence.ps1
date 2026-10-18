#requires -Version 5.1
<# Instructor-only manual transcription of observations made in a real EDR console.
Do not run on participant VM with accessible instructor evidence share.
Does not call or impersonate vendor APIs, does not fabricate detections.
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][ValidateSet('SentinelOne','ESET','Other')][string]$Vendor,
 [Parameter(Mandatory=$true)][string]$Endpoint,
 [Parameter(Mandatory=$true)][string]$DetectionTimeUtc,
 [Parameter(Mandatory=$true)][string]$ThreatName,
 [Parameter(Mandatory=$true)][string]$DetectedFileName,
 [Parameter(Mandatory=$true)][string]$OriginalPath,
 [string]$ObservedSHA256='',
 [Parameter(Mandatory=$true)][ValidateSet('Detected','Blocked','Quarantined','Deleted','Remediated','AlertOnly','Unknown')][string]$ObservedAction,
 [Parameter(Mandatory=$true)][string]$AlertReference,
 [Parameter(Mandatory=$true)][string]$EvidenceReference,
 [string]$EvidenceExportPath='C:\CTF-Instructor\AV01-Evidence',
 [string]$CaseId='AV01-2026-001'
)
$ErrorActionPreference='Stop'
if([string]::IsNullOrWhiteSpace($EvidenceExportPath) -or -not ($EvidenceExportPath -match '^[A-Za-z]:\\' -or $EvidenceExportPath -match '^\\\\[^\\]+\\[^\\]+')) { throw 'Provide an absolute local path or external UNC share.' }
if(-not (Test-Path -LiteralPath $EvidenceExportPath -PathType Container)){ New-Item -Path $EvidenceExportPath -ItemType Directory -Force | Out-Null }
if($EvidenceExportPath -match '^[A-Za-z]:\\') { Write-Warning 'Development-mode local instructor evidence is not isolated from administrators on this VM.' }
try { [void][DateTime]::Parse($DetectionTimeUtc) } catch { throw 'DetectionTimeUtc must be a valid date/time' }
if($ObservedSHA256 -ne '' -and $ObservedSHA256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'SHA256 must be exactly 64 hexadecimal characters, or blank if not shown in console' }
$record=[ordered]@{
 schema_version=1; case_id=$CaseId; vendor=$Vendor; endpoint=$Endpoint;
 detection_time_utc=$DetectionTimeUtc; threat_name=$ThreatName;
 detected_filename=$DetectedFileName; original_path=$OriginalPath;
 observed_sha256=$ObservedSHA256.ToLowerInvariant(); observed_action=$ObservedAction;
 alert_reference=$AlertReference; evidence_reference=$EvidenceReference;
 evidence_origin='Instructor transcription from observed EDR console';
 recorded_utc=[DateTime]::UtcNow.ToString('o')
}
$folder=Join-Path $EvidenceExportPath ('AV01_'+$Endpoint)
New-Item -ItemType Directory -Force -Path $folder | Out-Null
$dest=Join-Path $folder 'observed_edr_event.json'
$record | ConvertTo-Json -Depth 4 | Set-Content -Path $dest -Encoding UTF8
Write-Host '[AV01] Observed EDR evidence recorded:' $dest
Write-Host '[AV01] Attach actual console screenshot or native export matching EvidenceReference.'
