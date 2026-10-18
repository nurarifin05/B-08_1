#requires -Version 5.1
<# Instructor-only evidence correlation. Manual review still required before awarding flags.
The validator does not communicate with vendor consoles and cannot authenticate screenshots.
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$EvidenceExportPath,[Parameter(Mandatory=$true)][string]$Endpoint,[string]$CaseId='AV01-2026-001')
$ErrorActionPreference='Stop'
$folder=Join-Path $EvidenceExportPath ('AV01_'+$Endpoint)
$expectedPath=Join-Path $folder 'instructor_expected_metadata.json'
$actualPath=Join-Path $folder 'observed_edr_event.json'
if(-not (Test-Path $expectedPath)) { throw 'Expected metadata missing: '+$expectedPath }
if(-not (Test-Path $actualPath)) { throw 'Observed EDR evidence missing: '+$actualPath }
$e=Get-Content -Raw $expectedPath | ConvertFrom-Json
$a=Get-Content -Raw $actualPath | ConvertFrom-Json
function Test-Criterion([string]$name,[bool]$pass) {
 if($pass) { Write-Host ('[PASS] '+$name) } else { Write-Host ('[FAIL] '+$name) }
 return $pass
}
$checks=@()
$checks+=Test-Criterion 'Case/endpoint correlation' (($a.case_id -eq $CaseId) -and ($a.case_id -eq $e.case_id) -and ($a.endpoint -eq $Endpoint))
$checks+=Test-Criterion 'Flag 01: filename' ($a.detected_filename -ieq $e.filename)
$checks+=Test-Criterion 'Flag 02: original path' ($a.original_path -ieq $e.first_path)
if(-not [string]::IsNullOrWhiteSpace($a.observed_sha256)) {
 $checks+=Test-Criterion 'Flag 03: observed EDR SHA256 matches expected' ($a.observed_sha256 -ieq $e.sha256)
} else {
 Write-Host '[REVIEW] Flag 03: EDR has no SHA256; instructor must correlate expected hash with original artefact metadata and other alert attributes.'
 $checks+=$false
}
$checks+=Test-Criterion 'Flag 04: recorded specific EDR action' ($a.observed_action -in @('Blocked','Quarantined','Deleted','Remediated'))
$checks+=Test-Criterion 'Audit references provided' ((-not [string]::IsNullOrWhiteSpace($a.alert_reference)) -and (-not [string]::IsNullOrWhiteSpace($a.evidence_reference)))
if($checks -contains $false) {
 Write-Host '[AV01] NOT COMPLETE: review console evidence and missing checks. No flags issued.'
 exit 2
}
Write-Host '[AV01] Structured correlation passed. Instructor must independently review screenshots/native exports and verify actual vendor action before awarding four flags.'
Write-Host '[AV01] No static final flag is emitted by this script.'
