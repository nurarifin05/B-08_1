# CTF AV-01 — EDR-Centric Revision (Windows Server 2016)

## Purpose
Investigate a harmless EICAR antivirus test pattern as SOC analyst primarily through the **EDR console**. Development: SentinelOne. Final implementation: ESET. One active EDR product per VM. Never disable protection to force an outcome.

## What changed versus old package
- 15 questions now emphasize EDR console discovery, threat investigation, response, and evidence, rather than mostly filesystem commands.
- `setup.ps1` supports `-Action Preflight -EDRVendor SentinelOne|ESET|Other`.
- `record_edr_evidence.ps1` provides an instructor-only normalized event JSON format, not an invented EDR event.
- `validate_av01.ps1` correlates metadata and instructor-recorded EDR observations; it does **not** authenticate actual console evidence or automatically award flags.
- Four checkpoints remain filename (20), original path (20), SHA256 (30), observed protection action (30). Fifteen activity questions are scored as a separate learning rubric, **not added** to checkpoint weights.

## Safe deployment order
1. Snapshot Windows Server 2016 VM. Set hostname CTF-AV01-SRV2016 if suitable. Configure network and clock; never use real user documents.
2. Unzip package, PowerShell as Administrator, run `Set-ExecutionPolicy -Scope Process Bypass -Force`.
3. Run `./setup.ps1 -Action Install -EDRVendor SentinelOne` to create baseline only (no EICAR).
4. Install/activate SentinelOne with authorized installer and management token. Confirm endpoint ONLINE in management console, appropriate policy assigned, and test EICAR handling approved. **No installer or token is bundled.** When ESET arrives, use ESET instead and update vendor parameter.
5. Run `./setup.ps1 -Action Preflight -EDRVendor SentinelOne`. Local service names are indicative only; verify actual agent connectivity and policy in the console.
6. For development on a single VM, the installer automatically creates `C:\CTF-Instructor\AV01-Evidence`. No additional VM or network share is required. For formal CTF exams, export instructor evidence to a separate protected UNC share before admitting participants.
7. Instructor executes `./setup.ps1 -Action TriggerEicar -EDRVendor SentinelOne` **once**, after verifying agent readiness. Expected hash and metadata are exported before attempted write. EDR may block file creation synchronously.
8. In console, find actual detection by endpoint and time; capture original path, filename, threat classification, timestamp, action and hash if shown. Preserve screenshot/native export externally.
9. In **instructor-only administration PowerShell**, run `record_edr_evidence.ps1` with observed fields, then `validate_av01.ps1`; award checkpoint flags only after reviewing authentic console evidence.
10. Open the Word student module. Do not distribute instructor external metadata or the scripts used for evidence recording/grading to participants.

## Useful commands
```powershell
cd C:\CTF\AV01\AV01_CTF
.\setup.ps1 -Action Install -EDRVendor SentinelOne
.\setup.ps1 -Action Status -EDRVendor SentinelOne
.\setup.ps1 -Action Preflight -EDRVendor SentinelOne
.\setup.ps1 -Action TriggerEicar -EDRVendor SentinelOne
```

## Recording actual console evidence
Example **template only; replace every sample with observations from the real event**:
```powershell
.\record_edr_evidence.ps1 -Vendor SentinelOne `
 -Endpoint CTF-AV01-SRV2016 -DetectionTimeUtc '2026-10-18T09:00:00Z' `
 -ThreatName '<exact name shown in console>' `
 -DetectedFileName 'suspicious_attachment.com' `
 -OriginalPath 'C:\CTF-Lab\SharedFiles\suspicious_attachment.com' `
 -ObservedSHA256 '<64-character hash if EDR displays it; otherwise omit parameter>' `
 -ObservedAction Blocked `
 -AlertReference '<real event identifier>' `
 -EvidenceReference '<filename of saved console evidence>' `
 -EvidenceExportPath 'C:\CTF-Instructor\AV01-Evidence'
.\validate_av01.ps1 -Endpoint CTF-AV01-SRV2016 -EvidenceExportPath 'C:\CTF-Instructor\AV01-Evidence'
```
A local evidence directory is suitable for initial development but NOT tamper-resistant. Before a graded exercise, preserve a copy of the evidence outside the student VM. Do not hand students evidence-recording/validator scripts.

If EDR does not expose SHA256, do not substitute arbitrary values. Instructors may use original expected bytes/file inventory and a matching alert path/time/name to review checkpoint 3 manually. The automated check deliberately shows REVIEW/NOT COMPLETE in that situation.

## EDR navigation (version dependent)
- SentinelOne: Management Console → endpoint inventory / Agents, then Threats/Incidents, filter by hostname and time; open event and examine detail, classification, hashes (if present), action and remediation.
- ESET: ESET PROTECT → Computers → target endpoint, then Detections and relevant device detail/logs; view policy/protection status and recorded action (feature names vary by product/version/license).
- Neither console is guaranteed to label EICAR 'quarantined'. Record true observed action exactly; if only `Detected` or `AlertOnly`, it is **not** a passed blocking/quarantine acceptance test.

## Risks/constraints
- EICAR is an innocuous AV test string, never replace with live malware.
- Trigger may cause immediate blocking or deletion; this is expected. Do not disable security controls or keep duplicate malicious-test files.
- Different engines and policies may show different events. If no detection appears, investigate agent connectivity, supported test policy, and event delay rather than inventing an alert.
- In a shared lab, isolate VM and external evidence share appropriately.
- Scripts are not tested live on your Windows 2016 + SentinelOne installation; inspect and take a snapshot before first use.


## Single-VM quick start (revised)
Run PowerShell as Administrator in the extracted `AV01_CTF` directory:
```powershell
.\setup.ps1 -Action Install -EDRVendor SentinelOne
.\setup.ps1 -Action Preflight -EDRVendor SentinelOne
# Only after verifying the live EDR console and approval for the test:
.\setup.ps1 -Action TriggerEicar -EDRVendor SentinelOne
Get-ChildItem 'C:\CTF-Instructor\AV01-Evidence' -Recurse
.\setup.ps1 -Action Status -EDRVendor SentinelOne
```
Expected evidence folder: `C:\CTF-Instructor\AV01-Evidence\AV01_<COMPUTERNAME>\`. It contains `instructor_expected_metadata.json`, `file_inventory.csv`, `instructor_instructions.txt` and `trigger_attempt.json`. The presence of those files does NOT prove an EDR alert or quarantine. Inspect the real SentinelOne console for the actual outcome.

To use a network share later, pass `-EvidenceExportPath '\\INSTRUCTOR-PC\AV01-Evidence'`. The same override applies to `record_edr_evidence.ps1` and `validate_av01.ps1`. If the file was blocked at creation, keep the resulting error and correlate it with EDR logs. Do not lower protection.
