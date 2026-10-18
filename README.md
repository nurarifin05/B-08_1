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
6. Create **instructor-only writable UNC network share** on separate machine, e.g. `\\INSTRUCTOR-PC\AV01-Evidence`. Never expose it to participants. Consider using a dedicated lab instructor share instead of a participant-visible path.
7. Instructor executes `./setup.ps1 -Action TriggerEicar -EDRVendor SentinelOne -EvidenceExportPath '\\INSTRUCTOR-PC\AV01-Evidence'` **once**, after verifying agent readiness. Expected hash and metadata are exported before attempted write. EDR may block file creation synchronously.
8. In console, find actual detection by endpoint and time; capture original path, filename, threat classification, timestamp, action and hash if shown. Preserve screenshot/native export externally.
9. In **instructor-only administration PowerShell**, run `record_edr_evidence.ps1` with observed fields, then `validate_av01.ps1`; award checkpoint flags only after reviewing authentic console evidence.
10. Open the Word student module. Do not distribute instructor external metadata or the scripts used for evidence recording/grading to participants.

## Useful commands
```powershell
cd C:\CTF\AV01\AV01_CTF
.\setup.ps1 -Action Install -EDRVendor SentinelOne
.\setup.ps1 -Action Status -EDRVendor SentinelOne
.\setup.ps1 -Action Preflight -EDRVendor SentinelOne
.\setup.ps1 -Action TriggerEicar -EDRVendor SentinelOne -EvidenceExportPath '\\INSTRUCTOR-PC\AV01-Evidence'
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
 -EvidenceExportPath '\\INSTRUCTOR-PC\AV01-Evidence'
.\validate_av01.ps1 -Endpoint CTF-AV01-SRV2016 -EvidenceExportPath '\\INSTRUCTOR-PC\AV01-Evidence'
```
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
