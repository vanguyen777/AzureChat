# INC-005 — Suspicious Certutil Decode Process

## Executive summary

An authorized local certutil encode/decode simulation on `LAB-WIN01` produced Windows Security Event ID 4688 with a populated command line. The event was ingested into Log Analytics `SecurityEvent`, matched the verified detection logic, and was followed by named Microsoft Sentinel scheduled-rule alerts and incidents.

**Classification: True Positive — Benign / Authorized Simulation.**

Only benign local text files were used. No download, executable payload, persistence or security-control bypass occurred. This is a completed lab case study; unexpected equivalent activity in production requires investigation.

## Detection objective

Detect `certutil.exe` executing a decode operation on the lab endpoint. The detection identifies behavior associated with decoding files; it does not establish malicious intent or determine the decoded file's contents.

## Endpoint evidence

| Field | Verified value |
|---|---|
| Endpoint | `LAB-WIN01` |
| Account | `LAB-WIN01\azureadmin` |
| Simulation time | 2026-09-13 21:39:58 UTC |
| SecurityEvent TimeGenerated | 2026-09-13T21:39:58.1740411Z |
| Event ID / record ID | 4688 / 15852 |
| Process | `C:\Windows\System32\certutil.exe` |
| Parent for record 15852 | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Marker | `SOC-LAB-SAFE-CERTUTIL-20260913T213958Z` |
| Decode verification | `True` |

Captured command line, transcribed from the safe simulation and fresh telemetry screenshots:

```text
"C:\Windows\system32\certutil.exe" -f -decode C:\Windows\Temp\soclab-safe-source-20260913T213958Z.b64 C:\Windows\Temp\soclab-safe-decoded-20260913T213958Z.txt
```

**Parent-process reconciliation:** The supplied summary named `cmd.exe` as the parent. The earlier ingestion screenshot shows a separate certutil event at 2026-09-13T21:12:27.688229Z with `C:\Windows\System32\cmd.exe` as parent. Both the endpoint capture and fresh Log Analytics record 15852 show PowerShell as the immediate parent. This report uses the record-specific screenshot evidence.

## Safe simulation

The source file was `C:\Windows\Temp\soclab-safe-source-20260913T213958Z.txt`. It contained the benign marker, was encoded into the local `.b64` file, and was decoded to `C:\Windows\Temp\soclab-safe-decoded-20260913T213958Z.txt`. The endpoint evidence compares source and decoded file hashes and reports `DecodeVerified=True`.

No executable payload was created or run. The utility process itself executed solely to encode/decode local text. The evidence capture command reads the existing event and files; it is not a command to reproduce the simulation.

## Log Analytics validation and KQL

The initial ingestion screenshot proves that Event ID 4688, certutil process name, decode command line and parent process reached `SecurityEvent`. Fresh telemetry identifies record 15852, the timestamped filenames, account and PowerShell parent.

The deployed detection is [suspicious-process-detection.kql](../detections/suspicious-process-detection.kql). Its verified logic:

- Search the previous 15 minutes in `SecurityEvent`.
- Match `LAB-WIN01` or its dotted hostname form and Event ID 4688.
- Require a populated `CommandLine` and `NewProcessName` ending in `\certutil.exe`.
- Match `-decode` or `/decode` in the command line.
- Return process, account, host and event context using the existing verified fields.

The standalone KQL screenshot shows a simpler manual 24-hour query and no results pane. The fresh-record query uses a 30-minute window. These are validation queries, not the deployed rule query. The Cloud Shell screenshot displays the full deployed 15-minute query, which matches the stored detection body. Successful full-query testing is established by the supplied verified lab facts; the screenshots additionally support ingestion, configuration and generated outputs.

The `extend` expressions create output aliases. They do not, by themselves, prove configured Sentinel entity mappings; no entity-mapping configuration is claimed here.

## Verified scheduled rule

| Setting | Value |
|---|---|
| Display name | Suspicious Certutil Decode Process |
| Rule ID | `267e9526-fc0f-4957-b8d9-10f60eaa5c2b` |
| Kind / enabled | Scheduled / True |
| Severity | Medium |
| Frequency / lookback | 5 minutes / 15 minutes (`PT5M` / `PT15M`) |
| Trigger | `GreaterThan` 0 |
| Incident creation | Enabled (`CreateIncident=True`) |
| Configured tactic / technique | Defense Evasion / T1140 |

These settings and the query are visible in the [Cloud Shell verification](../screenshots/day7-suspicious-process-rule-verified-cloudshell.png).

## Alert validation

The [SecurityAlert screenshot](../screenshots/day7-suspicious-process-security-alert.png) shows `Suspicious Certutil Decode Process`, Medium severity, provider `ASI Scheduled Alerts`, product `Azure Sentinel`, at 2026-09-13T21:46:03.9275618Z. This supports generation of a fresh matching scheduled-rule alert after the 21:39:58 simulation. The image does not expand the underlying event entities.

## Incident validation

The [SecurityIncident screenshot](../screenshots/day7-suspicious-process-security-incident.png) shows three same-title incidents: 53, 54 and 55. The selected example is **incident 55**, Medium severity, status **New**, created and last modified at 2026-09-13T21:56:16.25Z.

Its expanded `AlertIds` contains a different identifier from the alert shown in the separate alert screenshot. These captures prove named alert and incident generation, but do not directly establish linkage between the displayed alert and incident 55. Incident 53 is visible at 21:46:20.866 UTC, shortly after the displayed alert; temporal proximity alone is not proof of linkage.

The case-study disposition below is an analyst assessment of the authorized activity. The captured Sentinel status remains New; no portal closure or containment action is claimed.

## Investigation timeline

| UTC time on 2026-09-13 | Observed stage |
|---|---|
| 21:12:27.688229 | Earlier certutil decode event ingested; cmd.exe parent |
| 21:39:58 | Authorized benign local simulation; endpoint record 15852; decode verification True |
| 21:39:58.1740411 | Fresh record 15852 in SecurityEvent; PowerShell parent |
| Time not shown | Full deployed query and enabled scheduled-rule settings captured in Cloud Shell |
| 21:46:03.9275618 | Named Medium SecurityAlert recorded |
| 21:46:20.866 | Same-title incident 53 visible |
| 21:51:14.526 | Same-title incident 54 visible |
| 21:56:16.25 | Selected same-title incident 55 created, New, Medium |

Record timestamps are not ingestion-latency measurements. Rule creation and screenshot capture times are not inferred.

## Evidence table

| Evidence | Stage | What it establishes |
|---|---|---|
| [Safe simulation](../screenshots/day7-certutil-safe-simulation.png) | Endpoint | Marker, hash verification, record 15852, account, process, command and PowerShell parent |
| [4688 ingestion](../screenshots/day7-4688-certutil-ingestion.png) | Log Analytics | Earlier certutil decode event in SecurityEvent with cmd.exe parent |
| [Fresh telemetry](../screenshots/day7-fresh-certutil-telemetry.png) | Log Analytics | Fresh record 15852 and captured process/account/command context |
| [Manual detection KQL](../screenshots/day7-suspicious-process-detection-kql.png) | Query design | Simpler 24-hour validation query; no visible results pane |
| [Deployed rule verification](../screenshots/day7-suspicious-process-rule-verified-cloudshell.png) | Analytics rule | Full stored query and enabled Scheduled rule settings |
| [Security alert](../screenshots/day7-suspicious-process-security-alert.png) | Alert | Named Medium scheduled-rule alert |
| [Security incident](../screenshots/day7-suspicious-process-security-incident.png) | Incident | Same-title incidents, selected incident 55 and its separate alert reference |

See the [repository evidence inventory](../screenshots/EVIDENCE_INVENTORY.md) for other scenarios and evidence limits.

## MITRE ATT&CK mapping

**Defense Evasion — T1140: Deobfuscate/Decode Files or Information.**

Certutil decoding is consistent with the behavior described by T1140. This is the configured rule mapping and a behavioral interpretation, not proof that an adversary operated in the lab. Base64 decoding alone does not establish evasion intent.

## False-positive considerations

Certificate administration, software packaging, troubleshooting and approved scripts may legitimately use certutil to decode local files. The command substring also matches decode variants, so the full command and output must be reviewed. A signed Windows binary can be used legitimately or abused.

In production, tune the host scope and approved activity patterns only after reviewing representative telemetry. Do not broadly suppress certutil based solely on its Microsoft signature.

## Recommended production investigation actions

1. Confirm activity authorization and identify the initiating account and logon session.
2. Review the complete command line and immediate parent/ancestor processes.
3. Preserve the source, encoded and decoded files and hashes; analyze suspicious contents safely.
4. Review adjacent process creation, PowerShell, authentication and endpoint-security records.
5. Investigate any network retrieval, follow-on execution, persistence or related activity across hosts.
6. Determine impact and scope before selecting a response.

These are recommended actions, not actions performed during this lab.

## Response and containment considerations

No containment was required for the authorized benign simulation. No additional Azure or VM activity was performed for this documentation phase.

For unexpected production activity, preserve evidence and consider endpoint isolation, blocking confirmed malicious artifacts, or restricting compromised accounts according to the incident's impact and organizational response procedures. Decoding alone is insufficient reason to assert compromise. No post-simulation file deletion or Sentinel incident closure is claimed.

## Final disposition

**True Positive — Benign / Authorized Simulation.**

Scenario 5 is complete: safe simulation, endpoint 4688, SecurityEvent ingestion with command-line context, verified KQL, enabled scheduled analytics rule, named SecurityAlert and SecurityIncident outputs are documented. The evidence distinguishes separate executions, manual queries and the displayed alert/incident examples without inventing direct identifier linkage.
