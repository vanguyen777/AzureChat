# Screenshot Evidence Inventory

This inventory covers every screenshot in this repository. Proof statements are limited to visible content; query filters and filenames alone do not establish event ingestion or detection success. Existing incident reports supply additional verified lab context. All times below are UTC.

## Evidence limits and privacy

- Manual query windows can differ from deployed rule windows; the stored detection and rule-verification evidence identify deployed behavior.
- Day 5's configuration image verifies incident creation, not every rule property.
- Day 6's alert and incident captures predate the second account's fresh telemetry. They cannot be attributed to that later run from these images.
- Day 7 record 15852 has a PowerShell parent; the earlier certutil ingestion event has a cmd.exe parent.
- Day 7 shows multiple same-title incidents. Incident 55 references a different alert ID from the separate alert capture; direct linkage between those displayed examples is not proven.
- Visual review found no visible token, password, credential, actual subscription/tenant ID or personal email address. Existing images include lab account/resource identifiers and a Cloud Shell home-directory username. The failed-logon image includes a public source IP; its value is not transcribed here. Optional redaction of that pre-existing IP and shell username may improve portfolio privacy.
- No screenshot is an exact duplicate by Git blob SHA. Some lifecycle captures intentionally overlap. All screenshots were retrieved and visually inspected.
- The unreferenced architecture `.png` was actually a text diagram, not a PNG image. It was removed after verifying the SVG as valid XML; the SVG remains the architecture illustration.

## Scenario 1 — Failed logons 

| Filename | Scenario | Evidence stage | What the image proves / visible limits | Detection | Incident report |
|---|---|---|---|---|---|
| [failed-logons-detection.png](failed-logons-detection.png) | 1 | Log Analytics ingestion | SecurityEvent query for Event ID 4625 returns LAB-WIN01 records; this image does not show the five-failure aggregate threshold or an alert. A public source IP is visible. | [KQL](../detections/failed-logon-detection.kql) | [INC-001](../incidents/INC-001-failed-logon-investigation.md) |

## Day 4 — Scenario 2 

| Filename | Scenario | Evidence stage | What the image proves / visible limits | Detection | Incident report |
|---|---|---|---|---|---|
| [day4-4104-detection.png](day4-4104-detection.png) | 2 | KQL / script-block ingestion | Event ID 4104 query returns LAB-WIN01 script-block content containing FromBase64String; the full stored query is visible. | [KQL](../detections/suspicious-powershell.kql) | [INC-002](../incidents/INC-002-powershell-investigation.md) |
| [day4-security-alert.png](day4-security-alert.png) | 2 | SecurityAlert | SecurityAlert returns Medium Suspicious PowerShell Base64 Decoding records from ASI Scheduled Alerts. | [KQL](../detections/suspicious-powershell.kql) | [INC-002](../incidents/INC-002-powershell-investigation.md) |
| [day4-security-incident.png](day4-security-incident.png) | 2 | SecurityIncident | SecurityIncident returns incident 5, New, Medium, with the PowerShell detection title; AlertIds are not expanded. | [KQL](../detections/suspicious-powershell.kql) | [INC-002](../incidents/INC-002-powershell-investigation.md) |

## Day 5 — Scenario 3 

| Filename | Scenario | Evidence stage | What the image proves / visible limits | Detection | Incident report |
|---|---|---|---|---|---|
| [day5-correlation2-kql.png](day5-correlation2-kql.png) | 3 | Manual correlation result | Cross-table SecurityEvent 4625 / Event 4104 query returns joined LAB-WIN01 rows. The visible exploratory query uses a two-hour search; lower temporal conditions are outside the crop. | [KQL](../detections/multi-stage-logon-powershell-correlation.kql) | [INC-003](../incidents/INC-003-multi-stage-correlation.md) |
| [day5-rule-configuration.png](day5-rule-configuration.png) | 3 | Incident configuration | Cloud Shell output verifies createIncident=true and incident grouping disabled for the named multi-stage rule; frequency, lookback and severity are not shown. | [KQL](../detections/multi-stage-logon-powershell-correlation.kql) | [INC-003](../incidents/INC-003-multi-stage-correlation.md) |
| [day5-security-alert.png](day5-security-alert.png) | 3 | SecurityAlert | SecurityAlert returns High multi-stage detection records from 2026-09-07. | [KQL](../detections/multi-stage-logon-powershell-correlation.kql) | [INC-003](../incidents/INC-003-multi-stage-correlation.md) |
| [day5-security-incident.png](day5-security-incident.png) | 3 | SecurityIncident | SecurityIncident returns multi-stage incident 40, New, High, at 2026-09-07T22:32:48.03Z; alert linkage is not expanded. | [KQL](../detections/multi-stage-logon-powershell-correlation.kql) | [INC-003](../incidents/INC-003-multi-stage-correlation.md) |

## Day 6 — Scenario 4 

| Filename | Scenario | Evidence stage | What the image proves / visible limits | Detection | Incident report |
|---|---|---|---|---|---|
| [day6-4732-administrators-group-details.png](day6-4732-administrators-group-details.png) | 4 | Expanded group event | Expanded Event ID 4732 identifies Builtin\\Administrators and TargetSid S-1-5-32-544. | [KQL](../detections/privileged-account-correlation.kql) | [INC-004](../incidents/INC-004-privileged-account-investigation.md) |
| [day6-4732-member-sid-evidence.png](day6-4732-member-sid-evidence.png) | 4 | Raw EventData / identity | Expanded 4732 EventData shows unresolved MemberName (-) and a populated MemberSid; LAB-WIN01 and Security channel are visible. | [KQL](../detections/privileged-account-correlation.kql) | [INC-004](../incidents/INC-004-privileged-account-investigation.md) |
| [day6-account-modification-events.png](day6-account-modification-events.png) | 4 | Lifecycle telemetry | SecurityEvent results show 4720, 4722, 4724, 4732, 4733 and 4725 lifecycle telemetry; IDs appearing only in the query filter are not proof of ingestion. | [KQL](../detections/privileged-account-correlation.kql) | [INC-004](../incidents/INC-004-privileged-account-investigation.md) |
| [day6-account-privilege-timeline.png](day6-account-privilege-timeline.png) | 4 | Ordered lifecycle telemetry | Ordered results show soclab-tempadmin creation, enablement, password-reset attempt and subsequent Administrators membership addition. | [KQL](../detections/privileged-account-correlation.kql) | [INC-004](../incidents/INC-004-privileged-account-investigation.md) |
| [day6-fresh-privileged-account-telemetry.png](day6-fresh-privileged-account-telemetry.png) | 4 | Fresh-run ingestion | Results show soclab-tempadmin2 creation at 04:44:59 UTC and a SID-selected 4732 addition at 04:45:05 UTC on 2026-09-13; alert generation is not shown. | [KQL](../detections/privileged-account-correlation.kql) | [INC-004](../incidents/INC-004-privileged-account-investigation.md) |
| [day6-more-mod.png](day6-more-mod.png) | 4 | Additional lifecycle telemetry | Additional 4720/4732 records support account/group activity; overlaps earlier telemetry but is a distinct crop, not an exact duplicate. | [KQL](../detections/privileged-account-correlation.kql) | [INC-004](../incidents/INC-004-privileged-account-investigation.md) |
| [day6-privileged-account-rule-configuration.png](day6-privileged-account-rule-configuration.png) | 4 | Historical correlation result | Historical SID correlation query returns soclab-tempadmin, matching SID, Administrators group and creation/privilege times; despite its filename, this is KQL result evidence, not scheduled-rule configuration. | [KQL](../detections/privileged-account-correlation.kql) | [INC-004](../incidents/INC-004-privileged-account-investigation.md) |
| [day6-privileged-account-rule-verified-cloudshell.png](day6-privileged-account-rule-verified-cloudshell.png) | 4 | Scheduled-rule verification | Cloud Shell verifies enabled High rule, PT5M frequency, PT30M lookback, GreaterThan 0, createIncident=true, PrivilegeEscalation and T1098. | [KQL](../detections/privileged-account-correlation.kql) | [INC-004](../incidents/INC-004-privileged-account-investigation.md) |
| [day6-privileged-account-security-alert.png](day6-privileged-account-security-alert.png) | 4 | SecurityAlert | High named scheduled-rule alerts are visible at 04:17 and 04:22 UTC on 2026-09-13; they predate the 04:44/04:45 second-account simulation. | [KQL](../detections/privileged-account-correlation.kql) | [INC-004](../incidents/INC-004-privileged-account-investigation.md) |
| [day6-privileged-account-security-incident.png](day6-privileged-account-security-incident.png) | 4 | SecurityIncident | Incident 46 is New, High, at 04:22:17 UTC on 2026-09-13; it predates second-account telemetry and does not display AlertIds. | [KQL](../detections/privileged-account-correlation.kql) | [INC-004](../incidents/INC-004-privileged-account-investigation.md) |

## Day 7 — Scenario 5 

| Filename | Scenario | Evidence stage | What the image proves / visible limits | Detection | Incident report |
|---|---|---|---|---|---|
| [day7-4688-certutil-ingestion.png](day7-4688-certutil-ingestion.png) | 5 | Earlier Log Analytics ingestion | SecurityEvent returns an earlier certutil decode event at 21:12:27 UTC with cmd.exe parent; not the fresh record 15852. | [KQL](../detections/suspicious-process-detection.kql) | [INC-005](../incidents/INC-005-suspicious-process-investigation.md) |
| [day7-certutil-safe-simulation.png](day7-certutil-safe-simulation.png) | 5 | Safe simulation / endpoint 4688 | Endpoint capture shows benign marker, DecodeVerified=True (source/decoded hash comparison), 4688 record 15852, account, certutil decode command and PowerShell parent; it is an evidence-extraction capture, not the full simulation script. | [KQL](../detections/suspicious-process-detection.kql) | [INC-005](../incidents/INC-005-suspicious-process-investigation.md) |
| [day7-fresh-certutil-telemetry.png](day7-fresh-certutil-telemetry.png) | 5 | Fresh Log Analytics ingestion | SecurityEvent shows fresh record 15852 at 21:39:58.1740411 UTC, LAB-WIN01, azureadmin, timestamped decode paths and PowerShell parent. | [KQL](../detections/suspicious-process-detection.kql) | [INC-005](../incidents/INC-005-suspicious-process-investigation.md) |
| [day7-suspicious-process-detection-kql.png](day7-suspicious-process-detection-kql.png) | 5 | Manual query text | Shows a simpler manual 24-hour certutil/4688/decode query. No results pane is visible; it does not independently prove successful execution or the deployed 15-minute query. | [KQL](../detections/suspicious-process-detection.kql) | [INC-005](../incidents/INC-005-suspicious-process-investigation.md) |
| [day7-suspicious-process-rule-verified-cloudshell.png](day7-suspicious-process-rule-verified-cloudshell.png) | 5 | Scheduled rule / deployed KQL | Cloud Shell displays the full stored query and enabled Scheduled rule: Medium, PT5M, PT15M, GreaterThan 0, createIncident=True, DefenseEvasion and T1140. | [KQL](../detections/suspicious-process-detection.kql) | [INC-005](../incidents/INC-005-suspicious-process-investigation.md) |
| [day7-suspicious-process-security-alert.png](day7-suspicious-process-security-alert.png) | 5 | SecurityAlert | SecurityAlert shows named Medium Suspicious Certutil Decode Process alert at 21:46:03.9275618 UTC from ASI Scheduled Alerts / Azure Sentinel; underlying event entities are not expanded. | [KQL](../detections/suspicious-process-detection.kql) | [INC-005](../incidents/INC-005-suspicious-process-investigation.md) |
| [day7-suspicious-process-security-incident.png](day7-suspicious-process-security-incident.png) | 5 | SecurityIncident | SecurityIncident shows same-title incidents 53, 54 and 55. Expanded incident 55 is New, Medium, created 21:56:16.25 UTC; its AlertIds differs from the separately displayed alert ID. | [KQL](../detections/suspicious-process-detection.kql) | [INC-005](../incidents/INC-005-suspicious-process-investigation.md) |

