# 06 — Detection Engineering

How the incidents became detection content. Rules target attacker **behaviour**, not the indicators from this lab, so they still fire when the infrastructure changes.

---

## Approach

```text
incident ─▶ what behaviour gave the attacker away? ─▶ which log source sees it?
         ─▶ Sigma rule (portable) ─▶ SPL / KQL hunt (aggregation and context)
         ─▶ false positives and tuning notes
```

| Principle | How it is applied |
|---|---|
| Behaviour over indicators | `w3wp.exe` spawning a shell, not "IP 203.0.113.55" |
| Portable first | Sigma for the single-event logic; SIEM queries for thresholds and correlation |
| Documented false positives | Every rule lists what legitimate activity could trigger it |
| Severity reflects action needed | `critical` means isolate now (recovery inhibition); `medium` means review (single spray failures) |

---

## Sigma Rules

| Rule | Logic | Level | False positives |
|---|---|---|---|
| [Kerberos password spray](../detections/sigma/win_kerberos_password_spray.yml) | 4771 with status `0x18` (bad password); threshold in the SIEM | medium | Stale cached passwords, mobile mail after a password change |
| [Kerberoasting via RC4 TGS](../detections/sigma/win_kerberoasting_rc4_tgs.yml) | 4769 with `0x17` encryption, excluding machine accounts and `krbtgt` | high | Legacy RC4-only applications |
| [Shadow copy or backup deletion](../detections/sigma/proc_inhibit_system_recovery.yml) | `vssadmin delete shadows` or `wbadmin delete` | critical | Backup software maintenance |
| [IIS worker spawns shell](../detections/sigma/proc_webserver_spawns_shell.yml) | Parent `w3wp.exe`, child cmd, PowerShell, schtasks or whoami | high | Rare application health checks |
| [Office spawns encoded PowerShell](../detections/sigma/proc_office_spawns_encoded_powershell.yml) | Word, Excel or Outlook parent, PowerShell child with `-enc` | high | Signed internal add-ins |
| [Inbox rule hides or forwards mail](../detections/sigma/m365_inbox_rule_hide_or_forward.yml) | `New-InboxRule`/`Set-InboxRule` with move, forward, redirect or delete | high | Users organising their own mail |
| [Service account logon from workstation](../detections/sigma/win_service_account_network_logon_from_workstation.yml) | `svc_backup` type 3 logon not from the backup server | high | Backup server IP change |

---

## SIEM Hunts

| # | Hunt | Splunk | Sentinel |
|---|---|---|---|
| 1 | Password spray by distinct accounts per IP | ✅ | ✅ |
| 2 | Spray success: targeted accounts that then logged on | ✅ | ✅ |
| 3 | Kerberoasting burst | ✅ | ✅ |
| 4 | Recovery inhibition | ✅ | ✅ |
| 5 | Beaconing by interval regularity | ✅ | ✅ |
| 6 | Web shell process tree | ✅ | ✅ |
| 7 | WAF allowed injection | ✅ | — |
| 8 | BEC inbox rules | ✅ | ✅ |
| 9 | Office macro dropper | ✅ | ✅ |
| 10 | Service account off its host | ✅ | — |
| — | MFA fatigue | — | ✅ |

Files: [`splunk_hunts.spl`](../detections/splunk_hunts.spl), [`sentinel_hunts.kql`](../detections/sentinel_hunts.kql).

---

## Testing Plan

| Step | Method |
|---|---|
| Syntax | `sigma check` on every rule |
| Conversion | `sigma convert -t splunk -p sysmon` and `-t microsoft365defender` |
| True positive | Run each hunt against the case `evidence/events.csv` loaded into Splunk as a lookup or index |
| False positive | Run against a week of baseline data and record hits in the rule's `falsepositives` |

Conversion commands are in the [detections README](../detections/README.md).
