# 04 — Indicators (IOCs)

## Network indicators
| Indicator | Value |
|---|---|
| Attacker IP | `192.168.100.107` (Kali) |
| Target IP | `192.168.100.108` (winhome01) |
| Target port | TCP/445 (SMB), also TCP/139 (NetBIOS) |
| Protocol | SMB / NTLMSSP authentication |

## Host / account indicators
| Indicator | Value |
|---|---|
| Targeted usernames | `jdoe`, `mreyes`, `adminlab`, `administrator`, `guest` |
| Compromised accounts | `jdoe` (`Password1`, first compromise) + `adminlab` (`P@ssw0rd`, local administrator) |
| Guessed passwords | `Password1` (jdoe), `P@ssw0rd` (adminlab) — lab-only |
| Locked-out account | `mreyes` (4740; lockout threshold = 5 failures) |
| Logon type | `3` (Network — SMB share access) |
| Authentication package | NTLM |
| Target domain name | `DESKTOP-F0JVTQT` (local machine, workgroup) |

## Windows Event IDs
| Event ID | Meaning | Count (observed) |
|---|---|---|
| **4625** | An account failed to log on | **41** — logon type 3, NTLM; Status `0xC000006D`, SubStatus `0xC000006A` |
| **4740** | A user account was locked out | **1** — `mreyes` |
| **4624** | An account successfully logged on (type 3) | **2** — `jdoe`, then `adminlab` |
| **4648** | A logon was attempted using explicit credentials | not observed in captured telemetry |

## Status / SubStatus codes (inside 4625)
| Code | Field | Meaning |
|---|---|---|
| `0xC000006D` | Status | "The user name or password is incorrect" — top-level failure on every 4625 in this case |
| `0xC000006A` | SubStatus | User name exists but password wrong (the bulk — `jdoe`, `mreyes`, `adminlab` guesses) |
| `0xC0000064` | SubStatus | User name does not exist (`guest` / `administrator` don't exist locally on Win10 Home) |
| `0xC0000234` | SubStatus | User account currently locked out (after `mreyes` hit threshold) |
| `0x0` | — | Success — seen in the two 4624s |

## Wazuh / SIEM indicators
| Indicator | Value |
|---|---|
| Wazuh rule (single failure) | `18106` — fired per 4625 (low severity) |
| Wazuh rule (brute-force correlation) | not captured — no high-severity correlation alert observed → custom rule in `09-Remediation.md` |
| Wazuh rule (lockout / 4740) | not captured in screenshots |
| Archives index pattern | `wazuh-archives-*` — every 4625 raw event searchable |
| Detection query | `data.win.system.eventID:4625 AND data.win.eventdata.ipAddress:"192.168.100.107"` |

## Tooling indicator (attack-side — documented honestly)
- **Hydra (`smb://`) → no telemetry.** SMBv1 disabled on target; Hydra's SMB module could not negotiate modern dialect → zero pairs returned, zero 4625s generated.
- **NetExec → full attack.** Produced all 41 failures + 2 successes + 1 lockout.
- **Defender lesson:** absence of 4625 telemetry ≠ attack stopped — may mean the tool never reached the authentication stage.

## Behavioral indicators
- Burst of 4625 events (dozens) from a **single source IP** within minutes → brute force.
- Failures concentrated on **one or few accounts** → password guessing; failures spread across **many accounts** with one password → password spray (Week-1 case #2).
- A **4624 success immediately following** the burst → brute force succeeded (compromise).
