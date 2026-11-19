# SOC Case — Brute Force Attack (SMB)

**Week:** 1 — Windows Fundamentals
**Lab:** Kali (`192.168.100.107`) → Windows 10 Home (`192.168.100.108`), detected by Wazuh SIEM (`192.168.100.102`)
**ATT&CK:** T1110.001 — Brute Force (Password Guessing)
**MITRE Tactic:** Credential Access
**Severity:** **Critical** — successful brute force against a local administrator account
**Status:** ✅ Completed — event sequence and counts are real; exact clock times in `06-Timeline.md` were not captured in screenshots (fill from Wazuh archives if still indexed)

## Case Structure
| File | Contents |
|---|---|
| `01-Scenario.md` | Background, assumed breach context, lab setup |
| `02-Attack-Simulation.md` | **Kali Linux step-by-step** (recon → Hydra *failed* → NetExec succeeded) |
| `03-Alert.md` | Wazuh alerts that fired (rule IDs, levels, MITRE mapping) |
| `04-Indicators.md` | IOCs: source IP, usernames, event IDs, status/substatus codes, tooling failure |
| `05-Investigation.md` | How to triage in Wazuh (Security Events + Discover/archives) |
| `06-Timeline.md` | Event timeline (real sequence/counts; exact times blank) |
| `07-Analysis.md` | What happened, logon type 3, Hydra vs NetExec, brute-force vs spray |
| `08-Conclusion.md` | Findings, severity rating, lessons learned |
| `09-Remediation.md` | Hardening, account lockout, custom Wazuh rule + Sigma rule |
| `evidence/` | All screenshots (filenames listed in `05-Investigation.md`) |
| `kali-commands.txt` | Copy-paste command sheet for the Kali side |

## Quick Result Summary
- Attacker IP: `192.168.100.107` (Kali)
- Target: `192.168.100.108` (winhome01), SMB TCP/445
- Total failed logons (4625): **41** — logon type 3, NTLM; Status `0xC000006D`, SubStatus `0xC000006A`
- Account lockouts (4740): **1** — `mreyes` (lockout threshold = 5)
- Successful logons (4624 type 3): **2** — `jdoe:Password1` (first compromise), then `adminlab:P@ssw0rd` (local admin, `(Pwn3d!)`, ADMIN$/C$ accessible)
- **Tooling failure documented:** Hydra (`smb://`) returned no pairs (SMBv1 disabled, zero 4625 telemetry); attack succeeded with NetExec. See `02-Attack-Simulation.md` Step 3 + `07-Analysis.md`.
- Wazuh rule fired: `18106` per 4625 (low severity); no high-severity correlation rule captured → custom rule in `09-Remediation.md`
- Outcome: attacker gained local-admin SMB access → contained, passwords rotated
