# 06 — Timeline

Event sequence and event counts are real (from Wazuh telemetry). Exact clock times were not captured in screenshots — fill the Time column from `wazuh-archives-*` if the index is still available.

Format: `YYYY-MM-DD HH:MM:SS` (Wazuh stores UTC; lab is UTC+8).

| # | Time (UTC+8) | Event | Source | Evidence |
|---|---|---|---|---|
| 1 | ______ | Attacker runs nmap scan of winhome01 (445/tcp open) | Kali | `01-kali-nmap-scan.png` |
| 2 | ______ | SMB null-session enumeration (netexec / smbclient) | Kali | `02-kali-smb-enum.png` |
| 3 | ______ | **Hydra attempted → FAILED** (SMBv1 disabled; no pairs returned, no 4625 telemetry). Attacker switches to NetExec → first 4625 | Kali → winhome01 | `03-kali-hydra-brute-force.png`, 07 |
| 4 | ______ | Burst of **41×4625** failures (NetExec) — rule 18106 fires repeatedly; all logon type 3, NTLM, SubStatus `0xC000006A` | Wazuh | 07, 11 |
| 5 | ______ | Lockout threshold (5) hit → **4740: `mreyes` locked out** | winhome01 | `09-wazuh-account-lockout-4740.png` |
| 6 | ______ | No high-severity correlation rule fired — only repeated low-severity 18106 (detection gap; custom rule → `09-Remediation.md`) | Wazuh | 07 |
| 7 | ______ | **First success: 4624 (type 3) as `jdoe`** (`Password1`) — brute force succeeded | winhome01 | `10-wazuh-successful-logon-4624.png` |
| 8 | ______ | **Second success: `adminlab:P@ssw0rd` → `(Pwn3d!)`** — local admin; ADMIN$ / C$ shares enumerated | Kali | `04-kali-netexec-brute-force.png`, `05-kali-successful-access.png` |
| 9 | ______ | SOC analyst acknowledges alert, begins triage (4625 burst → 4624 correlation) | Wazuh | — |
| 10 | ______ | Containment: `jdoe` + `adminlab` passwords rotated, attacker IP blocked, lockout policy verified | winhome01 | `14-remediation-lockout-policy.png` |

## Key correlation
The signature `[burst of 41×4625 from a single IP] → [4740 lockout] → [2×4624 success from the same IP]` within minutes is definitive for a **successful brute-force attack**. Note the **Hydra failure** (row 3): the first tool produced zero 4625s — a brute-force tool that generates no failure telemetry is failing at the protocol layer, not at password guessing. Documented in `07-Analysis.md`.
