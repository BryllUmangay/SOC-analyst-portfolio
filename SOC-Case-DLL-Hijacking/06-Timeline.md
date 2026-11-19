# 06 — Timeline

> **Honesty flag (recurring lab issue):** the Windows victim clock and the Wazuh/Sysmon UTC clock show a large offset, and the file-planting vs. execution appear to be separate sessions. All timestamps below are recorded **exactly as observed** in the screenshots; no times have been normalized or fabricated. PHT = UTC+8 (Manila).

| # | Time (as observed) | Event | Source |
|---|---|---|---|
| 1 | `Nov 11 10:58` (Kali local) | `vulnapp.exe` (122,421 B) + `hijackme.dll` (87,775 B) cross-compiled on Kali | `02-kali-binaries-built.png` |
| 2 | — | Kali `python3 -m http.server 80` started on `192.168.100.107` | (runbook) |
| 3 | `11/11/2026 8:01 AM` (Windows local, victim) | `certutil -urlcache` downloads both files to `C:\Users\Public\hijack\`; `dir` confirms LastWriteTime | `03-win-binaries-planted.png` |
| 4 | `2026-11-11 16:01:50.948` UTC = `2026-11-12 00:01:50.948` PHT | `vulnapp.exe` (PID 7472) loads `hijackme.dll` — Sysmon EID 7 fires | `06-wazuh-sysmon7-expanded.png` (`utcTime`) |
| 5 | ~same moment | `DllMain` → MessageBox "PWNED / DLL Hijack OK - code executed" on victim desktop | `04-win-payload-executed.png` |
| 6 | `Nov 12, 2026 @ 00:01:51.983` (dashboard local PHT) | Event visible in Wazuh archives (`~1s` ingestion lag vs Sysmon `utcTime`) | `05-wazuh-sysmon7.png` |
| 7 | `Nov 12, 2026 ~00:07` (dashboard local) | Analyst runs hunting query, single hit, expands document | `05-wazuh-sysmon7.png` time picker |

## Time-offset notes

- Step 3 (file write, `08:01` Windows local) and Step 4 (DLL load, `16:01:50 UTC` = `00:01:50 PHT` next day) are separated by ~16 hours — consistent with **planting and execution being done in separate sessions**, plus the known recurring lab NTP skew (Windows local vs Sysmon UTC drift seen across Week-1 cases). Do not collapse them into one minute.
- The Wazuh dashboard timestamp (`00:01:51.983` PHT) and Sysmon `utcTime` (`16:01:50.948` UTC) agree within ~1 second, confirming the SIEM clock is correct; any skew is on the **Windows endpoint**. Fix by syncing the victim to the DC time authority once AD is fully deployed.
- Kali build time (`Nov 11 10:58`) is Kali-local and not correlated to the victim clock.

## Screenshot reference

- `evidence/02-kali-binaries-built.png` (build time)
- `evidence/03-win-binaries-planted.png` (file LastWriteTime)
- `evidence/05-wazuh-sysmon7.png` (dashboard event time + query window)
- `evidence/06-wazuh-sysmon7-expanded.png` (Sysmon `utcTime`)
