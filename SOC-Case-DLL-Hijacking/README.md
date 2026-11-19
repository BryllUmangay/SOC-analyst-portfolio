# SOC Case — DLL Search Order Hijacking (T1574.001)

**Week:** WEEK-3-MALWARE-AND-NETWORK
**Case ID:** SOC-Case-DLL-Hijacking
**Severity:** High
**MITRE ATT&CK:** T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) — primary
**Ancillary techniques:** T1105 (Ingress Tool Transfer), T1218.007 (Signed Binary Proxy Execution: Mshta/Certutil — `certutil -urlcache` LOLBin)

## Summary

An unsigned, attacker-compiled executable (`vulnapp.exe`) calls `LoadLibraryA("hijackme.dll")` using a bare DLL name (no absolute path). Because Windows resolves bare DLL names through a search order and the application directory is searched first, a malicious `hijackme.dll` planted in the same directory is loaded and executed. The DLL's `DllMain` fires on `DLL_PROCESS_ATTACH` and pops a "PWNED" message box as proof of arbitrary code execution. The defender detects it via a single high-fidelity **Sysmon Event ID 7 (Image Loaded)** record in Wazuh archives.

## Environment

| Role | Host | IP | Wazuh agent |
|---|---|---|---|
| Victim (Windows 10 Home, workgroup) | DESKTOP-F0JVTQT | 192.168.100.108 | `winhome01` (agent.id 002) |
| Attacker (Kali, hostname `butch`) | — | **192.168.100.107** (observed this run) | — |
| SIEM | Wazuh manager `wazuh-server` | 192.168.100.102 | — |

Logged-on victim user: `DESKTOP-F0JVTQT\bryll`.

## Key Evidence (single Sysmon 7 event)

- Loading process: `C:\Users\Public\hijack\vulnapp.exe` (PID **7472**, ProcessGuid `{03477e4a-916e-6af4-7012-000000000800}`), unsigned, empty version/company/product fields.
- Loaded DLL (malicious): `C:\Users\Public\hijack\hijackme.dll`, `signed: false`, `SignatureStatus: Unavailable`.
- `vulnapp.exe` hashes: SHA1 `1BD1CE4A3C40E9973373D5A68F062E416BD11214`, MD5 `5675FDE1A801C900A8D10AD5E4D0F8D7`, SHA256 `CF8E8BE4D8E04C9CF983CFF0789F3993DBC11CF798DF014CB7B0659350FE243C`, IMPHASH `4647F0D2EB73045909425574099B68FA`.
- Sysmon `ruleName`: `technique_id=T1574.001,technique_name=DLL` (SwiftOnSecurity tag; name display-truncated).
- Sysmon `utcTime`: `2026-11-11 16:01:50.948` (UTC) = `2026-11-12 00:01:50` PHT (UTC+8).

## Documents

| File | Contents |
|---|---|
| `01-Scenario.md` | Threat scenario & objectives |
| `02-Attack-Simulation.md` | Step-by-step attack reproduction |
| `03-Alert.md` | Detection query & recommended Wazuh custom rule |
| `04-Indicators.md` | IOCs (hashes, IPs, paths, filenames) |
| `05-Investigation.md` | Hunter workflow & event expansion |
| `06-Timeline.md` | Observed timeline (clock-skew noted) |
| `07-Analysis.md` | Why one Sysmon 7 event is sufficient; limitations |
| `08-Conclusion.md` | Findings & lessons learned |
| `09-Remediation.md` | Hardening & detection engineering |
| `kali-commands.txt` | Exact Kali-side commands |

## Evidence screenshots (referenced by exact filename — not embedded)

- `evidence/01-payload.png` — `vulnapp.c` + `evil.c` source (Kali)
- `evidence/02-kali-binaries-built.png` — cross-compiled binaries + sizes
- `evidence/03-win-binaries-planted.png` — `certutil` download + `dir` on victim
- `evidence/04-win-payload-executed.png` — execution + "PWNED" MessageBox
- `evidence/05-wazuh-sysmon7.png` — Wazuh Discover DQL query, single hit
- `evidence/06-wazuh-sysmon7-expanded.png` — expanded Sysmon 7 JSON document

## Notes / honesty flags

- Only **one** Sysmon EID 7 event was captured — that is expected and sufficient (see `07-Analysis.md`).
- No real-time Wazuh alert fired; detection was a **hunting query** against `wazuh-archives-*`. A custom rule (`100253`) is provided in `03-Alert.md` for real-time detection.
- The SHA256/MD5/SHA1/IMPHASH captured in the EID 7 `hashes` field belongs to the **loading process** (`vulnapp.exe`), not the DLL. A hash of `hijackme.dll` was **not** captured in this run (recommend `Get-FileHash` / Sysmon 11 follow-up).
- Attacker IP observed this run = `192.168.100.107` (Kali DHCP/static; earlier Week-1 cases observed `.106`). Document the observed value.
- Recurring lab NTP/clock offset: file LastWriteTime (`11/11/2026 08:01` local) and Sysmon `utcTime` (`11/11 16:01:50 UTC`) are from separate planting/execution sessions; see `06-Timeline.md`.
