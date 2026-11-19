# SOC Case — Process Injection / DLL Injection via CreateRemoteThread (T1055.001)

**Week:** WEEK-3-MALWARE-AND-NETWORK
**Case ID:** SOC-Case-Process-Injection
**Severity:** High
**MITRE ATT&CK:** T1055 (Process Injection) — primary; **T1055.001 (Dynamic-link Library Injection)** specific vector
**Ancillary techniques:** T1105 (Ingress Tool Transfer — `certutil -urlcache` LOLBin download)

## Summary

An attacker cross-compiles a custom Windows injector (`injector.exe`) on Kali with MinGW and delivers it, together with a malicious payload DLL (`inject.dll`), to the victim's `C:\Users\Public\` folder using `certutil -urlcache`. The injector takes a target PID (a benign `notepad.exe` launched by the logged-on user) and the DLL path, then performs the classic **OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread(LoadLibraryA)** chain to force `notepad.exe` to load `inject.dll`. The DLL's `DllMain` fires on `DLL_PROCESS_ATTACH` and pops a "PWNED" message box as proof of arbitrary code execution **inside a legitimate, signed Microsoft process** — a defense-evasion win. The defender detects it via a single high-fidelity **Sysmon Event ID 8 (CreateRemoteThread)** record in Wazuh archives, with `StartFunction: LoadLibraryA` as the smoking gun.

## Environment

| Role | Host | IP | Wazuh agent |
|---|---|---|---|
| Victim (Windows 10 Home, workgroup) | DESKTOP-F0JVTQT | 192.168.100.108 | `winhome01` (agent.id 002) |
| Attacker (Kali, hostname `butch`) | — | **192.168.100.107** (observed this run) | — |
| SIEM | Wazuh manager `wazuh-server` | 192.168.100.102 | — |

Logged-on victim user: `DESKTOP-F0JVTQT\bryll`. Injection was **same-user / same integrity** (bryll → bryll) — no privilege escalation required to inject into a medium-IL process owned by the same user.

## Key Evidence (single Sysmon 8 event)

- **Source (injector):** `C:\Users\Public\injector.exe`, PID **3128**, ProcessGuid `{03477e4a-0775-6af7-5b14-000000000800}`, user `DESKTOP-F0JVTQT\bryll`. Cross-compiled with `x86_64-w64-mingw32-gcc`, size **270465 bytes**.
- **Target (victim process):** `C:\Windows\System32\notepad.exe`, PID **2052**, ProcessGuid `{03477e4a-96ba-6af4-b112-000000000800}`, user `DESKTOP-F0JVTQT\bryll`.
- **Remote thread:** NewThreadId **912**, StartAddress `0x00007FFADC2E0C50`, StartModule `C:\Windows\System32\KERNEL32.DLL`, **StartFunction `LoadLibraryA`** (smoking gun).
- **Payload DLL:** `C:\Users\Public\inject.dll` (path written into target memory by the injector; loaded via `LoadLibraryA` in the remote thread). `DllMain` → `MessageBoxA("Injected into remote process - code exec", "PWNED", MB_OK | MB_ICONINFORMATION)`.
- Sysmon `ruleName`: `technique_id=T1055, technique_name=Process Injection` (SwiftOnSecurity config).
- Sysmon `utcTime`: **`2026-11-13 12:49:57.225`** (UTC) = `2026-11-13 20:49:57` PHT (UTC+8) on the dashboard. `eventRecordID` **12279**.

## Documents

| File | Contents |
|---|---|
| `01-Scenario.md` | Threat scenario & objectives |
| `02-Attack-Simulation.md` | Full injector source + step-by-step reproduction |
| `03-Alert.md` | Detection query & recommended Wazuh custom rule |
| `04-Indicators.md` | IOCs (IPs, paths, PIDs, GUIDs, thread ID) |
| `05-Investigation.md` | Hunter workflow & event expansion |
| `06-Timeline.md` | Observed timeline (clock consistency noted) |
| `07-Analysis.md` | Why one Sysmon 8 event is sufficient; limitations |
| `08-Conclusion.md` | Findings & lessons learned |
| `09-Remediation.md` | Hardening & detection engineering |
| `kali-commands.txt` | Exact Kali-side commands |

## Evidence screenshots (referenced by exact filename — not embedded)

- `evidence/01-win-target-process.png` — launch `notepad.exe`, confirm PID **2052** via `tasklist`
- `evidence/02-kali-malicious-exe-built.png` — MinGW cross-compile of `injector.exe` + `ls` size **270465** bytes
- `evidence/kali-injector.c-exe-payload.png` — `injector.c` source open in `nano` on Kali
- `evidence/04-win-injection-popup.png` — `certutil` download, injector execution, and "PWNED" MessageBox popup
- `evidence/wazuh-sysmon8-expanded.png` — expanded Sysmon EID 8 JSON document in Wazuh (the smoking gun)

## Notes / honesty flags

- Only **Sysmon EID 8** was captured as a Wazuh screenshot. Corroborating events (Sysmon 1 `injector.exe` process creation, Sysmon 10 `OpenProcess`/ProcessAccess, Sysmon 7 `inject.dll` image load into notepad, Sysmon 11 file creation, Sysmon 1 `certutil` download, Kali HTTP server log) were **not captured this run** — recommended follow-up queries are in `03-Alert.md`.
- `inject.dll` source, build command, and file hash were **not captured**; its behavior is inferred from the observed "PWNED" popup. An illustrative source that reproduces the popup exactly is included in `02-Attack-Simulation.md`, clearly labeled.
- `injector.exe` hash was **not captured** (size only: 270465 bytes). Recommend `Get-FileHash` / Sysmon 1 `hashes` field follow-up.
- Delivery of `inject.dll` to `C:\Users\Public\` was **not captured** in screenshots; only the `injector.exe` `certutil` download is shown. The DLL was present at execution time (injector succeeded).
- **No real-time Wazuh alert fired**; detection was a **hunting query** against `wazuh-archives-*`. A recommended custom rule (`100264`) is provided in `03-Alert.md`.
- Screenshot numbering has a gap (no `03-*` file); filenames are referenced exactly as provided.
- Attacker IP observed this run = `192.168.100.107` (Week 2/3 pattern; Week-1 cases observed `.106`). Document the observed value.
- Clock check: Kali build mtime `Nov 13 07:48` (EST, UTC-5) = `12:48 UTC`; Sysmon injection `12:49:57.225 UTC` — ~2 min later, **consistent, no skew this run**.
