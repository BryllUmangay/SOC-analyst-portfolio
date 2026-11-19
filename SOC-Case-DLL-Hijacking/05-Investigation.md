# 05 — Investigation

## Hunter workflow (what was actually done)

1. **Hypothesis-driven hunt:** unsigned DLLs loaded from user-writable directories are a classic T157.001 signal. Query `wazuh-archives-*` for Sysmon EID 7 filtered to the suspected DLL name.
2. **Query:** `data.win.system.eventID: 7 AND data.win.eventdata.imageLoaded: *hijackme*` → **1 hit** on agent `winhome01` at `Nov 12, 2026 00:01:51.983` (dashboard local). → `evidence/05-wazuh-sysmon7.png`
3. **Expand the document** → full JSON. → `evidence/06-wazuh-sysmon7-expanded.png`
4. **Pivot fields:**
   - `imageLoaded` = `C:\Users\Public\hijack\hijackme.dll` — user-writable path, `signed: false`.
   - `image` (loading process) = `C:\Users\Public\hijack\vulnapp.exe` — **same directory**, also unsigned, empty version/company/product metadata (MinGW-compiled, unbranded).
   - `user` = `DESKTOP-F0JVTQT\bryll`; `processId` `7472`; `processGuid` `{03477e4a-916e-6af4-7012-000000000800}`.
   - `ruleName` already tagged `T1574.001` by the SwiftOnSecurity Sysmon config.
5. **Confidence escalation:** co-located unsigned EXE + unsigned DLL in `C:\Users\Public\` + bare-name load = high-confidence DLL search-order hijack. Escalate as **High**.

## Evidence chain (captured)

| Link | Evidence | Screenshot |
|---|---|---|
| Malicious source authored | `vulnapp.c` (bare `LoadLibraryA`), `evil.c` (MessageBox payload) | `01-payload.png` |
| Binaries built on Kali | sizes 87,775 / 122,421 bytes | `02-kali-binaries-built.png` |
| Binaries landed on victim | `certutil -urlcache` from `192.168.100.107`; `dir` confirms sizes + `11/11/2026 8:01 AM` write times | `03-win-binaries-planted.png` |
| Code execution confirmed | MessageBox `PWNED / DLL Hijack OK - code executed` | `04-win-payload-executed.png` |
| Detection telemetry | single Sysmon 7 hit in Wazuh archives | `05-wazuh-sysmon7.png` |
| Full forensics of the hit | expanded JSON: hashes, PID, GUID, paths, user, signed=false | `06-wazuh-sysmon7-expanded.png` |

## Recommended follow-up pivots (NOT captured this run — run these to harden the case)

These events **should exist** in the archives but were not screenshotted; query them to complete the kill chain:

1. **Sysmon 1 (Process Create)** — `certutil.exe` with `*urlcache*` command line; parent `powershell.exe`. Gives PID/parent chain and exact command line.
2. **Sysmon 3 (Network Connect)** — `certutil.exe` → `192.168.100.107:80` (two connections, one per file).
3. **Sysmon 11 (File Create)** — `vulnapp.exe` + `hijackme.dll` written to `C:\Users\Public\hijack\` by `certutil.exe`; **this would capture the hash of `hijackme.dll`**, which the EID 7 event does not.
4. **Sysmon 1 (Process Create)** — `vulnapp.exe` PID 7472 spawned by PowerShell; correlate ProcessGuid.
5. **Wazuh FIM** — if `C:\Users\Public\` is under syscheck, file-creation alerts should exist.
6. **HTTP server log on Kali** — two `GET /vulnapp.exe` and `GET /hijackme.dll` 200 responses from `192.168.100.108`.

## Containment (lab)

Delete `C:\Users\Public\hijack\*`, kill PID 7472 if still running, block `192.168.100.107` at egress (lab only), and reset `bryll`'s password if a real credential stealer payload is suspected.
