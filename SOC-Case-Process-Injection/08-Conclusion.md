# 08 — Conclusion

## Findings

1. **Adversary success:** A custom MinGW-compiled injector (`C:\Users\Public\injector.exe`, 270465 bytes, PID 3128) successfully performed classic `OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread(LoadLibraryA)` DLL injection into a benign `notepad.exe` (PID 2052) owned by the same user (`bryll`). The payload `C:\Users\Public\inject.dll` executed inside notepad and proved code execution with a "PWNED / Injected into remote process - code exec" MessageBox. **No privilege escalation was required.**
2. **Delivery:** `certutil -urlcache` (LOLBin, T1105) pulled `injector.exe` from Kali at `192.168.100.107:80`. `inject.dll` delivery was not captured but must have occurred (injector succeeded).
3. **Detection:** A single **Sysmon EID 8 (CreateRemoteThread)** event (`eventRecordID 12279`, `2026-11-13 12:49:57.225 UTC`, agent `winhome01`) is independently conclusive: `SourceImage C:\Users\Public\injector.exe` → `TargetImage notepad.exe` → `StartFunction LoadLibraryA` (NewThreadId 912, StartModule `KERNEL32.DLL`). The `ruleName` tag `technique_id=T1055, technique_name=Process Injection` confirms the SwiftOnSecurity config flagged it.
4. **No real-time alert fired** — detection was a retrospective archive hunt. A custom Wazuh rule (`100264`, level 13) is provided in `03-Alert.md` to make the next occurrence real-time.
5. **Clock:** clean this run — Kali build (07:48 EST = 12:48 UTC) → injection (12:49:57 UTC) ≈ 2 min, consistent.

## Lessons learned (portfolio talking points)

- **Sysmon EID 8 is the crown-jewel detection for DLL injection** — enable it in your config and alert on it; it is far higher fidelity than process-creation alone.
- The **SourceImage / TargetImage / StartFunction triad** is the analyst's 3-second triage. User-writable source path + signed-system target + `LoadLibrary*` = escalate.
- **Same-user injection needs no admin.** Don't assume "no admin = no risk." Medium-IL processes are injectable by any code running as the same user.
- **LOLBin delivery (`certutil -urlcache`) bypasses "suspicious PowerShell" heuristics** — monitor Sysmon EID 1 command lines for `urlcache`, `split`, `-f`, and outbound HTTP from `certutil.exe`.
- **Capture the full event chain on a re-run:** EID 1 (injector + certutil), EID 3 (network), EID 7 (DLL load, `signed:false`), EID 8 (smoking gun), EID 10 (`GrantedAccess`), EID 11 (file drops), plus file hashes. EID 8 alone proves the technique; the rest prove scope and attribution.
- **Hashing dropped files on the way out** (`Get-FileHash` before cleanup) turns a narrative into blocklistable IOCs.

## What I would do differently on a re-run

1. Capture `Get-FileHash` of both files before deleting.
2. Screenshot Wazuh Discover hits for EID 1, 3, 7, 10, 11 in addition to EID 8.
3. Capture the Kali `python3 -m http.server` access log (proves both GETs from .108).
4. Keep the same Sysmon config but add the `100264` rule *before* the run so a real-time alert fires — screenshot the Wazuh Security Events alert.
5. Optionally re-run with the injector targeting an elevated process (expected `OpenProcess failed: 5`) to demonstrate the integrity boundary — good portfolio contrast.
