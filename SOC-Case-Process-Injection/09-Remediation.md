# 09 — Remediation & Hardening

## Immediate containment (this incident)

1. Kill the injected target: `taskkill /PID 2052 /F` (or close the injected `notepad.exe`). Injected memory is removed with the process.
2. Delete the drops: `del C:\Users\Public\injector.exe C:\Users\Public\inject.dll`.
3. Reset `bryll`'s password as a precaution (delivery implies the host was staged; assume the user context is compromised until proven clean).
4. Block attacker IP `192.168.100.107` at egress / isolate `winhome01` (lab: this is the Kali host).
5. Hunt EID 8 + EID 10 across all agents for the prior 7–30 days to confirm no other injection occurred.

## Detection engineering (Wazuh / Sysmon)

1. **Deploy custom rule `100264`** (level 13) for Sysmon EID 8 with `StartFunction = LoadLibraryA/W` or `LdrLoadDll`; add a frequency-override (e.g., 3× from one sourceImage in 60 s → level 14). See `03-Alert.md`.
2. **Add a Sysmon EID 10 rule** alerting on `GrantedAccess` masks `0x1F0FFF`, `0x143A`, `0x1FFFFF`, `0x1F3FFF` from non-whitelisted source images to system/signed targets (the `OpenProcess` precursor).
3. **Add a Sysmon EID 7 rule** for unsigned DLLs (`signed:false`) loaded from `\Users\Public\`, `\Downloads\`, `\AppData\`, `\Temp\` into signed system processes.
4. **LOLBin rule:** Sysmon EID 1 where `Image` ends with `certutil.exe` and `CommandLine` contains `urlcache` (T1105). Also watch `bitsadmin`, `powershell -enc`, `mshta`, `regsvr32 /s /n /u /i:`.
5. **Baseline EID 8** across the fleet; whitelist known-good remote-thread sources (debuggers, AV, backup agents) and alert on everything else.

## Endpoint hardening

1. **Enable Attack Surface Reduction (ASR) rules** (Windows 10 Pro/Enterprise; Home has limited ASR): "Block process creations originating from PSExec and WMI commands", "Block abuse of exploited vulnerable signed drivers", "Prevent credential theft" (LSASS protection). On Home, at minimum ensure Defender real-time + cloud protection is on and tamper protection enabled.
2. **Enable Windows Defender Application Control (WDAC) / AppLocker** where licensed — deny DLL/EXE execution from `C:\Users\Public\`, `%APPDATA%`, `%TEMP%`, `C:\Windows\Temp` (user-writable paths). This single control would have blocked both `injector.exe` execution and `inject.dll` load.
3. **Run standard user (no local admin)** for daily accounts — already the case here (`bryll` is not admin); injection still works same-user, but lateral escalation is contained.
4. **Restrict outbound HTTP/HTTPS** from workstations via a proxy; direct `certutil`/PowerShell fetches to arbitrary IPs should be blocked or alerted.
5. **Disable or monitor `certutil` URL cache** usage via application control / SRP; it is a top-tier LOLBin.
6. **Keep Sysmon current** and use a maintained config (SwiftOnSecurity / Olaf Hartong's Sysmon modular) with EID 8 and EID 10 enabled and tuned.

## Process / people

1. **User awareness:** `bryll` (or the initial-access vector) should not be running binaries from `C:\Users\Public` or browser-downloaded EXEs without review.
2. **IR playbook:** add a "Process Injection (T1055)" runbook step — on EID 8 alert: capture full memory of target process, pull `Get-FileHash` of source image, enumerate loaded modules (`listdlls -accepteula notepad.exe`), isolate host.
3. **Tabletop exercise:** use this case's timeline (`06-Timeline.md`) as a 15-minute detection-engineering tabletop — ask analysts which single event they'd alert on and why.

## Metrics to track after hardening

- Mean time to detect (MTTD) for EID-8-based alerts after rule `100264` is live (target: real-time, < 1 min).
- False-positive rate on rule `100264` (target: near-zero after baseline whitelist).
- Coverage: % of endpoints with Sysmon EID 8 + EID 10 logging enabled (target: 100%).
