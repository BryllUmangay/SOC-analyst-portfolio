# 01 — Scenario

## Threat scenario

An adversary has obtained a foothold on a Windows 10 workstation (`winhome01`, `DESKTOP-F0JVTQT`, 192.168.100.108) in the context of regular user `bryll` (e.g., via a phishing download or a prior webshell — in this lab, manual staging). Rather than dropping a standalone malicious EXE that AV/EDR might flag on disk and in process lists, the adversary chooses **process injection**: they will force a benign, signed Microsoft process (`notepad.exe`) to load their malicious DLL, so the malicious code executes **inside notepad.exe** — hiding behind a legitimate process name, memory space, and network attribution.

This is a classic **defense evasion + execution** play (MITRE T1055 / T1055.001). In the wild, the injected DLL would typically establish C2, dump credentials, or perform lateral movement; in this lab it pops a "PWNED" message box as proof of code execution.

## Adversary objectives

1. Build a custom injector on Kali and cross-compile it for Windows.
2. Stage the injector + payload DLL on the victim via a LOLBin (`certutil -urlcache`) to avoid PowerShell download cradles.
3. Pick a benign target process owned by the same user (`notepad.exe`, PID 2052).
4. Execute the classic `OpenProcess → VirtualAllocEx → WriteProcessMemory → CreateRemoteThread(LoadLibraryA)` DLL-injection chain.
5. Confirm arbitrary code execution inside `notepad.exe` (payload popup).
6. (Adversary hope) avoid detection — no new suspicious process appears in Task Manager; only a thread inside notepad.

## Defender objectives

1. Detect the injection with **Sysmon Event ID 8 (CreateRemoteThread)** — the highest-fidelity signal for this technique.
2. Correlate `SourceImage` (unusual path `C:\Users\Public\injector.exe`) with `TargetImage` (legitimate `notepad.exe`) and `StartFunction = LoadLibraryA`.
3. Hunt for corroborating Sysmon events (EID 1, 7, 10, 11) and `certutil` LOLBin usage.
4. Write a Wazuh custom rule so the next occurrence fires a real-time alert.

## Scope & assumptions

- Victim is Windows 10 Home (workgroup), Wazuh agent `winhome01` + Sysmon (SwiftOnSecurity config) installed.
- Attacker is Kali (`butch`) at observed IP **192.168.100.107**, serving files over HTTP (port 80).
- Injection is same-user / same integrity (medium IL). No privilege escalation is demonstrated. (Injecting into a high-IL/system process would require the injector to run elevated.)
- Wazuh archives (`wazuh-archives-*`, time field `timestamp`, DQL query language) are enabled and retain the Sysmon events.

→ Target process launch & PID confirmation: `evidence/01-win-target-process.png`
