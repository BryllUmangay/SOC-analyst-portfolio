# 01 — Scenario

## Adversary scenario

An adversary has obtained low-privileged code execution or physical/lateral access to a Windows 10 workstation (`DESKTOP-F0JVTQT`, user `bryll`) and wants to establish reliable, userland execution without dropping an obviously malicious `.exe` that might be flagged by application control. Instead the adversary plants a pair of files in a user-writable directory:

1. A **legitimate-looking or custom vulnerable application** (`vulnapp.exe`) that loads a DLL by **bare name only** — `LoadLibraryA("hijackme.dll")` — with no absolute path and no manifest controlling the search path.
2. A **malicious DLL** (`hijackme.dll`) placed in the **same directory** as the EXE.

When `vulnapp.exe` runs, Windows resolves the bare DLL name using the **DLL search order**. With SafeDllSearchMode enabled (default), the application directory is searched **before** system directories — so the attacker's `hijackme.dll` in `C:\Users\Public\hijack\` is loaded in preference to any system copy. `DllMain` executes automatically with the privileges of the loading process (here, `DESKTOP-F0JVTQT\bryll`), giving the adversary arbitrary code execution. In this lab the payload is a benign `MessageBoxA` pop-up titled **"PWNED"** as proof of execution; in the wild it would be a C2 beacon, credential stealer, or loader.

## Why this matters for a SOC

- DLL search-order hijacking is a staple of **defense evasion** and **persistence**: malware (e.g., APT groups, commodity loaders) frequently side-load malicious DLLs next to signed, trusted EXEs to inherit their reputation and bypass application allowlisting.
- The only reliable, low-noise telemetry for it is **Sysmon Event ID 7 (Image Loaded)** — which most organizations disable or over-filter because it is high-volume. This case demonstrates that a well-tuned Sysmon config (SwiftOnSecurity) plus a short Wazuh hunting query produces a **single, high-fidelity hit**.
- The ingress vector here is also a LOLBin: `certutil.exe -urlcache` (T1218.007-adjacent / T1105), a common living-off-the-land downloader.

## Objective of this case

Reproduce a minimal DLL search-order hijack end to end, capture the victim-side telemetry in Wazuh, and prove that **one Sysmon 7 event** — unsigned DLL loaded from a user-writable path by an unsigned EXE in the same path — is enough to escalate a high-confidence incident.

## Screenshot reference

- Source code of both binaries: `evidence/01-payload.png`
