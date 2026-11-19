# 07 — Analysis

## Why a single Sysmon EID 8 event is conclusive

Process injection via `CreateRemoteThread(LoadLibraryA)` has a **necessary, observable, high-fidelity step**: the injector must create a thread in the target process whose start routine is `LoadLibraryA`/`LoadLibraryW` (or `LdrLoadDll`, or shellcode). Sysmon EID 8 logs exactly that, with both process endpoints and the resolved start function. There is no way to perform this specific injection technique without generating EID 8 (short of unhooking/evading Sysmon itself, which was not in scope).

The three fields together form a signature that has essentially **zero legitimate positives** in a standard enterprise fleet:

1. `SourceImage` in a user-writable drop path (`\Users\Public\`, `\Downloads\`, `\AppData\Local\Temp\`, `\Windows\Temp\`).
2. `TargetImage` a signed system/LOLBIN binary (`notepad.exe`, `explorer.exe`, `svchost.exe`, `rundll32.exe`, browsers).
3. `StartFunction` = `LoadLibraryA` / `LoadLibraryW` / `LdrLoadDll`, or `StartModule` empty/unbacked (shellcode injection).

Legitimate `CreateRemoteThread` use exists (e.g., some debuggers, antivirus, `rundll32`-style tooling) but originates from signed, known-good images and rarely targets `LoadLibraryA` with a DLL path written from a Public folder. Baseline your fleet; anything outside the baseline is high-confidence malicious.

## Why the corroborating events (not captured) matter for a full case

EID 8 proves *that* injection happened and *which* processes were involved. It does **not** by itself prove:
- **What** DLL was loaded (the DLL path is written into target memory by `WriteProcessMemory` and is not in the EID 8 payload). → Need **Sysmon EID 7** (`imageLoaded = C:\Users\Public\inject.dll`, `signed: false`) to name and hash the module.
- **How** the injector got on disk and who ran it. → Need **Sysmon EID 1** (injector + certutil command lines, hashes, parent) and **EID 11** (file creation).
- **When** the handle was opened and with what rights. → Need **Sysmon EID 10** (`GrantedAccess` mask — `0x1F0FFF` full access or `0x143A`/`0x1FFFFF` injection-typical rights).

For a portfolio-grade case, capture all five (EID 1×2, EID 3, EID 7, EID 8, EID 10, EID 11). This run captured EID 8 only; the rest are documented as recommended follow-up and honest gaps.

## Injection mechanics vs. detection mapping

| Attacker action | WinAPI | Required rights | Detection (captured? ) |
|---|---|---|---|
| Open handle to notepad | `OpenProcess` | `PROCESS_CREATE_THREAD \| PROCESS_VM_OPERATION \| PROCESS_VM_WRITE \| PROCESS_VM_READ \| PROCESS_QUERY_INFORMATION` | Sysmon EID 10 — **not captured** |
| Allocate memory in target | `VirtualAllocEx` | (handle rights above) | no direct event |
| Write DLL path into target | `WriteProcessMemory` | `PROCESS_VM_WRITE` | no direct event |
| Start remote thread at LoadLibraryA | `CreateRemoteThread` | `PROCESS_CREATE_THREAD` | **Sysmon EID 8 — captured (smoking gun)** |
| notepad loads inject.dll | `LoadLibraryA` (in remote thread) | — | Sysmon EID 7 — **not captured** |
| Payload executes in notepad | `DllMain` → `MessageBoxA` | — | popup (visual proof) |

## Same-user / same-integrity observation

Both `SourceUser` and `TargetUser` are `DESKTOP-F0JVTQT\bryll`. The injector did **not** need admin rights: a process can open and inject into another process owned by the same user at the same integrity level. This is important for scoping: injection alone does **not** imply privilege escalation. Had the target been an elevated process (e.g., a SYSTEM service), `OpenProcess` would have failed with `ACCESS_DENIED` unless the injector ran elevated — which would show up as a high-IL source in EID 8/EID 10 and a UAC/4672 event.

## Severity rationale: High (not Critical)

- Arbitrary code execution achieved, but: no privilege escalation, no lateral movement, no persistence, no C2/data exfil observed (popup payload only).
- Single host, single user, trivially contained (kill notepad, delete two files).
- Critical would require escalation to SYSTEM/DA, lateral movement, or data impact. → **High** is consistent with the DLL-Hijacking case in this same week.

## Limitations / what this case does not show

- No reflective injection / direct syscalls / unhooking — if the injector had used `NtCreateThreadEx` + manual mapping with Sysmon unhooked, EID 8 might still fire (kernel-side callback) but `StartFunction` would be unbacked memory. Out of scope.
- No EDR/AV was challenged; Defender real-time protection state not recorded.
- `inject.dll` and `injector.exe` hashes not captured — cannot add to a blocklist from this run alone.
