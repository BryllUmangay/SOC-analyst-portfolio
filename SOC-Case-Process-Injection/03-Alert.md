# 03 — Alert / Detection

## How this case was detected

**No real-time Wazuh alert fired.** Detection was a **proactive hunting query** against the Wazuh archives index (`wazuh-archives-*`, time field `timestamp`, DQL syntax — not Lucene):

```
data.win.system.eventID: 8
```

Refined to the smoking-gun pattern:

```
data.win.system.eventID: 8 AND data.win.eventdata.startFunction: "LoadLibraryA"
```

Result: the **Sysmon EID 8 (CreateRemoteThread)** event at `2026-11-13 12:49:57.225 UTC`, `eventRecordID 12279`, agent `winhome01`.

## Expanded event (the smoking gun)

Expanded JSON document — key fields (→ `evidence/wazuh-sysmon8-expanded.png`):

| Field | Value |
|---|---|
| `agent.name` / `agent.id` | `winhome01` / `002` (192.168.100.108) |
| `data.win.system.eventID` | **8** (CreateRemoteThread) |
| `data.win.system.eventRecordID` | **12279** |
| `data.win.system.providerName` / `providerGuid` | `Microsoft-Windows-Sysmon` / `{5770385f-c22a-43e0-bf4c-06f5698ffbd9}` |
| `data.win.system.level` / `keywords` / `opcode` | `4` (Information) / `0x8000000000000000` / `0` |
| `data.win.system.processID` | `8312` (logging process) |
| `data.win.eventdata.utcTime` | **`2026-11-13 12:49:57.225`** |
| `data.win.eventdata.ruleName` | `technique_id=T1055, technique_name=Process Injection` |
| `data.win.eventdata.sourceProcessId` | **3128** |
| `data.win.eventdata.sourceImage` | **`C:\Users\Public\injector.exe`** |
| `data.win.eventdata.sourceProcessGuid` | `{03477e4a-0775-6af7-5b14-000000000800}` |
| `data.win.eventdata.sourceUser` | `DESKTOP-F0JVTQT\bryll` |
| `data.win.eventdata.targetProcessId` | **2052** |
| `data.win.eventdata.targetImage` | **`C:\Windows\System32\notepad.exe`** |
| `data.win.eventdata.targetProcessGuid` | `{03477e4a-96ba-6af4-b112-000000000800}` |
| `data.win.eventdata.targetUser` | `DESKTOP-F0JVTQT\bryll` |
| `data.win.eventdata.newThreadId` | **912** |
| `data.win.eventdata.startAddress` | `0x00007FFADC2E0C50` |
| `data.win.eventdata.startModule` | `C:\Windows\System32\KERNEL32.DLL` |
| `data.win.eventdata.startFunction` | **`LoadLibraryA`** ← smoking gun |

**Why this is high fidelity:** a remote thread whose start address resolves to `KERNEL32.DLL!LoadLibraryA` (or `LoadLibraryW` / `LdrLoadDll` / `ntdll!RtlUserThreadStart` pointing at shellcode) launched by a non-system binary in `C:\Users\Public\` against a signed Microsoft binary is, for all practical purposes, never legitimate. Legitimate software very rarely uses `CreateRemoteThread` at all, and never with `LoadLibraryA` from a user-writable drop path.

## Recommended Wazuh custom rule (for real-time alerting)

Local rule IDs used so far: `100220–100253`, `100260–100263`. Add as **`100264`** in `/var/ossec/etc/rules/local_rules.xml`, then `sudo systemctl restart wazuh-manager`:

```xml
<rule id="100264" level="13">
  <!-- Sysmon EID 8 CreateRemoteThread with LoadLibrary* start function = DLL injection (T1055.001) -->
  <field name="win.system.eventID">^8$</field>
  <field name="win.eventdata.startFunction">^LoadLibrary(A|W)$|LdrLoadDll</field>
  <description>Sysmon EID 8: $(win.eventdata.sourceImage) created remote thread $(win.eventdata.newThreadId) in $(win.eventdata.targetImage) at $(win.eventdata.startModule)!$(win.eventdata.startFunction) — DLL injection (T1055.001)</description>
  <mitre>
    <id>T1055</id>
    <id>T1055.001</id>
  </mitre>
</rule>
```

> Parent this under your Wazuh build's Sysmon/Windows base rule group (verify the correct `<if_sid>` for Sysmon events in your version; if uncertain, match on `win.system.providerName: Microsoft-Windows-Sysmon` + `win.system.eventID: 8`). Confirm the rule fires against this exact captured event before relying on it. Optionally add a frequency/correlation rule (e.g., 3× EID 8 from one sourceImage in 60s → level 14) for injection sprees.

## Companion hunting queries (DQL, `wazuh-archives-*`)

```
# Primary: all CreateRemoteThread events
data.win.system.eventID: 8

# Corroborate 1 — injector process creation (Sysmon 1) — NOT captured this run
data.win.system.eventID: 1 AND data.win.eventdata.image: "*injector.exe"

# Corroborate 2 — OpenProcess / ProcessAccess to notepad (Sysmon 10) — NOT captured this run
data.win.system.eventID: 10 AND data.win.eventdata.targetImage: "*notepad.exe"
#   look for GrantedAccess containing 0x1F0FFF / 0x143A / 0x1FFFFF (injection rights)

# Corroborate 3 — inject.dll image load inside notepad (Sysmon 7) — NOT captured this run
data.win.system.eventID: 7 AND data.win.eventdata.image: "*notepad.exe" AND data.win.eventdata.imageLoaded: "*inject.dll"

# Corroborate 4 — certutil LOLBin download (Sysmon 1) — NOT captured this run
data.win.system.eventID: 1 AND data.win.eventdata.image: "*\\certutil.exe" AND data.win.eventdata.commandLine: "*urlcache*"

# Corroborate 5 — file creation of injector.exe / inject.dll in C:\Users\Public (Sysmon 11) — NOT captured
data.win.system.eventID: 11 AND data.win.eventdata.targetFilename: "*\\Users\\Public\\inject*"

# Corroborate 6 — outbound HTTP 80 to Kali from certutil (Sysmon 3) — NOT captured
data.win.system.eventID: 3 AND data.win.eventdata.image: "*\\certutil.exe" AND data.win.eventdata.destinationIp: 192.168.100.107
```
