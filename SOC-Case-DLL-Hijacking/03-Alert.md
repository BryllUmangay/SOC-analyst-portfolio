# 03 — Alert / Detection

## How this case was detected

**No real-time Wazuh alert fired.** Detection was a **proactive hunting query** against the Wazuh archives index (`wazuh-archives-*`, time field `timestamp`, DQL syntax):

```
data.win.system.eventID: 7 AND data.win.eventdata.imageLoaded: *hijackme*
```

Time range: `Nov 11, 2026 @ 00:07:41.598 → Nov 12, 2026 @ 00:07:41.598` (dashboard local, PHT).

Result: **exactly 1 hit** — histogram shows a single count in the final bucket; the event table shows the record at `Nov 12, 2026 @ 00:01:51.983`.

→ `evidence/05-wazuh-sysmon7.png`

## Expanded event (the smoking gun)

Expanded JSON document — key fields:

| Field | Value |
|---|---|
| `agent.name` / `agent.id` / `agent.ip` | `winhome01` / `002` / `192.168.100.108` |
| `manager.name` | `wazuh-server` |
| `data.win.system.eventID` | `7` |
| `data.win.system.channel` | `Microsoft-Windows-Sysmon/Operational` |
| `data.win.system.providerGuid` | `{5770385f-c22a-43e0-bf4c-06f5698ffbd9}` (Sysmon) |
| `data.win.system.level` | `4` (Information) |
| `data.win.eventdata.image` | `C:\Users\Public\hijack\vulnapp.exe` |
| `data.win.eventdata.imageLoaded` | `C:\Users\Public\hijack\hijackme.dll` |
| `data.win.eventdata.processId` | `7472` |
| `data.win.eventdata.processGuid` | `{03477e4a-916e-6af4-7012-000000000800}` |
| `data.win.eventdata.utcTime` | `2026-11-11 16:01:50.948` |
| `data.win.eventdata.signed` | `false` |
| `data.win.eventdata.signatureStatus` | `Unavailable` |
| `data.win.eventdata.user` | `DESKTOP-F0JVTQT\bryll` |
| `data.win.eventdata.ruleName` | `technique_id=T1574.001,technique_name=DLL` (display-truncated) |
| `data.win.eventdata.hashes` (of **vulnapp.exe**) | SHA1 `1BD1CE4A3C40E9973373D5A68F062E416BD11214`, MD5 `5675FDE1A801C900A8D10AD5E4D0F8D7`, SHA256 `CF8E8BE4D8E04C9CF983CFF0789F3993DBC11CF798DF014CB7B0659350FE243C`, IMPHASH `4647F0D2EB73045909425574099B68FA` |
| FileVersion / Description / Product / Company / OriginalFileName | all empty (unbranded MinGW binary) |

→ `evidence/06-wazuh-sysmon7-expanded.png`

## Recommended Wazuh custom rule (for real-time alerting)

Existing local rule IDs used so far: `100220–100252`. Add as **`100253`** in `/var/ossec/etc/rules/local_rules.xml`, then `sudo systemctl restart wazuh-manager`:

```xml
<rule id="100253" level="13">
  <if_sid>61601</if_sid> <!-- Sysmon event 7 (Image Loaded) base rule; verify SID in your build -->
  <field name="win.eventdata.imageLoaded">\\Users\\Public\\|\\Downloads\\|\\AppData\\|\\Temp\\|\\\\Windows\\\\Temp\\</field>
  <field name="win.eventdata.signed">false</field>
  <description>Sysmon EID 7: unsigned DLL loaded from user-writable path by $(win.eventdata.image) — possible DLL search-order hijack (T1574.001)</description>
  <mitre>
    <id>T1574.001</id>
  </mitre>
</rule>
```

> If `61601` does not match your Wazuh version's Sysmon decoder SID, replace `<if_sid>` with a match on `win.system.eventID: 7` using `<field name="win.system.eventID">^7$</field>` and parent it to the generic Sysmon/Windows rule group. Confirm the rule fires against this exact event before relying on it.

## Companion hunting queries (DQL, `wazuh-archives-*`)

```
# All unsigned image-loads from user-writable paths (broad hunt)
data.win.system.eventID: 7 AND data.win.eventdata.signed: false AND data.win.eventdata.imageLoaded: (*\\Users\\* OR *\\Public\\* OR *\\Temp\\*)

# Corroborate: certutil LOLBin download (Sysmon 1)
data.win.system.eventID: 1 AND data.win.eventdata.image: "*\\certutil.exe" AND data.win.eventdata.commandLine: "*urlcache*"

# Corroborate: file creation in the hijack dir (Sysmon 11) — NOT captured this run, recommended follow-up
data.win.system.eventID: 11 AND data.win.eventdata.targetFilename: "*\\Users\\Public\\hijack\\*"

# Corroborate: outbound HTTP from certutil to Kali (Sysmon 3) — NOT captured this run, recommended follow-up
data.win.system.eventID: 3 AND data.win.eventdata.image: "*\\certutil.exe" AND data.win.eventdata.destinationIp: 192.168.100.107
```
