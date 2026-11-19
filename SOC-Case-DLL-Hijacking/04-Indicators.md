# 04 — Indicators of Compromise (IOCs)

## Network indicators

| Indicator | Value | Context |
|---|---|---|
| Attacker IP (observed this run) | `192.168.100.107` | Kali `butch`, HTTP server TCP/80 |
| URL | `http://192.168.100.107/vulnapp.exe` | downloaded via `certutil -urlcache` |
| URL | `http://192.168.100.107/hijackme.dll` | downloaded via `certutil -urlcache` |
| LOLBin | `certutil.exe -urlcache -split -f` | T1105 / T1218.007-adjacent ingress |

## Host / file indicators

| Indicator | Value | Notes |
|---|---|---|
| Dropped EXE path | `C:\Users\Public\hijack\vulnapp.exe` | 122,421 bytes |
| Dropped DLL path | `C:\Users\Public\hijack\hijackme.dll` | 87,775 bytes |
| `vulnapp.exe` SHA256 | `CF8E8BE4D8E04C9CF983CFF0789F3993DBC11CF798DF014CB7B0659350FE243C` | from Sysmon 7 `hashes` (loading process) |
| `vulnapp.exe` SHA1 | `1BD1CE4A3C40E9973373D5A68F062E416BD11214` | — |
| `vulnapp.exe` MD5 | `5675FDE1A801C900A8D10AD5E4D0F8D7` | — |
| `vulnapp.exe` IMPHASH | `4647F0D2EB73045909425574099B68FA` | — |
| `hijackme.dll` hash | **NOT captured this run** | recommend `Get-FileHash` / Sysmon 11 follow-up; only size (87,775) confirmed |
| Signature status (both) | `signed: false`, `SignatureStatus: Unavailable` | empty FileVersion/Company/Product/Description/OriginalFileName |

## Process / telemetry indicators

| Indicator | Value |
|---|---|
| Loading process | `C:\Users\Public\hijack\vulnapp.exe` |
| Loaded DLL | `C:\Users\Public\hijack\hijackme.dll` |
| PID | `7472` |
| ProcessGuid | `{03477e4a-916e-6af4-7012-000000000800}` |
| User context | `DESKTOP-F0JVTQT\bryll` |
| Sysmon Event ID | `7` (Image Loaded), channel `Microsoft-Windows-Sysmon/Operational` |
| Sysmon ruleName tag | `technique_id=T1574.001,technique_name=DLL` (display-truncated) |
| Sysmon utcTime | `2026-11-11 16:01:50.948` UTC |
| Wazuh agent | `winhome01` (id `002`, ip `192.168.100.108`) |
| Payload artifact | MessageBox titled `PWNED`, body `DLL Hijack OK - code executed` |

## Detection queries (DQL, `wazuh-archives-*`)

```
# Primary — this case's hit
data.win.system.eventID: 7 AND data.win.eventdata.imageLoaded: *hijackme*

# Generic unsigned-DLL-from-user-path hunt
data.win.system.eventID: 7 AND data.win.eventdata.signed: false AND data.win.eventdata.imageLoaded: (*\\Users\\* OR *\\Public\\* OR *\\Temp\\*)
```

## Screenshot reference

- `evidence/05-wazuh-sysmon7.png`, `evidence/06-wazuh-sysmon7-expanded.png` (hashes, paths, PID, GUID, signature status)
- `evidence/03-win-binaries-planted.png` (file sizes, timestamps, certutil command lines)
