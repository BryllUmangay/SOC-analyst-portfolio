# 09 — Remediation & Hardening

## Immediate containment (this incident)

1. Delete `C:\Users\Public\hijack\vulnapp.exe` and `hijackme.dll`; kill PID 7472 if alive.
2. Add `vulnapp.exe` SHA256 `CF8E8BE4D8E04C9CF983CFF0789F3993DBC11CF798DF014CB7B0659350FE243C` to blocklists; obtain and block `hijackme.dll` hash via `Get-FileHash`.
3. Block egress to `192.168.100.107` (lab) / investigate any other hosts that contacted it.
4. Rotate `bryll` password (payload was PoC, but assume code execution = credential exposure).

## Preventive controls

| Control | Detail |
|---|---|
| **Developer fix** | Never `LoadLibrary` by bare name. Use absolute paths or `LoadLibraryEx(..., LOAD_LIBRARY_SEARCH_SYSTEM32)`; call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` at process start. |
| **SafeDllSearchMode** | Ensure enabled (default); verify `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode = 1`. |
| **Application control** | Deploy WDAC / AppLocker allowlist: block unsigned EXE/DLL in `\Users\*`, `\Public\`, `\AppData\`, `\Temp`. This single control stops this attack at execution. |
| **Restrict write paths** | Remove write/modify rights on `C:\Users\Public\` subdirectories for standard users; monitor writes there. |
| **Block LOLBin download** | Defender ASR rule "Block abuse of exploited vulnerable signed drivers" / GPO SRP deny `certutil.exe -urlcache`; EDR rule on `certutil` with `urlcache|split|f` command line. |
| **Endpoint clock sync** | Point Windows endpoints to the DC time authority (NTP) — eliminates the recurring ~hour offset seen across cases and makes timeline correlation reliable. |

## Detective controls (detection engineering)

1. **Wazuh custom rule `100253`** (level 13) — Sysmon EID 7 where `imageLoaded` matches user-writable paths AND `signed: false`. XML in `03-Alert.md`. Verify parent SID against your Wazuh build.
2. **Sysmon EID 7 coverage** — keep SwiftOnSecurity filter (it's the reason this hit was clean); do NOT disable EID 7. Optionally add your own inclusions for `\Users\Public\` loads.
3. **Companion rules** (add to `local_rules.xml`, IDs `100254+`):
   - `certutil.exe` command line containing `urlcache` (Sysmon 1) — level 10.
   - File creation (Sysmon 11) of `.dll` in `\Users\Public\` / `\Downloads\` / `\AppData\Local\Temp` — level 8, correlate with EID 7.
   - Unsigned process creation (Sysmon 1) from `\Users\Public\` — level 10.
4. **Hunting queries** (DQL, `wazuh-archives-*`) — run weekly:
   ```
   data.win.system.eventID: 7 AND data.win.eventdata.signed: false AND data.win.eventdata.imageLoaded: (*\\Users\\* OR *\\Public\\* OR *\\Temp\\*)
   data.win.system.eventID: 1 AND data.win.eventdata.image: "*\\certutil.exe" AND data.win.eventdata.commandLine: "*urlcache*"
   ```
5. **File integrity monitoring** — add `C:\Users\Public\` to Wazuh syscheck (`<directories check_all="yes" realtime="yes">`) for alert-level file writes.

## Validation after hardening

- Re-run the attack: `vulnapp.exe` should be blocked by AppLocker/WDAC, or the EID 7 event should fire rule `100253` in real time (not just archives).
- Confirm `certutil -urlcache` is blocked/alerted.
- Confirm endpoint clocks agree with Wazuh UTC within <60s.

## Screenshot reference

- Detection query + expanded event: `evidence/05-wazuh-sysmon7.png`, `evidence/06-wazuh-sysmon7-expanded.png`
