# 07 — Analysis

## Why a **single** Sysmon EID 7 event is sufficient (not a weakness)

The user's question — "there's only 1 Sysmon event, is this worth documenting?" — is the key analytical point. **Yes, and the single event is expected and high-fidelity:**

1. **SwiftOnSecurity's Sysmon config aggressively filters EID 7.** It excludes Microsoft-signed DLLs, known-good paths, and commonly-loaded libraries by default. An EID 7 event that **survives** that filter and lands in the archive is already pre-vetted as anomalous.
2. **This one event carries four independent suspicious signals stacked:**
   - DLL loaded from `C:\Users\Public\` (user-writable, never a legitimate DLL load path for production software);
   - `signed: false` / `SignatureStatus: Unavailable`;
   - Loading process (`vulnapp.exe`) is **also** unsigned, in the **same directory**, with empty version/company/product metadata (unbranded MinGW binary);
   - `ruleName` auto-tagged `T1574.001` by the Sysmon config.
   Any one of these is notable; all four on one record is a high-confidence hit.
3. **`vulnapp.exe` only calls `LoadLibraryA` once**, so exactly one image-load of `hijackme.dll` occurs — more events would be suspicious in the other direction.
4. The event contains everything needed to escalate: full path, PID, ProcessGuid, user, and four hashes of the loading process. One good event beats ten noisy ones.

## DLL search-order mechanics (why the hijack works)

`LoadLibraryA("hijackme.dll")` supplies no path. With SafeDllSearchMode enabled (Windows default), the search order is:

1. Directory from which the application loaded (`C:\Users\Public\hijack\`) ← **attacker's DLL wins here**
2. System directory (`C:\Windows\System32`)
3. 16-bit system directory
4. Windows directory
5. Current working directory
6. Directories in `PATH`

Because the attacker placed `hijackme.dll` in the application directory, it is found and loaded before any system copy. The fix on the developer side is to always load DLLs by **absolute path** or use `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` / `LoadLibraryEx` with `LOAD_LIBRARY_SEARCH_SYSTEM32`.

## Ingress vector analysis

Both files arrived via `certutil.exe -urlcache -split -f` — a signed Microsoft binary abused for download (living off the land). `certutil` is normally used for certificate/CRL operations; `-urlcache` fetches arbitrary HTTP content. Its hex progress output (`01de35` = 122,421 bytes; `0156df` = 87,775 bytes) exactly matches the Kali build sizes, proving the same files were transferred. This is T1105 (Ingress Tool Transfer) executed through T1218-adjacent LOLBin abuse.

## Payload assessment

The payload (`MessageBoxA`) is **benign proof-of-concept**, not a C2 beacon. In a real incident, `DllMain` would drop/reflectively load a second-stage implant. Severity is therefore **High** (arbitrary code execution confirmed, user-writable persistence path, LOLBin ingress) rather than Critical (no C2, no credential access, no privilege escalation observed).

## Limitations / honesty flags

1. **Hash of `hijackme.dll` not captured.** Sysmon EID 7's `hashes` field hashes the **loading process** (`vulnapp.exe`), not the loaded image. A DLL hash would come from Sysmon 11 (file create) or a manual `Get-FileHash`. Documented as missing; follow-up query provided in `05-Investigation.md`.
2. **No corroborating events captured** (Sysmon 1 for certutil/vulnapp, Sysmon 3 network, Sysmon 11 file write, Wazuh FIM). They should exist in archives; the case is built on the one captured event plus the attacker/victim desktop screenshots.
3. **No real-time alert** — detection was a hunting query. Custom rule `100253` in `03-Alert.md` closes this gap (verify the parent `<if_sid>` against your Wazuh build).
4. **Endpoint clock skew** (see `06-Timeline.md`) — recurring lab issue; does not affect detection fidelity but complicates timeline correlation.

## Screenshot reference

- `evidence/06-wazuh-sysmon7-expanded.png` (all four stacked signals on one event)
- `evidence/01-payload.png` (bare-name `LoadLibraryA` — root cause)
