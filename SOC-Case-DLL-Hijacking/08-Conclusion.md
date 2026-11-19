# 08 — Conclusion

## Verdict

**Confirmed DLL search-order hijacking (T1574.001) resulting in arbitrary code execution** as `DESKTOP-F0JVTQT\bryll` on `winhome01` (192.168.100.108).

- Attacker (Kali `butch`, observed `192.168.100.107`) cross-compiled `vulnapp.exe` (bare-name `LoadLibraryA("hijackme.dll")`) and malicious `hijackme.dll` (MessageBox payload).
- Victim downloaded both via `certutil -urlcache` into `C:\Users\Public\hijack\` (sizes match exactly: 122,421 / 87,775 bytes).
- Execution loaded the attacker DLL from the application directory; `DllMain` fired → "PWNED / DLL Hijack OK - code executed".
- Detected via **one high-fidelity Sysmon EID 7 event** in Wazuh archives (PID 7472, unsigned DLL in `\Users\Public\`, unsigned parent EXE same dir, auto-tagged T1574.001). Severity: **High**.

## Key lessons for the portfolio

1. **One event can be enough** when it is high-fidelity and multi-signal. Volume ≠ detection quality; a well-tuned Sysmon config + a short hunt query beats a flood of raw telemetry.
2. **EID 7 is the only reliable telemetry for this technique** — but most orgs over-filter it. Demonstrating that you know *what* survives the filter and *why* it's suspicious is exactly what a SOC analyst portfolio should show.
3. **LOLBin ingress (`certutil -urlcache`) + user-writable drop path + unsigned binaries** is a complete, realistic intrusion chain worth documenting end-to-end.
4. **Hunting ≠ alerting.** This case was found by a human query; the custom rule `100253` (see `03-Alert.md`) converts it into real-time detection. Showing both halves (find it → automate it) is strong portfolio material.
5. **Document gaps honestly** (missing DLL hash, missing corroborating events, endpoint clock skew, PoC-only payload) — interviewers value knowing what you *don't* have as much as what you do.

## What would make this case stronger (optional re-run)

- Capture Sysmon 1 (`certutil` + `vulnapp.exe`), Sysmon 3 (`certutil`→`.107:80`), and Sysmon 11 (file writes → DLL hash) screenshots.
- Swap the MessageBox payload for a real reverse shell and add the C2 network telemetry (raises severity to Critical).
- Side-load the DLL next to a **signed, legitimate** EXE (e.g., a known utility) to demonstrate true "DLL side-loading" (T1574.002) and application-control bypass.

## Screenshot reference

All six: `evidence/01-payload.png` → `evidence/06-wazuh-sysmon7-expanded.png`.
