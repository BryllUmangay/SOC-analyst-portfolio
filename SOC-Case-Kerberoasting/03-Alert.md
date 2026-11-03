# 03 — Alert / Detection (actual events)

Agent `Windows-server` (DC, 192.168.100.105, agent.id 003). Index `wazuh-archives-*`. Query: `data.win.system.eventID: 4769` → **33 hits**.

## 1. Event ID 4769 — Kerberos TGS requested (the money shot)

Expanded event (eventRecordID **7568**):

| Field | Value |
|---|---|
| `eventID` | **4769** — "A Kerberos service ticket was requested." |
| `targetUserName` | **jdoe@BRYLL.LOCAL** (the requesting user) |
| `targetDomainName` | BRYLL.LOCAL |
| `serviceName` / `serviceSid` | **svc_sql** / `S-1-5-21-1845810679-4027539410-2363447484-1602` |
| `ipAddress` / `ipPort` | **`::ffff:192.168.100.107`** / 33910 (Kali attacker) |
| **`ticketEncryptionType`** | **`0x17`** — **RC4-HMAC (etype 23) — smoking gun** |
| `ticketOptions` / `status` | 0x40810010 / 0x0 (success) |
| `logonGuid` | `{5D383B63-3681-0783-D26B-9B403DDB62D3}` (correlates to 4768) |
| `channel` / `computer` | Security / `WIN-BPME02TD5L2.bryll.local` |
| `keywords` | 0x8020000000000000 (Audit Success) |
📸 `evidence/05-wazuh-4769-expanded-rc4.png`, `05-wazuh-4769-expanded-rc4-.2.png`

**Why 0x17 is suspicious:** modern Windows requests AES tickets (`0x12` = AES-256, `0x11` = AES-128). A TGS encrypted with **RC4 (0x17)** means the service account supports only RC4 — its TGS is crackable offline. RC4 TGS requests from a single client for multiple SPNs = kerberoasting.

## 2. Event ID 4768 — TGT requested (correlation)

Expanded event (eventRecordID **7567** — consecutive with 4769's 7568):

| Field | Value |
|---|---|
| `eventID` | **4768** — TGT requested (AS-REQ) |
| `targetUserName` / `targetSid` | jdoe / `S-1-5-21-...-1601` |
| `serviceName` / `serviceSid` | krbtgt / `S-1-5-21-...-502` |
| `ipAddress` / `ipPort` | `::ffff:192.168.100.107` / 33908 (same Kali, port +2) |
| `preAuthType` | 2 (encrypted timestamp — normal) |
| `ticketEncryptionType` | 0x17 (RC4 — TGT also RC4; AES not enforced) |
| `status` | 0x0 (success) |
📸 `evidence/06-wazuh-4768-tgt.png`

**Correlation chain:** 4768 (jdoe TGT from .107:33908, record 7567) → 4769 (jdoe TGS for svc_sql, RC4, from .107:33910, record 7568). Same client IP, consecutive eventRecordIDs, same logonGuid → same session.

## Detection gap note

Built-in Wazuh rules for 4769 fire at low severity and don't flag RC4. A custom rule alerting on **`ticketEncryptionType: 0x17` from external/unmanaged IPs** (or many SPNs from one client) is required. Rule in `09-Remediation.md`.
