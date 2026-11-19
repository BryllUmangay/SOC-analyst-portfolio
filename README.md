# SOC Analyst Portfolio

A hands-on portfolio documenting security monitoring, alert triage, threat investigation, and detection engineering in a controlled home lab. The case studies trace activity from scenario and telemetry collection through analysis, findings, and remediation recommendations.

**Investigation workflow:** Scope → Baseline → Observe → Triage → Correlate → Assess → Document

> **Scope:** Attack simulations are conducted only on systems and networks owned by the author or explicitly authorized for testing. The material is for defensive learning and lab use; it is not a claim of production SOC experience.

## Portfolio at a glance

- **[SOC Lab Infrastructure](./SOC-Lab-Infrastructure/README.md)** — four-VM lab design, network topology, Wazuh, Active Directory, setup, and connectivity validation.
- **Ten SOC investigation cases** — Windows endpoint, authentication, Active Directory, and process-behavior investigations. Each case folder contains its own README and supporting documents; evidence and command notes are present where available.

## SOC Lab Infrastructure

The current infrastructure baseline documents an isolated `192.168.100.0/24` lab with four VMs: Wazuh on Ubuntu Server (`192.168.100.102`), Kali Linux (`192.168.100.107`), a Windows Home workgroup endpoint (`192.168.100.108`), and a Windows Server domain controller (`dc01`, `192.168.100.109`). The current domain is `soclab.local`. Wazuh agents collect endpoint telemetry from Windows; Kali is the authorized simulation host. The DC provides AD DS and DNS. Windows Home remains workgroup-only and cannot accept incoming RDP, so the exact target and configuration vary by case.

**Environment history matters:** the Kerberoasting and AS-REP Roasting case READMEs document an earlier or separate environment using `BRYLL.LOCAL` and a domain controller at `192.168.100.105`. Do not assume those case-specific details describe the current infrastructure baseline. For run-specific hostnames, addresses, domains, and evidence, each case's documentation is the source of truth.

Start with the [infrastructure overview](./SOC-Lab-Infrastructure/README.md), then see:

- [Network topology and traffic flows](./SOC-Lab-Infrastructure/01-Network-Topology.md)
- [VM build specifications](./SOC-Lab-Infrastructure/02-VM-Build-Specs.md)
- [Wazuh SIEM deployment and archives configuration](./SOC-Lab-Infrastructure/03-Wazuh-SIEM-Deployment.md)
- [Active Directory build](./SOC-Lab-Infrastructure/04-Active-Directory-Build.md)
- [Kali attacker setup](./SOC-Lab-Infrastructure/05-Kali-Attacker-Setup.md)
- [Screenshot checklist](./SOC-Lab-Infrastructure/06-Screenshot-Checklist.md)
- [Connectivity and telemetry validation](./SOC-Lab-Infrastructure/07-Validation-Connectivity.md)
- [Kali-to-Windows Home case plan](./SOC-Lab-Infrastructure/Kali-to-WinHome-Cases-Plan.md)

The infrastructure notes document Wazuh 4.14.x all-in-one, Windows agents, Sysmon and PowerShell logging, and Wazuh JSON archives configured for raw-event investigation. The documented VM hardware guidance assumes a host with 16 GB RAM and 8 cores; the infrastructure README and VM specs contain the full configuration and relevant constraints.

### Credential hygiene follow-up

The current [infrastructure README](./SOC-Lab-Infrastructure/README.md) contains a credential matrix with plaintext passwords. Those credentials are intentionally not reproduced here. Remove the exposed credential matrix from the public repository and rotate any listed credentials that are still valid or have been reused. This README update does not modify the infrastructure file.

## SOC Investigation Cases

All ten existing cases are listed below. Links point to the case README at its actual repository path. The SMB Brute Force and Password Spraying case READMEs both document a Windows Home target at `192.168.100.108`.

| Case | Investigation focus | ATT&CK reference |
|---|---|---|
| [SMB Brute Force](./SOC-Case-Brute-Force-FINAL-v2/SOC-Case-Brute-Force/README.md) | Repeated SMB authentication failures, account lockout and successful network logons; the case records 41 failed logons, one lockout, and two successful logons against Windows Home at `192.168.100.108`. | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| [Password Spraying](./SOC-Case-Password-Spraying/README.md) | SMB password attempts distributed across accounts; the case records 21 failures, no lockouts, and two successful logons against Windows Home at `192.168.100.108`. | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| [Account Creation](./SOC-Case-Account-Creation/README.md) | Masqueraded local account creation and addition to the local Administrators group. | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) |
| [Scheduled Task Persistence](./SOC-Case-Scheduled-Task/README.md) | A masqueraded, hidden scheduled task and the related task-creation, process, and file telemetry. | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| [Suspicious PowerShell](./SOC-Case-Suspicious-PowerShell/README.md) | PowerShell download cradle, encoded command, AMSI-bypass attempt, script-block logging, and network telemetry. The case distinguishes the attempted bypass from the run where the download failed. | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) |
| [Windows Event Log Clearing](./SOC-Case-Event-Log-Clearing/README.md) | Security, System, and Application log clearing; compares endpoint and SIEM evidence that remained available. | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) |
| [Kerberoasting](./SOC-Case-Kerberoasting/README.md) | Kerberos service-ticket request investigation, including observed RC4 ticket fields and service-account exposure. The case documents `BRYLL.LOCAL` and DC `192.168.100.105`, distinct from the current infrastructure baseline. | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| [AS-REP Roasting](./SOC-Case-ASREP-Roasting/README.md) | Kerberos pre-authentication investigation, including an observed 4768 with `preAuthType: 0`. The case documents `BRYLL.LOCAL` and DC `192.168.100.105`, distinct from the current infrastructure baseline. | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| [DLL Search Order Hijacking](./SOC-Case-DLL-Hijacking/README.md) | Sysmon image-load investigation of an unsigned DLL loaded from a user-writable directory. | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) |
| [Process Injection](./SOC-Case-Process-Injection/README.md) | CreateRemoteThread-based DLL injection investigated through Sysmon Event ID 8 and source-to-target process context. | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) |

Case completion describes the exercise and the documentation—not proof that every proposed detection is production-ready, that all expected telemetry was captured, or that every case generated a real-time alert. Refer to each case's notes for scope, observed results, limitations, and evidence status.

## Investigation Methodology

The case write-ups follow a repeatable, evidence-led approach:

1. **Scope the scenario:** identify the systems involved, expected behavior, and defensive question; keep simulation activity within the isolated, authorized lab.
2. **Establish a baseline:** check host and agent health, relevant audit/logging configuration, connectivity, and time context before interpreting events.
3. **Record the activity:** preserve the case's simulation notes and command record where available; avoid treating an intended action as proof it succeeded.
4. **Validate collection:** confirm whether endpoint events were generated and whether they reached Wazuh. A missing alert is not proof that no activity occurred.
5. **Triage and correlate:** examine event fields, account and host context, source/destination, process ancestry, timestamps, and nearby events. Use raw archives where available to investigate telemetry that did not create an alert.
6. **Assess evidence:** distinguish directly observed facts from interpretation; note missing artifacts, timing or clock issues, and alternative explanations.
7. **Document findings and response:** state the impact supported by evidence, investigation gaps, containment or remediation recommendations, and detection improvements.

## Telemetry Sources

Sources vary by case and by what was captured. The repository includes or discusses:

- **Windows Security and AD events:** logon success/failure and lockout (4624, 4625, 4740); account creation and local group membership (4720, 4732); Kerberos TGT/TGS requests (4768, 4769); scheduled task creation (4698); and audit/System log clearing (1102, 104).
- **Sysmon:** process creation (Event ID 1), network connection (3), image load (7), remote thread creation (8), and file creation (11). Event types listed here are case-dependent; not every source or corroborating event was captured in every investigation.
- **PowerShell:** Script Block Logging, including Event ID 4104, where configured and observed.
- **Wazuh:** agent-collected events, rule matches and alerts, Discover/hunting queries, and `wazuh-archives-*` raw-event indexes where enabled.
- **Supporting artifacts:** case screenshots, event details, indicators, timelines, and Kali command notes where present.

Event IDs and ATT&CK mappings are investigation pivots, not standalone proof of malicious activity. Evaluate fields and context, and verify timestamp/time-zone assumptions before building a timeline.

## Detection Engineering and Validation

The case documents distinguish among three different kinds of evidence and detection work:

- **Observed Wazuh alerts:** explicitly evidenced rule matches include the SMB Brute Force case's Wazuh rule `18106` for individual 4625 events (the case reports no captured high-severity correlation alert) and the Event Log Clearing case's rule `63103`, level 5, for Event ID 1102. The case notes describe the severity and limitations of these observed alerts.
- **Observed telemetry and proactive hunting:** a Windows event appearing in Wazuh or being found in `wazuh-archives-*` is not automatically a Wazuh alert. The DLL Search Order Hijacking and Process Injection cases explicitly report archive hunting rather than a real-time alert. Other cases document event observations, searches, or telemetry; consult each case's Alert and Investigation documents for what actually fired.
- **Proposed custom detections:** some case documents include suggested Wazuh XML rules, rule overrides, or Sigma logic. These are proposals unless the case provides test evidence. Their presence does not establish that they loaded, matched representative events, or were validated.

Before treating a proposed rule as validated, test it in the target environment: confirm decoded fields and parent-rule behavior for the installed version, verify syntax and successful loading, exercise matching and benign non-matching events with appropriate test tooling (for example `wazuh-logtest` for Wazuh rules), then confirm the resulting alert fields, severity, and mapping. Record false positives, coverage boundaries, and limitations. **This README makes no claim that proposed custom Wazuh or Sigma rules have passed those tests.**

## Repository Structure

```text
SOC-analyst-portfolio/
├── README.md
├── SOC-Lab-Infrastructure/
│   ├── README.md
│   ├── 01-Network-Topology.md
│   ├── 02-VM-Build-Specs.md
│   ├── 03-Wazuh-SIEM-Deployment.md
│   ├── 04-Active-Directory-Build.md
│   ├── 05-Kali-Attacker-Setup.md
│   ├── 06-Screenshot-Checklist.md
│   ├── 07-Validation-Connectivity.md
│   ├── Kali-to-WinHome-Cases-Plan.md
│   └── screenshots/
├── SOC-Case-ASREP-Roasting/
├── SOC-Case-Account-Creation/
├── SOC-Case-Brute-Force-FINAL-v2/
│   └── SOC-Case-Brute-Force/
├── SOC-Case-DLL-Hijacking/
├── SOC-Case-Event-Log-Clearing/
├── SOC-Case-Kerberoasting/
├── SOC-Case-Password-Spraying/
├── SOC-Case-Process-Injection/
├── SOC-Case-Scheduled-Task/
└── SOC-Case-Suspicious-PowerShell/
```

Each case directory contains a case README and numbered investigation documents. Evidence directories and `kali-commands.txt` files are present where shown in the repository; they are not assumed to exist for every case. The brute-force case README is nested at `SOC-Case-Brute-Force-FINAL-v2/SOC-Case-Brute-Force/README.md`.

## Tools and Technologies

- **SIEM and collection:** Wazuh 4.14.x, Wazuh agents, Filebeat, indexed alerts, and raw archives.
- **Lab systems:** Kali Linux, Windows 10/11 Home, Windows Server 2022, and Ubuntu Server; VirtualBox or VMware Workstation are described in the infrastructure notes.
- **Endpoint logging:** Sysmon, Windows Security auditing, Windows Event Viewer, and PowerShell logging.
- **Directory and authentication:** Active Directory Domain Services, DNS, Kerberos, SMB, and SPN-based service-account investigations.
- **Analysis and documentation:** Wazuh Discover, event correlation, timelines, indicators, MITRE ATT&CK, Markdown, Git, and GitHub.

Tool names describe technologies referenced in the lab materials; they do not imply production deployment or expertise beyond the documented exercises.

## Evidence and Reproducibility

Case folders organize the available scenario, simulation, alert, indicator, investigation, timeline, analysis, conclusion, and remediation notes. Where included, screenshots support specific observations and command notes record lab activity. Use the individual case documents for exact event fields, observed outcomes, and evidence limitations. Some cases explicitly note missing corroborating telemetry, uncaptured timestamps, or that a finding came from a hunting query rather than an alert. Missing evidence is not inferred or represented as a result.

## Safety Scope

- Simulations are limited to systems and networks owned by the author or covered by explicit authorization, in a controlled lab environment.
- The lab's attack tooling and payload exercises are for defensive learning and observation; do not run them against systems outside that scope.
- Lab IPs, hostnames, usernames, and indicators are artifacts of these exercises, not verified real-world threat intelligence.
- Never reuse lab credentials in production or publish live credentials, tokens, private keys, or other secrets.
- Findings and detection recommendations are educational case documentation, not a substitute for production security review or incident-response procedures.

## About

An ongoing learning portfolio focused on SOC analysis, SIEM monitoring, Windows and Active Directory telemetry, and evidence-based threat investigation.

**Author:** Bryll Wrex Umangay  
**Focus:** SOC Analysis · SIEM Monitoring · Windows Security Events · Active Directory · Threat Investigation
