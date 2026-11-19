# SOC Analyst Portfolio

A hands-on cybersecurity portfolio documenting security monitoring, alert investigation, attack simulations, and detection engineering in a personal lab environment.

**Analyst workflow:** Understand → Simulate → Detect → Investigate → Analyze → Document

The goal is to demonstrate how Windows and Active Directory activity can be collected, correlated, investigated, and translated into defensible findings using Wazuh, Windows event telemetry, Sysmon, PowerShell logging, and Kali Linux.

> **Scope:** All offensive activity is performed in an isolated, personally controlled lab for learning and defensive validation. These projects are not representations of production incident-response work.

---

## Portfolio Overview

This repository contains two main areas:

1. **[SOC Lab Infrastructure](./SOC-Lab-Infrastructure/README.md)** — lab topology, VM configuration, Wazuh deployment, Active Directory setup, connectivity checks, and evidence-capture guidance.
2. **SOC Investigation Cases** — attack simulations and defensive investigations documented with scenarios, telemetry, indicators, investigation steps, timelines, analysis, conclusions, and remediation recommendations.

## Lab Environment

The lab has evolved as new exercises and Active Directory scenarios were introduced. Each case's documentation is the source of truth for its exact IP addresses, hostnames, domain names, and VM configuration.

| Component | Role | Technology |
|---|---|---|
| SIEM | Centralized log collection, alerting, and investigation | Wazuh 4.14.x |
| Attacker | Authorized attack simulation and validation | Kali Linux |
| Windows endpoint | Endpoint telemetry and attack target | Windows 10 Home |
| Domain environment | Active Directory and Kerberos exercises | Windows Server / AD DS |
| Endpoint telemetry | Process, network, and Windows security events | Sysmon, Windows Security logs, PowerShell logging |

See [SOC Lab Infrastructure](./SOC-Lab-Infrastructure/README.md) for build and deployment details.

## Investigation Cases

The repository currently contains ten case studies. Start with each case's README for its investigation summary, documentation, and evidence.

| Case | Technique / Focus | MITRE ATT&CK |
|---|---|---|
| [SMB Brute Force](./SOC-Case-Brute-Force-FINAL-v2/SOC-Case-Brute-Force/README.md) | Repeated SMB authentication failures, account lockout, successful network logons, and credential-attack analysis | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| [Password Spraying (SMB)](./SOC-Case-Password-Spraying/README.md) | Low-and-slow attempts across multiple accounts; comparison with brute force and lockout gaps | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| [Backdoor Local Account Creation](./SOC-Case-Account-Creation/README.md) | Local account creation, masquerading, and addition to the local Administrators group | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) · [T1098.007](https://attack.mitre.org/techniques/T1098/007/) |
| [Scheduled Task Persistence](./SOC-Case-Scheduled-Task/README.md) | Suspicious task creation, masquerading, hidden execution, and persistence telemetry | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| [Suspicious PowerShell](./SOC-Case-Suspicious-PowerShell/README.md) | Download cradle, encoded execution, AMSI-bypass attempt, script-block logging, and network telemetry | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) · [T1105](https://attack.mitre.org/techniques/T1105/) |
| [Windows Event Log Clearing](./SOC-Case-Event-Log-Clearing/README.md) | Attempts to clear Windows logs and validation of telemetry that remained available | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) |
| [Kerberoasting](./SOC-Case-Kerberoasting/README.md) | Kerberos service-ticket requests, RC4 ticket analysis, and service-account exposure | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| [AS-REP Roasting](./SOC-Case-ASREP-Roasting/README.md) | Kerberos pre-authentication analysis and identification of accounts configured without pre-authentication | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| [DLL Search Order Hijacking](./SOC-Case-DLL-Hijacking/README.md) | Suspicious DLL loading from a user-writable directory and Sysmon image-load investigation | [T1574.001](https://attack.mitre.org/techniques/T1574/001/) |
| [Process Injection](./SOC-Case-Process-Injection/README.md) | CreateRemoteThread-based DLL injection, source-to-target process analysis, and Sysmon Event ID 8 hunting | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) |

**Case status:** Completed means the lab exercise and its documented investigation were carried out. It does not mean every proposed rule is production-ready, every event was captured, or every detection fired in real time. Each case's notes identify known limitations.

## Investigation Methodology

1. **Understand the scenario** — identify the behavior, target systems, expected telemetry, and defensive objective.
2. **Establish a baseline** — validate connectivity, endpoint-agent health, audit settings, and logging sources.
3. **Simulate in the lab** — perform authorized activity and record commands.
4. **Validate telemetry** — confirm whether Windows Security, Sysmon, PowerShell, or Active Directory events were generated and received by Wazuh.
5. **Triage and investigate** — review alert context, event fields, timestamps, users, IP addresses, process relationships, and related activity.
6. **Analyze and conclude** — separate observed facts from hypotheses, assess the lab activity, and document gaps.
7. **Recommend remediation** — describe hardening, logging improvements, detection logic, and response actions.

## Telemetry and Event Sources

Depending on the case, investigations use or examine:

- **Windows Security:** authentication (4624, 4625, 4740), account management (4720, 4732), Kerberos (4768, 4769), scheduled task creation (4698), and log clearing (1102, 104).
- **Sysmon:** process creation (1), network connections (3), image loading (7), remote thread creation (8), and file creation (11). Additional event types may be recommended pivots even when not captured in a specific run.
- **PowerShell:** Script Block Logging, including Event ID 4104.
- **Wazuh:** Security Events, indexed events, archives, rule matches, and hunting queries.

Event IDs are investigation pivots, not standalone proof of malicious activity. Interpret them with event fields, host context, surrounding activity, and corroborating evidence.

## Detection Engineering and Validation

Some case studies include proposed custom Wazuh XML rules and Sigma detections to illustrate how observed behavior could be converted into reusable detection logic.

**A rule documented in a case is a draft until tested against representative raw events.** Validation should include:

- Confirming decoded field names and parent rule IDs for the installed Wazuh version.
- Checking XML syntax and rule loading.
- Testing matching and non-matching events with `wazuh-logtest`.
- Confirming the expected alert appears in Wazuh and checking its rule ID, severity, fields, and MITRE mapping.
- Testing benign lookalikes and documenting false positives and limitations.

Not every case currently has a custom rule proven to fire. Some investigations used hunting queries against Wazuh archives rather than real-time alerts. Individual case notes distinguish observed detections from recommended rules where known.

## Repository Structure

```text
SOC-analyst-portfolio/
├── SOC-Lab-Infrastructure/
│   ├── README.md
│   ├── 01-Network-Topology.md
│   ├── 02-VM-Build-Specs.md
│   ├── 03-Wazuh-SIEM-Deployment.md
│   ├── 04-Active-Directory-Build.md
│   ├── 05-Kali-Attacker-Setup.md
│   ├── 06-Screenshot-Checklist.md
│   ├── 07-Validation-Connectivity.md
│   └── Kali-to-WinHome-Cases-Plan.md
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

Each case contains a README, numbered investigation documents, command notes, and an evidence directory where applicable. The brute-force case is nested under `SOC-Case-Brute-Force-FINAL-v2/SOC-Case-Brute-Force/`.

## Tools and Technologies

- **SIEM / monitoring:** Wazuh
- **Operating systems:** Kali Linux, Windows 10, Windows Server, Ubuntu Server
- **Endpoint telemetry:** Sysmon, Windows Event Viewer, PowerShell logging
- **Network investigation:** Nmap, SMB enumeration tools, Wireshark
- **Active Directory:** AD DS, Kerberos, SPN enumeration
- **Analysis and documentation:** MITRE ATT&CK, event correlation, timelines, indicators of compromise, Markdown, Git, and GitHub

Tools are listed to describe their use in the lab; inclusion does not imply expert-level proficiency or production deployment experience.

## Evidence and Reproducibility

Evidence is organized with the corresponding case. Screenshots and event details support findings, while command notes help make lab activity reproducible. Where telemetry or corroborating events were not captured during a run, the case should identify them as follow-up investigation steps rather than observed evidence.

Use the relevant case notes for exact host details, timestamps, event fields, and outcomes.

## Safety and Lab Use

- All attack simulations are restricted to systems and networks under my control or for which I have explicit authorization.
- Malware and payload behavior is tested only with controlled, lab-safe samples and isolated environments.
- Credentials, tokens, private keys, and other secrets should never be committed to this public repository.
- Network indicators and account names are lab artifacts and should not be interpreted as real-world threat intelligence without independent validation.

## About This Portfolio

This is an ongoing learning project documenting my development toward security operations and defensive security work. It emphasizes practical investigation, Windows and Active Directory telemetry, SIEM visibility, and clear communication of findings.

**Author:** Bryll Wrex Umangay  
**Focus:** SOC Analysis · SIEM Monitoring · Windows Security Events · Active Directory · Threat Investigation

---

*This repository is updated as additional lab exercises, detections, and investigation write-ups are completed.*
