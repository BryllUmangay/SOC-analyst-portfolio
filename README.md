# SOC Analyst Portfolio

A hands-on cybersecurity portfolio documenting security monitoring, alert investigation, attack simulations, and detection engineering in a personal lab environment.

The portfolio focuses on the analyst workflow:

**Understand → Simulate → Detect → Investigate → Analyze → Document**

The goal is to demonstrate how endpoint and authentication activity can be collected, correlated, investigated, and translated into actionable security findings using Wazuh, Windows event telemetry, Sysmon, and Kali Linux.

> **Scope:** All offensive activity documented here is performed in an isolated, personally controlled lab for learning and defensive validation. These projects are not representations of production incident-response work.

---

## Portfolio Overview

This repository contains two main areas:

1. **SOC Lab Infrastructure** — environment design, VM configuration, Wazuh deployment, Active Directory setup, connectivity validation, and evidence-capture guidance.
2. **SOC Investigation Cases** — individual attack simulations and defensive investigations, each documented with its scenario, execution steps, telemetry, indicators, investigation, timeline, analysis, conclusion, and remediation.

## Lab Environment

The lab has evolved as new exercises and Active Directory scenarios were introduced. Case-specific documentation is the source of truth for the exact IP addresses, hostnames, domain names, and VM configuration used in each exercise.

| Component | Role | Technology |
|---|---|---|
| SIEM | Centralized log collection, alerting, and investigation | Wazuh 4.14.x |
| Attacker machine | Authorized attack simulation and validation | Kali Linux |
| Windows endpoint | Endpoint telemetry and attack target | Windows 10 Home |
| Domain environment | Active Directory authentication and Kerberos exercises | Windows Server / AD DS |
| Endpoint telemetry | Process, network, and Windows security events | Sysmon, Windows Security logs, PowerShell logging |

For the infrastructure design, deployment notes, and current build details, see **[SOC Lab Infrastructure](./SOC-Lab-Infrastructure/README.md)**.

## Investigation Cases

The following cases are documented in this repository. Each case includes its own detailed README and supporting investigation notes.

| Case | Technique / Focus | ATT&CK Mapping | Status |
|---|---|---|---|
| [Brute Force Attack (SMB)](./SOC-Case-Brute-Force-/README.md) | Repeated authentication failures followed by successful SMB access; account lockout and authentication-event analysis | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Completed |
| [Password Spraying (SMB)](./SOC-Case-Password-Spraying/README.md) | Low-and-slow password attempts across multiple accounts; compare spraying patterns with brute force | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Completed |
| [Scheduled Task Persistence](./SOC-Case-Scheduled-Task/README.md) | Suspicious scheduled task creation, masquerading, hidden execution, and persistence telemetry | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) · [T1036](https://attack.mitre.org/techniques/T1036/) | Completed |
| [Suspicious PowerShell](./SOC-Case-Suspicious-PowerShell/README.md) | PowerShell download cradle, encoded execution, AMSI-bypass attempt, script-block logging, and network telemetry | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) · [T1027](https://attack.mitre.org/techniques/T1027/) · [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Completed |
| [Windows Event Log Clearing](./SOC-Case-Event-Log-Clearing/README.md) | Detect attempts to clear Windows logs and validate what telemetry remains available in the SIEM | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Completed |
| [Kerberoasting](./SOC-Case-Kerberoasting/README.md) | Active Directory Kerberos service-ticket requests, RC4 ticket analysis, and offline service-account password assessment | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Completed |

**Status note:** “Completed” means the lab exercise and its documented investigation were carried out. It does not imply that every detection is production-ready or that every simulated action succeeded exactly as initially planned. Each case records relevant limitations and findings.

## Investigation Methodology

Each case follows a repeatable workflow:

1. **Understand the scenario** — identify the behavior being simulated, target systems, expected telemetry, and defensive objective.
2. **Establish the baseline** — validate host connectivity, endpoint-agent health, audit settings, and relevant logging sources.
3. **Simulate in the lab** — perform the authorized activity from Kali or the designated lab host and record the commands used.
4. **Validate telemetry** — confirm that Windows Security logs, Sysmon, PowerShell logs, or Active Directory events were generated and received by Wazuh.
5. **Triage and investigate** — review alert context, event fields, timestamps, users, source and destination addresses, process relationships, and related activity.
6. **Analyze and conclude** — distinguish observed facts from hypotheses, assess whether the activity is malicious or benign in the lab scenario, and document gaps or limitations.
7. **Recommend remediation** — describe hardening, logging improvements, detection logic, and response actions relevant to the finding.

## Telemetry and Event Sources

Depending on the case, investigations may use:

- Windows Security event logs, including authentication and account-management events.
- Sysmon process creation, network connection, and file-creation telemetry.
- PowerShell Script Block Logging.
- Active Directory domain-controller security events, including Kerberos service-ticket activity.
- Wazuh alerts, indexed events, and archives.

Examples of event IDs examined in the case studies include **4624**, **4625**, **4740**, **4768**, **4769**, **4698**, **1102**, **104**, and Sysmon **1**, **3**, and **11**. The relevant IDs and their interpretation are explained in each case rather than treated as standalone proof of malicious activity.

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
│   └── 07-Validation-Connectivity.md
│
├── SOC-Case-Brute-Force-/
├── SOC-Case-Password-Spraying/
├── SOC-Case-Scheduled-Task/
├── SOC-Case-Suspicious-PowerShell/
├── SOC-Case-Event-Log-Clearing/
└── SOC-Case-Kerberoasting/
```

Each case folder contains a case README, numbered investigation documents, command notes, and an evidence directory where applicable. Refer to the individual case README for the exact contents and evidence inventory.

## Tools and Technologies

- **SIEM / monitoring:** Wazuh
- **Operating systems:** Kali Linux, Windows 10, Windows Server, Ubuntu Server
- **Endpoint telemetry:** Sysmon, Windows Event Viewer, PowerShell logging
- **Network and service investigation:** Nmap, SMB enumeration tools, Wireshark
- **Active Directory security:** AD DS, Kerberos, SPN enumeration, BloodHound-related concepts
- **Analysis and documentation:** MITRE ATT&CK, event correlation, timelines, indicators of compromise, Markdown, Git, and GitHub

Tools are listed to describe their use in the lab exercises; inclusion does not imply expert-level proficiency or production deployment experience.

## Evidence and Reproducibility

Evidence is organized with the corresponding case. Screenshots and event details are intended to support the documented findings, while command notes help make the lab activity reproducible.

When reviewing a case, start with its README, then follow the numbered documents in order. Exact host details, timestamps, event fields, and outcomes should be taken from the evidence and case notes.

## Safety and Lab Use

- All attack simulations are restricted to systems and networks under my control or for which I have explicit authorization.
- Malware and payload behavior is tested only with controlled, lab-safe samples and isolated environments.
- Credentials, tokens, private keys, and other secrets should never be committed to this public repository.
- Network indicators and account names are lab artifacts and should not be interpreted as real-world threat intelligence without independent validation.

## About This Portfolio

This is an ongoing learning project documenting my development toward security operations and defensive security work. It emphasizes practical investigation, understanding Windows and Active Directory telemetry, validating SIEM visibility, and communicating findings clearly.

**Author:** Bryll Wrex Umangay  
**Focus:** SOC Analysis · SIEM Monitoring · Windows Security Events · Active Directory · Threat Investigation

---

*This repository is updated as additional lab exercises, detections, and investigation write-ups are completed.*
