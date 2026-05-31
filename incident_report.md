# Incident Report: SSH Brute Force and Lateral Movement Detection

## Executive Summary

This report documents a simulated cyber attack scenario conducted in a controlled lab environment. The objective was to validate the effectiveness of Splunk Enterprise in detecting and correlating multiple stages of an attack, including SSH brute force attempts, successful authentication, lateral movement, privilege escalation, and command execution.

The attack was successfully detected through log analysis, correlation searches, dashboard monitoring, and automated alerting.

---

# Incident Details

| Field              | Value                                       |
| ------------------ | ------------------------------------------- |
| Incident ID        | SOC-001                                     |
| Incident Type      | Brute Force & Lateral Movement              |
| Detection Platform | Splunk Enterprise                           |
| Severity           | Critical                                    |
| Status             | Closed (Lab Simulation)                     |
| Investigation Type | Security Monitoring & Detection Engineering |

---

# Environment

## Systems Involved

### Ubuntu Target

* Hostname: mars-VirtualBox
* Operating System: Ubuntu
* Log Source: /var/log/auth.log
* Sourcetype: auth
* Index: main

### Windows Host

* Hostname: LAPTOP-7S5H8RIM
* Operating System: Windows
* Log Source: WinEventLog:Security
* Index: main

### Splunk Enterprise

* Installed on Windows Host
* Centralized log collection and analysis

---

# Attack Timeline

## Phase 1: SSH Brute Force Attempt

### Description

Multiple failed SSH authentication attempts were observed against the Ubuntu system.

### Evidence

Example log events:

```text
Failed password for user from source_ip
Failed password for invalid user from source_ip
```

### Detection Query

```spl
index=main host="mars-VirtualBox" "Failed password"
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| stats count by src
| where count > 10
```

### Result

Splunk successfully identified excessive failed authentication attempts originating from a single source.

---

## Phase 2: Successful Authentication

### Description

Following multiple failed attempts, a successful SSH login was detected.

### Evidence

```text
Accepted password for user from source_ip
```

### Detection Query

```spl
index=main host="mars-VirtualBox"
("Failed password" OR "Accepted password")
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| transaction src maxspan=10m
| search eventcount > 5 AND "Accepted password"
```

### Result

Splunk correlated multiple failed login attempts with a successful login event, indicating possible credential compromise.

---

## Phase 3: Lateral Movement

### Description

After gaining access to the Ubuntu system, activity consistent with movement toward the Windows host was observed.

### Detection Query

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4624 Logon_Type=3
| stats count by Account_Name Source_Network_Address
```

### Windows Event

| Event ID | Description      |
| -------- | ---------------- |
| 4624     | Successful Logon |

### Result

Network logon activity was detected on the Windows host.

---

## Phase 4: Privilege Escalation

### Description

Elevated privileges were assigned to an authenticated account.

### Detection Query

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4672
| stats count by Account_Name
```

### Windows Event

| Event ID | Description                 |
| -------- | --------------------------- |
| 4672     | Special Privileges Assigned |

### Result

Administrative privileges were granted after authentication.

---

## Phase 5: Process Execution

### Description

Process creation events were monitored to identify potentially suspicious activity.

### Detection Query

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4688
| search Image="*cmd*" OR Image="*powershell*" OR Image="*psexec*"
| table _time Account_Name Image CommandLine
```

### Windows Event

| Event ID | Description      |
| -------- | ---------------- |
| 4688     | Process Creation |

### Result

Process execution activity was successfully captured and monitored.

---

# Correlation Analysis

The attack chain was reconstructed using log correlation across Linux and Windows systems.

## Attack Sequence

1. Multiple failed SSH login attempts detected.
2. Successful SSH authentication observed.
3. Windows network logon recorded.
4. Elevated privileges assigned.
5. Process execution activity detected.

### Correlation Query

```spl
index=main
(host="mars-VirtualBox" "Accepted password")
OR (host="LAPTOP-7S5H8RIM" EventCode=4624 OR EventCode=4672 OR EventCode=4688)
| sort _time
| table _time host EventCode _raw
```

---

# Alerts Generated

## SSH Brute Force Alert

Severity: High

Trigger Condition:

```text
Failed login attempts greater than 10
```

---

## Brute Force Success Alert

Severity: Critical

Trigger Condition:

```text
Multiple failures followed by successful login
```

---

## Lateral Movement Alert

Severity: Critical

Trigger Condition:

```text
Windows authentication, privilege assignment, and execution activity detected
```

---

# Dashboard Components

The following dashboard panels were implemented:

1. SSH Brute Force Activity
2. Top Attacking IP Addresses
3. Successful SSH Logins
4. Windows Authentication Activity
5. Privilege Escalation Events
6. Process Execution Activity
7. Attack Timeline Correlation

---

# MITRE ATT&CK Mapping

| Technique                         | ID    |
| --------------------------------- | ----- |
| Brute Force                       | T1110 |
| Valid Accounts                    | T1078 |
| Remote Services                   | T1021 |
| Privilege Escalation              | T1068 |
| Command and Scripting Interpreter | T1059 |

---

# Lessons Learned

* Splunk Enterprise effectively centralizes Linux and Windows log analysis.
* Authentication events provide valuable indicators of compromise.
* Correlation searches improve detection accuracy.
* Dashboard visualizations help analysts identify attack patterns quickly.
* Alerting mechanisms provide timely notification of suspicious activity.

---

# Conclusion

The project successfully demonstrated end-to-end detection engineering within a SOC environment. Using Splunk Enterprise, multiple stages of the attack lifecycle were identified, correlated, visualized, and alerted upon. The lab validates the effectiveness of centralized log analysis and correlation-based detections for identifying brute force attacks and lateral movement activity.

---
