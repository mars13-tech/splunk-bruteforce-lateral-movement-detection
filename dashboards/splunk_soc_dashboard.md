# Splunk SOC Dashboard

## Dashboard Name

Brute Force + Lateral Movement Detection Lab

---

## Dashboard Objective

The purpose of this dashboard is to provide centralized visibility into authentication attacks, successful compromises, lateral movement activity, privilege escalation events, and suspicious process execution across Linux and Windows systems.

---

## Dashboard Architecture

```text
Kali Linux
    ↓
Ubuntu VM (SSH Authentication Logs)
    ↓
Windows Host (Security Event Logs)
    ↓
Splunk Enterprise
```

---

# Dashboard Panels

## Panel 1 – SSH Brute Force Activity

### Purpose

Visualize failed SSH login attempts over time.

### Visualization

Line Chart

### SPL Query

```spl
index=main host="mars-VirtualBox" "Failed password"
| timechart span=1m count
```

### Security Value

* Detect brute force activity
* Identify attack spikes
* Monitor authentication failures

---

## Panel 2 – Top Attacking IP Addresses

### Purpose

Identify the most active source IP addresses.

### Visualization

Bar Chart

### SPL Query

```spl
index=main host="mars-VirtualBox" "Failed password"
| rex "from (?<src>\d+\.\d+\.\d+\.\d+)"
| top src
```

### Security Value

* Identify attacker IPs
* Support investigation activities
* Prioritize response efforts

---

## Panel 3 – Successful SSH Logins

### Purpose

Monitor successful SSH authentication events.

### Visualization

Line Chart

### SPL Query

```spl
index=main host="mars-VirtualBox" "Accepted password"
| timechart count
```

### Security Value

* Detect successful access
* Identify compromise events
* Monitor authentication trends

---

## Panel 4 – Windows Authentication Activity

### Purpose

Monitor successful Windows logons.

### Visualization

Area Chart

### SPL Query

```spl
index=main host="LAPTOP-7S5H8RIM"
EventCode=4624
| timechart count
```

### Security Value

* Detect lateral movement
* Monitor user authentication activity
* Track Windows access events

---

## Panel 5 – Privilege Escalation & Process Activity

### Purpose

Monitor elevated privilege assignments and process execution.

### Visualization

Column Chart

### SPL Query

```spl
index=main host="LAPTOP-7S5H8RIM"
(EventCode=4672 OR EventCode=4688)
| timechart count
```

### Security Value

* Detect privilege escalation
* Identify suspicious execution activity
* Support threat hunting operations

---

## Panel 6 – Attack Timeline

### Purpose

Provide a complete timeline of attack activity.

### Visualization

Table

### SPL Query

```spl
index=main
(host="mars-VirtualBox" "Accepted password")
OR (host="LAPTOP-7S5H8RIM" EventCode=4624 OR EventCode=4672 OR EventCode=4688)
| table _time host EventCode _raw
| sort _time
```

### Security Value

* Reconstruct attack chain
* Support incident investigations
* Provide forensic visibility

---

# Detection Coverage

| Attack Stage         | Detection             |
| -------------------- | --------------------- |
| Initial Access       | SSH Brute Force       |
| Credential Access    | Failed Authentication |
| Valid Accounts       | Successful Login      |
| Lateral Movement     | Windows Logon Events  |
| Privilege Escalation | Event ID 4672         |
| Execution            | Event ID 4688         |

---

# MITRE ATT&CK Mapping

| Technique                         | ATT&CK ID |
| --------------------------------- | --------- |
| Brute Force                       | T1110     |
| Valid Accounts                    | T1078     |
| Remote Services                   | T1021     |
| Privilege Escalation              | T1068     |
| Command and Scripting Interpreter | T1059     |

---

# Expected Outcome

The dashboard enables security analysts to:

* Detect SSH brute force attacks
* Identify successful compromises
* Monitor Windows authentication activity
* Detect privilege escalation
* Investigate suspicious process execution
* Reconstruct complete attack timelines
* Improve incident response capabilities

---

# Screenshots

Add screenshots from the `screenshots/` folder:

* dashboard_overview.png
* brute_force_activity.png
* top_attacking_ips.png
* successful_ssh_logins.png
* windows_logons.png
* privilege_process_activity.png
* attack_timeline.png
