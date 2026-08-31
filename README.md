\# Turning My Windows 11 Laptop into a Mini SOC



\## 🛡️ Overview



This project documents my journey of turning my personal Windows 11 laptop into a small Security Operations Center (SOC) monitoring lab using Splunk.



The objective is to collect security telemetry from the endpoint, analyze the events in Splunk, build detections, and practice real-world SOC investigation workflows.



\## 🎯 Project Goals



\* Collect Windows security telemetry

\* Monitor authentication activity

\* Monitor DNS activity

\* Monitor DHCP activity

\* Monitor PowerShell activity

\* Monitor Windows Defender events

\* Integrate Gmail security metadata

\* Investigate suspicious activity using Splunk

\* Build SPL detection queries

\* Practice false-positive and false-negative analysis

\* Develop phishing investigation workflows

\* Create SOC dashboards and alerts



\## 🏗️ Architecture



```text

&#x20;                    Windows 11 Laptop

&#x20;                           │

&#x20;       ┌───────────────────┼───────────────────┐

&#x20;       │                   │                   │

&#x20;   Security              DNS/DHCP         PowerShell

&#x20;       │                   │                   │

&#x20;       ├───────────────────┼───────────────────┤

&#x20;       │                                       │

&#x20;   Windows Defender                     Endpoint Events

&#x20;       │                                       │

&#x20;       └───────────────────┬───────────────────┘

&#x20;                           │

&#x20;                           ▼

&#x20;                        Splunk

&#x20;                           ▲

&#x20;                           │

&#x20;                    Gmail Collector

&#x20;                           │

&#x20;                           ▼

&#x20;                         Gmail

```



\## 📊 Current Telemetry



| Source              | Status      |

| ------------------- | ----------- |

| Windows Security    | ✅ Enabled   |

| Windows System      | ✅ Enabled   |

| Windows Application | ✅ Enabled   |

| DNS Client          | ✅ Enabled   |

| DHCP Client         | ✅ Enabled   |

| PowerShell          | ✅ Enabled   |

| Windows Defender    | ✅ Enabled   |

| Gmail metadata      | ✅ Connected |

| Splunk              | ✅ Running   |



\## 🔎 Example Investigations



\### Windows Authentication



Investigating failed logons:



```spl

index=windows sourcetype="WinEventLog:Security" EventCode=4625

```



Investigating successful logons:



```spl

index=windows sourcetype="WinEventLog:Security" EventCode=4624

```



\### DNS Investigation



```spl

index=windows sourcetype="WinEventLog:Microsoft-Windows-DNS-Client/Operational"

```



\### Gmail Investigation



```spl

index=windows sourcetype="gmail:email"

| table \_time from to subject date message\_id

```



\## 🧪 SOC Investigation Workflow



```text

Alert

&#x20; ↓

Validate

&#x20; ↓

Collect Evidence

&#x20; ↓

Correlate Events

&#x20; ↓

Determine Scope

&#x20; ↓

Classify Activity

&#x20; ↓

Document Findings

```



\## 📁 Repository Structure



```text

├── collector/

│   └── gmail\_collector.py

│

├── splunk/

│   └── inputs.conf.example

│

├── queries/

│   ├── dns-investigation.spl

│   ├── gmail-investigation.spl

│   ├── windows-security.spl

│   ├── powershell-investigation.spl

│   └── defender-investigation.spl

│

├── docs/

│   ├── architecture.md

│   └── investigation-workflow.md

│

├── screenshots/

│

├── .gitignore

└── README.md

```



\## 🔐 Security \& Privacy



This repository does not contain:



\* Gmail passwords

\* Gmail App Passwords

\* API keys

\* Authentication tokens

\* Personal email contents

\* Private credentials

\* Sensitive configuration files



Real Gmail data is kept locally and excluded using `.gitignore`.



\## 🚧 Future Improvements



\* Email URL extraction

\* SPF analysis

\* DKIM analysis

\* DMARC analysis

\* Attachment analysis

\* Phishing detection

\* Sysmon integration

\* Process monitoring

\* Splunk dashboards

\* Automated alerts

\* MITRE ATT\&CK mapping

\* Detection engineering

\* Incident-response case studies



\## 📚 Learning Objective



This is a hands-on cybersecurity learning project focused on developing practical SOC analyst skills through endpoint monitoring, log analysis, detection engineering, and security investigation.



\## ⚠️ Disclaimer



This is a personal defensive security lab intended for learning, experimentation, and cybersecurity portfolio development.



