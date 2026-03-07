# 🎯 Sigma Honeypot Lab

A detection engineering environment for learning Sigma rule development against real attack data.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Docker](https://img.shields.io/badge/docker-required-blue.svg)

## 🚀 Quick Start

```bash
curl -sSL https://raw.githubusercontent.com/iimp0ster/Linux-Webshell-Honeypot/main/install.sh | sudo bash
```

In ~15 minutes you'll have a running honeypot and analysis dashboard. Access the dashboard via SSH tunnel:

```bash
ssh -L 8501:localhost:8501 youruser@honeypot-ip
# Browse to: http://localhost:8501
```

## 🏗️ Architecture

```
┌──────────────────────────────────────────┐
│  Internet                                │
└──────────────┬───────────────────────────┘
               │ Port 80
               ▼
┌──────────────────────────────────────────┐
│  OwnCloud Honeypot (PHP + Apache)        │
│  • Fake OwnCloud 10.12.0 login page      │
│  • Logs all credential attempts          │
│  • Accepts file uploads (any type)       │
│  • Webshells stored outside webroot      │
└──────────────┬───────────────────────────┘
               │ NDJSON logs
               ▼
┌──────────────────────────────────────────┐
│  Logging Stack                           │
│  • Apache access/error logs              │
│  • Auditd — file system & process events │
│  • Sysmon for Linux — process telemetry  │
└──────────────┬───────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────┐
│  Streamlit Dashboard (localhost only)    │
│  • Attack analysis & visualization       │
│  • Sigma rule editor + live tester       │
│  • Webshell classification               │
└──────────────────────────────────────────┘
```

## 📊 Features

### Honeypot

- **OwnCloud disguise** — poses as OwnCloud 10.12.0 with a realistic login page and file manager UI
- **Credential logging** — every login attempt (username, password, IP, User-Agent) logged to `credentials.log` as NDJSON
- **Safe capture** — uploaded files are stored outside the webroot so webshells land on disk but cannot execute
- **Rich telemetry** — 10+ fields per upload event: IP, X-Forwarded-For, User-Agent, filename, size, MIME type, and more

### Dashboard

Ten pages covering the full detection-engineering workflow:

| Page | Purpose |
|------|---------|
| 📊 Overview | Attack timeline and summary metrics |
| 📋 Upload Log | Filterable table of all upload events |
| 📂 Captured Files | Inspect uploaded files with webshell family classification |
| 💻 Command Telemetry | Auditd-parsed post-exploitation commands |
| 🌍 IP Intelligence | Geolocation and threat enrichment per source IP |
| 📏 Sigma Rules | Browse the saved rule library |
| ✏️ Rule Editor | Write rules with templates; validate and save |
| 🧪 Rule Tester | Test any rule against real honeypot data |
| 🔬 Sample Webshells | Pre-loaded reference samples with classification |
| 📜 Raw Logs | Raw Apache, auditd, and syslog output |

**Detection engineering loop:**

1. Open **✏️ Rule Editor** — choose a template (Upload event, File content, or Process creation)
2. Write your detection logic, then click **Send to Rule Tester**
3. In **🧪 Rule Tester** — pick a data source (upload log events or captured file content) and click **Run Test**
4. Review match count, matched records table, and a per-selection breakdown chart showing which clauses fired
5. Refine and **Save Rule** to the library

### Detection Stack

- **Auditd** — file writes, process execution, network connections
- **Sysmon for Linux** — process creation with command-line arguments
- **Apache logs** — full HTTP request telemetry

## 📦 Requirements

- Ubuntu 22.04 or 24.04 LTS
- 2 GB RAM minimum (4 GB recommended)
- 20 GB disk space
- Public IP address (to capture real attacks)

**Recommended platforms:** DigitalOcean ($6–12/mo), AWS EC2 t3.small, Azure B2s, GCP e2-small

## 🔧 Manual Setup

```bash
git clone https://github.com/iimp0ster/Linux-Webshell-Honeypot.git
cd Linux-Webshell-Honeypot
sudo bash install.sh
```

## 🎓 Example Workflow

**1. Deploy** — run the installer, then SSH-tunnel to the dashboard.

**2. Explore samples** — the 🔬 Sample Webshells page has four pre-loaded webshell families (China Chopper, WSO, b374k, generic eval shell) to study before real attacks arrive.

**3. Write your first rule** — use the Upload event template in the Rule Editor:

```yaml
title: PHP Webshell Upload
logsource:
    product: linux
    category: webshell_upload
detection:
    selection:
        filename|endswith:
            - '.php'
            - '.phtml'
            - '.phar'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1505.003
```

**4. Test it** — click **Send to Rule Tester**, switch to 🧪 Rule Tester, and run against your upload log events. The per-selection breakdown shows exactly which clause matched each event.

**5. Wait for real attacks** — internet scanners typically find an exposed port 80 within 24–48 hours. Webshell uploads follow within the first week.

**6. Iterate** — analyze new samples, refine rules, build your detection library.

## 🛡️ Security Notes

- This honeypot is **intentionally vulnerable** — deploy on an isolated system with no production data
- Do **not** use on networks with sensitive systems
- The dashboard is **localhost-only** by default; access via SSH tunnel
- Uploaded webshells cannot execute (stored outside Apache's webroot), but treat the host as compromised by design

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Commit and push (`git commit -m 'description'`)
4. Open a pull request

Ideas: new honeypot disguises, additional Sigma rule templates, dashboard features, bug fixes.

## 🙏 Acknowledgments

- **Sigma Project** — detection rule format
- **MITRE ATT&CK** — attack taxonomy
- **SwiftOnSecurity** — Sysmon configuration
- **Wiz Research** — HoneyBee inspiration

## 📄 License & Disclaimer

MIT License — see [LICENSE](LICENSE) for details.

This tool is for **educational and research purposes only**. Deploy only in isolated environments. The authors are not responsible for misuse or damage caused by this software.
