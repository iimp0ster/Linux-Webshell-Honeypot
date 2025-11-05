# 🎯 Sigma Honeypot Lab

**A complete detection engineering environment for learning threat detection and Sigma rule development.**

Deploy a vulnerable web application honeypot, capture real attacks, and build production-ready Sigma detection rules.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Docker](https://img.shields.io/badge/docker-required-blue.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)

## 🚀 Quick Start

### One-Line Installation

```bash
curl -sSL https://raw.githubusercontent.com/iimp0ster/Linux-Webshell-Honeypot/main/install.sh | sudo bash
```

**That's it!** In 15 minutes you'll have:
- ✅ Vulnerable PHP honeypot (capturing real attacks)
- ✅ Streamlit dashboard (analyze attacks in real-time)
- ✅ Pre-loaded sample webshells (start immediately)
- ✅ Full logging stack (auditd, Sysmon, Apache)
- ✅ Sigma rule builder & tester

### Access Your Lab

```bash
# From your local machine, create SSH tunnel:
ssh -L 8501:localhost:8501 youruser@honeypot-ip

# Browse to: http://localhost:8501
```

## 📋 What You'll Learn

This project teaches practical **Detection Engineering** skills:

1. **Threat Analysis** - Analyze real webshell attacks
2. **Sigma Rule Development** - Write detection rules from scratch
3. **Rule Testing** - Validate rules against attack logs
4. **Threat Intelligence** - Understand attacker TTPs
5. **Log Analysis** - Parse and correlate security events

## 🎯 Use Cases

### For Detection Engineers
- Practice writing Sigma rules with real attack data
- Test rule quality before production deployment
- Build a personal library of validated detections

### For Threat Researchers
- Capture live webshell samples
- Study attacker behavior post-exploitation
- Collect IOCs for threat intelligence

### For Blue Teams
- Train junior analysts on attack patterns
- Validate existing detection rules
- Research new detection techniques

### For Students
- Learn detection engineering fundamentals
- Build cybersecurity portfolio projects
- Hands-on practice with real threats

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│  Internet                           │
└────────────┬────────────────────────┘
             │ Port 80
             ▼
┌─────────────────────────────────────┐
│  Vulnerable PHP Honeypot            │
│  (Intentional file upload vuln)     │
└────────────┬────────────────────────┘
             │ All activity logged
             ▼
┌─────────────────────────────────────┐
│  Logging Stack                      │
│  • Apache logs                      │
│  • Auditd events                    │
│  • Sysmon telemetry                 │
│  • File system monitoring           │
└────────────┬────────────────────────┘
             │ Real-time analysis
             ▼
┌─────────────────────────────────────┐
│  Streamlit Dashboard (localhost)    │
│  • View attacks                     │
│  • Write Sigma rules                │
│  • Test detections                  │
│  • Export rules                     │
└─────────────────────────────────────┘
```

## 📊 Features

### Honeypot
- **Vulnerable by Design** - File upload with zero validation
- **Realistic UI** - Looks like internal document management system
- **Comprehensive Logging** - Every interaction captured
- **Docker Isolated** - Safe to expose to internet

### Dashboard
- **Live Attack Monitoring** - See attacks in real-time
- **Sigma Rule Builder** - Write rules with templates
- **Rule Testing Engine** - Validate against logs
- **Sample Webshells** - Pre-loaded for immediate analysis
- **Attack Statistics** - Visualize attacker behavior

### Detection Stack
- **Auditd** - File system & process monitoring
- **Sysmon for Linux** - Advanced telemetry
- **Apache Logs** - Web request analysis
- **EDR Ready** - Compatible with commercial EDR agents

## 📦 Requirements

- Ubuntu 22.04 or 24.04 LTS
- 2GB RAM minimum (4GB recommended)
- 20GB disk space
- Public IP (for capturing real attacks)

**Recommended Platforms:**
- DigitalOcean ($6-12/month droplet)
- AWS EC2 (t3.small)
- Azure VM (B2s)
- Google Cloud (e2-small)

## 🔧 Manual Installation

If you prefer manual setup or need customization:

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/sigma-honeypot-lab.git
cd sigma-honeypot-lab

# Run setup
sudo bash install.sh

# Follow prompts for username and password
```

See [docs/QUICK_START.md](docs/QUICK_START.md) for detailed instructions.

## 📖 Documentation

- **[Quick Start Guide](docs/QUICK_START.md)** - Get running in 5 minutes
- **[Architecture Overview](docs/ARCHITECTURE.md)** - How it works
- **[Detection Guide](docs/DETECTION_GUIDE.md)** - Writing Sigma rules
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues

## 🎓 Example Workflow

**1. Deploy the lab** (15 minutes)
```bash
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sigma-honeypot-lab/main/install.sh | sudo bash
```

**2. Analyze pre-loaded samples** (30 minutes)
- Review 4 different webshell types
- Identify malicious patterns
- Understand attacker techniques

**3. Write your first Sigma rule** (15 minutes)
```yaml
title: PHP Webshell Upload Detection
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'PATH'
        name|contains: '/var/www/'
        name|endswith: '.php'
    condition: selection
level: high
```

**4. Test the rule** (5 minutes)
- Run attack simulator
- Validate rule matches
- Refine detection logic

**5. Wait for real attacks** (24-48 hours)
- Internet scanners find your honeypot
- Attackers upload webshells
- Collect real-world samples

**6. Iterate and improve** (ongoing)
- Analyze new attacks
- Write additional rules
- Build detection library

## 🛡️ Security Notes

**⚠️ IMPORTANT:**
- This honeypot is **intentionally vulnerable**
- Deploy on an **isolated system** with no production data
- Do NOT use on networks with sensitive systems
- Dashboard is **localhost-only** by default (SSH tunnel required)
- Consider this system **compromised by design**

## 🤝 Contributing

Contributions welcome! Here's how:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add new Sigma rule template'`)
4. Push to branch (`git push origin feature/improvement`)
5. Create Pull Request

**Ideas for contributions:**
- Additional Sigma rule templates
- New honeypot types (databases, APIs)
- Improved dashboard features
- Documentation improvements
- Bug fixes

## 📝 Example Sigma Rules

The project includes production-ready Sigma rules:

- **Webshell Upload Detection** - File creation in web directories
- **Command Execution** - Web processes spawning shells
- **Network Connections** - Outbound C2 callbacks
- **Persistence** - Cron job creation
- **Reconnaissance** - System enumeration commands

See [sigma_rules/](sigma_rules/) for complete collection.

## 🎯 Real-World Results

**What you'll capture:**

| Week | Expected Activity |
|------|------------------|
| **Day 1-2** | Port scans, vulnerability scanners (Shodan, Masscan) |
| **Week 1** | First webshell uploads (automated bots) |
| **Week 2** | China Chopper, WSO shells, command execution |
| **Week 3+** | Cryptominers, persistence attempts, lateral movement |

**Typical webshells collected:**
- China Chopper variants
- WSO (Web Shell by Orb)
- c99, r57, b374k
- Custom PHP shells
- Obfuscated payloads

## 📊 Project Stats

- **Setup Time:** 15 minutes (fully automated)
- **Time to First Rule:** 20 minutes (using samples)
- **Time to Real Attacks:** 24-48 hours
- **Cost:** $6-12/month (cloud hosting)

## 🙏 Acknowledgments

- **Wiz Research** - HoneyBee inspiration
- **Sigma Project** - Detection rule format
- **MITRE ATT&CK** - Attack taxonomy
- **SwiftOnSecurity** - Sysmon configuration

## 📄 License

MIT License - See [LICENSE](LICENSE) for details

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**. The honeypot is intentionally vulnerable and should only be deployed in isolated environments. The authors are not responsible for misuse or damage caused by this software.

## 📞 Contact

**Tyler** - Detection Engineer / Threat Researcher

Questions? Open an issue or submit a PR!

---

**⭐ Star this repo if it helped you learn detection engineering!**

**Found it useful? Share with your blue team colleagues!**
