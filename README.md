<!-- # 🔍 Reconnaissance Tool v2.0

A comprehensive, modular reconnaissance tool for network intelligence gathering and security testing.

## ⚠️ Legal Disclaimer

**IMPORTANT:** This tool should **ONLY** be used on systems that:
- You own
- You have explicit written permission to test

Unauthorized scanning may be **ILLEGAL** in your jurisdiction. The developers assume **NO** liability for misuse of this tool.

## 🚀 Features

### Passive Reconnaissance
- **WHOIS Lookup**: Domain registration information
- **DNS Enumeration**: A, AAAA, MX, NS, TXT, SOA records
- **Subdomain Discovery**: Certificate transparency logs, public APIs

### Active Reconnaissance
- **Port Scanning**: Socket-based or Nmap scanning
- **Banner Grabbing**: Service version detection
- **Technology Detection**: CMS, frameworks, libraries, CDNs

### Reporting
- **TXT Reports**: Human-readable text format
- **JSON Reports**: Machine-parseable format
- **PDF Reports**: Professional formatted reports

## 📦 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/recon-tool.git
cd recon-tool
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Install Nmap for enhanced scanning:
```bash
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap

# Then install Python wrapper
pip install python-nmap
```

## 📁 Project Structure

```
recon-tool/
├── main.py              # Main entry point
├── config.py            # Configuration settings
├── utils.py             # Utility functions
├── requirements.txt     # Python dependencies
├── modules/
│   ├── __init__.py
│   ├── passive.py       # Passive recon module
│   ├── active.py        # Active recon module
│   └── reporter.py      # Report generation
├── reports/             # Generated reports (auto-created)
└── logs/                # Log files (auto-created)
```

## 🎯 Usage

### Basic Examples

**Run all modules:**
```bash
python main.py example.com --all
```

**WHOIS and DNS only:**
```bash
python main.py example.com --whois --dns
```

**Port scanning and technology detection:**
```bash
python main.py example.com --ports --tech
```

**Subdomain enumeration with report:**
```bash
python main.py example.com --subdomains --report txt
```

**Full scan with Nmap and PDF report:**
```bash
python main.py example.com --all --nmap --report pdf
```

### Command-Line Options

```
positional arguments:
  target                Target domain or IP address

Passive Reconnaissance:
  --whois              Perform WHOIS lookup
  --dns                Perform DNS enumeration
  --subdomains         Perform subdomain enumeration

Active Reconnaissance:
  --ports              Perform port scanning
  --banner             Grab banners from open ports
  --tech               Detect web technologies
  --nmap               Use Nmap for port scanning

Reporting:
  --report {txt,json,pdf}
                       Generate report in specified format
  -o, --output         Custom output directory for reports

Miscellaneous:
  --all                Run all reconnaissance modules
  -v, --verbose        Verbose output (show debug logs)
  --skip-disclaimer    Skip legal disclaimer (not recommended)
  -h, --help           Show help message
```

## 📊 Sample Output

```
==================================================================
    
    🔍 RECONNAISSANCE TOOL v2.0
    Network Intelligence Gathering Tool
    
    For Authorized Security Testing Only
    
==================================================================

============================================================
🔍 WHOIS LOOKUP: example.com
============================================================

Domain Name: example.com
Organization: Example Organization
Registrar: Example Registrar Inc.
Created: 1995-08-14 04:00:00
Expires: 2025-08-13 04:00:00

============================================================
🔍 PORT SCANNING: example.com (93.184.216.34)
============================================================

Progress: 5/15 ports scanned...
Port    80 | OPEN      | HTTP
Port   443 | OPEN      | HTTPS
Progress: 15/15 ports scanned...

SCAN COMPLETE
Open Ports: 2/15
```

## ⚙️ Configuration

Edit `config.py` to customize:

```python
# Default ports to scan
COMMON_PORTS = [21, 22, 80, 443, 3306, 8080]

# Timeouts (in seconds)
SOCKET_TIMEOUT = 2
WEB_REQUEST_TIMEOUT = 10

# Reports directory
REPORTS_FOLDER = "reports"
```

## 📝 Generated Reports

Reports are saved in the `reports/` directory with timestamps:

- **TXT**: `reports/example_com_20250121_143022.txt`
- **JSON**: `reports/example_com_20250121_143022.json`
- **PDF**: `reports/example_com_20250121_143022.pdf`

## 🐛 Troubleshooting

### "No module named 'whois'"
```bash
pip install python-whois
```

### "Nmap not available"
```bash
pip install python-nmap
# Also install nmap itself (see Installation section)
```

### "Permission denied" errors
- Some scans may require elevated privileges
- Run with `sudo` if necessary (use caution!)

### SSL Certificate Warnings
- These are normal when scanning unknown sites
- The tool disables SSL verification for testing purposes

## 🔒 Security Best Practices

1. **Always get permission** before scanning any target
2. **Use VPN or authorized networks** when testing
3. **Respect rate limits** to avoid overwhelming targets
4. **Review logs** regularly for any issues
5. **Don't scan critical infrastructure** without proper authorization

## 📚 Learning Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Port Scanning Techniques](https://nmap.org/book/man-port-scanning-techniques.html)
- [DNS Enumeration](https://en.wikipedia.org/wiki/DNS_enumeration)

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is for educational purposes only. Use responsibly and ethically.

## 👨‍💻 Author

Created for security research and educational purposes.

## 🙏 Acknowledgments

- [python-whois](https://github.com/richardpenman/whois)
- [dnspython](https://www.dnspython.org/)
- [Nmap](https://nmap.org/)
- [ReportLab](https://www.reportlab.com/)

---

**Remember:** With great power comes great responsibility. Use this tool ethically and legally! 🛡️ -->


# TEHQEEQ - تحقیق

<img width="924" height="308" alt="tehqeeq" src="https://github.com/user-attachments/assets/69d46c82-ac62-4ad9-863b-2c50a94fa408" />



<div align="center">
Advanced Network Intelligence Gathering Framework

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com)

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Examples](#examples) • [Documentation](#documentation)

</div>

---

## 📖 About TEHQEEQ

**TEHQEEQ** (تحقیق - meaning "Investigation" in Urdu/Arabic) is a comprehensive network reconnaissance framework designed for security professionals and penetration testers. Built with modularity and ease of use in mind, TEHQEEQ provides extensive intelligence gathering capabilities with beautiful terminal output.

### 🎯 Key Highlights

- **Pakistani Domain Support** - Native PKNIC API integration for .pk domains
- **Comprehensive Scanning** - WHOIS, DNS, subdomains, ports, banners, technologies
- **Multiple Report Formats** - PDF, HTML, JSON, and TXT reports
- **Auto Verification** - Built-in result verification against external sources
- **Fast & Efficient** - Optimized scanning with minimal false positives

---

## ✨Features

### 🔐 Passive Reconnaissance
- **WHOIS Lookup**
  - Standard WHOIS for international domains
  - PKNIC API integration for .pk domains
  - Fallback web scraping for limited data
  - Registration dates, nameservers, contacts

- **DNS Enumeration**
  - A, AAAA, CNAME, MX, NS, TXT, SOA records
  - Configurable DNS resolvers
  - Timeout handling for large record sets

- **Subdomain Discovery**
  - DNS Zone Transfer (AXFR) attempts
  - SSL Certificate Subject Alternative Names
  - DNS brute-force (100+ common subdomains)
  - Deduplication and validation

### 🎯 Active Reconnaissance
- **Port Scanning**
  - TCP Connect scanning
  - 15 most common ports by default
  - Custom port list support
  - Auto-detection of www subdomain

- **Banner Grabbing**
  - Protocol-specific probes
  - HTTP, SMTP, POP3, IMAP, FTP support
  - Timeout handling

- **Technology Detection**
  - Web server identification
  - CMS detection (WordPress, Drupal, Joomla)
  - JavaScript frameworks (Angular, React, Vue)
  - Security headers analysis
  - CDN detection

### 📊 Reporting & Verification
- **Report Generation**
  - PDF reports with professional formatting
  - HTML reports with interactive elements
  - JSON for programmatic access
  - TXT for quick reference

- **Auto Verification**
  - DNS cross-validation
  - Port state verification
  - Technology cross-checking
  - Confidence scoring

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Internet connection

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/tehqeeq.git
cd tehqeeq

# Install dependencies
pip install -r requirements.txt

# Run TEHQEEQ
python main.py --help
```

### Dependencies

```txt
dnspython>=2.6.1
python-whois>=0.9.27
requests>=2.31.0
colorama>=0.4.6
reportlab>=4.0.0
```

**Optional:**
```txt
python-nmap>=0.7.1  # For Nmap integration
```

---

## 📚 Usage

### Basic Syntax

```bash
python main.py [TARGET] [OPTIONS]
```

### Command Line Options

```
Positional Arguments:
  target                Target domain or IP address
  -d, --domain         Alternative target specification

Scan Options:
  --whois              Perform WHOIS lookup
  --dns                Perform DNS enumeration
  --subdomains         Perform subdomain enumeration
  --ports              Perform port scanning
  --banner             Grab banners from open ports
  --tech               Detect web technologies
  --all, --full        Run all reconnaissance modules

Reporting:
  --report {txt,json,pdf,html}
                       Generate report in specified format
  --output, -o         Custom output directory for reports
  --verify             Verify results against external sources

Verbosity:
  -v, -vv, -vvv        Increase verbosity level
  --skip-disclaimer    Skip legal disclaimer (not recommended)
```

---

## 💡 Examples

### Basic Scans

```bash
# Full scan with verbose output
python main.py google.com --all -vv

# WHOIS lookup only
python main.py neduet.edu.pk --whois

# DNS enumeration
python main.py example.com --dns -vv

# Port scan and technology detection
python main.py www.example.com --ports --tech
```

### Advanced Usage

```bash
# Full scan with PDF report
python main.py www.neduet.edu.pk --all --report pdf -vv

# Scan with verification
python main.py google.com --all --verify -vv

# RedScout-style syntax
python main.py -d www.example.com --full -vvv

# Custom output directory
python main.py target.com --all --report json -o /path/to/reports
```

### Pakistani Domains

```bash
# Scan .pk domain with PKNIC integration
python main.py neduet.edu.pk --all -vv

# WHOIS for .edu.pk domain
python main.py uet.edu.pk --whois

# Full scan with all features
python main.py www.pide.org.pk --full --report pdf -vv
```

---

## 📊 Sample Output

### WHOIS Lookup (.pk domain)
```
╔══════════════════════════════════════════════════════════════════╗
║        PERFORMING WHOIS ENUMERATION FOR NEDUET.EDU.PK            ║
╚══════════════════════════════════════════════════════════════════╝

🇵🇰 Detected .pk domain - Using PKNIC API

[INFO] Querying PKNIC API for neduet.edu.pk...

📋 Domain Name: neduet.edu.pk
📝 Registrar: PKNIC
📅 Created: 1999-06-09
📅 Expires: 2028-06-09
📊 Status: Registered

🖥️  Name Servers:
   - ns1.neduet.edu.pk
   - ns2.neduet.edu.pk
```

### DNS Enumeration
```
╔══════════════════════════════════════════════════════════════════╗
║         PERFORMING DNS ENUMERATION FOR WWW.NEDUET.EDU.PK         ║
╚══════════════════════════════════════════════════════════════════╝

[A] Records for www.neduet.edu.pk:
  - 111.68.110.16
  (Queried A record for www.neduet.edu.pk using ['8.8.8.8', '1.1.1.1'])

[MX] Records for neduet.edu.pk:
  - smtp.google.com (Priority: 1)
  (Queried MX record for neduet.edu.pk using ['8.8.8.8', '1.1.1.1'])
```

### Port Scanning
```
╔══════════════════════════════════════════════════════════════════╗
║           PERFORMING PORT SCAN FOR WWW.NEDUET.EDU.PK             ║
╚══════════════════════════════════════════════════════════════════╝

[DEBUG] Scanning port 25
[OPEN] Port   25 | State: Open | Service: SMTP | Method: TCP Connect
[DEBUG] Scanning port 110
[OPEN] Port  110 | State: Open | Service: POP3 | Method: TCP Connect
[DEBUG] Scanning port 443
[OPEN] Port  443 | State: Open | Service: HTTPS | Method: TCP Connect
```

---

## 🎨 Verbosity Levels

| Flag | Level | Output |
|------|-------|--------|
| (none) | 0 | Minimal - Results only |
| `-v` | 1 | Normal - Results with context |
| `-vv` | 2 | Verbose - Query details, progress |
| `-vvv` | 3 | Debug - All debug messages |

### Verbosity Examples

```bash
# Silent mode
python main.py target.com --all

# Normal mode
python main.py target.com --all -v

# Verbose mode (shows query details like RedScout)
python main.py target.com --all -vv

# Debug mode (shows everything)
python main.py target.com --all -vvv
```

---

## 📁 Project Structure

```
tehqeeq/
├── main.py                      # Main entry point
├── config.py                    # Configuration settings
├── requirements.txt             # Dependencies
├── README.md                    # This file
├── modules/
│   ├── __init__.py
│   ├── passive.py              # Passive reconnaissance
│   ├── active.py               # Active reconnaissance
│   ├── reporter.py             # Report generation
│   ├── verification.py         # Result verification
│   └── output_formatter.py     # Terminal output formatting
├── utils.py                     # Utility functions
├── reports/                     # Generated reports
└── logs/                        # Log files
```

---

## 🔒 Legal & Ethical Use

### ⚠️ IMPORTANT DISCLAIMER

This tool is designed for **authorized security testing only**. 

**YOU MUST:**
- ✅ Own the target system
- ✅ Have explicit written permission to test
- ✅ Comply with local laws and regulations
- ✅ Respect rate limits and resources

**NEVER:**
- ❌ Scan systems without authorization
- ❌ Use for malicious purposes
- ❌ Violate terms of service
- ❌ Perform denial-of-service attacks

**The developers assume NO liability for misuse of this tool.**

Unauthorized scanning may be **ILLEGAL** in your jurisdiction and could result in:
- Criminal charges
- Civil lawsuits
- Network bans
- Professional consequences

---

## 🌟 Features in Detail

### PKNIC Integration

TEHQEEQ is one of the few tools with native support for Pakistani (.pk) domains:

- **Primary**: PKNIC JSON API
- **Fallback**: PKNIC web scraping
- **Handles**: .edu.pk, .gov.pk, .org.pk, .com.pk, .net.pk
- **Features**: Registration dates, nameservers, registrar info

### Auto WWW Detection

When scanning base domains without A records:
```
⚠️  neduet.edu.pk has no A record
🔍 Checking www subdomain: www.neduet.edu.pk...
✅ Found! www.neduet.edu.pk → 111.68.110.16
🔄 Automatically switching to www.neduet.edu.pk
```

### Zone Transfer Success

Many educational institutions (.edu.pk) allow zone transfers:
```
Method 1: DNS Zone Transfer (AXFR)
   🔄 Attempting zone transfer from ns2.neduet.edu.pk...
      ✅ Zone transfer successful!
   Found 375 subdomains
```

---

## 🛠️ Troubleshooting

### Common Issues

**Problem**: Colors not showing on Windows
```bash
# Solution: Install/update colorama
pip install colorama --upgrade

# Or use Windows Terminal instead of CMD
```

**Problem**: Box characters showing as `?`
```bash
# Solution: Set console to UTF-8
chcp 65001

# Or disable Unicode boxes in config
```

**Problem**: DNS timeout errors
```python
# Solution: Increase timeout in config.py
DNS_TIMEOUT = 15  # Increase from 10
```

**Problem**: PKNIC API not working
```bash
# Solution: Check internet connection
# The tool will fallback to web scraping automatically
```

---

## 📈 Roadmap

### Planned Features
- [ ] Multi-threaded subdomain enumeration
- [ ] Integration with more TLDs (India .in, Bangladesh .bd)
- [ ] Vulnerability scanning module
- [ ] Email enumeration
- [ ] Continuous monitoring mode
- [ ] API for programmatic access
- [ ] Web interface
- [ ] Export to OSINT frameworks

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup
```bash
git clone https://github.com/yourusername/tehqeeq.git
cd tehqeeq
pip install -r requirements.txt
```

### Guidelines
- Follow PEP 8 style guide
- Add tests for new features
- Update documentation
- Use meaningful commit messages

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


---

## Acknowledgments

- **PKNIC** for providing API access for .pk domains
- **RedScout** for inspiration on terminal output design
- **Nmap** project for port scanning methodology
- **Python Security Community** for tools and libraries

---

## Support & Queries 

- 📧 Email: laiba244m@gmail.com

---

<div align="center">

**Made with ❤️ for the Security Community**

⭐ Star this repo if you find it useful!

[Report Bug](https://github.com/yourusername/tehqeeq/issues) • [Request Feature](https://github.com/yourusername/tehqeeq/issues) • [Documentation](https://github.com/yourusername/tehqeeq/wiki)

</div>
