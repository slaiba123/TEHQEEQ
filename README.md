# TEHQEEQ - تحقیق


<img width="1536" height="1024" alt="tehqeeq" src="https://github.com/user-attachments/assets/e23fbaba-eb9a-433f-a542-e59e17fc6a58" />

<div align="center">
Advanced Network Intelligence Gathering Framework

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com)

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Examples](#examples) • [Documentation](#documentation)

</div>

---

## 📖 About TEHQEEQ

**TEHQEEQ** (تحقیق - meaning "Investigation" in Urdu/Arabic) is a comprehensive network reconnaissance framework designed for security professionals and penetration testers. Built with modularity and ease of use in mind, TEHQEEQ provides extensive intelligence gathering capabilities with beautiful terminal output and professional reporting.

### 🎯 Key Highlights

- **Pakistani Domain Support** - Native PKNIC API integration for .pk domains
- **Certificate Transparency Logs** - Discover subdomains from SSL certificate databases
- **Subdomain Verification** - Built-in DNS and HTTP verification to filter dead subdomains
- **Nmap Integration** - Advanced port scanning with service version detection
- **Multiple Scan Modes** - Quick, normal, and full scanning options
- **Stealth Mode** - Randomized, slower scanning to avoid detection
- **Detection Modes** - Strict, balanced, and loose technology detection
- **Comprehensive Reports** - PDF, JSON, and TXT reports with complete data
- **Fast & Concurrent** - Multi-threaded scanning for optimal performance

---

## ✨ Features

### 🔐 Passive Reconnaissance

#### **WHOIS Lookup**
- Standard WHOIS for international domains
- **PKNIC API integration** for .pk domains with fallback web scraping
- Registration dates, nameservers, contacts, status
- Handles .edu.pk, .gov.pk, .org.pk, .com.pk domains

#### **DNS Enumeration**
- A, AAAA, CNAME, MX, NS, TXT, SOA records
- Configurable DNS resolvers (Google DNS, Cloudflare)
- Smart timeout handling for Pakistani networks
- Complete record display (no truncation)

#### **Subdomain Discovery** (4 Methods)
1. **Certificate Transparency Logs** (crt.sh)
   - Most effective passive method
   - Searches all publicly logged SSL certificates
   - Can discover 100+ subdomains instantly
   
2. **DNS Zone Transfer (AXFR)**
   - Attempts zone transfers from nameservers
   - Often successful for .edu.pk domains
   
3. **SSL Certificate Analysis**
   - Extracts Subject Alternative Names
   - Direct certificate inspection
   
4. **DNS Brute Force** (Enhanced Wordlist)
   - 200+ common subdomains for general domains
   - 250+ for .pk domains (education-specific)
   - Concurrent testing for speed
   - Smart progress indicators

#### **Subdomain Verification** 
- **DNS Verification** (fast): Checks if subdomains resolve to IPs
- **HTTP Verification** (thorough): Tests actual web service availability
- Identifies live, dead, and internal-only subdomains
- Concurrent verification (20 workers)
- Shows IP addresses, HTTP status, page titles

### 🎯 Active Reconnaissance

#### **Port Scanning** (Enhanced)
- **Three Scan Modes:**
  - `quick`: 11 common ports (~2 seconds)
  - `normal`: 15 essential ports (~3 seconds) [default]
  - `full`: 1000 ports (~30 seconds)

- **Two Scanning Methods:**
  - **Socket (Default)**: Concurrent scanning with 50 threads
  - **Nmap**: Advanced service detection, version info, OS hints

- **Stealth Mode:**
  - Randomized port order
  - Slower, less detectable scanning
  - Rate limiting to avoid detection

- **Features:**
  - Service name detection (30+ services)
  - Auto WWW subdomain detection
  - Progress indicators
  - Concurrent scanning for speed

#### **Banner Grabbing**
- Protocol-specific probes for HTTP, SMTP, FTP, SSH, POP3, IMAP
- Version extraction from banners
- OS detection from banner signatures
- Timeout handling (3 seconds)
- Truncates long banners intelligently

#### **Technology Detection** (Mode-Aware)
- **Three Detection Modes:**
  - `strict`: Fewer false positives (requires strong evidence)
  - `balanced`: Good middle ground [default]
  - `loose`: More detections (may have false positives)

- **Detects:**
  - Web servers (Apache, Nginx, IIS)
  - Backend technologies (PHP, Python, Node.js)
  - CMS platforms (WordPress with versions, Drupal, Joomla)
  - JavaScript frameworks (React, Vue, Angular, Next.js, Nuxt.js)
  - CSS frameworks (Bootstrap, Tailwind)
  - Libraries (jQuery)
  - CDNs (Cloudflare, AWS CloudFront, Akamai)
  - Analytics (Google Analytics, Tag Manager)
  - Security features (reCAPTCHA, HSTS, CSP)

- **Works Without Port Scanning:**
  - Auto-probes common HTTP ports (443, 80, 8080, 8443)
  - Can run standalone: `--tech` only

### 📊 Reporting & Export

#### **Report Formats**
- **PDF Reports:**
  - Professional formatting with colors
  - Complete data including ALL subdomains
  - Verification results with details
  - Appendices for large datasets
  - Summary statistics

- **JSON Reports:**
  - Machine-readable format
  - Complete nested data structure
  - Verification results included
  - Timestamps and metadata

- **TXT Reports:**
  - Human-readable format
  - Complete data (no truncation)
  - Shows ALL DNS records
  - Shows ALL subdomains
  - Verification summaries

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager
- Internet connection
- *Optional:* Nmap binary (for `--use-nmap`)

### Quick Install (Recommended)

```bash
# Clone the repository
git clone https://github.com/slaiba123/tehqeeq.git
cd tehqeeq

# Install dependencies
pip install -r requirements.txt

# Run TEHQEEQ
python main.py --help
```

### Install from PyPI 

```bash
# Install the tool and core dependencies
pip install tehqeeq

# Run from anywhere
tehqeeq example.com --whois --dns
tehqeeq example.com --all --report pdf
```

**Optional extras:**

```bash
# PDF report generation
pip install tehqeeq[pdf]

# Nmap integration
pip install tehqeeq[nmap]

# All extras
pip install tehqeeq[pdf,nmap]
```

### Install from Source (Development)

```bash
git clone https://github.com/slaiba123/tehqeeq.git
cd tehqeeq

# Editable install (changes apply immediately)
pip install -e .

# With optional features
pip install -e ".[pdf,nmap]"

# Run
tehqeeq example.com --all
```

### Install Nmap (Optional Recommended if you want in-depth analysis)

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nmap
pip install python-nmap
```

**macOS:**
```bash
brew install nmap
pip install python-nmap
```

**Windows:**
- Download from [nmap.org](https://nmap.org/download.html)
- Install python-nmap: `pip install python-nmap`

### Dependencies

**Core (Required):**
```txt
dnspython>=2.3.0
python-whois>=0.8.0
requests>=2.28.0
colorama>=0.4.6
urllib3>=2.0.0
```

**Optional:**
```txt
reportlab>=4.0.7      # For PDF reports
python-nmap>=0.7.1    # For Nmap integration
beautifulsoup4>=4.12  # For HTML parsing in verification
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

Passive Reconnaissance:
  --whois              Perform WHOIS lookup
  --dns                Perform DNS enumeration
  --subdomains         Perform subdomain enumeration

Active Reconnaissance:
  --ports              Perform port scanning
  --banner             Grab banners from open ports
  --tech               Detect web technologies

Scan Configuration:
  --all, --full        Run all reconnaissance modules
  --scan-mode {quick,normal,full}
                       Port scan mode (default: normal)
  --use-nmap           Use Nmap for advanced port scanning
  --stealth            Use stealth mode (slower, less detectable)

Subdomain Verification:
  --verify             Verify discovered subdomains (auto with --all)
  --no-verify          Skip verification even with --all
  --verify-method {dns,http}
                       Verification method (default: dns)

Technology Detection:
  --detection-mode {strict,balanced,loose}
                       Detection sensitivity (default: balanced)

Reporting:
  --report {txt,json,pdf}
                       Generate report in specified format
  --output, -o         Custom output directory for reports
  --export-json        Export active scan results to JSON

General Options:
  -v, -vv, -vvv        Increase verbosity level
  --skip-disclaimer    Skip legal disclaimer
  --version            Show version and exit
```

---

## 💡 Examples

### Basic Scans

```bash
# Full scan with verbose output
python main.py google.com --all -vv

# Full scan with subdomain verification
python main.py example.com --all --verify-method http

# WHOIS lookup only
python main.py neduet.edu.pk --whois

# DNS enumeration
python main.py example.com --dns -vv

# Subdomain discovery with verification
python main.py example.com --subdomains --verify
```

### Port Scanning Modes

```bash
# Quick scan (11 ports, ~2s)
python main.py target.com --ports --scan-mode quick

# Normal scan (15 ports, ~3s) [default]
python main.py target.com --ports --scan-mode normal

# Full scan (1000 ports, ~30s)
python main.py target.com --ports --scan-mode full

# Using Nmap (better accuracy)
python main.py target.com --ports --use-nmap

# Stealth scanning
python main.py target.com --ports --stealth --scan-mode normal
```

### Technology Detection

```bash
# Strict mode (fewer false positives)
python main.py example.com --tech --detection-mode strict

# Balanced mode (default)
python main.py example.com --tech

# Loose mode (more detections)
python main.py example.com --tech --detection-mode loose

# Technology detection without port scan
python main.py example.com --tech
```

### Advanced Usage

```bash
# Full scan with Nmap and PDF report
python main.py www.neduet.edu.pk --all --use-nmap --report pdf -vv

# Full scan without verification
python main.py target.com --all --no-verify --report json

# Stealth full scan with HTTP verification
python main.py target.com --all --stealth --verify-method http

# Custom output directory
python main.py target.com --all --report pdf -o /path/to/reports

# Export active scan results
python main.py target.com --ports --tech --export-json
```

### Pakistani Domains

```bash
# Scan .pk domain with PKNIC integration
python main.py neduet.edu.pk --all -vv

# WHOIS for .edu.pk domain
python main.py uet.edu.pk --whois

# Full scan with verification and Nmap
python main.py www.pide.org.pk --all --use-nmap --verify --report pdf

# Subdomain discovery for Pakistani university
python main.py neduet.edu.pk --subdomains --verify-method dns -vv
```

---

## 📊 Sample Output

### Certificate Transparency Logs Discovery
```
[Method 0] Certificate Transparency Logs (crt.sh)
   This is the most effective passive method - searches all SSL certificates
   [INFO] Querying crt.sh database...
   [INFO] This may take 10-30 seconds for large domains...
   [INFO] Processing 1247 certificate entries...
      Progress: Found 25 unique subdomains...
      Progress: Found 50 unique subdomains...
      Progress: Found 75 unique subdomains...
   [SUCCESS] CT logs search complete
   [INFO] Sample findings:
      - www.example.com
      - mail.example.com
      - api.example.com
      - cdn.example.com
      - blog.example.com
      ... and 95 more
   ✓ Found 100 subdomains from CT logs
```

### Subdomain Verification
```
================================================================
🔍 VERIFYING 156 DISCOVERED SUBDOMAINS
================================================================
Method: DNS Resolution
Concurrent workers: 20
This may take a few minutes...

   [1/156] ✓ LIVE: www.example.com → 93.184.216.34
   [2/156] ✓ LIVE: mail.example.com → 93.184.216.35
   [3/156] ❌ DEAD (no DNS): old.example.com
   [4/156] 🔒 INTERNAL: vpn.example.com → 192.168.1.50
   [5/156] ✓ LIVE: api.example.com → 93.184.216.36

   Progress: 20/156 | Live: 15 | Dead: 3 | Internal: 2

================================================================
VERIFICATION COMPLETE
================================================================
✓ Live subdomains: 87
Dead subdomains: 65
Internal-only: 4
================================================================

[SUCCESS] Verified subdomains exported to verified_example.com_20250208_143022.txt
```

### Nmap Scanning
```
[PORT SCAN] target.com (93.184.216.34)
Mode: normal | Ports: 15 | Method: Nmap
Started: 14:30:45
================================================================

[INFO] Using Nmap for advanced scanning...
   Benefits: Service detection, version info, OS fingerprinting

[INFO] Running: nmap -sV -T4 -Pn --open 93.184.216.34 -p 22,25,80,443...

[OPEN] Port    22 | ssh (OpenSSH 8.2p1)
[OPEN] Port    80 | http (Apache httpd 2.4.41)
[OPEN] Port   443 | https (Apache httpd 2.4.41)

[OS DETECTION] Linux 4.15 - 5.6 (accuracy: 95%)

================================================================
SCAN COMPLETE
Open Ports: 3/15
Finished: 14:30:58
================================================================
```

### Technology Detection (Balanced Mode)
```
================================================================
[TECHNOLOGY DETECTION] www.example.com
Detection Mode: balanced
================================================================

[INFO] Using scanned port: 443
[INFO] Analyzing https://www.example.com...
   [SUCCESS] Connected successfully

[DETECTED TECHNOLOGIES] (Mode: balanced)

   Web Server: nginx/1.18.0 (Ubuntu)
   Backend: PHP/8.1.2
   CMS: WordPress 6.4.2
   JS Framework: React
   Framework: Next.js (React)
   Library: jQuery 3.6.0
   CSS Framework: Tailwind CSS
   CDN: Cloudflare
   Analytics: Google Analytics
   Tag Manager: Google Tag Manager
   Security: Google reCAPTCHA

Security Headers:
   - X-Frame-Options: SAMEORIGIN
   - HSTS Enabled
   - CSP Enabled
   - XSS Protection Enabled
   - Content-Type Options: nosniff

================================================================
```

---

## 🎨 Verbosity Levels

| Flag | Level | Output |
|------|-------|--------|
| (none) | 0 | Minimal - Results only |
| `-v` | 1 | Normal - Results with context |
| `-vv` | 2 | Verbose - Query details, progress |
| `-vvv` | 3 | Debug - All debug messages, DNS queries |

### Verbosity Examples

```bash
# Silent mode
python main.py target.com --all

# Normal mode
python main.py target.com --all -v

# Verbose mode (recommended)
python main.py target.com --all -vv

# Debug mode (shows DNS queries, timeouts, errors)
python main.py target.com --all -vvv
```

---

## 📁 Project Structure

```
tehqeeq/
├── main.py                      # Main entry point with argument parsing
├── config.py                    # Configuration settings (timeouts, ports, etc.)
├── utils.py                     # Utility functions (validation, parsing)
├── pyproject.toml               # Package metadata & dependencies
├── requirements.txt             # Python dependencies
├── README.md                    # This file
├── LICENSE                      # MIT License
├── modules/
│   ├── __init__.py
│   ├── passive.py              # Passive recon (WHOIS, DNS, subdomains)
│   ├── active.py               # Active recon (ports, banners, tech)
│   ├── reporter.py             # Report generation (PDF, JSON, TXT)
│   └── output_formatter.py     # Terminal output formatting
├── tests/                       # Unit tests
│   ├── test_utils.py
│   ├── test_passive.py
│   ├── test_active.py
│   └── test_reporter.py
├── reports/                     # Generated reports (auto-created)
└── logs/                        # Log files (auto-created)
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
- ❌ Overwhelm servers with requests

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

- **Primary Method**: PKNIC JSON API (`https://pknic.domainwhois.pk/api/json`)
- **Fallback Method**: PKNIC web scraping (`https://pk6.pknic.net.pk/pk5/lookup.PK`)
- **Supports**: .edu.pk, .gov.pk, .org.pk, .com.pk, .net.pk, .pk
- **Features**: 
  - Registration dates
  - Nameservers
  - Registrar information
  - Status codes
  - Automatic fallback on API failure

### Auto WWW Detection

When scanning base domains without A records:
```
⚠️  neduet.edu.pk has no A record (no direct IP address)
   Base domains often only have MX/NS records

   [INFO] Checking www subdomain: www.neduet.edu.pk...
   [SUCCESS] Found! www.neduet.edu.pk → 111.68.110.16
   [INFO] Automatically switching to www.neduet.edu.pk for active scanning
```

### Certificate Transparency Logs

Most effective subdomain discovery method:
- Queries crt.sh database (aggregates all CT logs)
- Discovers subdomains from historical SSL certificates
- Can find 100+ subdomains instantly
- Processes wildcard certificates
- Shows progress for large datasets

### Concurrent Scanning

All scanning operations use concurrent processing:
- **Port Scanning**: 50 concurrent threads (socket mode)
- **Subdomain Brute Force**: Concurrent DNS queries
- **Subdomain Verification**: 20 concurrent workers
- **Progress Indicators**: Real-time updates

### Scan Modes Comparison

| Mode | Ports | Time | Use Case |
|------|-------|------|----------|
| `quick` | 11 | ~2s | Fast reconnaissance |
| `normal` | 15 | ~3s | Balanced (default) |
| `full` | 1000 | ~30s | Thorough scanning |

### Detection Modes Comparison

| Mode | Accuracy | Coverage | False Positives |
|------|----------|----------|-----------------|
| `strict` | Highest | Lowest | Very Few |
| `balanced` | High | Medium | Few (default) |
| `loose` | Medium | Highest | Some |

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

# Or run in Windows Terminal
```

**Problem**: DNS timeout errors
```python
# Solution: Increase timeout in config.py
DNS_TIMEOUT = 15  # Increase from 10
SOCKET_TIMEOUT = 3  # Increase from 2
```

**Problem**: PKNIC API not working
```
# The tool automatically falls back to web scraping
# Check your internet connection
# Some .pk domains have limited WHOIS data
```

**Problem**: Nmap not found
```bash
# Install Nmap binary first:
# Ubuntu: sudo apt install nmap
# macOS: brew install nmap
# Windows: Download from nmap.org

# Then install Python wrapper:
pip install python-nmap
```

**Problem**: Certificate Transparency timeout
```
# crt.sh can be slow or busy
# The tool will continue with other methods
# Try again later or use --verify to filter results
```

**Problem**: Too many subdomains in PDF
```
# PDFs automatically create appendices for large datasets
# First 100 subdomains in main section
# Complete list in Appendix A
# Verified list in Appendix B
```

---

## 📈 Performance Tips

### Optimize Scanning Speed

```bash
# Fastest configuration
python main.py target.com --all --scan-mode quick --verify-method dns

# Best accuracy
python main.py target.com --all --use-nmap --verify-method http

# Balanced (recommended)
python main.py target.com --all --verify --report pdf
```

### Network-Specific Optimizations

For slow/unreliable networks (edit `config.py`):
```python
DNS_TIMEOUT = 15        # Increase from 10
SOCKET_TIMEOUT = 3      # Increase from 2
WEB_REQUEST_TIMEOUT = 15  # Increase from 10
```

For fast networks:
```python
# Use full scan mode with Nmap
python main.py target.com --all --scan-mode full --use-nmap
```

---

## 📚 Configuration Options

Edit `config.py` to customize:

```python
# Common ports for scanning
COMMON_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 3389, 8080, 8443]

# Timeouts
DNS_TIMEOUT = 10
SOCKET_TIMEOUT = 2
BANNER_TIMEOUT = 3
WEB_REQUEST_TIMEOUT = 10

# Report settings
REPORTS_FOLDER = "reports"
ENABLE_SSL_VERIFICATION = False  # Ignore SSL errors

# Banner grabbing
BANNER_MAX_SIZE = 4096

# Subdomain brute force
MAX_SUBDOMAIN_THREADS = 50
```

---

## 🧪 Testing

### Run Unit Tests

```bash
# From project root
python -m unittest discover -s tests -p "test_*.py" -v

# Run specific test file
python -m unittest tests.test_passive -v

# With coverage
pip install pytest pytest-cov
pytest --cov=modules --cov-report=html
```

### Test Scenarios

```bash
# Test PKNIC integration
python main.py neduet.edu.pk --whois -vvv

# Test subdomain verification
python main.py example.com --subdomains --verify --verify-method http

# Test Nmap integration
python main.py scanme.nmap.org --ports --use-nmap -vv

# Test stealth mode
python main.py target.com --ports --stealth --scan-mode normal

# Test PDF generation
python main.py example.com --all --report pdf
```

---

## 📖 API Documentation

### Using as a Library

```python
from modules.passive import PassiveRecon
from modules.active import ActiveRecon
from modules.reporter import Reporter

# Passive reconnaissance
p = PassiveRecon("example.com")
p.whois_lookup()
p.dns_enumeration()
subdomains = p.subdomain_enumeration()

# Verify subdomains
verified = p.verify_subdomains(verification_type='dns')

# Active reconnaissance
a = ActiveRecon("example.com")
a.port_scan(scan_mode='normal', use_nmap=True)
a.banner_grab()
a.detect_technologies(detection_mode='balanced')

# Generate report
r = Reporter("example.com", p.results, a.results)
r.generate_pdf_report()
```


---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup
```bash
git clone https://github.com/slaiba123/tehqeeq.git
cd tehqeeq
pip install -e ".[dev,pdf,nmap]"
```

### Guidelines
- Follow PEP 8 style guide
- Add tests for new features
- Update documentation
- Use meaningful commit messages
- Test with both Python 3.8 and 3.12

### Areas for Contribution
- Additional subdomain discovery methods
- More TLD integrations (India .in, Bangladesh .bd)
- Web interface development
- Performance optimizations
- Documentation improvements
- Test coverage expansion

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2024 LAIBA MUSHTAQ

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 🙏 Acknowledgments

- **PKNIC** for providing API access for .pk domains
- **crt.sh** for Certificate Transparency log aggregation
- **Nmap Project** for port scanning methodology
- **Python Security Community** for tools and libraries
- **Contributors** who have helped improve this tool

---

## 📧 Support & Contact

- **Email**: laiba244m@gmail.com
- **GitHub Issues**: [Report bugs or request features](https://github.com/slaiba123/tehqeeq/issues)
- **Documentation**: [Full documentation](https://github.com/slaiba123/tehqeeq#readme)


---

<div align="center">

**Made with ❤️ for the Security Community**

⭐ Star this repo if you find it useful!

[Report Bug](https://github.com/slaiba123/tehqeeq/issues) • [Request Feature](https://github.com/slaiba123/tehqeeq/issues) • [Documentation](https://github.com/slaiba123/tehqeeq#readme)

---

**TEHQEEQ v1.0** - Advanced Network Reconnaissance  
*For authorized security testing and educational purposes only*

</div>
