# """
# Configuration settings for the Reconnaissance Tool
# FIXED VERSION - Optimized timeouts and settings
# """

# # Ports to scan by default (most common ports)
# COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
#                 3306, 3389, 5432, 8080, 8443]

# # Extended port list (optional - use with caution, slower scans)
# EXTENDED_PORTS = [20, 21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 
#                   443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8000, 
#                   8008, 8080, 8443, 8888, 10000]

# # Timeouts (in seconds)
# SOCKET_TIMEOUT = 2          # Port scanning timeout
# BANNER_TIMEOUT = 5          # Banner grabbing timeout (increased)
# WEB_REQUEST_TIMEOUT = 15    # Web requests timeout (increased)
# DNS_TIMEOUT = 15            # DNS resolution timeout

# # Where to save reports
# REPORTS_FOLDER = "reports"

# # Subdomain brute force settings
# SUBDOMAIN_TIMEOUT = 2       # Timeout for each subdomain check
# MAX_SUBDOMAIN_THREADS = 15  # For threaded subdomain scanning (future enhancement)

# # Banner grabbing settings
# BANNER_MAX_SIZE = 4096      # Maximum bytes to read from banner

# # Technology detection settings
# CONTENT_ANALYSIS_LIMIT = 100000  # Limit content analysis to first 100KB

# # Logging settings
# LOG_LEVEL = "INFO"          # DEBUG, INFO, WARNING, ERROR
# LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# # User agent for web requests
# USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

# # Feature flags
# # SSL verification: True = secure (recommended for public use). False = lab/testing only (MITM risk).
# ENABLE_SSL_VERIFICATION = True
# ENABLE_REDIRECTS = True          # Follow HTTP redirects
# MAX_REDIRECTS = 5                # Maximum redirect hops

"""
Configuration file for TEHQEEQ Reconnaissance Tool
Contains all configurable parameters and settings
"""

import os

# ===== GENERAL SETTINGS =====
TOOL_NAME = "TEHQEEQ"
TOOL_VERSION = "2.0"
TOOL_DESCRIPTION = "Advanced Network Reconnaissance Tool"

# ===== OUTPUT SETTINGS =====
REPORTS_FOLDER = "reports"
LOGS_FOLDER = "logs"

# Create folders if they don't exist
for folder in [REPORTS_FOLDER, LOGS_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

# ===== PORT SCANNING SETTINGS =====

# Quick scan - 11 most common ports (fast, ~2 seconds)
COMMON_PORTS_QUICK = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    3389,  # RDP
    8080,  # HTTP-Proxy
    8443   # HTTPS-Alt
]

# Normal scan - 15 common ports (balanced, ~3 seconds)
COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    8080,  # HTTP-Proxy
    8443   # HTTPS-Alt
]

# Full scan - Top 100 most common ports (~15 seconds with concurrent scanning)
COMMON_PORTS_FULL = [
    # Web services
    80, 443, 8080, 8443, 8000, 8888, 3000, 5000,
    # SSH/Telnet/FTP
    20, 21, 22, 23, 69,
    # Email
    25, 110, 143, 465, 587, 993, 995,
    # DNS
    53,
    # Windows services
    135, 137, 138, 139, 445, 3389,
    # Databases
    1433, 1521, 3306, 5432, 27017, 6379,
    # Other common services
    88, 111, 119, 161, 162, 389, 514, 636,
    902, 1080, 1194, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    3128, 4443, 5060, 5061, 5432, 5900, 5984, 6379, 7001, 7002,
    8000, 8008, 8009, 8081, 8089, 8090, 8140, 8161, 8180, 8222,
    8333, 8834, 9000, 9001, 9080, 9090, 9100, 9200, 9443,
    9999, 10000, 11211, 27017, 50000, 50070
]

# Network timeouts
SOCKET_TIMEOUT = 2  # seconds for port connection
BANNER_TIMEOUT = 3  # seconds for banner grabbing (reduced from default)
BANNER_MAX_SIZE = 4096  # bytes (4KB is plenty)

# DNS settings
DNS_TIMEOUT = 5  # seconds
DNS_LIFETIME = 5  # seconds

# ===== WEB TECHNOLOGY DETECTION =====
WEB_REQUEST_TIMEOUT = 10  # seconds
ENABLE_SSL_VERIFICATION = True 
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ===== SUBDOMAIN ENUMERATION =====
# DNS brute force settings
DNS_BRUTE_FORCE_WORKERS = 20  # Concurrent DNS queries
DNS_BRUTE_FORCE_TIMEOUT = 5  # seconds per query

# Subdomain verification settings
SUBDOMAIN_VERIFY_WORKERS = 20  # Concurrent verification workers
SUBDOMAIN_VERIFY_TIMEOUT = 5  # seconds per verification

# ===== NMAP SETTINGS =====
NMAP_ENABLED = True  # Set to False to disable Nmap support
NMAP_TIMING = "T4"  # T0-T5 (0=paranoid, 5=insane, 4=aggressive)
NMAP_ARGUMENTS = "-sV -T4 -Pn --open"  # Default Nmap arguments

# ===== LOGGING SETTINGS =====
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# ===== REPORT SETTINGS =====
REPORT_FORMATS = ['txt', 'json', 'pdf']  # Available report formats
DEFAULT_REPORT_FORMAT = 'txt'

# PDF report settings
PDF_PAGE_SIZE = "letter"
PDF_MARGIN = 0.75  # inches

# ===== SECURITY SETTINGS =====
# Rate limiting
ENABLE_RATE_LIMITING = True
RATE_LIMIT_DELAY = 0.05  # seconds between requests (normal mode)
STEALTH_MODE_DELAY = (0.5, 2.0)  # random delay range for stealth mode

# Maximum concurrent connections
MAX_CONCURRENT_PORTS = 50  # Normal scanning
MAX_CONCURRENT_PORTS_STEALTH = 5  # Stealth scanning

# ===== FEATURE FLAGS =====
ENABLE_BANNER_GRABBING = True
ENABLE_TECH_DETECTION = True
ENABLE_OS_DETECTION = True
ENABLE_SUBDOMAIN_VERIFICATION = True

# ===== PASSIVE RECON SETTINGS =====
# Certificate Transparency logs
CT_LOGS_TIMEOUT = 45  # seconds
CT_LOGS_ENABLED = True

# Zone transfer attempt
ZONE_TRANSFER_ENABLED = True
ZONE_TRANSFER_TIMEOUT = 10  # seconds

# ===== WHOIS SETTINGS =====
WHOIS_TIMEOUT = 15  # seconds
PKNIC_API_URL = "https://pknic.domainwhois.pk/api/json"
PKNIC_WEB_URL = "https://pk6.pknic.net.pk/pk5/lookup.PK"

# ===== ADVANCED SETTINGS =====
# Threading
THREAD_POOL_SIZE = 50

# Retry settings
MAX_RETRIES = 3
RETRY_DELAY = 1  # seconds

# ===== DISCLAIMER =====
LEGAL_DISCLAIMER = """
This reconnaissance tool should ONLY be used on systems that:
  • You own
  • You have explicit written permission to test

Unauthorized scanning may be ILLEGAL in your jurisdiction!
The developers assume NO liability for misuse of this tool.
"""

# ===== COLORS (for terminal output) =====
class Colors:
    """ANSI color codes"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'