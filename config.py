"""
Configuration settings for the Reconnaissance Tool
FIXED VERSION - Optimized timeouts and settings
"""

# Ports to scan by default (most common ports)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                3306, 3389, 5432, 8080, 8443]

# Extended port list (optional - use with caution, slower scans)
EXTENDED_PORTS = [20, 21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 
                  443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8000, 
                  8008, 8080, 8443, 8888, 10000]

# Timeouts (in seconds)
SOCKET_TIMEOUT = 2          # Port scanning timeout
BANNER_TIMEOUT = 5          # Banner grabbing timeout (increased)
WEB_REQUEST_TIMEOUT = 15    # Web requests timeout (increased)
DNS_TIMEOUT = 15            # DNS resolution timeout

# Where to save reports
REPORTS_FOLDER = "reports"

# Subdomain brute force settings
SUBDOMAIN_TIMEOUT = 2       # Timeout for each subdomain check
MAX_SUBDOMAIN_THREADS = 15  # For threaded subdomain scanning (future enhancement)

# Banner grabbing settings
BANNER_MAX_SIZE = 4096      # Maximum bytes to read from banner

# Technology detection settings
CONTENT_ANALYSIS_LIMIT = 100000  # Limit content analysis to first 100KB

# Logging settings
LOG_LEVEL = "INFO"          # DEBUG, INFO, WARNING, ERROR
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

# User agent for web requests
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

# Feature flags
ENABLE_SSL_VERIFICATION = False  # Set to True for production
ENABLE_REDIRECTS = True          # Follow HTTP redirects
MAX_REDIRECTS = 5                # Maximum redirect hops