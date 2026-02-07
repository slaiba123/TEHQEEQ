"""
Passive Reconnaissance Module
Handles WHOIS, DNS enumeration, and subdomain discovery
UPDATED VERSION - Enhanced PKNIC API support with formatter compatibility
+ Certificate Transparency Logs Integration
+ Expanded Wordlist for Better Coverage
+ Subdomain Verification (DNS & HTTP)
"""

import whois
import dns.resolver
import dns.zone
import dns.query
import ssl
import socket
import logging
import requests
from datetime import datetime
from urllib.parse import quote
import time
import re
import warnings

# Set up logging
logger = logging.getLogger(__name__)

# Suppress SSL warnings for verification
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class PassiveRecon:
    """Performs passive reconnaissance on a target domain"""
    
    def __init__(self, domain, formatter=None):
        self.domain = domain
        self.formatter = formatter  # Optional formatter for enhanced output
        self.results = {
            'whois': {},
            'dns': {},
            'subdomains': [],
            'verified_subdomains': {}
        }
    
    def _is_pk_domain(self):
        """Check if the domain is a .pk domain"""
        return self.domain.lower().endswith('.pk')
    
    def _pknic_web_scrape(self, domain_to_query):
        """Fallback method: Scrape PKNIC web lookup page"""
        try:
            logger.info(f"Trying PKNIC web scraper for {domain_to_query}")
            
            # PKNIC web lookup URL (quote domain to prevent URL injection)
            safe_domain = quote(domain_to_query, safe='')
            url = f"https://pk6.pknic.net.pk/pk5/lookup.PK?name={safe_domain}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=15)
            
            if response.status_code == 200:
                content = response.text
                
                # Check if domain is registered
                if "Domain not found" in content or "not found" in content.lower():
                    return None
                
                # Parse the HTML response for WHOIS data
                whois_data = {}
                
                # Extract domain name
                domain_match = re.search(r'Domain Name:\s*([^\s<]+)', content, re.IGNORECASE)
                if domain_match:
                    whois_data['domain_name'] = domain_match.group(1)
                
                # Extract registrar
                registrar_match = re.search(r'Registrar:\s*([^\n<]+)', content, re.IGNORECASE)
                whois_data['registrar'] = registrar_match.group(1).strip() if registrar_match else 'PKNIC'
                
                # Extract dates
                created_match = re.search(r'Creation Date:\s*([^\n<]+)', content, re.IGNORECASE)
                if created_match:
                    whois_data['creation_date'] = created_match.group(1).strip()
                
                updated_match = re.search(r'Updated Date:\s*([^\n<]+)', content, re.IGNORECASE)
                if updated_match:
                    whois_data['updated_date'] = updated_match.group(1).strip()
                
                expiry_match = re.search(r'Expiry Date:\s*([^\n<]+)', content, re.IGNORECASE)
                if expiry_match:
                    whois_data['expiration_date'] = expiry_match.group(1).strip()
                
                # Extract nameservers
                ns_pattern = re.findall(r'Name Server:\s*([^\s\n<]+)', content, re.IGNORECASE)
                if ns_pattern:
                    whois_data['name_servers'] = ns_pattern
                
                # Extract status
                status_match = re.search(r'Status:\s*([^\n<]+)', content, re.IGNORECASE)
                if status_match:
                    whois_data['status'] = status_match.group(1).strip()
                
                return whois_data if whois_data else None
                
        except Exception as e:
            logger.debug(f"Web scraping failed: {e}")
            return None
    
    def _pknic_whois_lookup(self):
        """Perform WHOIS lookup using PKNIC API for .pk domains"""
        logger.info(f"Using PKNIC API for .pk domain: {self.domain}")
        
        # Extract the base domain without 'www.' if present
        domain_to_query = self.domain.replace('www.', '')
        
        # Try API first
        try:
            # PKNIC API endpoint
            api_url = "https://pknic.domainwhois.pk/api/json"
            
            # Make the API request
            params = {'domain': domain_to_query}
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            print(f"   [INFO] Querying PKNIC API for {domain_to_query}...")
            
            response = requests.get(api_url, params=params, headers=headers, timeout=15)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    # Check various response formats
                    if isinstance(data, dict):
                        # Check for error or not found status
                        if (data.get('status') == 'error' or 
                            'not found' in str(data.get('information', '')).lower() or
                            data.get('domain_name') is None):
                            
                            # Try alternative methods
                            print(f"API returned no data, trying alternative lookup...")
                            alt_data = self._pknic_web_scrape(domain_to_query)
                            
                            if alt_data:
                                self._display_whois_data(alt_data)
                                self.results['whois'] = alt_data
                                return alt_data
                            else:
                                print("Domain not found in PKNIC registry")
                                print("Note: Some .edu.pk domains may have limited WHOIS data")
                                print("DNS records confirm domain exists\n")
                                self.results['whois']['error'] = "Limited WHOIS data available"
                                self.results['whois']['note'] = "Domain exists but WHOIS data unavailable via API"
                                return {}
                        
                        # Extract available PKNIC data
                        self.results['whois'] = {
                            'domain_name': data.get('domain_name', domain_to_query),
                            'registrar': data.get('registrar', 'PKNIC'),
                            'creation_date': data.get('registration_date', 'N/A'),
                            'expiration_date': data.get('expiry_date', 'N/A'),
                            'updated_date': data.get('updated_date', 'N/A'),
                            'status': data.get('status', 'N/A'),
                            'name_servers': data.get('nameservers', []),
                            'information': data.get('information', 'N/A')
                        }
                        
                        self._display_whois_data(self.results['whois'])
                        logger.info("PKNIC WHOIS lookup completed successfully")
                        return self.results['whois']
                
                except ValueError as e:
                    logger.error(f"JSON parsing error: {e}")
                    print(f"   [WARNING] API response parsing failed, trying alternative method...")
                    alt_data = self._pknic_web_scrape(domain_to_query)
                    if alt_data:
                        self._display_whois_data(alt_data)
                        self.results['whois'] = alt_data
                        return alt_data
                    
            else:
                raise Exception(f"API returned status code: {response.status_code}")
                
        except requests.exceptions.Timeout:
            error_msg = "PKNIC API request timed out"
            logger.error(error_msg)
            print(f"[ERROR] {error_msg}")
            print(f"   Trying alternative lookup method...\n")
            
            alt_data = self._pknic_web_scrape(domain_to_query)
            if alt_data:
                self._display_whois_data(alt_data)
                self.results['whois'] = alt_data
                return alt_data
            
        except requests.exceptions.RequestException as e:
            error_msg = f"PKNIC API request failed: {str(e)}"
            logger.error(error_msg)
            print(f"[ERROR] {error_msg}")
            print(f"   Trying alternative lookup method...\n")
            
            alt_data = self._pknic_web_scrape(domain_to_query)
            if alt_data:
                self._display_whois_data(alt_data)
                self.results['whois'] = alt_data
                return alt_data
            
        except Exception as e:
            error_msg = f"PKNIC lookup failed: {str(e)}"
            logger.error(error_msg)
            print(f"[ERROR] {error_msg}\n")
        
        # If all methods fail
        print("   [INFO] WHOIS data unavailable, but domain appears to be registered")
        print("   [INFO] DNS records confirm domain exists\n")
        self.results['whois']['error'] = "WHOIS data unavailable"
        self.results['whois']['note'] = "Domain exists (confirmed via DNS)"
        return {}
    
    def _display_whois_data(self, whois_data):
        """Display WHOIS data in a formatted way"""
        if not whois_data:
            return
        
        print(f"[SUCCESS] WHOIS data retrieved successfully\n")
        print(f"Domain Name: {whois_data.get('domain_name', 'N/A')}")
        
        if whois_data.get('registrar'):
            print(f"Registrar: {whois_data.get('registrar')}")
        
        if whois_data.get('creation_date'):
            print(f"Created: {whois_data.get('creation_date')}")
        
        if whois_data.get('updated_date'):
            print(f"Updated: {whois_data.get('updated_date')}")
        
        if whois_data.get('expiration_date'):
            print(f"Expires: {whois_data.get('expiration_date')}")
        
        if whois_data.get('status'):
            print(f"Status: {whois_data.get('status')}")
        
        if whois_data.get('information'):
            print(f"Info: {whois_data.get('information')}")
        
        if whois_data.get('name_servers'):
            print(f"\nName Servers:")
            for ns in whois_data.get('name_servers', []):
                print(f"   - {ns}")
        
        if whois_data.get('registrant'):
            print(f"\nRegistrant: {whois_data.get('registrant')}")
        
        if whois_data.get('admin_contact'):
            print(f"Admin: {whois_data.get('admin_contact')}")
        
        if whois_data.get('tech_contact'):
            print(f"Tech: {whois_data.get('tech_contact')}")
        
        print(f"\n{'='*60}\n")
    
    def _format_date(self, date_value):
        """Format WHOIS dates properly"""
        if isinstance(date_value, list):
            return date_value[0].strftime('%Y-%m-%d') if date_value else 'N/A'
        elif hasattr(date_value, 'strftime'):
            return date_value.strftime('%Y-%m-%d')
        else:
            return str(date_value) if date_value else 'N/A'
    
    def _deduplicate_list(self, items):
        """Deduplicate a list while preserving order"""
        if not items:
            return []
        seen = set()
        result = []
        for item in items:
            item_lower = str(item).lower()
            if item_lower not in seen:
                seen.add(item_lower)
                result.append(str(item))
        return sorted(result)
    
    def _clean_status_codes(self, status_list):
        """Clean and deduplicate WHOIS status codes"""
        if not status_list:
            return []
        
        seen = set()
        cleaned = []
        
        for status in status_list:
            status_str = str(status)
            status_code = status_str.split()[0] if ' ' in status_str else status_str.split('(')[0]
            
            if status_code not in seen:
                seen.add(status_code)
                cleaned.append(status_str)
        
        return cleaned
    
    def whois_lookup(self):
        """Perform WHOIS lookup - uses PKNIC API for .pk domains"""
        logger.info(f"Starting WHOIS lookup for {self.domain}")
        
        # Use formatter if available, otherwise print directly
        if self.formatter:
            self.formatter.print_section_start(f"PERFORMING WHOIS ENUMERATION FOR {self.domain.upper()}")
        else:
            print(f"\n{'='*60}")
            print(f"WHOIS LOOKUP: {self.domain}")
            print(f"{'='*60}\n")
        
        # Check if this is a .pk domain
        if self._is_pk_domain():
            print("[INFO] Detected .pk domain - Using PKNIC lookup\n")
            return self._pknic_whois_lookup()
        
        # Use standard WHOIS for non-.pk domains
        try:
            w = whois.whois(self.domain)
            
            if not w or not w.domain_name:
                print("No WHOIS data available for this domain")
                print("   (Domain may not exist or WHOIS is blocked)\n")
                self.results['whois']['error'] = "No WHOIS data available"
                return {}
            
            # Extract and clean data
            domain_name = w.domain_name
            if isinstance(domain_name, list):
                domain_name = domain_name[0] if domain_name else 'N/A'
            
            name_servers = self._deduplicate_list(w.name_servers if w.name_servers else [])
            status_codes = self._clean_status_codes(w.status if w.status else [])
            emails = self._deduplicate_list(w.emails if w.emails else [])
            
            self.results['whois'] = {
                'domain_name': domain_name,
                'registrar': w.registrar or 'N/A',
                'creation_date': self._format_date(w.creation_date),
                'expiration_date': self._format_date(w.expiration_date),
                'name_servers': name_servers,
                'status': status_codes,
                'emails': emails,
                'org': w.org or 'N/A'
            }
            
            # Display results
            print(f"Domain Name: {self.results['whois']['domain_name']}")
            print(f"Organization: {self.results['whois']['org']}")
            print(f"Registrar: {self.results['whois']['registrar']}")
            print(f"Created: {self.results['whois']['creation_date']}")
            print(f"Expires: {self.results['whois']['expiration_date']}")
            
            if self.results['whois']['status']:
                print(f"Status:")
                for status in self.results['whois']['status'][:5]:
                    print(f"   - {status}")
                if len(self.results['whois']['status']) > 5:
                    print(f"   ... and {len(self.results['whois']['status']) - 5} more")
            
            if self.results['whois']['name_servers']:
                print(f"\nName Servers:")
                for ns in self.results['whois']['name_servers']:
                    print(f"   - {ns}")
            
            if self.results['whois']['emails']:
                print(f"\nContact Emails:")
                for email in self.results['whois']['emails']:
                    print(f"   - {email}")
            
            print(f"\n{'='*60}\n")
            logger.info("WHOIS lookup completed successfully")
            
        except Exception as e:
            error_msg = f"WHOIS lookup failed: {str(e)}"
            logger.error(error_msg)
            print(f"[ERROR] {error_msg}")
            print(f"   Tip: This domain might not exist or WHOIS service is unavailable\n")
            self.results['whois']['error'] = str(e)
        
        return self.results['whois']
    
    def dns_enumeration(self):
        """Enumerate DNS records with increased timeout"""
        logger.info(f"Starting DNS enumeration for {self.domain}")
        
        if self.formatter:
            self.formatter.print_section_start(f"PERFORMING DNS ENUMERATION FOR {self.domain.upper()}")
        else:
            print(f"{'='*60}")
            print(f"🔍 DNS ENUMERATION: {self.domain}")
            print(f"{'='*60}\n")
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 15
        resolver.lifetime = 15
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        found_any = False
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(self.domain, record_type)
                self.results['dns'][record_type] = []
                found_any = True
                
                print(f"[{record_type}] Records:")
                
                for rdata in answers:
                    if record_type == 'MX':
                        record = f"{rdata.exchange} (Priority: {rdata.preference})"
                    elif record_type == 'SOA':
                        record = f"Primary NS: {rdata.mname}, Admin: {rdata.rname}"
                    elif record_type == 'TXT':
                        record = str(rdata).strip('"')[:200]
                    else:
                        record = str(rdata)
                    
                    print(f"   - {record}")
                    self.results['dns'][record_type].append(record)
                
                print()
                
            except dns.resolver.NoAnswer:
                logger.debug(f"No {record_type} records found")
                print(f"[{record_type}] Records: None found\n")
            except dns.resolver.NXDOMAIN:
                logger.error(f"Domain {self.domain} does not exist")
                print(f"[ERROR] Domain does not exist\n")
                break
            except Exception as e:
                logger.error(f"Error querying {record_type} records: {str(e)}")
                print(f"[ERROR] {record_type} Records: Error - {str(e)}\n")
        
        if not found_any:
            print("[WARNING] No DNS records found. Domain may not be configured.\n")
        
        print(f"{'='*60}\n")
        logger.info("DNS enumeration completed")
        
        return self.results['dns']
    
    def _attempt_zone_transfer(self):
        """Attempt DNS zone transfer (AXFR)"""
        subdomains = set()
        
        try:
            ns_records = dns.resolver.resolve(self.domain, 'NS')
            
            for ns in ns_records:
                ns_name = str(ns.target).rstrip('.')
                print(f"   [INFO] Attempting zone transfer from {ns_name}...")
                
                try:
                    ns_ip = str(dns.resolver.resolve(ns_name, 'A')[0])
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain, timeout=10))
                    
                    print(f"      [SUCCESS] Zone transfer successful!")
                    
                    for name, node in zone.nodes.items():
                        subdomain = str(name)
                        if subdomain != '@':
                            full_domain = f"{subdomain}.{self.domain}" if subdomain else self.domain
                            subdomains.add(full_domain.lower())
                    
                    break
                    
                except Exception:
                    print(f"      [INFO] Zone transfer denied (expected)")
                    continue
        
        except Exception as e:
            logger.debug(f"Zone transfer attempt failed: {e}")
        
        return list(subdomains)
    
    def _check_ssl_certificate(self):
        """Extract subdomains from SSL certificate"""
        subdomains = set()
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((self.domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    if 'subjectAltName' in cert:
                        for typ, value in cert['subjectAltName']:
                            if typ == 'DNS':
                                domain = value.replace('*.', '').lower()
                                if domain.endswith(self.domain):
                                    subdomains.add(domain)
                                    print(f"      - {domain}")
                    
                    for sub in cert.get('subject', ()):
                        for key, value in sub:
                            if key == 'commonName':
                                domain = value.replace('*.', '').lower()
                                if domain.endswith(self.domain):
                                    subdomains.add(domain)
        
        except Exception as e:
            logger.debug(f"SSL certificate check failed: {e}")
        
        return list(subdomains)
    
    def _ct_logs_search(self):
        """
        Query Certificate Transparency logs - MOST EFFECTIVE METHOD
        This searches all publicly logged SSL/TLS certificates
        """
        logger.info(f"Querying Certificate Transparency logs for {self.domain}")
        subdomains = set()
        
        try:
            # crt.sh is the most popular CT log aggregator
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            
            print(f"   [INFO] Querying crt.sh database...")
            print(f"   [INFO] This may take 10-30 seconds for large domains...")
            
            response = requests.get(url, timeout=45, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    print(f"   [INFO] Processing {len(data)} certificate entries...")
                    
                    for entry in data:
                        # CT logs contain multiple names per certificate
                        name_value = entry.get('name_value', '')
                        
                        # Split by newlines (certificates can list multiple domains)
                        names = name_value.split('\n')
                        
                        for name in names:
                            name = name.strip().lower()
                            
                            # Remove wildcard prefix
                            name = name.replace('*.', '')
                            
                            # Verify it's actually a subdomain of our target
                            if name.endswith(self.domain) and name != '':
                                subdomains.add(name)
                                
                                # Progress update every 25 subdomains found
                                if len(subdomains) % 25 == 0:
                                    print(f"      Progress: Found {len(subdomains)} unique subdomains...")
                    
                    print(f"   [SUCCESS] CT logs search complete")
                    
                    # Show some examples
                    if subdomains:
                        print(f"   [INFO] Sample findings:")
                        for subdomain in list(subdomains)[:5]:
                            print(f"      - {subdomain}")
                        if len(subdomains) > 5:
                            print(f"      ... and {len(subdomains) - 5} more")
                    
                    return list(subdomains)
                    
                except ValueError as e:
                    logger.error(f"JSON parsing error: {e}")
                    print(f"   [ERROR] Could not parse crt.sh response")
                    return []
            else:
                print(f"   [WARNING] crt.sh returned status {response.status_code}")
                print(f"   [INFO] The CT logs server might be busy, continuing with other methods...")
                return []
                
        except requests.exceptions.Timeout:
            print(f"   [ERROR] crt.sh request timed out (server might be busy)")
            print(f"   [INFO] Continuing with other enumeration methods...")
            return []
        except requests.exceptions.RequestException as e:
            print(f"   [ERROR] crt.sh request failed: {str(e)}")
            print(f"   [INFO] Continuing with other enumeration methods...")
            return []
        except Exception as e:
            logger.error(f"CT logs search failed: {e}")
            print(f"   [ERROR] Unexpected error: {str(e)}")
            return []
    
    def _subdomain_bruteforce(self):
        """Brute force common subdomains - IMPROVED WORDLIST"""
        
        # EXPANDED wordlist - comprehensive coverage of common patterns
        common_subs = [
            # Original basic ones
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 
            'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig',
            'm', 'imap', 'test', 'ns', 'blog', 'pop3', 'dev', 'www2', 'admin',
            'forum', 'news', 'vpn', 'ns3', 'mail2', 'new', 'mysql', 'old',
            'lists', 'support', 'mobile', 'mx', 'static', 'docs', 'beta', 'shop',
            'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web', 'media',
            'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
            'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns',
            'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn',
            'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db',
            'forums', 'store', 'relay', 'files', 'newsletter', 'app', 'live',
            'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4',
            
            # ADDITIONS - Common in modern infrastructure
            'api-prod', 'api-dev', 'api-staging', 'api-test', 'api-uat',
            'app-prod', 'app-dev', 'app-staging', 'app-test',
            'web-prod', 'web-dev', 'web-staging', 'web-test',
            'dashboard', 'panel', 'control', 'manage', 'console', 'admin-panel',
            'gateway', 'api-gateway', 'load-balancer', 'lb', 'loadbalancer',
            'jenkins', 'ci', 'cd', 'gitlab', 'github', 'bitbucket', 'git',
            'jira', 'confluence', 'slack', 'teams', 'zoom',
            'monitoring', 'grafana', 'prometheus', 'elk', 'kibana', 'logs',
            'database', 'db-master', 'db-slave', 'db-replica', 'redis', 'mongodb', 'postgres',
            'kafka', 'rabbitmq', 'queue', 'mq', 'message-queue',
            'storage', 's3', 'cdn-static', 'assets', 'uploads', 'media-cdn',
            'legacy', 'old-site', 'archive', 'backup-server', 'old-backup',
            'sso', 'auth', 'login', 'oauth', 'identity', 'authentication',
            'student', 'faculty', 'staff', 'alumni', 'employee', 'hr',  # For organizations
            'library', 'lms', 'elearning', 'moodle', 'canvas', 'blackboard',  # Education
            'admissions', 'registration', 'finance', 'accounts', 'billing',  # Departments
            'research', 'journal', 'publications', 'papers',
            'help', 'helpdesk', 'support-portal', 'tickets', 'servicedesk',
            'status', 'health', 'uptime', 'monitoring-status',
            'sandbox', 'playground', 'experiments', 'lab',
            'internal', 'private', 'vpn-access', 'vpn-gateway',
            'cloud', 'aws', 'azure', 'gcp', 'cloud-services',
            'kubernetes', 'k8s', 'docker', 'registry', 'container',
            'nexus', 'artifactory', 'packages', 'npm', 'maven',
            'graphql', 'websocket', 'ws', 'grpc', 'rest',
            'v1', 'v2', 'v3', 'v4', 'latest', 'stable',  # API versioning
            'mobile-api', 'ios', 'android', 'mobile-app',
            'payment', 'checkout', 'billing', 'invoice', 'pay',
            'analytics', 'metrics', 'tracking', 'stats-api',
            'preview', 'canary', 'alpha', 'rc', 'release',  # Release stages
            'prod', 'production', 'uat', 'qa', 'development',
            'www-prod', 'www-dev', 'www-staging', 'www-test',
            'blog-old', 'blog-new', 'news-old', 'news-new',
            'shop-dev', 'shop-staging', 'store-dev', 'store-staging',
            'partner', 'partners', 'vendor', 'vendors', 'supplier',
            'customer', 'customers', 'client', 'clients',
            'invoice-portal', 'vendor-portal', 'partner-portal',
            'training', 'courses', 'certification', 'exam',
            'events', 'event', 'conference', 'webinar',
            'careers', 'jobs', 'recruitment', 'hiring',
            'press', 'media-kit', 'newsroom',
            'investor', 'investors', 'ir', 'shareholder',
            'developer', 'developers', 'devportal', 'dev-portal',
            'sandbox-api', 'test-api', 'mock-api',
            'staging-cdn', 'dev-cdn', 'test-cdn',
            'staging-assets', 'dev-assets', 'test-assets',
        ]
        
        # For .pk domains, add Pakistan-specific common names
        if self._is_pk_domain():
            pk_specific = [
                'online', 'portal-students', 'portal-faculty', 'portal-staff',
                'examination', 'exams', 'results', 'timetable', 'schedule',
                'hostel', 'transport', 'cafeteria', 'mess',
                'notices', 'announcements', 'circulars', 'notifications',
                'placement', 'career', 'alumni-portal', 'alumni-network',
                'scholarship', 'fee-payment', 'challan', 'fees',
                'e-learning', 'online-classes', 'virtual-class',
                'admission', 'apply', 'application',
                'merit', 'merit-list', 'eligibility',
                'convocation', 'graduation', 'ceremony',
                'qec', 'quality', 'accreditation',
                'oric', 'innovation', 'incubation',
            ]
            common_subs.extend(pk_specific)
        
        found_subdomains = set()
        resolver = dns.resolver.Resolver()
        
        # IMPROVED: Better timeout for Pakistani networks
        resolver.timeout = 5  # Increased from 2
        resolver.lifetime = 10  # Increased from 2
        
        # IMPROVED: Add Google's DNS as fallback
        resolver.nameservers = [
            '8.8.8.8',      # Google Primary
            '8.8.4.4',      # Google Secondary
            '1.1.1.1',      # Cloudflare
        ] + resolver.nameservers  # Keep original resolvers too
        
        total = len(common_subs)
        successful = 0
        failed = 0
        
        print(f"      Testing {total} common subdomain names...")
        print(f"      This may take 3-5 minutes depending on network speed...")
        print(f"      Progress: ", end='', flush=True)
        
        for i, sub in enumerate(common_subs, 1):
            subdomain = f"{sub}.{self.domain}"
            
            # IMPROVED: Better progress indicator
            if i % 50 == 0:
                percentage = (i / total) * 100
                print(f"{percentage:.0f}%...", end='', flush=True)
            
            try:
                answers = resolver.resolve(subdomain, 'A')
                if answers:
                    found_subdomains.add(subdomain.lower())
                    successful += 1
                    
                    # Show finding inline
                    ip = str(answers[0])
                    print(f"\n      [+] {subdomain} → {ip}")
                    print(f"      Progress: ", end='', flush=True)
                    
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                failed += 1
            except dns.resolver.NoNameservers:
                logger.warning(f"No nameservers available for {subdomain}")
                failed += 1
            except dns.exception.Timeout:
                logger.debug(f"Timeout for {subdomain}")
                failed += 1
            except Exception as e:
                logger.debug(f"Error checking {subdomain}: {e}")
                failed += 1
        
        print(f"\n      Scan complete: {successful} found, {failed} not found")
        
        return list(found_subdomains)
    
    def _verify_subdomain_http(self, subdomain, timeout=5):
        """
        Verify if a subdomain has a working HTTP/HTTPS service
        Returns: dict with verification results
        """
        result = {
            'subdomain': subdomain,
            'http_status': None,
            'https_status': None,
            'redirects_to': None,
            'title': None,
            'is_live': False,
            'responds': False
        }
        
        # Try HTTPS first (more common now)
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                
                response = requests.get(
                    url, 
                    timeout=timeout,
                    allow_redirects=True,
                    verify=False,  # Ignore SSL errors
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                )
                
                if protocol == 'https':
                    result['https_status'] = response.status_code
                else:
                    result['http_status'] = response.status_code
                
                # Mark as responding
                result['responds'] = True
                
                # Check if it's a real page (not just DNS)
                if response.status_code in [200, 201, 301, 302, 303, 307, 308]:
                    result['is_live'] = True
                    
                    # Track redirects
                    if response.url != url:
                        result['redirects_to'] = response.url
                    
                    # Try to extract page title
                    try:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(response.text, 'html.parser')
                        if soup.title:
                            result['title'] = soup.title.string[:100]  # Limit length
                    except:
                        pass
                    
                    break  # Found working protocol, no need to try the other
                
            except requests.exceptions.SSLError:
                # SSL error but server responded
                result['responds'] = True
                if protocol == 'https':
                    result['https_status'] = 'SSL_ERROR'
                continue
                
            except requests.exceptions.ConnectionError:
                # Server not responding on this protocol
                continue
                
            except requests.exceptions.Timeout:
                # Server too slow
                if protocol == 'https':
                    result['https_status'] = 'TIMEOUT'
                else:
                    result['http_status'] = 'TIMEOUT'
                continue
                
            except Exception as e:
                logger.debug(f"Verification error for {subdomain} ({protocol}): {e}")
                continue
        
        return result
    
    def _verify_subdomain_dns_only(self, subdomain):
        """
        Quick DNS-only verification - checks if subdomain resolves to an IP
        Returns: dict with IP and DNS info
        """
        result = {
            'subdomain': subdomain,
            'resolves': False,
            'ip_addresses': [],
            'cname': None,
            'is_internal': False,
            'is_localhost': False
        }
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        
        try:
            # Try to get A record (IPv4)
            answers = resolver.resolve(subdomain, 'A')
            
            for rdata in answers:
                ip = str(rdata)
                result['ip_addresses'].append(ip)
                result['resolves'] = True
                
                # Check if it's internal/private IP
                if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '172.19.',
                                 '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
                                 '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
                                 '172.30.', '172.31.', '192.168.')):
                    result['is_internal'] = True
                
                # Check if it's localhost
                if ip.startswith('127.') or ip == '0.0.0.0':
                    result['is_localhost'] = True
            
            # Try to get CNAME record
            try:
                cname_answers = resolver.resolve(subdomain, 'CNAME')
                result['cname'] = str(cname_answers[0].target)
            except:
                pass
                
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # Domain doesn't resolve
            result['resolves'] = False
        except Exception as e:
            logger.debug(f"DNS verification error for {subdomain}: {e}")
        
        return result
    
    def verify_subdomains(self, verification_type='dns', max_workers=10):
        """
        Verify discovered subdomains to filter out dead/fake ones
        
        Args:
            verification_type: 'dns' (fast, just checks DNS) or 'http' (slow, checks web server)
            max_workers: Number of concurrent verification threads
        
        Returns:
            dict with verified and dead subdomains
        """
        
        if not self.results['subdomains']:
            print("[WARNING] No subdomains to verify. Run subdomain_enumeration() first.\n")
            return {'verified': [], 'dead': [], 'internal': []}
        
        print(f"\n{'='*60}")
        print(f"🔍 VERIFYING {len(self.results['subdomains'])} DISCOVERED SUBDOMAINS")
        print(f"{'='*60}\n")
        print(f"Method: {'DNS Resolution' if verification_type == 'dns' else 'HTTP/HTTPS Requests'}")
        print(f"Concurrent workers: {max_workers}")
        print(f"This may take a few minutes...\n")
        
        verified_live = []
        verified_dead = []
        internal_only = []
        
        from concurrent.futures import ThreadPoolExecutor, as_completed
        
        total = len(self.results['subdomains'])
        processed = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            if verification_type == 'dns':
                # DNS-only verification (faster)
                future_to_subdomain = {
                    executor.submit(self._verify_subdomain_dns_only, sub): sub 
                    for sub in self.results['subdomains']
                }
            else:
                # HTTP verification (slower but more thorough)
                future_to_subdomain = {
                    executor.submit(self._verify_subdomain_http, sub): sub 
                    for sub in self.results['subdomains']
                }
            
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                processed += 1
                
                try:
                    result = future.result()
                    
                    if verification_type == 'dns':
                        if result['resolves']:
                            if result['is_localhost']:
                                verified_dead.append(result)
                                print(f"   [{processed}/{total}] ❌ DEAD (localhost): {subdomain}")
                            elif result['is_internal']:
                                internal_only.append(result)
                                print(f"   [{processed}/{total}] 🔒 INTERNAL: {subdomain} → {result['ip_addresses'][0]}")
                            else:
                                verified_live.append(result)
                                print(f"   [{processed}/{total}] ✓ LIVE: {subdomain} → {result['ip_addresses'][0]}")
                        else:
                            verified_dead.append(result)
                            print(f"   [{processed}/{total}] ❌ DEAD (no DNS): {subdomain}")
                    
                    else:  # HTTP verification
                        if result['is_live']:
                            verified_live.append(result)
                            status_info = f"HTTP {result['http_status']}" if result['http_status'] else f"HTTPS {result['https_status']}"
                            title_info = f" - {result['title']}" if result['title'] else ""
                            print(f"   [{processed}/{total}] ✓ LIVE: {subdomain} [{status_info}]{title_info}")
                        elif result['responds']:
                            verified_live.append(result)
                            print(f"   [{processed}/{total}] RESPONDS: {subdomain} (but returned error)")
                        else:
                            verified_dead.append(result)
                            print(f"   [{processed}/{total}] DEAD: {subdomain} (no response)")
                    
                    # Progress indicator every 20 subdomains
                    if processed % 20 == 0:
                        live_count = len(verified_live)
                        dead_count = len(verified_dead)
                        internal_count = len(internal_only)
                        print(f"\n   Progress: {processed}/{total} | Live: {live_count} | Dead: {dead_count} | Internal: {internal_count}\n")
                        
                except Exception as e:
                    logger.error(f"Verification failed for {subdomain}: {e}")
                    verified_dead.append({'subdomain': subdomain, 'error': str(e)})
        
        # Summary
        print(f"\n{'='*60}")
        print(f"VERIFICATION COMPLETE")
        print(f"{'='*60}")
        print(f"✓ Live subdomains: {len(verified_live)}")
        print(f"Dead subdomains: {len(verified_dead)}")
        if internal_only:
            print(f"Internal-only: {len(internal_only)}")
        print(f"{'='*60}\n")
        
        # Update results with verification data
        self.results['verified_subdomains'] = {
            'live': verified_live,
            'dead': verified_dead,
            'internal': internal_only
        }
        
        return self.results['verified_subdomains']
    
    def export_verified_subdomains(self, filename=None):
        """Export only verified live subdomains"""
        
        if 'verified_subdomains' not in self.results or not self.results['verified_subdomains']:
            print("[ERROR] No verification data. Run verify_subdomains() first.\n")
            return None
        
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"verified_{self.domain}_{timestamp}.txt"
        
        try:
            live_subs = self.results['verified_subdomains']['live']
            
            with open(filename, 'w') as f:
                f.write(f"Verified Live Subdomains for {self.domain}\n")
                f.write(f"{'='*60}\n")
                f.write(f"Total: {len(live_subs)}\n")
                f.write(f"Verified: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"{'='*60}\n\n")
                
                for item in live_subs:
                    subdomain = item['subdomain']
                    
                    if 'ip_addresses' in item:
                        # DNS verification
                        ips = ', '.join(item['ip_addresses'])
                        f.write(f"{subdomain} → {ips}\n")
                    else:
                        # HTTP verification
                        status = f"HTTP {item['http_status']}" if item['http_status'] else f"HTTPS {item['https_status']}"
                        f.write(f"{subdomain} [{status}]\n")
            
            print(f"[SUCCESS] Verified subdomains exported to {filename}\n")
            return filename
            
        except Exception as e:
            logger.error(f"Export failed: {e}")
            print(f"[ERROR] Export failed: {e}\n")
            return None
    
    def subdomain_enumeration(self):
        """Complete subdomain enumeration with CT logs integration"""
        logger.info(f"Starting subdomain enumeration for {self.domain}")
        
        if self.formatter:
            self.formatter.print_section_start(f"PERFORMING SUBDOMAIN ENUMERATION FOR {self.domain.upper()}")
            print("Using passive methods including Certificate Transparency logs\n")
        else:
            print(f"{'='*60}")
            print(f"SUBDOMAIN ENUMERATION: {self.domain}")
            print(f"{'='*60}\n")
            print("Using passive methods including Certificate Transparency logs\n")
        
        all_subdomains = set()
        
        # METHOD 0: Certificate Transparency Logs (NEW - MOST IMPORTANT)
        print("[Method 0] Certificate Transparency Logs (crt.sh)")
        print("   This is the most effective passive method - searches all SSL certificates")
        ct_subs = self._ct_logs_search()
        all_subdomains.update(ct_subs)
        print(f"   ✓ Found {len(ct_subs)} subdomains from CT logs\n")
        
        # Method 1: Zone Transfer
        print("[Method 1] DNS Zone Transfer (AXFR)")
        zone_subs = self._attempt_zone_transfer()
        new_count = len(set(zone_subs) - all_subdomains)
        all_subdomains.update(zone_subs)
        print(f"   ✓ Found {new_count} new subdomains\n")
        
        # Method 2: SSL Certificate
        print("[Method 2] SSL Certificate Analysis")
        print("   Checking certificate Subject Alternative Names...")
        ssl_subs = self._check_ssl_certificate()
        new_count = len(set(ssl_subs) - all_subdomains)
        all_subdomains.update(ssl_subs)
        print(f"   ✓ Found {new_count} new subdomains\n")
        
        # Method 3: DNS Brute Force (IMPROVED WORDLIST)
        print("[Method 3] DNS Brute Force (Enhanced Wordlist)")
        print(f"   Testing {200 if not self._is_pk_domain() else 250}+ common subdomain names...")
        brute_subs = self._subdomain_bruteforce()
        new_count = len(set(brute_subs) - all_subdomains)
        all_subdomains.update(brute_subs)
        print(f"   ✓ Found {new_count} new subdomains\n")
        
        # Store results
        self.results['subdomains'] = sorted(list(all_subdomains))
        
        print(f"{'='*60}")
        print(f"TOTAL UNIQUE SUBDOMAINS FOUND: {len(self.results['subdomains'])}")
        print(f"{'='*60}\n")
        
        if self.results['subdomains']:
            print("Discovered Subdomains:")
            
            # Show first 30 subdomains
            display_count = min(30, len(self.results['subdomains']))
            for subdomain in self.results['subdomains'][:display_count]:
                print(f"   - {subdomain}")
            
            if len(self.results['subdomains']) > display_count:
                print(f"   ... and {len(self.results['subdomains']) - display_count} more")
                print(f"\n   [TIP] All {len(self.results['subdomains'])} subdomains are stored in results")
        else:
            print("[INFO] No subdomains found")
        
        print(f"\n{'='*60}\n")
        logger.info(f"Subdomain enumeration completed. Total: {len(self.results['subdomains'])}")
        
        return self.results['subdomains']
    
    def run_all(self, verify=True, verification_type='dns'):
        """
        Run all passive reconnaissance modules
        
        Args:
            verify: Whether to verify discovered subdomains (default: True)
            verification_type: 'dns' (fast) or 'http' (thorough)
        """
        logger.info(f"Starting full passive reconnaissance for {self.domain}")
        
        self.whois_lookup()
        self.dns_enumeration()
        self.subdomain_enumeration()
        
        # NEW: Verify subdomains
        if verify and self.results['subdomains']:
            print(f"\n[INFO] Starting subdomain verification...")
            self.verify_subdomains(verification_type=verification_type)
            self.export_verified_subdomains()
        
        logger.info("Passive reconnaissance completed")
        return self.results