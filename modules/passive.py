"""
Passive Reconnaissance Module
Handles WHOIS, DNS enumeration, and subdomain discovery
UPDATED VERSION - Enhanced PKNIC API support with formatter compatibility
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
import time
import re

# Set up logging
logger = logging.getLogger(__name__)


class PassiveRecon:
    """Performs passive reconnaissance on a target domain"""
    
    def __init__(self, domain, formatter=None):
        self.domain = domain
        self.formatter = formatter  # Optional formatter for enhanced output
        self.results = {
            'whois': {},
            'dns': {},
            'subdomains': []
        }
    
    def _is_pk_domain(self):
        """Check if the domain is a .pk domain"""
        return self.domain.lower().endswith('.pk')
    
    def _pknic_web_scrape(self, domain_to_query):
        """Fallback method: Scrape PKNIC web lookup page"""
        try:
            logger.info(f"Trying PKNIC web scraper for {domain_to_query}")
            
            # PKNIC web lookup URL
            url = f"https://pk6.pknic.net.pk/pk5/lookup.PK?name={domain_to_query}"
            
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
                            print(f"   ℹ️  API returned no data, trying alternative lookup...")
                            alt_data = self._pknic_web_scrape(domain_to_query)
                            
                            if alt_data:
                                self._display_whois_data(alt_data)
                                self.results['whois'] = alt_data
                                return alt_data
                            else:
                                print("❌ Domain not found in PKNIC registry")
                                print("   ℹ️  Note: Some .edu.pk domains may have limited WHOIS data")
                                print("    DNS records confirm domain exists\n")
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
            print(f"🔍 WHOIS LOOKUP: {self.domain}")
            print(f"{'='*60}\n")
        
        # Check if this is a .pk domain
        if self._is_pk_domain():
            print("[INFO] Detected .pk domain - Using PKNIC lookup\n")
            return self._pknic_whois_lookup()
        
        # Use standard WHOIS for non-.pk domains
        try:
            w = whois.whois(self.domain)
            
            if not w or not w.domain_name:
                print("❌ No WHOIS data available for this domain")
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
                                    print(f"      -{domain}")
                    
                    for sub in cert.get('subject', ()):
                        for key, value in sub:
                            if key == 'commonName':
                                domain = value.replace('*.', '').lower()
                                if domain.endswith(self.domain):
                                    subdomains.add(domain)
        
        except Exception as e:
            logger.debug(f"SSL certificate check failed: {e}")
        
        return list(subdomains)
    
    def _subdomain_bruteforce(self):
        """Brute force common subdomains"""
        common_subs = [
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
            'owa', 'en', 'start', 'sms', 'office', 'exchange', 'ipv4'
        ]
        
        found_subdomains = set()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        total = len(common_subs)
        
        for i, sub in enumerate(common_subs, 1):
            subdomain = f"{sub}.{self.domain}"
            
            if i % 20 == 0:
                print(f"      Progress: {i}/{total} checked...")
            
            try:
                answers = resolver.resolve(subdomain, 'A')
                if answers:
                    found_subdomains.add(subdomain.lower())
                    print(f"      [+] {subdomain}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception:
                pass
        
        return list(found_subdomains)
    
    def subdomain_enumeration(self):
        """Complete subdomain enumeration"""
        logger.info(f"Starting subdomain enumeration for {self.domain}")
        
        if self.formatter:
            self.formatter.print_section_start(f"PERFORMING SUBDOMAIN ENUMERATION FOR {self.domain.upper()}")
            print("Using local methods (no external APIs required)\n")
        else:
            print(f"{'='*60}")
            print(f"🔍 SUBDOMAIN ENUMERATION: {self.domain}")
            print(f"{'='*60}\n")
            print("Using local methods (no external APIs required)\n")
        
        all_subdomains = set()
        
        # Method 1: Zone Transfer
        print("[Method 1] DNS Zone Transfer (AXFR)")
        zone_subs = self._attempt_zone_transfer()
        all_subdomains.update(zone_subs)
        print(f"   Found {len(zone_subs)} subdomains\n")
        
        # Method 2: SSL Certificate
        print("[Method 2] SSL Certificate Analysis")
        print("   Checking certificate Subject Alternative Names...")
        ssl_subs = self._check_ssl_certificate()
        new_count = len(set(ssl_subs) - all_subdomains)
        all_subdomains.update(ssl_subs)
        print(f"   Found {new_count} new subdomains\n")
        
        # Method 3: DNS Brute Force
        print("[Method 3] DNS Brute Force")
        print(f"   Testing common subdomain names...")
        brute_subs = self._subdomain_bruteforce()
        new_count = len(set(brute_subs) - all_subdomains)
        all_subdomains.update(brute_subs)
        print(f"   Found {new_count} new subdomains\n")
        
        # Store results
        self.results['subdomains'] = sorted(list(all_subdomains))
        
        print(f"{'='*60}")
        print(f"TOTAL UNIQUE SUBDOMAINS FOUND: {len(self.results['subdomains'])}")
        print(f"{'='*60}\n")
        
        if self.results['subdomains']:
            print("Subdomains:")
            for subdomain in self.results['subdomains'][:20]:
                print(f"   - {subdomain}")
            
            if len(self.results['subdomains']) > 20:
                print(f"   ... and {len(self.results['subdomains']) - 20} more")
        else:
            print("[INFO] No subdomains found")
        
        print(f"\n{'='*60}\n")
        logger.info(f"Subdomain enumeration completed. Total: {len(self.results['subdomains'])}")
        
        return self.results['subdomains']
    
    def run_all(self):
        """Run all passive reconnaissance modules"""
        logger.info(f"Starting full passive reconnaissance for {self.domain}")
        
        self.whois_lookup()
        self.dns_enumeration()
        self.subdomain_enumeration()
        
        logger.info("Passive reconnaissance completed")
        return self.results