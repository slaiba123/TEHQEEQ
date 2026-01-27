# # """
# # Active Reconnaissance Module
# # Handles port scanning, banner grabbing, and technology detection
# # ENHANCED VERSION - Auto-detects and scans www subdomain if base domain has no A record
# # """

# # import socket
# # import requests
# # import re
# # import logging
# # import dns.resolver
# # from datetime import datetime
# # import config

# # # Try to import nmap (optional)
# # try:
# #     import nmap
# #     NMAP_AVAILABLE = True
# # except ImportError:
# #     NMAP_AVAILABLE = False

# # # Set up logging
# # logger = logging.getLogger(__name__)


# # class ActiveRecon:
# #     """Performs active reconnaissance on a target"""
    
# #     def __init__(self, target):
# #         self.original_target = target
# #         self.target = target
# #         self.results = {
# #             'open_ports': [],
# #             'banners': {},
# #             'technologies': [],
# #             'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
# #         }
        
# #         # Try to resolve domain to IP with smart fallback
# #         self._resolve_target()
    
# #     def _resolve_target(self):
# #         """Resolve domain to IP with smart detection of www subdomain"""
# #         try:
# #             # Try to resolve the original target
# #             self.ip = socket.gethostbyname(self.target)
# #             self.results['ip_address'] = self.ip
# #             logger.info(f"Resolved {self.target} to {self.ip}")
# #             print(f"✅ Resolved {self.target} → {self.ip}")
            
# #         except socket.gaierror:
# #             # If original target doesn't resolve, check if it's a domain without A record
# #             logger.warning(f"Could not resolve {self.target} directly")
            
# #             # Check if domain has A record using DNS
# #             try:
# #                 resolver = dns.resolver.Resolver()
# #                 resolver.timeout = 5
# #                 resolver.lifetime = 5
                
# #                 # Try to get A record
# #                 try:
# #                     answers = resolver.resolve(self.target, 'A')
# #                     if answers:
# #                         self.ip = str(answers[0])
# #                         self.results['ip_address'] = self.ip
# #                         logger.info(f"Resolved {self.target} to {self.ip} via DNS")
# #                         return
# #                 except dns.resolver.NoAnswer:
# #                     logger.debug(f"No A record for {self.target}")
                
# #                 # No A record found - try www subdomain
# #                 print(f"⚠️  {self.target} has no A record (no direct IP address)")
# #                 print(f"   Base domains often only have MX/NS records\n")
                
# #                 # Check if www subdomain exists
# #                 www_target = f"www.{self.target}" if not self.target.startswith('www.') else self.target
                
# #                 try:
# #                     print(f"   🔍 Checking www subdomain: {www_target}...")
# #                     www_answers = resolver.resolve(www_target, 'A')
                    
# #                     if www_answers:
# #                         www_ip = str(www_answers[0])
# #                         print(f"   ✅ Found! {www_target} → {www_ip}")
# #                         print(f"   🔄 Automatically switching to {www_target} for active scanning\n")
                        
# #                         self.target = www_target
# #                         self.ip = www_ip
# #                         self.results['ip_address'] = self.ip
# #                         self.results['target_modified'] = True
# #                         self.results['original_target'] = self.original_target
# #                         logger.info(f"Auto-switched to {www_target} ({www_ip})")
# #                         return
                        
# #                 except dns.resolver.NoAnswer:
# #                     logger.debug(f"No A record for {www_target} either")
                
# #                 # If www doesn't work, inform user
# #                 print(f"   ❌ {www_target} also has no A record")
# #                 print(f"   ℹ️  Active scanning requires a target with an IP address")
# #                 print(f"   💡 Try: python main.py www.{self.target} --ports --tech\n")
                
# #                 self.ip = None
# #                 self.results['ip_address'] = None
# #                 self.results['error'] = 'No IP address found for target'
                
# #             except Exception as e:
# #                 logger.error(f"DNS resolution failed: {e}")
# #                 print(f"   ❌ Could not resolve domain: {e}\n")
# #                 self.ip = None
# #                 self.results['ip_address'] = None
# #                 self.results['error'] = str(e)
        
# #         except Exception as e:
# #             logger.warning(f"Could not resolve {self.target}: {e}")
# #             self.ip = self.target  # Assume it's already an IP
# #             self.results['ip_address'] = self.target
    
# #     def port_scan(self, ports=None, use_nmap=False):
# #         """Scan ports on the target"""
# #         if ports is None:
# #             ports = config.COMMON_PORTS
        
# #         # Check if we have a valid IP
# #         if not self.ip:
# #             logger.warning("No IP address available for port scanning")
# #             print(f"{'='*60}")
# #             print(f"⚠️  PORT SCANNING: Skipped")
# #             print(f"{'='*60}\n")
# #             print(f"Cannot perform port scan without a valid IP address.")
# #             print(f"The target '{self.original_target}' does not resolve to an IP.\n")
# #             print(f"{'='*60}\n")
# #             return []
        
# #         logger.info(f"Starting port scan on {self.target}")
# #         print(f"\n{'='*60}")
        
# #         # Show if target was auto-switched
# #         if self.results.get('target_modified'):
# #             print(f"🔍 PORT SCANNING: {self.target} ({self.ip})")
# #             print(f"   (Auto-switched from {self.original_target})")
# #         else:
# #             print(f"🔍 PORT SCANNING: {self.target} ({self.ip})")
        
# #         print(f"⏰ Started: {datetime.now().strftime('%H:%M:%S')}")
# #         print(f"📍 Scanning {len(ports)} ports...")
# #         print(f"{'='*60}\n")
        
# #         if use_nmap and NMAP_AVAILABLE:
# #             self._nmap_scan(ports)
# #         else:
# #             if use_nmap and not NMAP_AVAILABLE:
# #                 print("⚠️  Nmap not available, using socket scanning")
# #                 print("   Install python-nmap for better results\n")
# #                 logger.warning("Nmap requested but not available")
# #             self._socket_scan(ports)
        
# #         print(f"\n{'='*60}")
# #         print(f"📊 SCAN COMPLETE")
# #         print(f"✅ Open Ports: {len(self.results['open_ports'])}/{len(ports)}")
# #         print(f"⏰ Finished: {datetime.now().strftime('%H:%M:%S')}")
# #         print(f"{'='*60}\n")
        
# #         logger.info(f"Port scan completed. {len(self.results['open_ports'])} ports open")
        
# #         return self.results['open_ports']
    
# #     def _socket_scan(self, ports):
# #         """Scan ports using raw sockets"""
# #         total = len(ports)
        
# #         for i, port in enumerate(ports, 1):
# #             if i % 5 == 0 or i == total:
# #                 print(f"Progress: {i}/{total} ports scanned...")
            
# #             try:
# #                 sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #                 sock.settimeout(config.SOCKET_TIMEOUT)
                
# #                 result = sock.connect_ex((self.ip, port))
                
# #                 if result == 0:
# #                     service = self._get_service_name(port)
# #                     print(f"✅ Port {port:5d} | OPEN      | {service}")
# #                     self.results['open_ports'].append({
# #                         'port': port,
# #                         'state': 'open',
# #                         'service': service
# #                     })
# #                 else:
# #                     logger.debug(f"Port {port} is closed")
                
# #                 sock.close()
                
# #             except socket.error as e:
# #                 logger.error(f"Error scanning port {port}: {str(e)}")
# #             except KeyboardInterrupt:
# #                 print("\n\n⚠️  Scan interrupted by user")
# #                 logger.warning("Port scan interrupted by user")
# #                 break
    
# #     def _nmap_scan(self, ports):
# #         """Scan ports using Nmap"""
# #         try:
# #             nm = nmap.PortScanner()
# #             port_string = ','.join(map(str, ports))
            
# #             print(f"🔧 Using Nmap for enhanced scanning...\n")
# #             nm.scan(self.ip, port_string, arguments='-sV')
            
# #             for host in nm.all_hosts():
# #                 for proto in nm[host].all_protocols():
# #                     port_list = nm[host][proto].keys()
                    
# #                     for port in port_list:
# #                         port_info = nm[host][proto][port]
# #                         state = port_info['state']
# #                         service = port_info.get('name', 'unknown')
# #                         version = port_info.get('version', '')
# #                         product = port_info.get('product', '')
                        
# #                         service_str = f"{product} {version}".strip() if product else service
                        
# #                         if state == 'open':
# #                             print(f"✅ Port {port:5d} | {state.upper():9s} | {service_str}")
# #                             self.results['open_ports'].append({
# #                                 'port': port,
# #                                 'state': state,
# #                                 'service': service_str
# #                             })
            
# #         except nmap.PortScannerError as e:
# #             if 'not found in path' in str(e):
# #                 logger.error("Nmap executable not found")
# #                 print("❌ Nmap program not installed!")
# #                 print("   Download from: https://nmap.org/download.html")
# #                 print("   After installation, add Nmap to your system PATH")
# #                 print("   Falling back to socket scanning...\n")
# #             else:
# #                 logger.error(f"Nmap scan failed: {str(e)}")
# #                 print(f"❌ Nmap scan failed: {str(e)}")
# #                 print("   Falling back to socket scanning...\n")
# #             self._socket_scan(ports)
# #         except Exception as e:
# #             logger.error(f"Nmap scan failed: {str(e)}")
# #             print(f"❌ Nmap scan failed: {str(e)}")
# #             print("   Falling back to socket scanning...\n")
# #             self._socket_scan(ports)
    
# #     def _get_service_name(self, port):
# #         """Get common service name for a port"""
# #         services = {
# #             21: 'FTP',
# #             22: 'SSH',
# #             23: 'Telnet',
# #             25: 'SMTP',
# #             53: 'DNS',
# #             80: 'HTTP',
# #             110: 'POP3',
# #             143: 'IMAP',
# #             443: 'HTTPS',
# #             445: 'SMB',
# #             3306: 'MySQL',
# #             3389: 'RDP',
# #             5432: 'PostgreSQL',
# #             8080: 'HTTP-Proxy',
# #             8443: 'HTTPS-Alt'
# #         }
# #         return services.get(port, 'unknown')
    
# #     def banner_grab(self):
# #         """Grab banners from open ports with improved protocol handling"""
# #         if not self.ip:
# #             logger.warning("No IP address available for banner grabbing")
# #             print(f"{'='*60}")
# #             print(f"📜 BANNER GRABBING: Skipped")
# #             print(f"{'='*60}\n")
# #             print(f"⚠️  Cannot grab banners without a valid IP address\n")
# #             return {}
        
# #         logger.info(f"Starting banner grabbing for {self.target}")
# #         print(f"{'='*60}")
# #         print(f"📜 BANNER GRABBING: {self.target}")
# #         print(f"{'='*60}\n")
        
# #         if not self.results['open_ports']:
# #             print("⚠️  No open ports to grab banners from\n")
# #             return {}
        
# #         for port_info in self.results['open_ports']:
# #             port = port_info['port'] if isinstance(port_info, dict) else port_info
            
# #             try:
# #                 sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# #                 sock.settimeout(config.BANNER_TIMEOUT)
# #                 sock.connect((self.ip, port))
                
# #                 # Send protocol-specific requests
# #                 if port == 80:
# #                     sock.send(b"GET / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
# #                 elif port == 443:
# #                     pass
# #                 elif port in [25, 21, 22, 110, 143]:
# #                     pass
# #                 else:
# #                     try:
# #                         sock.send(b"\r\n")
# #                     except:
# #                         pass
                
# #                 # Try to receive banner
# #                 try:
# #                     banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
# #                     if banner:
# #                         display_banner = banner[:300] if len(banner) > 300 else banner
# #                         print(f"Port {port} ({self._get_service_name(port)}):")
# #                         print(f"   {display_banner}")
# #                         if len(banner) > 300:
# #                             print(f"   ... (truncated)")
# #                         print()
# #                         self.results['banners'][port] = banner
# #                         logger.info(f"Banner grabbed from port {port}")
# #                 except socket.timeout:
# #                     logger.debug(f"Timeout receiving banner from port {port}")
# #                 except Exception as e:
# #                     logger.debug(f"Error receiving banner from port {port}: {e}")
                
# #                 sock.close()
                
# #             except Exception as e:
# #                 logger.debug(f"Could not grab banner from port {port}: {str(e)}")
        
# #         if not self.results['banners']:
# #             print("ℹ️  No banners available from scanned ports")
# #             print("   Note: Many modern services don't expose banners for security\n")
        
# #         print(f"{'='*60}\n")
# #         logger.info(f"Banner grabbing completed. {len(self.results['banners'])} banners found")
        
# #         return self.results['banners']
    
# #     def detect_technologies(self):
# #         """Detect web technologies"""
# #         if not self.ip:
# #             logger.warning("No IP address available for technology detection")
# #             print(f"{'='*60}")
# #             print(f"🔧 TECHNOLOGY DETECTION: Skipped")
# #             print(f"{'='*60}\n")
# #             print(f"⚠️  Cannot detect technologies without a valid IP address\n")
# #             return []
        
# #         logger.info(f"Starting technology detection for {self.target}")
# #         print(f"{'='*60}")
# #         print(f"🔧 TECHNOLOGY DETECTION: {self.target}")
# #         print(f"{'='*60}\n")
        
# #         # Check if HTTP/HTTPS ports are open
# #         http_port = None
# #         for port_info in self.results['open_ports']:
# #             port = port_info['port'] if isinstance(port_info, dict) else port_info
# #             if port in [80, 443, 8080, 8443]:
# #                 http_port = port
# #                 break
        
# #         if not http_port:
# #             print("⚠️  No HTTP/HTTPS ports open. Skipping web technology detection.\n")
# #             return []
        
# #         # Try both HTTP and HTTPS
# #         protocols = ['https', 'http']
# #         success = False
# #         response = None
        
# #         for protocol in protocols:
# #             if http_port in [443, 8443]:
# #                 url = f"https://{self.target}"
# #             else:
# #                 url = f"{protocol}://{self.target}"
            
# #             if http_port not in [80, 443]:
# #                 url += f":{http_port}"
            
# #             try:
# #                 print(f"🌐 Analyzing {url}...")
# #                 import urllib3
# #                 urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
# #                 response = requests.get(url, timeout=config.WEB_REQUEST_TIMEOUT, verify=False)
# #                 success = True
# #                 print(f"   ✅ Connected successfully\n")
# #                 break
# #             except Exception as e:
# #                 logger.debug(f"Failed to connect to {url}: {e}")
# #                 continue
        
# #         if not success or not response:
# #             print("❌ Could not connect to web server\n")
# #             return []
        
# #         content = response.text.lower()
# #         headers = response.headers
        
# #         technologies = []
        
# #         print(f"📋 DETECTED TECHNOLOGIES:\n")
        
# #         # Server
# #         if 'Server' in headers:
# #             tech = f"Web Server: {headers['Server']}"
# #             print(f"   🖥️  {tech}")
# #             technologies.append(tech)
        
# #         # Backend
# #         if 'X-Powered-By' in headers:
# #             tech = f"Backend: {headers['X-Powered-By']}"
# #             print(f"   ⚡ {tech}")
# #             technologies.append(tech)
        
# #         # CMS
# #         cms_detected = False
# #         if 'wp-content' in content or 'wp-includes' in content:
# #             version_match = re.search(r'wordpress/(\d+\.\d+\.\d+)', content)
# #             version = f" {version_match.group(1)}" if version_match else ""
# #             tech = f"CMS: WordPress{version}"
# #             print(f"   📝 {tech}")
# #             technologies.append(tech)
# #             cms_detected = True
        
# #         if 'drupal' in content and not cms_detected:
# #             print(f"   📝 CMS: Drupal")
# #             technologies.append("CMS: Drupal")
# #             cms_detected = True
        
# #         if 'joomla' in content and not cms_detected:
# #             print(f"   📝 CMS: Joomla")
# #             technologies.append("CMS: Joomla")
        
# #         # JavaScript Frameworks
# #         js_frameworks = []
# #         if 'react' in content or '_react' in content:
# #             js_frameworks.append('React.js')
# #         if 'vue' in content or 'vue.js' in content:
# #             js_frameworks.append('Vue.js')
# #         if 'angular' in content or 'ng-' in content:
# #             js_frameworks.append('Angular')
        
# #         if js_frameworks:
# #             for fw in js_frameworks:
# #                 tech = f"JS Framework: {fw}"
# #                 print(f"   ⚛️  {tech}")
# #                 technologies.append(tech)
        
# #         # JavaScript Libraries
# #         if 'jquery' in content:
# #             version_match = re.search(r'jquery[.-]?v?(\d+\.\d+\.\d+)', content)
# #             version = f" {version_match.group(1)}" if version_match else ""
# #             tech = f"Library: jQuery{version}"
# #             print(f"   📚 {tech}")
# #             technologies.append(tech)
        
# #         # CSS Frameworks
# #         if 'bootstrap' in content:
# #             version_match = re.search(r'bootstrap[/-]?v?(\d+\.\d+\.\d+)', content)
# #             version = f" {version_match.group(1)}" if version_match else ""
# #             tech = f"CSS Framework: Bootstrap{version}"
# #             print(f"   🎨 {tech}")
# #             technologies.append(tech)
        
# #         # CDN
# #         cdn_detected = []
# #         if 'CF-RAY' in headers or 'cloudflare' in content:
# #             cdn_detected.append('CloudFlare')
# #         if 'X-Amz-Cf-Id' in headers:
# #             cdn_detected.append('Amazon CloudFront')
# #         if 'X-CDN' in headers:
# #             cdn_detected.append('Generic CDN')
        
# #         for cdn in cdn_detected:
# #             tech = f"CDN: {cdn}"
# #             print(f"   🌐 {tech}")
# #             technologies.append(tech)
        
# #         # Analytics
# #         if 'google-analytics' in content or 'gtag' in content or 'ga.js' in content:
# #             print(f"   📊 Analytics: Google Analytics")
# #             technologies.append("Analytics: Google Analytics")
        
# #         # Security Headers
# #         security_headers = []
# #         if 'X-Frame-Options' in headers:
# #             security_headers.append(f"X-Frame-Options: {headers['X-Frame-Options']}")
# #         if 'Strict-Transport-Security' in headers:
# #             security_headers.append("HSTS Enabled")
# #         if 'Content-Security-Policy' in headers:
# #             security_headers.append("CSP Enabled")
# #         if 'X-XSS-Protection' in headers:
# #             security_headers.append("XSS Protection Enabled")
# #         if 'X-Content-Type-Options' in headers:
# #             security_headers.append("Content-Type Options Set")
        
# #         if security_headers:
# #             print(f"\n   🔒 Security Headers:")
# #             for header in security_headers:
# #                 print(f"      → {header}")
# #                 technologies.append(f"Security: {header}")
        
# #         if not technologies:
# #             print("   ℹ️  No technologies detected")
        
# #         print(f"\n{'='*60}\n")
        
# #         self.results['technologies'] = technologies
# #         logger.info(f"Technology detection completed. {len(technologies)} technologies found")
        
# #         return technologies
    
# #     def run_all(self, use_nmap=False):
# #         """Run all active reconnaissance modules"""
# #         logger.info(f"Starting full active reconnaissance for {self.target}")
        
# #         self.port_scan(use_nmap=use_nmap)
# #         self.banner_grab()
# #         self.detect_technologies()
        
# #         logger.info("Active reconnaissance completed")
# #         return self.results



# """
# Active Reconnaissance Module
# Handles port scanning, banner grabbing, and technology detection
# UPDATED VERSION - With formatter compatibility
# """

# import socket
# import requests
# import re
# import logging
# import dns.resolver
# from datetime import datetime
# import config

# # Set up logging
# logger = logging.getLogger(__name__)


# class ActiveRecon:
#     """Performs active reconnaissance on a target"""
    
#     def __init__(self, target, formatter=None):
#         self.original_target = target
#         self.target = target
#         self.formatter = formatter  # Optional formatter for enhanced output
#         self.results = {
#             'open_ports': [],
#             'banners': {},
#             'technologies': [],
#             'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#         }
        
#         # Resolve target to IP
#         self._resolve_target()
    
#     def _resolve_target(self):
#         """Resolve domain to IP with smart detection"""
#         try:
#             self.ip = socket.gethostbyname(self.target)
#             self.results['ip_address'] = self.ip
#             logger.info(f"Resolved {self.target} to {self.ip}")
#             print(f"✅ Resolved {self.target} → {self.ip}")
            
#         except socket.gaierror:
#             logger.warning(f"Could not resolve {self.target} directly")
            
#             try:
#                 resolver = dns.resolver.Resolver()
#                 resolver.timeout = 5
#                 resolver.lifetime = 5
                
#                 try:
#                     answers = resolver.resolve(self.target, 'A')
#                     if answers:
#                         self.ip = str(answers[0])
#                         self.results['ip_address'] = self.ip
#                         logger.info(f"Resolved {self.target} to {self.ip}")
#                         return
#                 except dns.resolver.NoAnswer:
#                     logger.debug(f"No A record for {self.target}")
                
#                 # No A record found - try www subdomain
#                 print(f"\n⚠️  {self.target} has no A record (no direct IP address)")
#                 print(f"   Base domains often only have MX/NS records\n")
                
#                 www_target = f"www.{self.target}" if not self.target.startswith('www.') else self.target
                
#                 try:
#                     print(f"   🔍 Checking www subdomain: {www_target}...")
#                     www_answers = resolver.resolve(www_target, 'A')
                    
#                     if www_answers:
#                         www_ip = str(www_answers[0])
#                         print(f"   ✅ Found! {www_target} → {www_ip}")
#                         print(f"   🔄 Automatically switching to {www_target} for active scanning\n")
                        
#                         self.target = www_target
#                         self.ip = www_ip
#                         self.results['ip_address'] = self.ip
#                         self.results['target_modified'] = True
#                         self.results['original_target'] = self.original_target
#                         logger.info(f"Auto-switched to {www_target} ({www_ip})")
#                         return
                        
#                 except dns.resolver.NoAnswer:
#                     logger.debug(f"No A record for {www_target} either")
                
#                 print(f"   ❌ {www_target} also has no A record")
#                 print(f"   ℹ️  Active scanning requires a target with an IP address")
#                 print(f"   💡 Try: python main.py www.{self.target} --ports --tech\n")
                
#                 self.ip = None
#                 self.results['ip_address'] = None
#                 self.results['error'] = 'No IP address found for target'
                
#             except Exception as e:
#                 logger.error(f"DNS resolution failed: {e}")
#                 print(f"   ❌ Could not resolve domain: {e}\n")
#                 self.ip = None
#                 self.results['ip_address'] = None
#                 self.results['error'] = str(e)
        
#         except Exception as e:
#             logger.warning(f"Could not resolve {self.target}: {e}")
#             self.ip = self.target  # Assume it's already an IP
#             self.results['ip_address'] = self.target
    
#     def port_scan(self, ports=None, use_nmap=False):
#         """Scan ports on the target"""
#         if ports is None:
#             ports = config.COMMON_PORTS
        
#         if not self.ip:
#             logger.warning("No IP address available for port scanning")
#             if self.formatter:
#                 self.formatter.print_section_start("PORT SCAN SKIPPED")
#                 print("Cannot perform port scan without a valid IP address.\n")
#             else:
#                 print(f"{'='*60}")
#                 print(f"⚠️  PORT SCANNING: Skipped")
#                 print(f"{'='*60}\n")
#                 print(f"Cannot perform port scan without a valid IP address.\n")
#             return []
        
#         logger.info(f"Starting port scan on {self.target}")
        
#         if self.formatter:
#             self.formatter.print_section_start(f"PERFORMING PORT SCAN FOR {self.target.upper()}")
#         else:
#             print(f"\n{'='*60}")
#             print(f"🔍 PORT SCANNING: {self.target} ({self.ip})")
#             if self.results.get('target_modified'):
#                 print(f"   (Auto-switched from {self.original_target})")
#             print(f"⏰ Started: {datetime.now().strftime('%H:%M:%S')}")
#             print(f"📍 Scanning {len(ports)} ports...")
#             print(f"{'='*60}\n")
        
#         self._socket_scan(ports)
        
#         print(f"\n{'='*60}")
#         print(f"📊 SCAN COMPLETE")
#         print(f"✅ Open Ports: {len(self.results['open_ports'])}/{len(ports)}")
#         print(f"⏰ Finished: {datetime.now().strftime('%H:%M:%S')}")
#         print(f"{'='*60}\n")
        
#         logger.info(f"Port scan completed. {len(self.results['open_ports'])} ports open")
        
#         return self.results['open_ports']
    
#     def _socket_scan(self, ports):
#         """Scan ports using raw sockets"""
#         total = len(ports)
        
#         for i, port in enumerate(ports, 1):
#             if i % 5 == 0 or i == total:
#                 print(f"Progress: {i}/{total} ports scanned...")
            
#             try:
#                 sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#                 sock.settimeout(config.SOCKET_TIMEOUT)
                
#                 result = sock.connect_ex((self.ip, port))
                
#                 if result == 0:
#                     service = self._get_service_name(port)
#                     print(f"✅ Port {port:5d} | OPEN      | {service}")
#                     self.results['open_ports'].append({
#                         'port': port,
#                         'state': 'open',
#                         'service': service
#                     })
#                 else:
#                     logger.debug(f"Port {port} is closed")
                
#                 sock.close()
                
#             except socket.error as e:
#                 logger.error(f"Error scanning port {port}: {str(e)}")
#             except KeyboardInterrupt:
#                 print("\n\n⚠️  Scan interrupted by user")
#                 logger.warning("Port scan interrupted by user")
#                 break
    
#     def _get_service_name(self, port):
#         """Get common service name for a port"""
#         services = {
#             21: 'FTP',
#             22: 'SSH',
#             23: 'Telnet',
#             25: 'SMTP',
#             53: 'DNS',
#             80: 'HTTP',
#             110: 'POP3',
#             143: 'IMAP',
#             443: 'HTTPS',
#             445: 'SMB',
#             3306: 'MySQL',
#             3389: 'RDP',
#             5432: 'PostgreSQL',
#             8080: 'HTTP-Proxy',
#             8443: 'HTTPS-Alt'
#         }
#         return services.get(port, 'unknown')
    
#     def banner_grab(self):
#         """Grab banners from open ports"""
#         if not self.ip:
#             logger.warning("No IP address available for banner grabbing")
#             print(f"{'='*60}")
#             print(f"📜 BANNER GRABBING: Skipped")
#             print(f"{'='*60}\n")
#             print(f"⚠️  Cannot grab banners without a valid IP address\n")
#             return {}
        
#         logger.info(f"Starting banner grabbing for {self.target}")
        
#         if self.formatter:
#             self.formatter.print_section_start(f"PERFORMING BANNER GRABBING FOR {self.target.upper()}")
#         else:
#             print(f"{'='*60}")
#             print(f"📜 BANNER GRABBING: {self.target}")
#             print(f"{'='*60}\n")
        
#         if not self.results['open_ports']:
#             print("⚠️  No open ports to grab banners from\n")
#             return {}
        
#         for port_info in self.results['open_ports']:
#             port = port_info['port'] if isinstance(port_info, dict) else port_info
            
#             try:
#                 sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#                 sock.settimeout(config.BANNER_TIMEOUT)
#                 sock.connect((self.ip, port))
                
#                 # Send protocol-specific requests
#                 if port == 80:
#                     sock.send(b"GET / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
#                 elif port == 443:
#                     pass
#                 elif port in [25, 21, 22, 110, 143]:
#                     pass
#                 else:
#                     try:
#                         sock.send(b"\r\n")
#                     except:
#                         pass
                
#                 # Try to receive banner
#                 try:
#                     banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
#                     if banner:
#                         display_banner = banner[:300] if len(banner) > 300 else banner
#                         print(f"Port {port} ({self._get_service_name(port)}):")
#                         print(f"   {display_banner}")
#                         if len(banner) > 300:
#                             print(f"   ... (truncated)")
#                         print()
#                         self.results['banners'][port] = banner
#                         logger.info(f"Banner grabbed from port {port}")
#                 except socket.timeout:
#                     logger.debug(f"Timeout receiving banner from port {port}")
#                 except Exception as e:
#                     logger.debug(f"Error receiving banner from port {port}: {e}")
                
#                 sock.close()
                
#             except Exception as e:
#                 logger.debug(f"Could not grab banner from port {port}: {str(e)}")
        
#         if not self.results['banners']:
#             print("ℹ️  No banners available from scanned ports")
#             print("   Note: Many modern services don't expose banners for security\n")
        
#         print(f"{'='*60}\n")
#         logger.info(f"Banner grabbing completed. {len(self.results['banners'])} banners found")
        
#         return self.results['banners']
    
#     def detect_technologies(self):
#         """Detect web technologies"""
#         if not self.ip:
#             logger.warning("No IP address available for technology detection")
#             print(f"{'='*60}")
#             print(f"🔧 TECHNOLOGY DETECTION: Skipped")
#             print(f"{'='*60}\n")
#             print(f"⚠️  Cannot detect technologies without a valid IP address\n")
#             return []
        
#         logger.info(f"Starting technology detection for {self.target}")
        
#         if self.formatter:
#             self.formatter.print_section_start(f"PERFORMING TECHNOLOGY DETECTION FOR {self.target.upper()}")
#         else:
#             print(f"{'='*60}")
#             print(f"🔧 TECHNOLOGY DETECTION: {self.target}")
#             print(f"{'='*60}\n")
        
#         # Check if HTTP/HTTPS ports are open
#         http_port = None
#         for port_info in self.results['open_ports']:
#             port = port_info['port'] if isinstance(port_info, dict) else port_info
#             if port in [80, 443, 8080, 8443]:
#                 http_port = port
#                 break
        
#         if not http_port:
#             print("⚠️  No HTTP/HTTPS ports open. Skipping web technology detection.\n")
#             return []
        
#         # Try both HTTP and HTTPS
#         protocols = ['https', 'http']
#         success = False
#         response = None
        
#         for protocol in protocols:
#             if http_port in [443, 8443]:
#                 url = f"https://{self.target}"
#             else:
#                 url = f"{protocol}://{self.target}"
            
#             if http_port not in [80, 443]:
#                 url += f":{http_port}"
            
#             try:
#                 print(f"🌐 Analyzing {url}...")
#                 import urllib3
#                 urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
#                 response = requests.get(url, timeout=config.WEB_REQUEST_TIMEOUT, verify=False)
#                 success = True
#                 print(f"   ✅ Connected successfully\n")
#                 break
#             except Exception as e:
#                 logger.debug(f"Failed to connect to {url}: {e}")
#                 continue
        
#         if not success or not response:
#             print("❌ Could not connect to web server\n")
#             return []
        
#         content = response.text.lower()
#         headers = response.headers
        
#         technologies = []
        
#         print(f"📋 DETECTED TECHNOLOGIES:\n")
        
#         # Server
#         if 'Server' in headers:
#             tech = f"Web Server: {headers['Server']}"
#             print(f"   🖥️  {tech}")
#             technologies.append(tech)
        
#         # Backend
#         if 'X-Powered-By' in headers:
#             tech = f"Backend: {headers['X-Powered-By']}"
#             print(f"   ⚡ {tech}")
#             technologies.append(tech)
        
#         # CMS
#         cms_detected = False
#         if 'wp-content' in content or 'wp-includes' in content:
#             version_match = re.search(r'wordpress/(\d+\.\d+\.\d+)', content)
#             version = f" {version_match.group(1)}" if version_match else ""
#             tech = f"CMS: WordPress{version}"
#             print(f"   📝 {tech}")
#             technologies.append(tech)
#             cms_detected = True
        
#         if 'drupal' in content and not cms_detected:
#             print(f"   📝 CMS: Drupal")
#             technologies.append("CMS: Drupal")
#             cms_detected = True
        
#         if 'joomla' in content and not cms_detected:
#             print(f"   📝 CMS: Joomla")
#             technologies.append("CMS: Joomla")
        
#         # JavaScript Frameworks
#         js_frameworks = []
#         if 'react' in content or '_react' in content:
#             js_frameworks.append('React.js')
#         if 'vue' in content or 'vue.js' in content:
#             js_frameworks.append('Vue.js')
#         if 'angular' in content or 'ng-' in content:
#             js_frameworks.append('Angular')
        
#         if js_frameworks:
#             for fw in js_frameworks:
#                 tech = f"JS Framework: {fw}"
#                 print(f"   ⚛️  {tech}")
#                 technologies.append(tech)
        
#         # JavaScript Libraries
#         if 'jquery' in content:
#             version_match = re.search(r'jquery[.-]?v?(\d+\.\d+\.\d+)', content)
#             version = f" {version_match.group(1)}" if version_match else ""
#             tech = f"Library: jQuery{version}"
#             print(f"   📚 {tech}")
#             technologies.append(tech)
        
#         # CSS Frameworks
#         if 'bootstrap' in content:
#             version_match = re.search(r'bootstrap[/-]?v?(\d+\.\d+\.\d+)', content)
#             version = f" {version_match.group(1)}" if version_match else ""
#             tech = f"CSS Framework: Bootstrap{version}"
#             print(f"   🎨 {tech}")
#             technologies.append(tech)
        
#         # Security Headers
#         security_headers = []
#         if 'X-Frame-Options' in headers:
#             security_headers.append(f"X-Frame-Options: {headers['X-Frame-Options']}")
#         if 'Strict-Transport-Security' in headers:
#             security_headers.append("HSTS Enabled")
#         if 'Content-Security-Policy' in headers:
#             security_headers.append("CSP Enabled")
#         if 'X-XSS-Protection' in headers:
#             security_headers.append("XSS Protection Enabled")
#         if 'X-Content-Type-Options' in headers:
#             security_headers.append("Content-Type Options Set")
        
#         if security_headers:
#             print(f"\n   🔒 Security Headers:")
#             for header in security_headers:
#                 print(f"      → {header}")
#                 technologies.append(f"Security: {header}")
        
#         if not technologies:
#             print("   ℹ️  No technologies detected")
        
#         print(f"\n{'='*60}\n")
        
#         self.results['technologies'] = technologies
#         logger.info(f"Technology detection completed. {len(technologies)} technologies found")
        
#         return technologies
    
#     def run_all(self, use_nmap=False):
#         """Run all active reconnaissance modules"""
#         logger.info(f"Starting full active reconnaissance for {self.target}")
        
#         self.port_scan(use_nmap=use_nmap)
#         self.banner_grab()
#         self.detect_technologies()
        
#         logger.info("Active reconnaissance completed")
#         return self.results


"""
Active Reconnaissance Module
Handles port scanning, banner grabbing, and technology detection
UPDATED VERSION - With formatter compatibility
"""

import socket
import requests
import re
import logging
import dns.resolver
from datetime import datetime
import config

# Set up logging
logger = logging.getLogger(__name__)


class ActiveRecon:
    """Performs active reconnaissance on a target"""
    
    def __init__(self, target, formatter=None):
        self.original_target = target
        self.target = target
        self.formatter = formatter  # Optional formatter for enhanced output
        self.results = {
            'open_ports': [],
            'banners': {},
            'technologies': [],
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Resolve target to IP
        self._resolve_target()
    
    def _resolve_target(self):
        """Resolve domain to IP with smart detection"""
        try:
            self.ip = socket.gethostbyname(self.target)
            self.results['ip_address'] = self.ip
            logger.info(f"Resolved {self.target} to {self.ip}")
            print(f"[INFO] Resolved {self.target} -> {self.ip}")
            
        except socket.gaierror:
            logger.warning(f"Could not resolve {self.target} directly")
            
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                
                try:
                    answers = resolver.resolve(self.target, 'A')
                    if answers:
                        self.ip = str(answers[0])
                        self.results['ip_address'] = self.ip
                        logger.info(f"Resolved {self.target} to {self.ip}")
                        return
                except dns.resolver.NoAnswer:
                    logger.debug(f"No A record for {self.target}")
                
                # No A record found - try www subdomain
                print(f"\n[WARNING] {self.target} has no A record (no direct IP address)")
                print(f"   Base domains often only have MX/NS records\n")
                
                www_target = f"www.{self.target}" if not self.target.startswith('www.') else self.target
                
                try:
                    print(f"   [INFO] Checking www subdomain: {www_target}...")
                    www_answers = resolver.resolve(www_target, 'A')
                    
                    if www_answers:
                        www_ip = str(www_answers[0])
                        print(f"   [SUCCESS] Found! {www_target} -> {www_ip}")
                        print(f"   [INFO] Automatically switching to {www_target} for active scanning\n")
                        
                        self.target = www_target
                        self.ip = www_ip
                        self.results['ip_address'] = self.ip
                        self.results['target_modified'] = True
                        self.results['original_target'] = self.original_target
                        logger.info(f"Auto-switched to {www_target} ({www_ip})")
                        return
                        
                except dns.resolver.NoAnswer:
                    logger.debug(f"No A record for {www_target} either")
                
                print(f"   [ERROR] {www_target} also has no A record")
                print(f"   [INFO] Active scanning requires a target with an IP address")
                print(f"   [TIP] Try: python main.py www.{self.target} --ports --tech\n")
                
                self.ip = None
                self.results['ip_address'] = None
                self.results['error'] = 'No IP address found for target'
                
            except Exception as e:
                logger.error(f"DNS resolution failed: {e}")
                print(f"   [ERROR] Could not resolve domain: {e}\n")
                self.ip = None
                self.results['ip_address'] = None
                self.results['error'] = str(e)
        
        except Exception as e:
            logger.warning(f"Could not resolve {self.target}: {e}")
            self.ip = self.target  # Assume it's already an IP
            self.results['ip_address'] = self.target
    
    def port_scan(self, ports=None, use_nmap=False):
        """Scan ports on the target"""
        if ports is None:
            ports = config.COMMON_PORTS
        
        if not self.ip:
            logger.warning("No IP address available for port scanning")
            if self.formatter:
                self.formatter.print_section_start("PORT SCAN SKIPPED")
                print("Cannot perform port scan without a valid IP address.\n")
            else:
                print(f"{'='*60}")
                print(f"[WARNING] PORT SCANNING: Skipped")
                print(f"{'='*60}\n")
                print(f"Cannot perform port scan without a valid IP address.\n")
            return []
        
        logger.info(f"Starting port scan on {self.target}")
        
        if self.formatter:
            self.formatter.print_section_start(f"PERFORMING PORT SCAN FOR {self.target.upper()}")
        else:
            print(f"\n{'='*60}")
            print(f"[PORT SCAN] {self.target} ({self.ip})")
            if self.results.get('target_modified'):
                print(f"   (Auto-switched from {self.original_target})")
            print(f"Started: {datetime.now().strftime('%H:%M:%S')}")
            print(f"Scanning {len(ports)} ports...")
            print(f"{'='*60}\n")
        
        self._socket_scan(ports)
        
        print(f"\n{'='*60}")
        print(f"SCAN COMPLETE")
        print(f"Open Ports: {len(self.results['open_ports'])}/{len(ports)}")
        print(f"Finished: {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*60}\n")
        
        logger.info(f"Port scan completed. {len(self.results['open_ports'])} ports open")
        
        return self.results['open_ports']
    
    def _socket_scan(self, ports):
        """Scan ports using raw sockets"""
        total = len(ports)
        
        for i, port in enumerate(ports, 1):
            if i % 5 == 0 or i == total:
                print(f"Progress: {i}/{total} ports scanned...")
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(config.SOCKET_TIMEOUT)
                
                result = sock.connect_ex((self.ip, port))
                
                if result == 0:
                    service = self._get_service_name(port)
                    print(f"[OPEN] Port {port:5d} | {service}")
                    self.results['open_ports'].append({
                        'port': port,
                        'state': 'open',
                        'service': service
                    })
                else:
                    logger.debug(f"Port {port} is closed")
                
                sock.close()
                
            except socket.error as e:
                logger.error(f"Error scanning port {port}: {str(e)}")
            except KeyboardInterrupt:
                print("\n\n[WARNING] Scan interrupted by user")
                logger.warning("Port scan interrupted by user")
                break
    
    def _get_service_name(self, port):
        """Get common service name for a port"""
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt'
        }
        return services.get(port, 'unknown')
    
    def banner_grab(self):
        """Grab banners from open ports"""
        if not self.ip:
            logger.warning("No IP address available for banner grabbing")
            print(f"{'='*60}")
            print(f"[BANNER GRABBING] Skipped")
            print(f"{'='*60}\n")
            print(f"[WARNING] Cannot grab banners without a valid IP address\n")
            return {}
        
        logger.info(f"Starting banner grabbing for {self.target}")
        
        if self.formatter:
            self.formatter.print_section_start(f"PERFORMING BANNER GRABBING FOR {self.target.upper()}")
        else:
            print(f"{'='*60}")
            print(f"[BANNER GRABBING] {self.target}")
            print(f"{'='*60}\n")
        
        if not self.results['open_ports']:
            print("[INFO] No open ports to grab banners from\n")
            return {}
        
        for port_info in self.results['open_ports']:
            port = port_info['port'] if isinstance(port_info, dict) else port_info
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(config.BANNER_TIMEOUT)
                sock.connect((self.ip, port))
                
                # Send protocol-specific requests
                if port == 80:
                    sock.send(b"GET / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                elif port == 443:
                    pass
                elif port in [25, 21, 22, 110, 143]:
                    pass
                else:
                    try:
                        sock.send(b"\r\n")
                    except:
                        pass
                
                # Try to receive banner
                try:
                    banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
                    if banner:
                        display_banner = banner[:300] if len(banner) > 300 else banner
                        print(f"Port {port} ({self._get_service_name(port)}):")
                        print(f"   {display_banner}")
                        if len(banner) > 300:
                            print(f"   ... (truncated)")
                        print()
                        self.results['banners'][port] = banner
                        logger.info(f"Banner grabbed from port {port}")
                except socket.timeout:
                    logger.debug(f"Timeout receiving banner from port {port}")
                except Exception as e:
                    logger.debug(f"Error receiving banner from port {port}: {e}")
                
                sock.close()
                
            except Exception as e:
                logger.debug(f"Could not grab banner from port {port}: {str(e)}")
        
        if not self.results['banners']:
            print("[INFO] No banners available from scanned ports")
            print("   Note: Many modern services don't expose banners for security\n")
        
        print(f"{'='*60}\n")
        logger.info(f"Banner grabbing completed. {len(self.results['banners'])} banners found")
        
        return self.results['banners']
    
    def detect_technologies(self):
        """Detect web technologies"""
        if not self.ip:
            logger.warning("No IP address available for technology detection")
            print(f"{'='*60}")
            print(f"[TECHNOLOGY DETECTION] Skipped")
            print(f"{'='*60}\n")
            print(f"[WARNING] Cannot detect technologies without a valid IP address\n")
            return []
        
        logger.info(f"Starting technology detection for {self.target}")
        
        if self.formatter:
            self.formatter.print_section_start(f"PERFORMING TECHNOLOGY DETECTION FOR {self.target.upper()}")
        else:
            print(f"{'='*60}")
            print(f"[TECHNOLOGY DETECTION] {self.target}")
            print(f"{'='*60}\n")
        
        # Check if HTTP/HTTPS ports are open
        http_port = None
        for port_info in self.results['open_ports']:
            port = port_info['port'] if isinstance(port_info, dict) else port_info
            if port in [80, 443, 8080, 8443]:
                http_port = port
                break
        
        if not http_port:
            print("[INFO] No HTTP/HTTPS ports open. Skipping web technology detection.\n")
            return []
        
        # Try both HTTP and HTTPS
        protocols = ['https', 'http']
        success = False
        response = None
        
        for protocol in protocols:
            if http_port in [443, 8443]:
                url = f"https://{self.target}"
            else:
                url = f"{protocol}://{self.target}"
            
            if http_port not in [80, 443]:
                url += f":{http_port}"
            
            try:
                print(f"[INFO] Analyzing {url}...")
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
                response = requests.get(url, timeout=config.WEB_REQUEST_TIMEOUT, verify=False)
                success = True
                print(f"   [SUCCESS] Connected successfully\n")
                break
            except Exception as e:
                logger.debug(f"Failed to connect to {url}: {e}")
                continue
        
        if not success or not response:
            print("[ERROR] Could not connect to web server\n")
            return []
        
        content = response.text.lower()
        headers = response.headers
        
        technologies = []
        
        print(f"[DETECTED TECHNOLOGIES]\n")
        
        # Server
        if 'Server' in headers:
            tech = f"Web Server: {headers['Server']}"
            print(f"   {tech}")
            technologies.append(tech)
        
        # Backend
        if 'X-Powered-By' in headers:
            tech = f"Backend: {headers['X-Powered-By']}"
            print(f"   {tech}")
            technologies.append(tech)
        
        # CMS
        cms_detected = False
        if 'wp-content' in content or 'wp-includes' in content:
            version_match = re.search(r'wordpress/(\d+\.\d+\.\d+)', content)
            version = f" {version_match.group(1)}" if version_match else ""
            tech = f"CMS: WordPress{version}"
            print(f"   {tech}")
            technologies.append(tech)
            cms_detected = True
        
        if 'drupal' in content and not cms_detected:
            print(f"   CMS: Drupal")
            technologies.append("CMS: Drupal")
            cms_detected = True
        
        if 'joomla' in content and not cms_detected:
            print(f"   CMS: Joomla")
            technologies.append("CMS: Joomla")
        
        # JavaScript Frameworks
        js_frameworks = []
        if 'react' in content or '_react' in content:
            js_frameworks.append('React.js')
        if 'vue' in content or 'vue.js' in content:
            js_frameworks.append('Vue.js')
        if 'angular' in content or 'ng-' in content:
            js_frameworks.append('Angular')
        
        if js_frameworks:
            for fw in js_frameworks:
                tech = f"JS Framework: {fw}"
                print(f"   {tech}")
                technologies.append(tech)
        
        # JavaScript Libraries
        if 'jquery' in content:
            version_match = re.search(r'jquery[.-]?v?(\d+\.\d+\.\d+)', content)
            version = f" {version_match.group(1)}" if version_match else ""
            tech = f"Library: jQuery{version}"
            print(f"   {tech}")
            technologies.append(tech)
        
        # CSS Frameworks
        if 'bootstrap' in content:
            version_match = re.search(r'bootstrap[/-]?v?(\d+\.\d+\.\d+)', content)
            version = f" {version_match.group(1)}" if version_match else ""
            tech = f"CSS Framework: Bootstrap{version}"
            print(f"   {tech}")
            technologies.append(tech)
        
        # Security Headers
        security_headers = []
        if 'X-Frame-Options' in headers:
            security_headers.append(f"X-Frame-Options: {headers['X-Frame-Options']}")
        if 'Strict-Transport-Security' in headers:
            security_headers.append("HSTS Enabled")
        if 'Content-Security-Policy' in headers:
            security_headers.append("CSP Enabled")
        if 'X-XSS-Protection' in headers:
            security_headers.append("XSS Protection Enabled")
        if 'X-Content-Type-Options' in headers:
            security_headers.append("Content-Type Options Set")
        
        if security_headers:
            print(f"\nSecurity Headers:")
            for header in security_headers:
                print(f"   - {header}")
                technologies.append(f"Security: {header}")
        
        if not technologies:
            print("   [INFO] No technologies detected")
        
        print(f"\n{'='*60}\n")
        
        self.results['technologies'] = technologies
        logger.info(f"Technology detection completed. {len(technologies)} technologies found")
        
        return technologies
    
    def run_all(self, use_nmap=False):
        """Run all active reconnaissance modules"""
        logger.info(f"Starting full active reconnaissance for {self.target}")
        
        self.port_scan(use_nmap=use_nmap)
        self.banner_grab()
        self.detect_technologies()
        
        logger.info("Active reconnaissance completed")
        return self.results