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
#             print(f"[INFO] Resolved {self.target} -> {self.ip}")
            
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
#                 print(f"\n[WARNING] {self.target} has no A record (no direct IP address)")
#                 print(f"   Base domains often only have MX/NS records\n")
                
#                 www_target = f"www.{self.target}" if not self.target.startswith('www.') else self.target
                
#                 try:
#                     print(f"   [INFO] Checking www subdomain: {www_target}...")
#                     www_answers = resolver.resolve(www_target, 'A')
                    
#                     if www_answers:
#                         www_ip = str(www_answers[0])
#                         print(f"   [SUCCESS] Found! {www_target} -> {www_ip}")
#                         print(f"   [INFO] Automatically switching to {www_target} for active scanning\n")
                        
#                         self.target = www_target
#                         self.ip = www_ip
#                         self.results['ip_address'] = self.ip
#                         self.results['target_modified'] = True
#                         self.results['original_target'] = self.original_target
#                         logger.info(f"Auto-switched to {www_target} ({www_ip})")
#                         return
                        
#                 except dns.resolver.NoAnswer:
#                     logger.debug(f"No A record for {www_target} either")
                
#                 print(f"   [ERROR] {www_target} also has no A record")
#                 print(f"   [INFO] Active scanning requires a target with an IP address")
#                 print(f"   [TIP] Try: python main.py www.{self.target} --ports --tech\n")
                
#                 self.ip = None
#                 self.results['ip_address'] = None
#                 self.results['error'] = 'No IP address found for target'
                
#             except Exception as e:
#                 logger.error(f"DNS resolution failed: {e}")
#                 print(f"   [ERROR] Could not resolve domain: {e}\n")
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
#                 print(f"[WARNING] PORT SCANNING: Skipped")
#                 print(f"{'='*60}\n")
#                 print(f"Cannot perform port scan without a valid IP address.\n")
#             return []
        
#         logger.info(f"Starting port scan on {self.target}")
        
#         if self.formatter:
#             self.formatter.print_section_start(f"PERFORMING PORT SCAN FOR {self.target.upper()}")
#         else:
#             print(f"\n{'='*60}")
#             print(f"[PORT SCAN] {self.target} ({self.ip})")
#             if self.results.get('target_modified'):
#                 print(f"   (Auto-switched from {self.original_target})")
#             print(f"Started: {datetime.now().strftime('%H:%M:%S')}")
#             print(f"Scanning {len(ports)} ports...")
#             print(f"{'='*60}\n")
        
#         self._socket_scan(ports)
        
#         print(f"\n{'='*66}")
#         print(f"SCAN COMPLETE")
#         print(f"Open Ports: {len(self.results['open_ports'])}/{len(ports)}")
#         print(f"Finished: {datetime.now().strftime('%H:%M:%S')}")
#         print(f"{'='*66}\n")
        
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
#                     print(f"[OPEN] Port {port:5d} | {service}")
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
#                 print("\n\n[WARNING] Scan interrupted by user")
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
#             print(f"[BANNER GRABBING] Skipped")
#             print(f"{'='*60}\n")
#             print(f"[WARNING] Cannot grab banners without a valid IP address\n")
#             return {}
        
#         logger.info(f"Starting banner grabbing for {self.target}")
        
#         if self.formatter:
#             self.formatter.print_section_start(f"PERFORMING BANNER GRABBING FOR {self.target.upper()}")
#         else:
#             print(f"{'='*60}")
#             print(f"[BANNER GRABBING] {self.target}")
#             print(f"{'='*60}\n")
        
#         if not self.results['open_ports']:
#             print("[INFO] No open ports to grab banners from\n")
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
#                     except OSError:
#                         pass
                
#                 # Try to receive banner
#                 try:
#                     banner = sock.recv(config.BANNER_MAX_SIZE).decode('utf-8', errors='ignore').strip()
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
#             print("[INFO] No banners available from scanned ports")
#             print("   Note: Many modern services don't expose banners for security\n")
        
#         print(f"{'='*60}\n")
#         logger.info(f"Banner grabbing completed. {len(self.results['banners'])} banners found")
        
#         return self.results['banners']
    
#     def detect_technologies(self):
#         """Detect web technologies"""
#         if not self.ip:
#             logger.warning("No IP address available for technology detection")
#             print(f"{'='*60}")
#             print(f"[TECHNOLOGY DETECTION] Skipped")
#             print(f"{'='*60}\n")
#             print(f"[WARNING] Cannot detect technologies without a valid IP address\n")
#             return []
        
#         logger.info(f"Starting technology detection for {self.target}")
        
#         if self.formatter:
#             self.formatter.print_section_start(f"PERFORMING TECHNOLOGY DETECTION FOR {self.target.upper()}")
#         else:
#             print(f"{'='*60}")
#             print(f"[TECHNOLOGY DETECTION] {self.target}")
#             print(f"{'='*60}\n")
        
#         # Check if HTTP/HTTPS ports are open
#         http_port = None
#         for port_info in self.results['open_ports']:
#             port = port_info['port'] if isinstance(port_info, dict) else port_info
#             if port in [80, 443, 8080, 8443]:
#                 http_port = port
#                 break
        
#         if not http_port:
#             print("[INFO] No HTTP/HTTPS ports open. Skipping web technology detection.\n")
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
#                 print(f"[INFO] Analyzing {url}...")
#                 if not config.ENABLE_SSL_VERIFICATION:
#                     import urllib3
#                     urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#                 response = requests.get(
#                     url,
#                     timeout=config.WEB_REQUEST_TIMEOUT,
#                     verify=config.ENABLE_SSL_VERIFICATION,
#                 )
#                 success = True
#                 print(f"   [SUCCESS] Connected successfully\n")
#                 break
#             except Exception as e:
#                 logger.debug(f"Failed to connect to {url}: {e}")
#                 continue
        
#         if not success or not response:
#             print("[ERROR] Could not connect to web server\n")
#             return []
        
#         content = response.text.lower()
#         headers = response.headers
        
#         technologies = []
        
#         print(f"[DETECTED TECHNOLOGIES]\n")
        
#         # Server
#         if 'Server' in headers:
#             tech = f"Web Server: {headers['Server']}"
#             print(f"   {tech}")
#             technologies.append(tech)
        
#         # Backend
#         if 'X-Powered-By' in headers:
#             tech = f"Backend: {headers['X-Powered-By']}"
#             print(f"   {tech}")
#             technologies.append(tech)
        
#         # CMS
#         cms_detected = False
#         if 'wp-content' in content or 'wp-includes' in content:
#             version_match = re.search(r'wordpress/(\d+\.\d+\.\d+)', content)
#             version = f" {version_match.group(1)}" if version_match else ""
#             tech = f"CMS: WordPress{version}"
#             print(f"   {tech}")
#             technologies.append(tech)
#             cms_detected = True
        
#         if 'drupal' in content and not cms_detected:
#             print(f"   CMS: Drupal")
#             technologies.append("CMS: Drupal")
#             cms_detected = True
        
#         if 'joomla' in content and not cms_detected:
#             print(f"   CMS: Joomla")
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
#                 print(f"   {tech}")
#                 technologies.append(tech)
        
#         # JavaScript Libraries
#         if 'jquery' in content:
#             version_match = re.search(r'jquery[.-]?v?(\d+\.\d+\.\d+)', content)
#             version = f" {version_match.group(1)}" if version_match else ""
#             tech = f"Library: jQuery{version}"
#             print(f"   {tech}")
#             technologies.append(tech)
        
#         # CSS Frameworks
#         if 'bootstrap' in content:
#             version_match = re.search(r'bootstrap[/-]?v?(\d+\.\d+\.\d+)', content)
#             version = f" {version_match.group(1)}" if version_match else ""
#             tech = f"CSS Framework: Bootstrap{version}"
#             print(f"   {tech}")
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
#             print(f"\nSecurity Headers:")
#             for header in security_headers:
#                 print(f"   - {header}")
#                 technologies.append(f"Security: {header}")
        
#         if not technologies:
#             print("   [INFO] No technologies detected")
        
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


# """
# Active Reconnaissance Module - FULLY UPDATED VERSION
# Handles port scanning, banner grabbing, and technology detection

# IMPROVEMENTS:
# - Concurrent port scanning (10-20x faster)
# - Full Nmap integration support
# - Improved technology detection (fewer false positives)
# - Rate limiting / stealth mode
# - Multiple scan modes (quick/normal/full)
# - Service version detection
# - OS detection hints
# - Better error handling
# """

# import socket
# import requests
# import re
# import logging
# import dns.resolver
# from datetime import datetime
# from concurrent.futures import ThreadPoolExecutor, as_completed
# import time
# import random
# import json
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
#             'os_hints': [],
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
#             print(f"[INFO] Resolved {self.target} -> {self.ip}")
            
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
#                 print(f"\n[WARNING] {self.target} has no A record (no direct IP address)")
#                 print(f"   Base domains often only have MX/NS records\n")
                
#                 www_target = f"www.{self.target}" if not self.target.startswith('www.') else self.target
                
#                 try:
#                     print(f"   [INFO] Checking www subdomain: {www_target}...")
#                     www_answers = resolver.resolve(www_target, 'A')
                    
#                     if www_answers:
#                         www_ip = str(www_answers[0])
#                         print(f"   [SUCCESS] Found! {www_target} -> {www_ip}")
#                         print(f"   [INFO] Automatically switching to {www_target} for active scanning\n")
                        
#                         self.target = www_target
#                         self.ip = www_ip
#                         self.results['ip_address'] = self.ip
#                         self.results['target_modified'] = True
#                         self.results['original_target'] = self.original_target
#                         logger.info(f"Auto-switched to {www_target} ({www_ip})")
#                         return
                        
#                 except dns.resolver.NoAnswer:
#                     logger.debug(f"No A record for {www_target} either")
                
#                 print(f"   [ERROR] {www_target} also has no A record")
#                 print(f"   [INFO] Active scanning requires a target with an IP address")
#                 print(f"   [TIP] Try: python main.py www.{self.target} --ports --tech\n")
                
#                 self.ip = None
#                 self.results['ip_address'] = None
#                 self.results['error'] = 'No IP address found for target'
                
#             except Exception as e:
#                 logger.error(f"DNS resolution failed: {e}")
#                 print(f"   [ERROR] Could not resolve domain: {e}\n")
#                 self.ip = None
#                 self.results['ip_address'] = None
#                 self.results['error'] = str(e)
        
#         except Exception as e:
#             logger.warning(f"Could not resolve {self.target}: {e}")
#             self.ip = self.target  # Assume it's already an IP
#             self.results['ip_address'] = self.target
    
#     def port_scan(self, ports=None, use_nmap=False, scan_mode='normal', stealth=False):
#         """
#         Scan ports on the target
        
#         Args:
#             ports: Custom port list (overrides scan_mode)
#             use_nmap: Use Nmap for scanning (faster, more accurate, requires installation)
#             scan_mode: 'quick' (11 ports, ~2s), 'normal' (15 ports, ~3s), 'full' (1000 ports, ~30s)
#             stealth: Use slower, less detectable scanning (only for socket scan)
        
#         Returns:
#             List of open ports with details
#         """
#         if not self.ip:
#             logger.warning("No IP address available for port scanning")
#             if self.formatter:
#                 self.formatter.print_section_start("PORT SCAN SKIPPED")
#                 print("Cannot perform port scan without a valid IP address.\n")
#             else:
#                 print(f"{'='*60}")
#                 print(f"[WARNING] PORT SCANNING: Skipped")
#                 print(f"{'='*60}\n")
#                 print(f"Cannot perform port scan without a valid IP address.\n")
#             return []
        
#         # Determine port list based on scan mode
#         if ports is None:
#             if scan_mode == 'quick':
#                 ports = getattr(config, 'COMMON_PORTS_QUICK', [21, 22, 23, 25, 80, 110, 143, 443, 3389, 8080, 8443])
#             elif scan_mode == 'full':
#                 ports = getattr(config, 'COMMON_PORTS_FULL', list(range(1, 1001)))
#             else:
#                 ports = config.COMMON_PORTS
        
#         logger.info(f"Starting port scan on {self.target} (mode: {scan_mode}, nmap: {use_nmap})")
        
#         if self.formatter:
#             self.formatter.print_section_start(f"PERFORMING PORT SCAN FOR {self.target.upper()}")
#         else:
#             print(f"\n{'='*60}")
#             print(f"[PORT SCAN] {self.target} ({self.ip})")
#             if self.results.get('target_modified'):
#                 print(f"   (Auto-switched from {self.original_target})")
#             print(f"Mode: {scan_mode} | Ports: {len(ports)} | Method: {'Nmap' if use_nmap else 'Socket'}")
#             if stealth and not use_nmap:
#                 print(f"Stealth: Enabled (slower, less detectable)")
#             print(f"Started: {datetime.now().strftime('%H:%M:%S')}")
#             print(f"{'='*60}\n")
        
#         # Use Nmap if requested and available
#         if use_nmap:
#             success = self._nmap_scan(ports)
#             if not success:
#                 print(f"[WARNING] Nmap failed, falling back to socket scan\n")
#                 self._socket_scan_concurrent(ports, stealth=stealth)
#         else:
#             self._socket_scan_concurrent(ports, stealth=stealth)
        
#         print(f"\n{'='*66}")
#         print(f"SCAN COMPLETE")
#         print(f"Open Ports: {len(self.results['open_ports'])}/{len(ports)}")
#         print(f"Finished: {datetime.now().strftime('%H:%M:%S')}")
#         print(f"{'='*66}\n")
        
#         logger.info(f"Port scan completed. {len(self.results['open_ports'])} ports open")
        
#         return self.results['open_ports']
    
#     def _nmap_scan(self, ports):
#         """
#         Use Nmap for port scanning - faster and more accurate
        
#         Returns:
#             True if successful, False if Nmap not available
#         """
#         try:
#             import nmap
            
#             print(f"[INFO] Using Nmap for advanced scanning...")
#             print(f"   Benefits: Service detection, version info, OS fingerprinting\n")
            
#             nm = nmap.PortScanner()
            
#             # Convert port list to Nmap format
#             if len(ports) > 100:
#                 # For large port lists, use range notation
#                 port_arg = f"1-{max(ports)}"
#             else:
#                 # For specific ports, list them
#                 port_arg = ','.join(str(p) for p in sorted(ports))
            
#             # Nmap arguments:
#             # -sV: Service version detection
#             # -T4: Faster timing (aggressive)
#             # -Pn: Skip ping (assume host is up)
#             # --open: Only show open ports
#             print(f"[INFO] Running: nmap -sV -T4 -Pn --open {self.ip} -p {port_arg[:50]}...")
            
#             try:
#                 nm.scan(
#                     self.ip, 
#                     port_arg,
#                     arguments='-sV -T4 -Pn --open'
#                 )
#             except Exception as e:
#                 print(f"[ERROR] Nmap scan failed: {e}")
#                 return False
            
#             # Check if host was scanned
#             if self.ip not in nm.all_hosts():
#                 print(f"[ERROR] Nmap could not scan host {self.ip}")
#                 return False
            
#             # Extract results
#             scanned_host = nm[self.ip]
            
#             if 'tcp' not in scanned_host:
#                 print(f"[INFO] No TCP ports scanned or all ports closed")
#                 return True
            
#             tcp_ports = scanned_host['tcp']
            
#             for port in sorted(tcp_ports.keys()):
#                 port_info = tcp_ports[port]
                
#                 if port_info['state'] == 'open':
#                     service = port_info.get('name', 'unknown')
#                     version = port_info.get('version', '')
#                     product = port_info.get('product', '')
                    
#                     # Build service string
#                     service_str = service
#                     if product:
#                         service_str = f"{service} ({product}"
#                         if version:
#                             service_str += f" {version}"
#                         service_str += ")"
#                     elif version:
#                         service_str = f"{service} {version}"
                    
#                     print(f"[OPEN] Port {port:5d} | {service_str}")
                    
#                     self.results['open_ports'].append({
#                         'port': port,
#                         'state': 'open',
#                         'service': service,
#                         'product': product,
#                         'version': version,
#                         'method': 'nmap'
#                     })
            
#             # Try to get OS detection if available
#             if 'osmatch' in scanned_host and scanned_host['osmatch']:
#                 os_match = scanned_host['osmatch'][0]
#                 os_name = os_match.get('name', 'Unknown')
#                 accuracy = os_match.get('accuracy', '0')
                
#                 print(f"\n[OS DETECTION] {os_name} (accuracy: {accuracy}%)")
#                 self.results['os_hints'].append(f"Nmap: {os_name} ({accuracy}% accuracy)")
            
#             logger.info(f"Nmap scan completed successfully")
#             return True
            
#         except ImportError:
#             print(f"[WARNING] python-nmap library not installed")
#             print(f"   Install with: pip install python-nmap")
#             print(f"   Note: Also requires nmap binary (apt install nmap / brew install nmap)\n")
#             logger.warning("python-nmap not available, cannot use Nmap scanning")
#             return False
        
#         except Exception as e:
#             logger.error(f"Nmap scan error: {e}")
#             print(f"[ERROR] Nmap scan failed: {e}\n")
#             return False
    
#     def _socket_scan_concurrent(self, ports, stealth=False):
#         """
#         Concurrent socket-based port scanning - MUCH faster than sequential
        
#         Args:
#             ports: List of ports to scan
#             stealth: Use slower, randomized scanning to avoid detection
#         """
#         # Stealth mode adjustments
#         if stealth:
#             max_workers = 5  # Fewer concurrent connections
#             port_list = list(ports)
#             random.shuffle(port_list)  # Random order
#             base_delay = 0.5  # Longer delay
#             print(f"[INFO] Stealth mode: Randomized order, slow scanning\n")
#         else:
#             max_workers = 50  # Fast scanning with 50 concurrent threads
#             port_list = ports
#             base_delay = 0.05  # Minimal delay for politeness
        
#         def scan_port(port):
#             """Scan a single port"""
#             # Add small delay for rate limiting
#             if stealth:
#                 time.sleep(random.uniform(0.5, 2.0))
#             else:
#                 time.sleep(base_delay)
            
#             try:
#                 sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#                 sock.settimeout(1)  # 1 second timeout
                
#                 result = sock.connect_ex((self.ip, port))
#                 sock.close()
                
#                 if result == 0:
#                     service = self._get_service_name(port)
#                     return {'port': port, 'state': 'open', 'service': service, 'method': 'socket'}
                
#                 return None
                
#             except socket.error as e:
#                 logger.debug(f"Error scanning port {port}: {e}")
#                 return None
#             except Exception as e:
#                 logger.debug(f"Unexpected error on port {port}: {e}")
#                 return None
        
#         # Execute concurrent scans
#         with ThreadPoolExecutor(max_workers=max_workers) as executor:
#             future_to_port = {executor.submit(scan_port, port): port for port in port_list}
            
#             completed = 0
#             total = len(port_list)
            
#             for future in as_completed(future_to_port):
#                 completed += 1
                
#                 # Progress indicator every 10 ports or at completion
#                 if completed % 10 == 0 or completed == total:
#                     print(f"Progress: {completed}/{total} ports scanned...")
                
#                 result = future.result()
#                 if result:
#                     print(f"[OPEN] Port {result['port']:5d} | {result['service']}")
#                     self.results['open_ports'].append(result)
    
#     def _get_service_name(self, port):
#         """Get common service name for a port"""
#         services = {
#             20: 'FTP-Data',
#             21: 'FTP',
#             22: 'SSH',
#             23: 'Telnet',
#             25: 'SMTP',
#             53: 'DNS',
#             67: 'DHCP',
#             68: 'DHCP',
#             69: 'TFTP',
#             80: 'HTTP',
#             110: 'POP3',
#             119: 'NNTP',
#             123: 'NTP',
#             135: 'MSRPC',
#             139: 'NetBIOS',
#             143: 'IMAP',
#             161: 'SNMP',
#             162: 'SNMP-Trap',
#             389: 'LDAP',
#             443: 'HTTPS',
#             445: 'SMB',
#             465: 'SMTPS',
#             514: 'Syslog',
#             587: 'SMTP-Submission',
#             636: 'LDAPS',
#             993: 'IMAPS',
#             995: 'POP3S',
#             1433: 'MSSQL',
#             1521: 'Oracle',
#             3306: 'MySQL',
#             3389: 'RDP',
#             5432: 'PostgreSQL',
#             5900: 'VNC',
#             6379: 'Redis',
#             8080: 'HTTP-Proxy',
#             8443: 'HTTPS-Alt',
#             27017: 'MongoDB'
#         }
#         return services.get(port, 'unknown')
    
#     def banner_grab(self):
#         """Grab banners from open ports with version detection"""
#         if not self.ip:
#             logger.warning("No IP address available for banner grabbing")
#             print(f"{'='*60}")
#             print(f"[BANNER GRABBING] Skipped")
#             print(f"{'='*60}\n")
#             print(f"[WARNING] Cannot grab banners without a valid IP address\n")
#             return {}
        
#         logger.info(f"Starting banner grabbing for {self.target}")
        
#         if self.formatter:
#             self.formatter.print_section_start(f"PERFORMING BANNER GRABBING FOR {self.target.upper()}")
#         else:
#             print(f"{'='*60}")
#             print(f"[BANNER GRABBING] {self.target}")
#             print(f"{'='*60}\n")
        
#         if not self.results['open_ports']:
#             print("[INFO] No open ports to grab banners from\n")
#             return {}
        
#         for port_info in self.results['open_ports']:
#             port = port_info['port'] if isinstance(port_info, dict) else port_info
            
#             try:
#                 sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#                 sock.settimeout(3)  # 3 second timeout (was too long before)
#                 sock.connect((self.ip, port))
                
#                 # Send protocol-specific requests
#                 if port == 80 or port == 8080:
#                     sock.send(b"GET / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
#                 elif port == 443 or port == 8443:
#                     pass  # HTTPS needs SSL handshake, skip
#                 elif port in [25, 21, 22, 110, 143]:
#                     pass  # These services send banner automatically
#                 else:
#                     try:
#                         sock.send(b"\r\n")
#                     except OSError:
#                         pass
                
#                 # Try to receive banner
#                 try:
#                     banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
                    
#                     if banner:
#                         # Extract version info
#                         version_info = self._extract_version(port, banner)
                        
#                         display_banner = banner[:300] if len(banner) > 300 else banner
#                         print(f"Port {port} ({self._get_service_name(port)}):")
                        
#                         if version_info:
#                             print(f"   Version: {version_info}")
                        
#                         print(f"   {display_banner}")
                        
#                         if len(banner) > 300:
#                             print(f"   ... (truncated)")
#                         print()
                        
#                         self.results['banners'][port] = banner
                        
#                         # Update port info with version
#                         for p in self.results['open_ports']:
#                             if p.get('port') == port and version_info:
#                                 p['banner_version'] = version_info
                        
#                         logger.info(f"Banner grabbed from port {port}")
                        
#                 except socket.timeout:
#                     logger.debug(f"Timeout receiving banner from port {port}")
#                 except Exception as e:
#                     logger.debug(f"Error receiving banner from port {port}: {e}")
                
#                 sock.close()
                
#             except Exception as e:
#                 logger.debug(f"Could not grab banner from port {port}: {str(e)}")
        
#         if not self.results['banners']:
#             print("[INFO] No banners available from scanned ports")
#             print("   Note: Many modern services don't expose banners for security\n")
        
#         # Try to detect OS from banners
#         self._detect_os_from_banners()
        
#         print(f"{'='*60}\n")
#         logger.info(f"Banner grabbing completed. {len(self.results['banners'])} banners found")
        
#         return self.results['banners']
    
#     def _extract_version(self, port, banner):
#         """Extract service version from banner"""
        
#         # HTTP servers
#         if port in [80, 8080]:
#             server_match = re.search(r'Server:\s*([^\r\n]+)', banner, re.I)
#             if server_match:
#                 return server_match.group(1).strip()
        
#         # SSH
#         if port == 22:
#             ssh_match = re.search(r'SSH-([0-9.]+)-([^\r\n]+)', banner)
#             if ssh_match:
#                 return f"SSH {ssh_match.group(1)} - {ssh_match.group(2)}"
        
#         # FTP
#         if port == 21:
#             ftp_match = re.search(r'220[- ]([^\r\n]+)', banner)
#             if ftp_match:
#                 return ftp_match.group(1).strip()
        
#         # SMTP
#         if port == 25:
#             smtp_match = re.search(r'220[- ]([^\r\n]+)', banner)
#             if smtp_match:
#                 return smtp_match.group(1).strip()
        
#         # Generic version patterns
#         version_patterns = [
#             r'(\w+)/(\d+\.\d+(?:\.\d+)?)',  # Apache/2.4.41
#             r'(\w+)\s+v?(\d+\.\d+(?:\.\d+)?)',  # nginx v1.18.0
#         ]
        
#         for pattern in version_patterns:
#             match = re.search(pattern, banner)
#             if match:
#                 return f"{match.group(1)} {match.group(2)}"
        
#         return None
    
#     def _detect_os_from_banners(self):
#         """Detect OS hints from banners"""
#         os_hints = []
        
#         for port, banner in self.results['banners'].items():
#             banner_lower = banner.lower()
            
#             # Windows indicators
#             if 'windows' in banner_lower or 'microsoft' in banner_lower:
#                 if 'windows server 2019' in banner_lower:
#                     os_hints.append("Windows Server 2019")
#                 elif 'windows server 2016' in banner_lower:
#                     os_hints.append("Windows Server 2016")
#                 elif 'windows' in banner_lower:
#                     os_hints.append("Windows (version unknown)")
            
#             # Linux distributions
#             if 'ubuntu' in banner_lower:
#                 version = re.search(r'ubuntu[/ ](\d+\.\d+)', banner_lower)
#                 if version:
#                     os_hints.append(f"Ubuntu {version.group(1)}")
#                 else:
#                     os_hints.append("Ubuntu Linux")
            
#             if 'debian' in banner_lower:
#                 os_hints.append("Debian Linux")
            
#             if 'centos' in banner_lower:
#                 os_hints.append("CentOS Linux")
            
#             if 'red hat' in banner_lower or 'redhat' in banner_lower:
#                 os_hints.append("Red Hat Linux")
        
#         # Add hints based on open ports
#         open_port_numbers = [p['port'] for p in self.results['open_ports']]
        
#         if 3389 in open_port_numbers:
#             os_hints.append("Likely Windows (RDP port open)")
        
#         if 445 in open_port_numbers and 139 in open_port_numbers:
#             os_hints.append("Likely Windows (SMB ports open)")
        
#         # Deduplicate
#         unique_hints = list(set(os_hints))
        
#         if unique_hints:
#             print(f"\n[OS DETECTION FROM BANNERS]")
#             for hint in unique_hints:
#                 print(f"   - {hint}")
#                 self.results['os_hints'].append(hint)
#             print()
    
#     def detect_technologies(self):
#         """Detect web technologies with improved accuracy"""
#         if not self.ip:
#             logger.warning("No IP address available for technology detection")
#             print(f"{'='*60}")
#             print(f"[TECHNOLOGY DETECTION] Skipped")
#             print(f"{'='*60}\n")
#             print(f"[WARNING] Cannot detect technologies without a valid IP address\n")
#             return []
        
#         logger.info(f"Starting technology detection for {self.target}")
        
#         if self.formatter:
#             self.formatter.print_section_start(f"PERFORMING TECHNOLOGY DETECTION FOR {self.target.upper()}")
#         else:
#             print(f"{'='*60}")
#             print(f"[TECHNOLOGY DETECTION] {self.target}")
#             print(f"{'='*60}\n")
        
#         # Check if HTTP/HTTPS ports are open
#         http_port = None
#         for port_info in self.results['open_ports']:
#             port = port_info['port'] if isinstance(port_info, dict) else port_info
#             if port in [80, 443, 8080, 8443]:
#                 http_port = port
#                 break
        
#         if not http_port:
#             print("[INFO] No HTTP/HTTPS ports open. Skipping web technology detection.\n")
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
#                 print(f"[INFO] Analyzing {url}...")
#                 if not config.ENABLE_SSL_VERIFICATION:
#                     import urllib3
#                     urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
#                 response = requests.get(
#                     url,
#                     timeout=config.WEB_REQUEST_TIMEOUT,
#                     verify=config.ENABLE_SSL_VERIFICATION,
#                     headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
#                 )
#                 success = True
#                 print(f"   [SUCCESS] Connected successfully\n")
#                 break
#             except Exception as e:
#                 logger.debug(f"Failed to connect to {url}: {e}")
#                 continue
        
#         if not success or not response:
#             print("[ERROR] Could not connect to web server\n")
#             return []
        
#         content = response.text
#         content_lower = content.lower()
#         headers = response.headers
        
#         technologies = []
        
#         print(f"[DETECTED TECHNOLOGIES]\n")
        
#         # ===== 1. WEB SERVER (from headers) =====
#         if 'Server' in headers:
#             server = headers['Server']
#             tech = f"Web Server: {server}"
#             print(f"   {tech}")
#             technologies.append(tech)
            
#             # Detect CDN/Proxy from server header
#             if 'cloudflare' in server.lower():
#                 tech = "CDN: Cloudflare"
#                 print(f"   {tech}")
#                 technologies.append(tech)
#             elif 'nginx' in server.lower():
#                 # Check if it's a reverse proxy
#                 if 'X-Served-By' in headers or 'Via' in headers:
#                     technologies.append("Reverse Proxy: Nginx")
        
#         # ===== 2. BACKEND TECHNOLOGY =====
#         if 'X-Powered-By' in headers:
#             powered = headers['X-Powered-By']
#             tech = f"Backend: {powered}"
#             print(f"   {tech}")
#             technologies.append(tech)
            
#             # Extract PHP version
#             if 'PHP' in powered:
#                 php_version = re.search(r'PHP/(\d+\.\d+\.\d+)', powered)
#                 if php_version:
#                     technologies.append(f"PHP Version: {php_version.group(1)}")
        
#         # ===== 3. CMS DETECTION (improved) =====
#         cms_detected = False
        
#         # WordPress (check meta generator and common paths)
#         wp_version = re.search(r'<meta name=["\']generator["\'] content=["\']WordPress ([0-9.]+)["\']', content, re.I)
#         if wp_version:
#             tech = f"CMS: WordPress {wp_version.group(1)}"
#             print(f"   {tech}")
#             technologies.append(tech)
#             cms_detected = True
#         elif 'wp-content' in content_lower or 'wp-includes' in content_lower:
#             # Look for version in scripts/styles
#             wp_ver = re.search(r'wp-(?:content|includes)/[^"\']*\?ver=([0-9.]+)', content_lower)
#             if wp_ver:
#                 tech = f"CMS: WordPress {wp_ver.group(1)}"
#             else:
#                 tech = "CMS: WordPress (version unknown)"
#             print(f"   {tech}")
#             technologies.append(tech)
#             cms_detected = True
        
#         # Drupal
#         if not cms_detected and ('drupal' in content_lower or 'sites/all/themes' in content_lower):
#             drupal_version = re.search(r'drupal["\']?\s*:\s*["\']([0-9.]+)["\']', content_lower)
#             if drupal_version:
#                 tech = f"CMS: Drupal {drupal_version.group(1)}"
#             else:
#                 tech = "CMS: Drupal"
#             print(f"   {tech}")
#             technologies.append(tech)
#             cms_detected = True
        
#         # Joomla
#         if not cms_detected and ('joomla' in content_lower or '/media/system/js/core.js' in content_lower):
#             tech = "CMS: Joomla"
#             print(f"   {tech}")
#             technologies.append(tech)
#             cms_detected = True
        
#         # ===== 4. JAVASCRIPT FRAMEWORKS (improved detection) =====
        
#         # React (check for actual React files, not just the word "react")
#         react_patterns = [
#             r'react[.-]?(?:dom)?[.-]?(?:production|development)?\.(?:min\.)?js',
#             r'/_next/static/',  # Next.js
#             r'/__NEXT_DATA__',
#         ]
        
#         if any(re.search(pattern, content_lower) for pattern in react_patterns):
#             # Look for React version
#             react_version = re.search(r'react["\']?\s*:\s*["\']([0-9.]+)["\']', content_lower)
#             if react_version:
#                 tech = f"JS Framework: React {react_version.group(1)}"
#             else:
#                 tech = "JS Framework: React"
#             print(f"   {tech}")
#             technologies.append(tech)
            
#             # Check for Next.js specifically
#             if '__NEXT_DATA__' in content or '_next/static' in content_lower:
#                 tech = "Framework: Next.js (React)"
#                 print(f"   {tech}")
#                 technologies.append(tech)
        
#         # Vue.js (improved)
#         vue_patterns = [
#             r'vue[.-]?(?:runtime)?[.-]?(?:prod|dev)?\.(?:min\.)?js',
#             r'data-v-[a-f0-9]{8}',  # Vue scoped CSS
#         ]
        
#         if any(re.search(pattern, content_lower) for pattern in vue_patterns):
#             vue_version = re.search(r'vue["\']?\s*:\s*["\']([0-9.]+)["\']', content_lower)
#             if vue_version:
#                 tech = f"JS Framework: Vue.js {vue_version.group(1)}"
#             else:
#                 tech = "JS Framework: Vue.js"
#             print(f"   {tech}")
#             technologies.append(tech)
            
#             # Check for Nuxt.js
#             if '__NUXT__' in content or '_nuxt/' in content_lower:
#                 tech = "Framework: Nuxt.js (Vue)"
#                 print(f"   {tech}")
#                 technologies.append(tech)
        
#         # Angular (improved - check for actual Angular, not just "angular" word)
#         if 'ng-version' in content_lower:
#             ng_version = re.search(r'ng-version=["\']([0-9.]+)["\']', content_lower)
#             if ng_version:
#                 tech = f"JS Framework: Angular {ng_version.group(1)}"
#             else:
#                 tech = "JS Framework: Angular"
#             print(f"   {tech}")
#             technologies.append(tech)
#         elif re.search(r'@angular/(?:core|common|platform)', content_lower):
#             tech = "JS Framework: Angular"
#             print(f"   {tech}")
#             technologies.append(tech)
        
#         # ===== 5. JAVASCRIPT LIBRARIES =====
        
#         # jQuery
#         if 'jquery' in content_lower:
#             jquery_version = re.search(r'jquery[.-]?v?([0-9.]+)(?:\.min)?\.js', content_lower)
#             if jquery_version:
#                 tech = f"Library: jQuery {jquery_version.group(1)}"
#             else:
#                 tech = "Library: jQuery"
#             print(f"   {tech}")
#             technologies.append(tech)
        
#         # ===== 6. CSS FRAMEWORKS =====
        
#         # Bootstrap
#         if 'bootstrap' in content_lower:
#             bootstrap_version = re.search(r'bootstrap[/-]?v?([0-9.]+)', content_lower)
#             if bootstrap_version:
#                 tech = f"CSS Framework: Bootstrap {bootstrap_version.group(1)}"
#             else:
#                 tech = "CSS Framework: Bootstrap"
#             print(f"   {tech}")
#             technologies.append(tech)
        
#         # Tailwind CSS
#         if 'tailwind' in content_lower or re.search(r'class=["\'][^"\']*\b(?:flex|grid|p-\d|m-\d|text-\w+)', content):
#             tech = "CSS Framework: Tailwind CSS"
#             print(f"   {tech}")
#             technologies.append(tech)
        
#         # ===== 7. CDN DETECTION =====
        
#         # Cloudflare (additional checks)
#         if 'CF-RAY' in headers or 'cf-ray' in str(headers).lower():
#             if "CDN: Cloudflare" not in technologies:
#                 tech = "CDN: Cloudflare"
#                 print(f"   {tech}")
#                 technologies.append(tech)
        
#         # AWS CloudFront
#         if 'cloudfront.net' in content_lower or 'X-Amz-Cf-Id' in headers:
#             tech = "CDN: AWS CloudFront"
#             print(f"   {tech}")
#             technologies.append(tech)
        
#         # Akamai
#         if 'akamai' in content_lower or 'X-Akamai' in str(headers):
#             tech = "CDN: Akamai"
#             print(f"   {tech}")
#             technologies.append(tech)
        
#         # ===== 8. ANALYTICS & TRACKING =====
        
#         # Google Analytics
#         if 'google-analytics.com' in content_lower or 'gtag' in content_lower:
#             tech = "Analytics: Google Analytics"
#             print(f"   {tech}")
#             technologies.append(tech)
        
#         # Google Tag Manager
#         if 'googletagmanager.com' in content_lower:
#             tech = "Tag Manager: Google Tag Manager"
#             print(f"   {tech}")
#             technologies.append(tech)
        
#         # ===== 9. SECURITY TECHNOLOGIES =====
        
#         # reCAPTCHA
#         if 'recaptcha' in content_lower or 'google.com/recaptcha' in content_lower:
#             tech = "Security: Google reCAPTCHA"
#             print(f"   {tech}")
#             technologies.append(tech)
        
#         # ===== 10. SECURITY HEADERS =====
        
#         security_headers = []
        
#         if 'X-Frame-Options' in headers:
#             value = headers['X-Frame-Options']
#             security_headers.append(f"X-Frame-Options: {value}")
        
#         if 'Strict-Transport-Security' in headers:
#             security_headers.append("HSTS Enabled")
        
#         if 'Content-Security-Policy' in headers:
#             security_headers.append("CSP Enabled")
        
#         if 'X-XSS-Protection' in headers:
#             security_headers.append("XSS Protection Enabled")
        
#         if 'X-Content-Type-Options' in headers:
#             value = headers['X-Content-Type-Options']
#             security_headers.append(f"Content-Type Options: {value}")
        
#         if 'Permissions-Policy' in headers or 'Feature-Policy' in headers:
#             security_headers.append("Permissions Policy Set")
        
#         if security_headers:
#             print(f"\nSecurity Headers:")
#             for header in security_headers:
#                 print(f"   - {header}")
#                 technologies.append(f"Security: {header}")
        
#         if not technologies:
#             print("   [INFO] No technologies detected")
        
#         print(f"\n{'='*60}\n")
        
#         self.results['technologies'] = technologies
#         logger.info(f"Technology detection completed. {len(technologies)} technologies found")
        
#         return technologies
    
#     def export_results_json(self, filename=None):
#         """Export scan results to JSON file"""
#         if not filename:
#             timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
#             filename = f"active_scan_{self.target.replace('.', '_')}_{timestamp}.json"
        
#         try:
#             with open(filename, 'w') as f:
#                 json.dump(self.results, f, indent=2, default=str)
            
#             print(f"[✓] Results exported to {filename}")
#             logger.info(f"Results exported to {filename}")
#             return filename
        
#         except Exception as e:
#             logger.error(f"Failed to export results: {e}")
#             print(f"[ERROR] Export failed: {e}")
#             return None
    
#     def run_all(self, use_nmap=False, scan_mode='normal', stealth=False):
#         """
#         Run all active reconnaissance modules
        
#         Args:
#             use_nmap: Use Nmap for port scanning
#             scan_mode: 'quick', 'normal', or 'full'
#             stealth: Use stealth scanning mode
#         """
#         logger.info(f"Starting full active reconnaissance for {self.target}")
        
#         self.port_scan(use_nmap=use_nmap, scan_mode=scan_mode, stealth=stealth)
#         self.banner_grab()
#         self.detect_technologies()
        
#         logger.info("Active reconnaissance completed")
#         return self.results


"""
Active Reconnaissance Module - COMPLETE UPDATED VERSION
Handles port scanning, banner grabbing, and technology detection

MAJOR IMPROVEMENTS:
- Concurrent port scanning (10-20x faster)
- Full Nmap integration support
- Technology detection works WITHOUT port scanning (auto HTTP probe)
- Detection modes: strict/balanced/loose for different accuracy levels
- Rate limiting / stealth mode
- Multiple scan modes (quick/normal/full)
- Service version detection
- OS detection hints
- Better error handling
- Improved technology detection (fewer false positives)
"""

import socket
import requests
import re
import logging
import dns.resolver
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random
import json
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
            'os_hints': [],
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
    
    def port_scan(self, ports=None, use_nmap=False, scan_mode='normal', stealth=False):
        """
        Scan ports on the target
        
        Args:
            ports: Custom port list (overrides scan_mode)
            use_nmap: Use Nmap for scanning (faster, more accurate, requires installation)
            scan_mode: 'quick' (11 ports, ~2s), 'normal' (15 ports, ~3s), 'full' (1000 ports, ~30s)
            stealth: Use slower, less detectable scanning (only for socket scan)
        
        Returns:
            List of open ports with details
        """
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
        
        # Determine port list based on scan mode
        if ports is None:
            if scan_mode == 'quick':
                ports = getattr(config, 'COMMON_PORTS_QUICK', [21, 22, 23, 25, 80, 110, 143, 443, 3389, 8080, 8443])
            elif scan_mode == 'full':
                ports = getattr(config, 'COMMON_PORTS_FULL', list(range(1, 1001)))
            else:
                ports = config.COMMON_PORTS
        
        logger.info(f"Starting port scan on {self.target} (mode: {scan_mode}, nmap: {use_nmap})")
        
        if self.formatter:
            self.formatter.print_section_start(f"PERFORMING PORT SCAN FOR {self.target.upper()}")
        else:
            print(f"\n{'='*60}")
            print(f"[PORT SCAN] {self.target} ({self.ip})")
            if self.results.get('target_modified'):
                print(f"   (Auto-switched from {self.original_target})")
            print(f"Mode: {scan_mode} | Ports: {len(ports)} | Method: {'Nmap' if use_nmap else 'Socket'}")
            if stealth and not use_nmap:
                print(f"Stealth: Enabled (slower, less detectable)")
            print(f"Started: {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'='*60}\n")
        
        # Use Nmap if requested and available
        if use_nmap:
            success = self._nmap_scan(ports)
            if not success:
                print(f"[WARNING] Nmap failed, falling back to socket scan\n")
                self._socket_scan_concurrent(ports, stealth=stealth)
        else:
            self._socket_scan_concurrent(ports, stealth=stealth)
        
        print(f"\n{'='*66}")
        print(f"SCAN COMPLETE")
        print(f"Open Ports: {len(self.results['open_ports'])}/{len(ports)}")
        print(f"Finished: {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*66}\n")
        
        logger.info(f"Port scan completed. {len(self.results['open_ports'])} ports open")
        
        return self.results['open_ports']
    
    def _nmap_scan(self, ports):
        """
        Use Nmap for port scanning - faster and more accurate
        
        Returns:
            True if successful, False if Nmap not available
        """
        try:
            import nmap
            
            print(f"[INFO] Using Nmap for advanced scanning...")
            print(f"   Benefits: Service detection, version info, OS fingerprinting\n")
            
            nm = nmap.PortScanner()
            
            # Convert port list to Nmap format
            if len(ports) > 100:
                # For large port lists, use range notation
                port_arg = f"1-{max(ports)}"
            else:
                # For specific ports, list them
                port_arg = ','.join(str(p) for p in sorted(ports))
            
            # Nmap arguments:
            # -sV: Service version detection
            # -T4: Faster timing (aggressive)
            # -Pn: Skip ping (assume host is up)
            # --open: Only show open ports
            print(f"[INFO] Running: nmap -sV -T4 -Pn --open {self.ip} -p {port_arg[:50]}...")
            
            try:
                nm.scan(
                    self.ip, 
                    port_arg,
                    arguments='-sV -T4 -Pn --open'
                )
            except Exception as e:
                print(f"[ERROR] Nmap scan failed: {e}")
                return False
            
            # Check if host was scanned
            if self.ip not in nm.all_hosts():
                print(f"[ERROR] Nmap could not scan host {self.ip}")
                return False
            
            # Extract results
            scanned_host = nm[self.ip]
            
            if 'tcp' not in scanned_host:
                print(f"[INFO] No TCP ports scanned or all ports closed")
                return True
            
            tcp_ports = scanned_host['tcp']
            
            for port in sorted(tcp_ports.keys()):
                port_info = tcp_ports[port]
                
                if port_info['state'] == 'open':
                    service = port_info.get('name', 'unknown')
                    version = port_info.get('version', '')
                    product = port_info.get('product', '')
                    
                    # Build service string
                    service_str = service
                    if product:
                        service_str = f"{service} ({product}"
                        if version:
                            service_str += f" {version}"
                        service_str += ")"
                    elif version:
                        service_str = f"{service} {version}"
                    
                    print(f"[OPEN] Port {port:5d} | {service_str}")
                    
                    self.results['open_ports'].append({
                        'port': port,
                        'state': 'open',
                        'service': service,
                        'product': product,
                        'version': version,
                        'method': 'nmap'
                    })
            
            # Try to get OS detection if available
            if 'osmatch' in scanned_host and scanned_host['osmatch']:
                os_match = scanned_host['osmatch'][0]
                os_name = os_match.get('name', 'Unknown')
                accuracy = os_match.get('accuracy', '0')
                
                print(f"\n[OS DETECTION] {os_name} (accuracy: {accuracy}%)")
                self.results['os_hints'].append(f"Nmap: {os_name} ({accuracy}% accuracy)")
            
            logger.info(f"Nmap scan completed successfully")
            return True
            
        except ImportError:
            print(f"[WARNING] python-nmap library not installed")
            print(f"   Install with: pip install python-nmap")
            print(f"   Note: Also requires nmap binary (apt install nmap / brew install nmap)\n")
            logger.warning("python-nmap not available, cannot use Nmap scanning")
            return False
        
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            print(f"[ERROR] Nmap scan failed: {e}\n")
            return False
    
    def _socket_scan_concurrent(self, ports, stealth=False):
        """
        Concurrent socket-based port scanning - MUCH faster than sequential
        
        Args:
            ports: List of ports to scan
            stealth: Use slower, randomized scanning to avoid detection
        """
        # Stealth mode adjustments
        if stealth:
            max_workers = 5  # Fewer concurrent connections
            port_list = list(ports)
            random.shuffle(port_list)  # Random order
            base_delay = 0.5  # Longer delay
            print(f"[INFO] Stealth mode: Randomized order, slow scanning\n")
        else:
            max_workers = 50  # Fast scanning with 50 concurrent threads
            port_list = ports
            base_delay = 0.05  # Minimal delay for politeness
        
        def scan_port(port):
            """Scan a single port"""
            # Add small delay for rate limiting
            if stealth:
                time.sleep(random.uniform(0.5, 2.0))
            else:
                time.sleep(base_delay)
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # 1 second timeout
                
                result = sock.connect_ex((self.ip, port))
                sock.close()
                
                if result == 0:
                    service = self._get_service_name(port)
                    return {'port': port, 'state': 'open', 'service': service, 'method': 'socket'}
                
                return None
                
            except socket.error as e:
                logger.debug(f"Error scanning port {port}: {e}")
                return None
            except Exception as e:
                logger.debug(f"Unexpected error on port {port}: {e}")
                return None
        
        # Execute concurrent scans
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {executor.submit(scan_port, port): port for port in port_list}
            
            completed = 0
            total = len(port_list)
            
            for future in as_completed(future_to_port):
                completed += 1
                
                # Progress indicator every 10 ports or at completion
                if completed % 10 == 0 or completed == total:
                    print(f"Progress: {completed}/{total} ports scanned...")
                
                result = future.result()
                if result:
                    print(f"[OPEN] Port {result['port']:5d} | {result['service']}")
                    self.results['open_ports'].append(result)
    
    def _get_service_name(self, port):
        """Get common service name for a port"""
        services = {
            20: 'FTP-Data',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP',
            68: 'DHCP',
            69: 'TFTP',
            80: 'HTTP',
            110: 'POP3',
            119: 'NNTP',
            123: 'NTP',
            135: 'MSRPC',
            139: 'NetBIOS',
            143: 'IMAP',
            161: 'SNMP',
            162: 'SNMP-Trap',
            389: 'LDAP',
            443: 'HTTPS',
            445: 'SMB',
            465: 'SMTPS',
            514: 'Syslog',
            587: 'SMTP-Submission',
            636: 'LDAPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1521: 'Oracle',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        return services.get(port, 'unknown')
    
    def banner_grab(self):
        """Grab banners from open ports with version detection"""
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
                sock.settimeout(3)  # 3 second timeout
                sock.connect((self.ip, port))
                
                # Send protocol-specific requests
                if port == 80 or port == 8080:
                    sock.send(b"GET / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
                elif port == 443 or port == 8443:
                    pass  # HTTPS needs SSL handshake, skip
                elif port in [25, 21, 22, 110, 143]:
                    pass  # These services send banner automatically
                else:
                    try:
                        sock.send(b"\r\n")
                    except OSError:
                        pass
                
                # Try to receive banner
                try:
                    banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
                    
                    if banner:
                        # Extract version info
                        version_info = self._extract_version(port, banner)
                        
                        display_banner = banner[:300] if len(banner) > 300 else banner
                        print(f"Port {port} ({self._get_service_name(port)}):")
                        
                        if version_info:
                            print(f"   Version: {version_info}")
                        
                        print(f"   {display_banner}")
                        
                        if len(banner) > 300:
                            print(f"   ... (truncated)")
                        print()
                        
                        self.results['banners'][port] = banner
                        
                        # Update port info with version
                        for p in self.results['open_ports']:
                            if p.get('port') == port and version_info:
                                p['banner_version'] = version_info
                        
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
        
        # Try to detect OS from banners
        self._detect_os_from_banners()
        
        print(f"{'='*60}\n")
        logger.info(f"Banner grabbing completed. {len(self.results['banners'])} banners found")
        
        return self.results['banners']
    
    def _extract_version(self, port, banner):
        """Extract service version from banner"""
        
        # HTTP servers
        if port in [80, 8080]:
            server_match = re.search(r'Server:\s*([^\r\n]+)', banner, re.I)
            if server_match:
                return server_match.group(1).strip()
        
        # SSH
        if port == 22:
            ssh_match = re.search(r'SSH-([0-9.]+)-([^\r\n]+)', banner)
            if ssh_match:
                return f"SSH {ssh_match.group(1)} - {ssh_match.group(2)}"
        
        # FTP
        if port == 21:
            ftp_match = re.search(r'220[- ]([^\r\n]+)', banner)
            if ftp_match:
                return ftp_match.group(1).strip()
        
        # SMTP
        if port == 25:
            smtp_match = re.search(r'220[- ]([^\r\n]+)', banner)
            if smtp_match:
                return smtp_match.group(1).strip()
        
        # Generic version patterns
        version_patterns = [
            r'(\w+)/(\d+\.\d+(?:\.\d+)?)',  # Apache/2.4.41
            r'(\w+)\s+v?(\d+\.\d+(?:\.\d+)?)',  # nginx v1.18.0
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner)
            if match:
                return f"{match.group(1)} {match.group(2)}"
        
        return None
    
    def _detect_os_from_banners(self):
        """Detect OS hints from banners"""
        os_hints = []
        
        for port, banner in self.results['banners'].items():
            banner_lower = banner.lower()
            
            # Windows indicators
            if 'windows' in banner_lower or 'microsoft' in banner_lower:
                if 'windows server 2019' in banner_lower:
                    os_hints.append("Windows Server 2019")
                elif 'windows server 2016' in banner_lower:
                    os_hints.append("Windows Server 2016")
                elif 'windows' in banner_lower:
                    os_hints.append("Windows (version unknown)")
            
            # Linux distributions
            if 'ubuntu' in banner_lower:
                version = re.search(r'ubuntu[/ ](\d+\.\d+)', banner_lower)
                if version:
                    os_hints.append(f"Ubuntu {version.group(1)}")
                else:
                    os_hints.append("Ubuntu Linux")
            
            if 'debian' in banner_lower:
                os_hints.append("Debian Linux")
            
            if 'centos' in banner_lower:
                os_hints.append("CentOS Linux")
            
            if 'red hat' in banner_lower or 'redhat' in banner_lower:
                os_hints.append("Red Hat Linux")
        
        # Add hints based on open ports
        open_port_numbers = [p['port'] for p in self.results['open_ports']]
        
        if 3389 in open_port_numbers:
            os_hints.append("Likely Windows (RDP port open)")
        
        if 445 in open_port_numbers and 139 in open_port_numbers:
            os_hints.append("Likely Windows (SMB ports open)")
        
        # Deduplicate
        unique_hints = list(set(os_hints))
        
        if unique_hints:
            print(f"\n[OS DETECTION FROM BANNERS]")
            for hint in unique_hints:
                print(f"   - {hint}")
                self.results['os_hints'].append(hint)
            print()
    
    def detect_technologies(self, detection_mode='balanced'):
        """
        Detect web technologies with improved accuracy
        
        Args:
            detection_mode: 'strict' (fewer false positives), 'balanced' (default), 'loose' (more detections)
        
        Returns:
            List of detected technologies
        """
        if not self.ip:
            logger.warning("No IP address available for technology detection")
            print(f"{'='*60}")
            print(f"[TECHNOLOGY DETECTION] Skipped")
            print(f"{'='*60}\n")
            print(f"[WARNING] Cannot detect technologies without a valid IP address\n")
            return []
        
        logger.info(f"Starting technology detection for {self.target} (mode: {detection_mode})")
        
        if self.formatter:
            self.formatter.print_section_start(f"PERFORMING TECHNOLOGY DETECTION FOR {self.target.upper()}")
        else:
            print(f"{'='*60}")
            print(f"[TECHNOLOGY DETECTION] {self.target}")
            print(f"Detection Mode: {detection_mode}")
            print(f"{'='*60}\n")
        
        # Check if HTTP/HTTPS ports are open from scan results
        http_port = None
        if self.results['open_ports']:
            for port_info in self.results['open_ports']:
                port = port_info['port'] if isinstance(port_info, dict) else port_info
                if port in [80, 443, 8080, 8443]:
                    http_port = port
                    print(f"[INFO] Using scanned port: {http_port}")
                    break
        
        # If no scan results, probe common HTTP ports
        if not http_port:
            print("[INFO] No port scan results. Probing common HTTP ports...")
            for test_port in [443, 80, 8080, 8443]:
                test_url = f"{'https' if test_port in [443, 8443] else 'http'}://{self.target}"
                if test_port not in [80, 443]:
                    test_url += f":{test_port}"
                
                try:
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                    
                    response = requests.head(
                        test_url, 
                        timeout=3, 
                        verify=False,
                        allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                    )
                    if response.status_code < 500:
                        http_port = test_port
                        print(f"   [✓] Found HTTP service on port {test_port}\n")
                        break
                except Exception as e:
                    logger.debug(f"Port {test_port} probe failed: {e}")
                    continue
            
            if not http_port:
                print("[INFO] No HTTP/HTTPS services responding. Skipping.\n")
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
                if not config.ENABLE_SSL_VERIFICATION:
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                
                response = requests.get(
                    url,
                    timeout=config.WEB_REQUEST_TIMEOUT,
                    verify=config.ENABLE_SSL_VERIFICATION,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                success = True
                print(f"   [SUCCESS] Connected successfully\n")
                break
            except Exception as e:
                logger.debug(f"Failed to connect to {url}: {e}")
                continue
        
        if not success or not response:
            print("[ERROR] Could not connect to web server\n")
            return []
        
        content = response.text
        content_lower = content.lower()
        headers = response.headers
        
        technologies = []
        
        print(f"[DETECTED TECHNOLOGIES] (Mode: {detection_mode})\n")
        
        # ===== 1. WEB SERVER (from headers) =====
        if 'Server' in headers:
            server = headers['Server']
            tech = f"Web Server: {server}"
            print(f"   {tech}")
            technologies.append(tech)
            
            # Detect CDN/Proxy from server header
            if 'cloudflare' in server.lower():
                tech = "CDN: Cloudflare"
                print(f"   {tech}")
                technologies.append(tech)
            elif 'nginx' in server.lower():
                # Check if it's a reverse proxy
                if 'X-Served-By' in headers or 'Via' in headers:
                    technologies.append("Reverse Proxy: Nginx")
        
        # ===== 2. BACKEND TECHNOLOGY =====
        if 'X-Powered-By' in headers:
            powered = headers['X-Powered-By']
            tech = f"Backend: {powered}"
            print(f"   {tech}")
            technologies.append(tech)
            
            # Extract PHP version
            if 'PHP' in powered:
                php_version = re.search(r'PHP/(\d+\.\d+\.\d+)', powered)
                if php_version:
                    technologies.append(f"PHP Version: {php_version.group(1)}")
        
        # ===== 3. CMS DETECTION (mode-aware) =====
        cms_detected = False
        
        # WordPress
        wp_version = re.search(r'<meta name=["\']generator["\'] content=["\']WordPress ([0-9.]+)["\']', content, re.I)
        if wp_version:
            tech = f"CMS: WordPress {wp_version.group(1)}"
            print(f"   {tech}")
            technologies.append(tech)
            cms_detected = True
        elif 'wp-content' in content_lower or 'wp-includes' in content_lower:
            # Look for version in scripts/styles
            wp_ver = re.search(r'wp-(?:content|includes)/[^"\']*\?ver=([0-9.]+)', content_lower)
            if wp_ver:
                tech = f"CMS: WordPress {wp_ver.group(1)}"
            else:
                tech = "CMS: WordPress (version unknown)"
            print(f"   {tech}")
            technologies.append(tech)
            cms_detected = True
        elif detection_mode == 'loose' and ('wordpress' in content_lower or '/wp-json/' in content_lower):
            tech = "CMS: WordPress (detected from keywords)"
            print(f"   {tech}")
            technologies.append(tech)
            cms_detected = True
        
        # Drupal
        if not cms_detected and ('drupal' in content_lower or 'sites/all/themes' in content_lower):
            drupal_version = re.search(r'drupal["\']?\s*:\s*["\']([0-9.]+)["\']', content_lower)
            if drupal_version:
                tech = f"CMS: Drupal {drupal_version.group(1)}"
            else:
                tech = "CMS: Drupal"
            print(f"   {tech}")
            technologies.append(tech)
            cms_detected = True
        
        # Joomla
        if not cms_detected and ('joomla' in content_lower or '/media/system/js/core.js' in content_lower):
            tech = "CMS: Joomla"
            print(f"   {tech}")
            technologies.append(tech)
            cms_detected = True
        
        # ===== 4. JAVASCRIPT FRAMEWORKS (mode-aware) =====
        
        # React detection
        if detection_mode == 'strict':
            react_patterns = [
                r'react[.-]?(?:dom)?[.-]?(?:production|development)?\.(?:min\.)?js',
                r'/_next/static/',
                r'/__NEXT_DATA__',
            ]
            if any(re.search(pattern, content_lower) for pattern in react_patterns):
                react_version = re.search(r'react["\']?\s*:\s*["\']([0-9.]+)["\']', content_lower)
                if react_version:
                    tech = f"JS Framework: React {react_version.group(1)}"
                else:
                    tech = "JS Framework: React"
                print(f"   {tech}")
                technologies.append(tech)
                
                # Check for Next.js
                if '__NEXT_DATA__' in content or '_next/static' in content_lower:
                    tech = "Framework: Next.js (React)"
                    print(f"   {tech}")
                    technologies.append(tech)
        
        elif detection_mode == 'loose':
            if 'react' in content_lower or '_react' in content_lower:
                tech = "JS Framework: React (keyword match)"
                print(f"   {tech}")
                technologies.append(tech)
                
                if '__NEXT_DATA__' in content or '_next/static' in content_lower:
                    tech = "Framework: Next.js (React)"
                    print(f"   {tech}")
                    technologies.append(tech)
        
        else:  # balanced
            react_patterns = [
                r'react[.-]?(?:dom)?[.-]?(?:production|development)?\.(?:min\.)?js',
                r'/_next/static/',
                r'/__NEXT_DATA__',
                r'from\s+["\']react["\']',  # import from 'react'
                r'@react',
            ]
            if any(re.search(pattern, content_lower) for pattern in react_patterns):
                react_version = re.search(r'react["\']?\s*:\s*["\']([0-9.]+)["\']', content_lower)
                if react_version:
                    tech = f"JS Framework: React {react_version.group(1)}"
                else:
                    tech = "JS Framework: React"
                print(f"   {tech}")
                technologies.append(tech)
                
                if '__NEXT_DATA__' in content or '_next/static' in content_lower:
                    tech = "Framework: Next.js (React)"
                    print(f"   {tech}")
                    technologies.append(tech)
        
        # Vue.js detection
        if detection_mode == 'strict':
            vue_patterns = [
                r'vue[.-]?(?:runtime)?[.-]?(?:prod|dev)?\.(?:min\.)?js',
                r'data-v-[a-f0-9]{8}',
            ]
            if any(re.search(pattern, content_lower) for pattern in vue_patterns):
                vue_version = re.search(r'vue["\']?\s*:\s*["\']([0-9.]+)["\']', content_lower)
                if vue_version:
                    tech = f"JS Framework: Vue.js {vue_version.group(1)}"
                else:
                    tech = "JS Framework: Vue.js"
                print(f"   {tech}")
                technologies.append(tech)
                
                if '__NUXT__' in content or '_nuxt/' in content_lower:
                    tech = "Framework: Nuxt.js (Vue)"
                    print(f"   {tech}")
                    technologies.append(tech)
        
        elif detection_mode == 'loose':
            if 'vue' in content_lower or 'vue.js' in content_lower:
                tech = "JS Framework: Vue.js (keyword match)"
                print(f"   {tech}")
                technologies.append(tech)
                
                if '__NUXT__' in content or '_nuxt/' in content_lower:
                    tech = "Framework: Nuxt.js (Vue)"
                    print(f"   {tech}")
                    technologies.append(tech)
        
        else:  # balanced
            vue_patterns = [
                r'vue[.-]?(?:runtime)?[.-]?(?:prod|dev)?\.(?:min\.)?js',
                r'data-v-[a-f0-9]{8}',
                r'from\s+["\']vue["\']',
            ]
            if any(re.search(pattern, content_lower) for pattern in vue_patterns):
                vue_version = re.search(r'vue["\']?\s*:\s*["\']([0-9.]+)["\']', content_lower)
                if vue_version:
                    tech = f"JS Framework: Vue.js {vue_version.group(1)}"
                else:
                    tech = "JS Framework: Vue.js"
                print(f"   {tech}")
                technologies.append(tech)
                
                if '__NUXT__' in content or '_nuxt/' in content_lower:
                    tech = "Framework: Nuxt.js (Vue)"
                    print(f"   {tech}")
                    technologies.append(tech)
        
        # Angular detection
        if detection_mode == 'strict':
            if 'ng-version' in content_lower:
                ng_version = re.search(r'ng-version=["\']([0-9.]+)["\']', content_lower)
                if ng_version:
                    tech = f"JS Framework: Angular {ng_version.group(1)}"
                else:
                    tech = "JS Framework: Angular"
                print(f"   {tech}")
                technologies.append(tech)
            elif re.search(r'@angular/(?:core|common|platform)', content_lower):
                tech = "JS Framework: Angular"
                print(f"   {tech}")
                technologies.append(tech)
        
        elif detection_mode == 'loose':
            if 'angular' in content_lower or 'ng-' in content_lower:
                tech = "JS Framework: Angular (keyword match)"
                print(f"   {tech}")
                technologies.append(tech)
        
        else:  # balanced
            if 'ng-version' in content_lower or re.search(r'@angular/(?:core|common|platform)', content_lower):
                ng_version = re.search(r'ng-version=["\']([0-9.]+)["\']', content_lower)
                if ng_version:
                    tech = f"JS Framework: Angular {ng_version.group(1)}"
                else:
                    tech = "JS Framework: Angular"
                print(f"   {tech}")
                technologies.append(tech)
        
        # ===== 5. JAVASCRIPT LIBRARIES =====
        
        # jQuery
        if 'jquery' in content_lower:
            jquery_version = re.search(r'jquery[.-]?v?([0-9.]+)(?:\.min)?\.js', content_lower)
            if jquery_version:
                tech = f"Library: jQuery {jquery_version.group(1)}"
            else:
                tech = "Library: jQuery"
            print(f"   {tech}")
            technologies.append(tech)
        
        # ===== 6. CSS FRAMEWORKS =====
        
        # Bootstrap
        if 'bootstrap' in content_lower:
            bootstrap_version = re.search(r'bootstrap[/-]?v?([0-9.]+)', content_lower)
            if bootstrap_version:
                tech = f"CSS Framework: Bootstrap {bootstrap_version.group(1)}"
            else:
                tech = "CSS Framework: Bootstrap"
            print(f"   {tech}")
            technologies.append(tech)
        
        # Tailwind CSS
        if 'tailwind' in content_lower or re.search(r'class=["\'][^"\']*\b(?:flex|grid|p-\d|m-\d|text-\w+)', content_lower):
            tech = "CSS Framework: Tailwind CSS"
            print(f"   {tech}")
            technologies.append(tech)
        
        # ===== 7. CDN DETECTION =====
        
        # Cloudflare (additional checks)
        if 'CF-RAY' in headers or 'cf-ray' in str(headers).lower():
            if "CDN: Cloudflare" not in technologies:
                tech = "CDN: Cloudflare"
                print(f"   {tech}")
                technologies.append(tech)
        
        # AWS CloudFront
        if 'cloudfront.net' in content_lower or 'X-Amz-Cf-Id' in headers:
            tech = "CDN: AWS CloudFront"
            print(f"   {tech}")
            technologies.append(tech)
        
        # Akamai
        if 'akamai' in content_lower or 'X-Akamai' in str(headers):
            tech = "CDN: Akamai"
            print(f"   {tech}")
            technologies.append(tech)
        
        # ===== 8. ANALYTICS & TRACKING =====
        
        # Google Analytics
        if 'google-analytics.com' in content_lower or 'gtag' in content_lower:
            tech = "Analytics: Google Analytics"
            print(f"   {tech}")
            technologies.append(tech)
        
        # Google Tag Manager
        if 'googletagmanager.com' in content_lower:
            tech = "Tag Manager: Google Tag Manager"
            print(f"   {tech}")
            technologies.append(tech)
        
        # ===== 9. SECURITY TECHNOLOGIES =====
        
        # reCAPTCHA
        if 'recaptcha' in content_lower or 'google.com/recaptcha' in content_lower:
            tech = "Security: Google reCAPTCHA"
            print(f"   {tech}")
            technologies.append(tech)
        
        # ===== 10. SECURITY HEADERS =====
        
        security_headers = []
        
        if 'X-Frame-Options' in headers:
            value = headers['X-Frame-Options']
            security_headers.append(f"X-Frame-Options: {value}")
        
        if 'Strict-Transport-Security' in headers:
            security_headers.append("HSTS Enabled")
        
        if 'Content-Security-Policy' in headers:
            security_headers.append("CSP Enabled")
        
        if 'X-XSS-Protection' in headers:
            security_headers.append("XSS Protection Enabled")
        
        if 'X-Content-Type-Options' in headers:
            value = headers['X-Content-Type-Options']
            security_headers.append(f"Content-Type Options: {value}")
        
        if 'Permissions-Policy' in headers or 'Feature-Policy' in headers:
            security_headers.append("Permissions Policy Set")
        
        if security_headers:
            print(f"\nSecurity Headers:")
            for header in security_headers:
                print(f"   - {header}")
                technologies.append(f"Security: {header}")
        
        if not technologies:
            print("   [INFO] No technologies detected")
            if detection_mode == 'strict':
                print("   [TIP] Try '--detection-mode balanced' or '--detection-mode loose' for more results")
        
        print(f"\n{'='*60}\n")
        
        self.results['technologies'] = technologies
        logger.info(f"Technology detection completed. {len(technologies)} technologies found")
        
        return technologies
    
    def export_results_json(self, filename=None):
        """Export scan results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"active_scan_{self.target.replace('.', '_')}_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            print(f"[✓] Results exported to {filename}")
            logger.info(f"Results exported to {filename}")
            return filename
        
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            print(f"[ERROR] Export failed: {e}")
            return None
    
    def run_all(self, use_nmap=False, scan_mode='normal', stealth=False, detection_mode='balanced'):
        """
        Run all active reconnaissance modules
        
        Args:
            use_nmap: Use Nmap for port scanning
            scan_mode: 'quick', 'normal', or 'full'
            stealth: Use stealth scanning mode
            detection_mode: 'strict', 'balanced', or 'loose' for technology detection
        """
        logger.info(f"Starting full active reconnaissance for {self.target}")
        
        self.port_scan(use_nmap=use_nmap, scan_mode=scan_mode, stealth=stealth)
        self.banner_grab()
        self.detect_technologies(detection_mode=detection_mode)
        
        logger.info("Active reconnaissance completed")
        return self.results