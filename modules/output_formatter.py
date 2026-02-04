"""
Enhanced Output Formatter
Beautiful terminal output with boxes and descriptive messages
"""

from colorama import Fore, Back, Style, init
import sys

# Initialize colorama
init(autoreset=True)


class OutputFormatter:
    """Formats output with beautiful boxes and colors"""
    
    # Box drawing characters
    BOX_TOP_LEFT = '╔'
    BOX_TOP_RIGHT = '╗'
    BOX_BOTTOM_LEFT = '╚'
    BOX_BOTTOM_RIGHT = '╝'
    BOX_HORIZONTAL = '═'
    BOX_VERTICAL = '║'
    
    # Colors
    HEADER_COLOR = Fore.CYAN + Style.BRIGHT
    SUCCESS_COLOR = Fore.GREEN + Style.BRIGHT
    WARNING_COLOR = Fore.YELLOW + Style.BRIGHT
    ERROR_COLOR = Fore.RED + Style.BRIGHT
    INFO_COLOR = Fore.BLUE
    DEBUG_COLOR = Fore.MAGENTA
    RECORD_COLOR = Fore.WHITE
    
    def __init__(self, verbosity=1):
        self.verbosity = verbosity  # 0=quiet, 1=normal, 2=verbose, 3=debug
    
    def print_banner(self):
        """Print tool banner"""
        banner = f"""{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ████████╗███████╗██╗  ██╗ ██████╗ ███████╗███████╗ ██████╗     ║
║   ╚══██╔══╝██╔════╝██║  ██║██╔═══██╗██╔════╝██╔════╝██╔═══██╗    ║
║      ██║   █████╗  ███████║██║   ██║█████╗  █████╗  ██║   ██║    ║
║      ██║   ██╔══╝  ██╔══██║██║▄▄ ██║██╔══╝  ██╔══╝  ██║▄▄ ██║    ║
║      ██║   ███████╗██║  ██║╚██████╔╝███████╗███████╗╚██████╔╝    ║
║      ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚══▀▀═╝ ╚══════╝╚══════╝ ╚══▀▀═╝     ║
║                                                                  ║
║                                                                  ║
║                 Advanced Network Reconnaissance Tool             ║
║                    For Authorized Security Testing               ║
║                              v2.0                                ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(banner)
    
    def print_box(self, message, width=66, color=HEADER_COLOR):
        """Print a boxed message"""
        if color is None:
            color = self.HEADER_COLOR
        
        # Ensure message fits
        if len(message) > width - 4:
            message = message[:width-7] + "..."
        
        padding = width - len(message) - 2
        left_pad = padding // 2
        right_pad = padding - left_pad+2
        
        print(f"\n{color}{self.BOX_TOP_LEFT}{self.BOX_HORIZONTAL * width}{self.BOX_TOP_RIGHT}")
        print(f"{self.BOX_VERTICAL}{' ' * left_pad}{message}{' ' * right_pad}{self.BOX_VERTICAL}")
        print(f"{self.BOX_BOTTOM_LEFT}{self.BOX_HORIZONTAL * width}{self.BOX_BOTTOM_RIGHT}{Style.RESET_ALL}\n")
    
    def print_section_start(self, title):
        """Print section start"""
        self.print_box(title, color=self.HEADER_COLOR)
    
    def print_scan_started(self, target):
        """Print scan started message"""
        self.print_box(f"SCAN STARTED FOR {target.upper()}", color=Fore.GREEN + Style.BRIGHT)
    
    def print_scan_completed(self, target):
        """Print scan completed message"""
        self.print_box(f"SCAN COMPLETED FOR {target.upper()}", color=Fore.GREEN + Style.BRIGHT)
    
    def print_record(self, record_type, domain, records, nameservers=None):
        """Print DNS records with details"""
        print(f"{self.SUCCESS_COLOR}[{record_type}]{Style.RESET_ALL} Records for {Fore.WHITE}{domain}{Style.RESET_ALL}:")
        
        if not records or len(records) == 0:
            print(f"  {self.WARNING_COLOR}- No records found!{Style.RESET_ALL}")
        else:
            for record in records:
                print(f"  {self.SUCCESS_COLOR}- {record}{Style.RESET_ALL}")
        
        # Add query info if verbose
        if self.verbosity >= 2 and nameservers:
            ns_str = str(nameservers) if isinstance(nameservers, list) else nameservers
            print(f"  {self.DEBUG_COLOR}(Queried {record_type} record for {domain} using {ns_str}){Style.RESET_ALL}")
        
        print()
    
    def print_open_port(self, port, service, method="TCP Connect"):
        """Print open port information"""
        print(f"{self.SUCCESS_COLOR}[OPEN]{Style.RESET_ALL} Port {Fore.WHITE}{port:5d}{Style.RESET_ALL} | State: {self.SUCCESS_COLOR}Open{Style.RESET_ALL} | Service: {Fore.CYAN}{service}{Style.RESET_ALL} | Method: {method}")
    
    def print_debug(self, message):
        """Print debug message"""
        if self.verbosity >= 3:
            print(f"{self.DEBUG_COLOR}[DEBUG]{Style.RESET_ALL} {message}")
    
    def print_info(self, message):
        """Print info message"""
        if self.verbosity >= 2:
            print(f"{self.INFO_COLOR}[INFO]{Style.RESET_ALL} {message}")
    
    def print_warning(self, message):
        """Print warning message"""
        print(f"{self.WARNING_COLOR}[!]{Style.RESET_ALL} {message}")
    
    def print_error(self, message):
        """Print error message"""
        print(f"{self.ERROR_COLOR}[ERROR]{Style.RESET_ALL} {message}")
    
    def print_success(self, message):
        """Print success message"""
        print(f"{self.SUCCESS_COLOR}[✓]{Style.RESET_ALL} {message}")
    
    def print_banner_info(self, port, banner, bytes_received=None):
        """Print banner grabbing info"""
        self.print_info(f"Connecting to {port}")
        print(f"\n{self.SUCCESS_COLOR}[PORT {port}]{Style.RESET_ALL}")
        
        if banner:
            # Print banner line by line
            for line in banner.split('\n')[:5]:  # First 5 lines
                if line.strip():
                    print(f"{Fore.WHITE}{line}{Style.RESET_ALL}")
        else:
            print(f"{self.WARNING_COLOR}No banner received{Style.RESET_ALL}")
        
        if bytes_received is not None:
            self.print_info(f"Bytes received: {bytes_received}")
        print()
    
    def print_technology(self, tech_type, tech_name):
        """Print detected technology"""
        icons = {
            'server': '',
            'cms': '',
            'framework': '',
            'library': '',
            'security': '',
            'cdn': '',
            'analytics': ''
        }
        
        icon = icons.get(tech_type.lower())
        print(f"   {icon}  {Fore.CYAN}{tech_name}{Style.RESET_ALL}")
    
    def print_whois_field(self, field_name, value, icon=''):
        """Print WHOIS field"""
        if value and value != 'N/A':
            print(f"{icon} {Fore.CYAN}{field_name}:{Style.RESET_ALL} {Fore.WHITE}{value}{Style.RESET_ALL}")
    
    def print_subdomain_found(self, subdomain):
        """Print found subdomain"""
        print(f"      {self.SUCCESS_COLOR} {subdomain}{Style.RESET_ALL}")
    
    def print_progress(self, current, total, message=""):
        """Print progress"""
        if message:
            print(f"      {self.INFO_COLOR}Progress: {current}/{total} {message}{Style.RESET_ALL}")
        else:
            print(f"      {self.INFO_COLOR}Progress: {current}/{total} checked...{Style.RESET_ALL}")
    
    def print_summary_line(self, label, value, color=None):
        """Print summary line"""
        if color is None:
            color = self.SUCCESS_COLOR
        print(f"   {color}• {label}: {value}{Style.RESET_ALL}")
    
    def print_target_info(self, target, verbosity, full_scan=False):
        """Print target information"""
        print(f"\n {Fore.CYAN}TARGET:{Style.RESET_ALL} {Fore.WHITE}{target}{Style.RESET_ALL}")
        print(f" {Fore.CYAN}VERBOSITY LEVEL:{Style.RESET_ALL} {Fore.WHITE}{verbosity}{Style.RESET_ALL}")
        if full_scan:
            print(f" {Fore.CYAN}FULL SCAN:{Style.RESET_ALL} {self.SUCCESS_COLOR}✔{Style.RESET_ALL}")
        print()
    
    def print_separator(self, char='═', length=66):
        """Print separator line"""
        print(f"{Fore.CYAN}{char * length}{Style.RESET_ALL}")
    
    def print_disclaimer(self):
        """Print legal disclaimer"""
        print(f"\n{self.BOX_TOP_LEFT}{self.BOX_HORIZONTAL * 66}{self.BOX_TOP_RIGHT}")
        print(f"{self.BOX_VERTICAL}{Fore.YELLOW + Style.BRIGHT}  ⚠️  LEGAL DISCLAIMER & IMPORTANT NOTICE {' ' * 25}{self.BOX_VERTICAL}{Style.RESET_ALL}")
        print(f"{self.BOX_BOTTOM_LEFT}{self.BOX_HORIZONTAL * 66}{self.BOX_BOTTOM_RIGHT}")
        
        print(f"""
{Fore.WHITE}This reconnaissance tool should ONLY be used on systems that:
  • You own
  • You have explicit written permission to test

{Fore.RED}Unauthorized scanning may be ILLEGAL in your jurisdiction!
{Fore.YELLOW}The developers assume NO liability for misuse of this tool.{Style.RESET_ALL}
""")
        
        response = input(f"{Fore.CYAN}Do you have authorization to scan this target? (yes/no): {Style.RESET_ALL}")
        
        if response.lower().strip() not in ('yes', 'y'):
            print(f"\n{self.ERROR_COLOR}[!] Exiting. Please obtain proper authorization first.{Style.RESET_ALL}\n")
            sys.exit(1)
        
        print(f"\n{self.SUCCESS_COLOR}[✓] Authorization confirmed. Proceeding with scan...{Style.RESET_ALL}\n")
    
    def print_report_saved(self, report_type, path):
        """Print report saved message"""
        print(f"{self.SUCCESS_COLOR}[✓]{Style.RESET_ALL} {report_type} Report: {Fore.WHITE}{path}{Style.RESET_ALL}")


# Convenience function
def create_formatter(verbosity=1):
    """Create and return an OutputFormatter instance"""
    return OutputFormatter(verbosity)