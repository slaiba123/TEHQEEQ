"""
Utility functions for input validation and helpers
"""

import re
import sys
from colorama import Fore, Style


def validate_domain(domain):
    """Validate domain format"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def validate_ip(ip):
    """Validate IP address format"""
    pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    return bool(re.match(pattern, ip))


def parse_target(target):
    """Parse and validate target input"""
    # Remove protocol if present
    target = target.replace('http://', '').replace('https://', '')
    target = target.split('/')[0]  # Remove path
    target = target.split(':')[0]  # Remove port
    
    if validate_domain(target):
        return target, 'domain'
    elif validate_ip(target):
        return target, 'ip'
    else:
        raise ValueError(f"Invalid target format: {target}")


def show_disclaimer():
    """Display legal disclaimer and get user confirmation"""
    print(Fore.YELLOW + "\n" + "="*70)
    print("⚠️  LEGAL DISCLAIMER & IMPORTANT NOTICE")
    print("="*70)
    print(Style.RESET_ALL)
    print("This reconnaissance tool should ONLY be used on systems that:")
    print("  • You own")
    print("  • You have explicit written permission to test")
    print()
    print(Fore.RED + "Unauthorized scanning may be ILLEGAL in your jurisdiction!")
    print("The developers assume NO liability for misuse of this tool." + Style.RESET_ALL)
    print("="*70 + "\n")
    
    response = input(Fore.CYAN + "Do you have authorization to scan this target? (yes/no): " + Style.RESET_ALL)
    
    if response.lower() != 'yes':
        print(Fore.RED + "\n[!] Exiting. Please obtain proper authorization first.\n")
        sys.exit(1)
    
    print(Fore.GREEN + "\n[✓] Authorization confirmed. Proceeding with scan...\n" + Style.RESET_ALL)


def print_banner():
    """Display tool banner"""
    banner = f"""{Fore.CYAN}
{'='*70}
    
    🔍 RECONNAISSANCE TOOL v2.0
    Network Intelligence Gathering Tool
    
    For Authorized Security Testing Only
    
{'='*70}
{Style.RESET_ALL}"""
    print(banner)