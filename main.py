# """
# TEHQEEQ - تحقیق
# Advanced Network Reconnaissance Tool v2.0
# For Authorized Security Testing Only
# """

# import argparse
# import sys
# import logging
# from pathlib import Path
# from datetime import datetime
# from colorama import init, Fore, Style

# # Initialize colorama
# init(autoreset=True)

# # Import modules
# from modules.passive import PassiveRecon
# from modules.active import ActiveRecon
# from modules.reporter import Reporter
# from modules.output_formatter import create_formatter
# from utils import parse_target, validate_output_path


# def setup_logging(verbose=False):
#     """Set up logging configuration"""
#     log_dir = Path('logs')
#     log_dir.mkdir(exist_ok=True)
    
#     log_level = logging.DEBUG if verbose else logging.INFO
    
#     logging.basicConfig(
#         level=log_level,
#         format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#         handlers=[
#             logging.FileHandler(f'logs/recon_{datetime.now().strftime("%Y%m%d")}.log'),
#             logging.NullHandler()
#         ]
#     )


# def main():
#     # Parse arguments
#     parser = argparse.ArgumentParser(
#         description="TEHQEEQ (تحقیق) - Advanced Network Reconnaissance Tool v2.0",
#         formatter_class=argparse.RawDescriptionHelpFormatter,
#         epilog="""
# Examples:
#   %(prog)s example.com --all --report pdf
#   %(prog)s example.com --whois --dns -vv
#   %(prog)s target.com --full --verify
#   %(prog)s neduet.edu.pk --all -vv
#   %(prog)s -d google.com --full -vvv --report html
#         """
#     )
    
#     parser.add_argument("target", help="Target domain or IP address")
#     parser.add_argument("-d", "--domain", dest="target_alt", help="Target domain (alternative)")
    
#     # Scan options
#     parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
#     parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
#     parser.add_argument("--subdomains", action="store_true", help="Perform subdomain enumeration")
#     parser.add_argument("--ports", action="store_true", help="Perform port scanning")
#     parser.add_argument("--banner", action="store_true", help="Grab banners from open ports")
#     parser.add_argument("--tech", action="store_true", help="Detect web technologies")
#     parser.add_argument("--all", "--full", action="store_true", help="Run all reconnaissance modules")
    
#     # Reporting
#     parser.add_argument("--report", choices=["txt", "json", "pdf"], help="Generate report (txt, json, pdf)")
#     parser.add_argument("--output", "-o", help="Custom output directory for reports")
    
#     # Verbosity
#     parser.add_argument("-v", "--verbose", action="count", default=0, 
#                        help="Increase verbosity (-v, -vv, -vvv)")
#     parser.add_argument("--skip-disclaimer", action="store_true", help="Skip legal disclaimer")
    
#     args = parser.parse_args()
    
#     # Use alternative target if specified
#     target = args.target_alt if args.target_alt else args.target
    
#     # Map verbosity levels (0=quiet, 1=normal, 2=verbose, 3=debug)
#     verbosity = min(args.verbose, 3)
    
#     # Create output formatter
#     formatter = create_formatter(verbosity)
    
#     # Set up logging
#     setup_logging(verbose=(verbosity >= 3))
#     logger = logging.getLogger(__name__)
#     logger.info("=== Reconnaissance Tool Started ===")
    
#     # Display banner
#     formatter.print_banner()
    
#     # Check if user specified at least one scan type
#     if not (args.whois or args.dns or args.subdomains or args.ports or 
#             args.banner or args.tech or args.all):
#         formatter.print_error("Please specify at least one scan type!")
#         print(f"\n{Fore.CYAN}Examples:{Style.RESET_ALL}")
#         print("  python main.py example.com --all")
#         print("  python main.py example.com --whois --dns -vv")
#         print("  python main.py example.com --ports --tech")
#         print("\nFor more help, use: python main.py --help\n")
#         sys.exit(1)
    
#     # Validate target
#     try:
#         target, target_type = parse_target(target)
#         logger.info(f"Target validated: {target} (type: {target_type})")
#     except ValueError as e:
#         formatter.print_error(f"Invalid target: {e}")
#         logger.error(f"Invalid target: {e}")
#         sys.exit(1)
    
#     # Show disclaimer
#     if not args.skip_disclaimer:
#         formatter.print_disclaimer()
    
#     # Set custom output directory if specified
#     if args.output:
#         try:
#             import config
#             config.REPORTS_FOLDER = validate_output_path(args.output)
#             logger.info(f"Custom output directory set: {config.REPORTS_FOLDER}")
#         except ValueError as e:
#             formatter.print_error(str(e))
#             sys.exit(1)
    
#     # Print target info
#     formatter.print_target_info(target, verbosity, full_scan=args.all)
    
#     # Print scan started
#     formatter.print_scan_started(target)
    
#     # Initialize results dictionaries
#     passive_results = {}
#     active_results = {}
    
#     # Run Passive Recon
#     if args.whois or args.dns or args.subdomains or args.all:
#         p = PassiveRecon(target, formatter=formatter)
        
#         if args.whois or args.all:
#             passive_results['whois'] = p.whois_lookup()
        
#         if args.dns or args.all:
#             passive_results['dns'] = p.dns_enumeration()
        
#         if args.subdomains or args.all:
#             passive_results['subdomains'] = p.subdomain_enumeration()
        
#         logger.info("Passive reconnaissance completed")
    
#     # Run Active Recon
#     if args.ports or args.banner or args.tech or args.all:
#         a = ActiveRecon(target, formatter=formatter)
        
#         if args.ports or args.all:
#             a.port_scan()
        
#         if args.banner or args.all:
#             a.banner_grab()
        
#         if args.tech or args.all:
#             a.detect_technologies()
        
#         active_results = a.results
#         logger.info("Active reconnaissance completed")
    
#     # Print scan completed
#     formatter.print_scan_completed(target)
    
#     # Generate report if requested
#     if args.report:
#         formatter.print_separator()
#         print(f"\n{Fore.CYAN}Generating Reports...{Style.RESET_ALL}\n")
        
#         r = Reporter(target, passive_results, active_results)
#         report_path = r.generate_reports(format_type=args.report)
        
#         if report_path:
#             report_type = args.report.upper()
#             formatter.print_report_saved(report_type, report_path)
#             logger.info(f"Report generated: {report_path}")
    
#     # Print summary
#     print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
    
#     if passive_results:
#         total_subdomains = len(passive_results.get('subdomains', []))
#         formatter.print_summary_line("Subdomains found", total_subdomains)
    
#     if active_results:
#         total_ports = len(active_results.get('open_ports', []))
#         total_techs = len(active_results.get('technologies', []))
#         formatter.print_summary_line("Open ports found", total_ports)
#         formatter.print_summary_line("Technologies detected", total_techs)
    
#     print()
#     logger.info("=== Reconnaissance Tool Finished ===")


# if __name__ == "__main__":
#     try:
#         main()
#     except KeyboardInterrupt:
#         print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user. Exiting...{Style.RESET_ALL}")
#         print(f"{Fore.CYAN}Goodbye!{Style.RESET_ALL}\n")
#         sys.exit(0)
#     except Exception as e:
#         logging.exception("Fatal error occurred")
#         print(f"\n{Fore.RED}[ERROR] Fatal error: {e}{Style.RESET_ALL}")
#         print("Check the log file in ./logs/ for more details\n")
#         sys.exit(1)


# """
# TEHQEEQ - تحقیق
# Advanced Network Reconnaissance Tool v2.0
# For Authorized Security Testing Only

# FIXED VERSION:
# - Now runs subdomain verification by default when using --all
# - Passes verification results to reporter
# - Improved summary output
# """

# import argparse
# import sys
# import logging
# from pathlib import Path
# from datetime import datetime
# from colorama import init, Fore, Style

# # Initialize colorama
# init(autoreset=True)

# # Import modules
# from modules.passive import PassiveRecon
# from modules.active import ActiveRecon
# from modules.reporter import Reporter
# from modules.output_formatter import create_formatter
# from utils import parse_target, validate_output_path


# def setup_logging(verbose=False):
#     """Set up logging configuration"""
#     log_dir = Path('logs')
#     log_dir.mkdir(exist_ok=True)
    
#     log_level = logging.DEBUG if verbose else logging.INFO
    
#     logging.basicConfig(
#         level=log_level,
#         format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#         handlers=[
#             logging.FileHandler(f'logs/recon_{datetime.now().strftime("%Y%m%d")}.log'),
#             logging.NullHandler()
#         ]
#     )


# def main():
#     # Parse arguments
#     parser = argparse.ArgumentParser(
#         description="TEHQEEQ (تحقیق) - Advanced Network Reconnaissance Tool v2.0",
#         formatter_class=argparse.RawDescriptionHelpFormatter,
#         epilog="""
# Examples:
#   %(prog)s example.com --all --report pdf
#   %(prog)s example.com --whois --dns -vv
#   %(prog)s target.com --full --verify
#   %(prog)s neduet.edu.pk --all -vv
#   %(prog)s -d google.com --full -vvv --report html
#         """
#     )
    
#     parser.add_argument("target", help="Target domain or IP address")
#     parser.add_argument("-d", "--domain", dest="target_alt", help="Target domain (alternative)")
    
#     # Scan options
#     parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
#     parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
#     parser.add_argument("--subdomains", action="store_true", help="Perform subdomain enumeration")
#     parser.add_argument("--ports", action="store_true", help="Perform port scanning")
#     parser.add_argument("--banner", action="store_true", help="Grab banners from open ports")
#     parser.add_argument("--tech", action="store_true", help="Detect web technologies")
#     parser.add_argument("--all", "--full", action="store_true", help="Run all reconnaissance modules")
    
#     # NEW: Verification options
#     parser.add_argument("--verify", action="store_true", 
#                        help="Verify discovered subdomains (enabled by default with --all)")
#     parser.add_argument("--no-verify", action="store_true",
#                        help="Skip subdomain verification even with --all")
#     parser.add_argument("--verify-method", choices=["dns", "http"], default="dns",
#                        help="Verification method: dns (fast) or http (thorough)")
    
#     # Reporting
#     parser.add_argument("--report", choices=["txt", "json", "pdf"], help="Generate report (txt, json, pdf)")
#     parser.add_argument("--output", "-o", help="Custom output directory for reports")
    
#     # Verbosity
#     parser.add_argument("-v", "--verbose", action="count", default=0, 
#                        help="Increase verbosity (-v, -vv, -vvv)")
#     parser.add_argument("--skip-disclaimer", action="store_true", help="Skip legal disclaimer")
    
#     args = parser.parse_args()
    
#     # Use alternative target if specified
#     target = args.target_alt if args.target_alt else args.target
    
#     # Map verbosity levels (0=quiet, 1=normal, 2=verbose, 3=debug)
#     verbosity = min(args.verbose, 3)
    
#     # Create output formatter
#     formatter = create_formatter(verbosity)
    
#     # Set up logging
#     setup_logging(verbose=(verbosity >= 3))
#     logger = logging.getLogger(__name__)
#     logger.info("=== Reconnaissance Tool Started ===")
    
#     # Display banner
#     formatter.print_banner()
    
#     # Check if user specified at least one scan type
#     if not (args.whois or args.dns or args.subdomains or args.ports or 
#             args.banner or args.tech or args.all):
#         formatter.print_error("Please specify at least one scan type!")
#         print(f"\n{Fore.CYAN}Examples:{Style.RESET_ALL}")
#         print("  python main.py example.com --all")
#         print("  python main.py example.com --whois --dns -vv")
#         print("  python main.py example.com --ports --tech")
#         print("\nFor more help, use: python main.py --help\n")
#         sys.exit(1)
    
#     # Validate target
#     try:
#         target, target_type = parse_target(target)
#         logger.info(f"Target validated: {target} (type: {target_type})")
#     except ValueError as e:
#         formatter.print_error(f"Invalid target: {e}")
#         logger.error(f"Invalid target: {e}")
#         sys.exit(1)
    
#     # Show disclaimer
#     if not args.skip_disclaimer:
#         formatter.print_disclaimer()
    
#     # Set custom output directory if specified
#     if args.output:
#         try:
#             import config
#             config.REPORTS_FOLDER = validate_output_path(args.output)
#             logger.info(f"Custom output directory set: {config.REPORTS_FOLDER}")
#         except ValueError as e:
#             formatter.print_error(str(e))
#             sys.exit(1)
    
#     # Print target info
#     formatter.print_target_info(target, verbosity, full_scan=args.all)
    
#     # Print scan started
#     formatter.print_scan_started(target)
    
#     # Initialize results dictionaries
#     passive_results = {}
#     active_results = {}
    
#     # FIXED: Determine if we should verify subdomains
#     should_verify = False
#     if args.verify:
#         should_verify = True
#     elif args.all and not args.no_verify:
#         # Default: verify when using --all unless --no-verify is specified
#         should_verify = True
    
#     # Run Passive Recon
#     if args.whois or args.dns or args.subdomains or args.all:
#         p = PassiveRecon(target, formatter=formatter)
        
#         if args.whois or args.all:
#             passive_results['whois'] = p.whois_lookup()
        
#         if args.dns or args.all:
#             passive_results['dns'] = p.dns_enumeration()
        
#         if args.subdomains or args.all:
#             passive_results['subdomains'] = p.subdomain_enumeration()
            
#             # FIXED: Run verification if enabled and subdomains were found
#             if should_verify and passive_results.get('subdomains'):
#                 print(f"\n{Fore.CYAN}[INFO] Verifying discovered subdomains...{Style.RESET_ALL}")
#                 print(f"{Fore.CYAN}[INFO] Using {args.verify_method.upper()} verification method{Style.RESET_ALL}\n")
                
#                 try:
#                     verified_data = p.verify_subdomains(
#                         verification_type=args.verify_method,
#                         max_workers=20  # Adjust based on your needs
#                     )
                    
#                     # Store verification results
#                     passive_results['verified_subdomains'] = verified_data
                    
#                     # Export verified list to file
#                     verified_file = p.export_verified_subdomains()
#                     if verified_file:
#                         print(f"{Fore.GREEN}[✓] Verified subdomains exported to: {verified_file}{Style.RESET_ALL}\n")
                    
#                 except Exception as e:
#                     logger.error(f"Verification failed: {e}")
#                     print(f"{Fore.RED}[ERROR] Verification failed: {e}{Style.RESET_ALL}")
#                     print(f"{Fore.YELLOW}[WARNING] Continuing without verification...{Style.RESET_ALL}\n")
        
#         logger.info("Passive reconnaissance completed")
    
#     # Run Active Recon
#     if args.ports or args.banner or args.tech or args.all:
#         a = ActiveRecon(target, formatter=formatter)
        
#         if args.ports or args.all:
#             a.port_scan()
        
#         if args.banner or args.all:
#             a.banner_grab()
        
#         if args.tech or args.all:
#             a.detect_technologies()
        
#         active_results = a.results
#         logger.info("Active reconnaissance completed")
    
#     # Print scan completed
#     formatter.print_scan_completed(target)
    
#     # Generate report if requested
#     if args.report:
#         formatter.print_separator()
#         print(f"\n{Fore.CYAN}Generating Reports...{Style.RESET_ALL}\n")
        
#         # FIXED: Pass both passive and active results (including verification data)
#         r = Reporter(target, passive_results, active_results)
#         report_path = r.generate_reports(format_type=args.report)
        
#         if report_path:
#             report_type = args.report.upper()
#             formatter.print_report_saved(report_type, report_path)
#             logger.info(f"Report generated: {report_path}")
    
#     # IMPROVED: Print comprehensive summary
#     print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
#     print(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
#     print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
#     if passive_results:
#         total_subdomains = len(passive_results.get('subdomains', []))
#         formatter.print_summary_line("Subdomains found", total_subdomains)
        
#         # Show verification summary if available
#         if 'verified_subdomains' in passive_results:
#             verified = passive_results['verified_subdomains']
#             total_live = len(verified.get('live', []))
#             total_dead = len(verified.get('dead', []))
#             total_internal = len(verified.get('internal', []))
            
#             formatter.print_summary_line("   ├─ Verified live", total_live)
#             formatter.print_summary_line("   ├─ Dead/unreachable", total_dead)
#             if total_internal > 0:
#                 formatter.print_summary_line("   └─ Internal only", total_internal)
    
#     if active_results:
#         total_ports = len(active_results.get('open_ports', []))
#         total_techs = len(active_results.get('technologies', []))
#         formatter.print_summary_line("Open ports found", total_ports)
#         formatter.print_summary_line("Technologies detected", total_techs)
    
#     print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
#     logger.info("=== Reconnaissance Tool Finished ===")


# if __name__ == "__main__":
#     try:
#         main()
#     except KeyboardInterrupt:
#         print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user. Exiting...{Style.RESET_ALL}")
#         print(f"{Fore.CYAN}Goodbye!{Style.RESET_ALL}\n")
#         sys.exit(0)
#     except Exception as e:
#         logging.exception("Fatal error occurred")
#         print(f"\n{Fore.RED}[ERROR] Fatal error: {e}{Style.RESET_ALL}")
#         print("Check the log file in ./logs/ for more details\n")
#         sys.exit(1)


"""
TEHQEEQ - تحقیق
Advanced Network Reconnaissance Tool v2.0
For Authorized Security Testing Only

UPDATED VERSION:
- Nmap integration support
- Multiple scan modes (quick/normal/full)
- Stealth scanning option
- Subdomain verification by default
- Improved performance and error handling
"""

import argparse
import sys
import logging
from pathlib import Path
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Import modules
from modules.passive import PassiveRecon
from modules.active import ActiveRecon
from modules.reporter import Reporter
from modules.output_formatter import create_formatter
from utils import parse_target, validate_output_path


def setup_logging(verbose=False):
    """Set up logging configuration"""
    log_dir = Path('logs')
    log_dir.mkdir(exist_ok=True)
    
    log_level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f'logs/recon_{datetime.now().strftime("%Y%m%d")}.log'),
            logging.NullHandler()
        ]
    )


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="TEHQEEQ (تحقیق) - Advanced Network Reconnaissance Tool v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic usage:
    %(prog)s example.com --all --report pdf
    %(prog)s example.com --whois --dns -vv
  
  Port scanning modes:
    %(prog)s target.com --ports --scan-mode quick    # Fast (11 ports, ~2s)
    %(prog)s target.com --ports --scan-mode normal   # Balanced (15 ports, ~3s)
    %(prog)s target.com --ports --scan-mode full     # Thorough (100 ports, ~15s)
  
  Using Nmap (requires installation):
    %(prog)s target.com --ports --use-nmap           # Better accuracy
    %(prog)s target.com --all --use-nmap --report pdf
  
  Stealth scanning:
    %(prog)s target.com --ports --stealth            # Slower, less detectable
  
  Subdomain verification:
    %(prog)s target.com --subdomains --verify-method dns    # Fast
    %(prog)s target.com --subdomains --verify-method http   # Thorough
    %(prog)s target.com --all --no-verify                   # Skip verification
  
  Pakistan domains:
    %(prog)s uet.edu.pk --all -vv --report pdf
    %(prog)s neduet.edu.pk --full --verify --use-nmap
        """
    )
    
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("-d", "--domain", dest="target_alt", help="Target domain (alternative)")
    
    # ===== PASSIVE RECON OPTIONS =====
    passive_group = parser.add_argument_group('Passive Reconnaissance')
    passive_group.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    passive_group.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
    passive_group.add_argument("--subdomains", action="store_true", help="Perform subdomain enumeration")
    
    # ===== ACTIVE RECON OPTIONS =====
    active_group = parser.add_argument_group('Active Reconnaissance')
    active_group.add_argument("--ports", action="store_true", help="Perform port scanning")
    active_group.add_argument("--banner", action="store_true", help="Grab banners from open ports")
    active_group.add_argument("--tech", action="store_true", help="Detect web technologies")
    
    # ===== SCAN MODES =====
    scan_group = parser.add_argument_group('Scan Configuration')
    scan_group.add_argument("--all", "--full", action="store_true", 
                           help="Run all reconnaissance modules")
    scan_group.add_argument("--scan-mode", choices=["quick", "normal", "full"], 
                           default="normal",
                           help="Port scan mode: quick (11 ports), normal (15 ports), full (100 ports)")
    scan_group.add_argument("--use-nmap", action="store_true",
                           help="Use Nmap for port scanning (requires nmap installation)")
    scan_group.add_argument("--stealth", action="store_true",
                           help="Use stealth mode (slower, randomized, less detectable)")
    
    # ===== SUBDOMAIN VERIFICATION =====
    verify_group = parser.add_argument_group('Subdomain Verification')
    verify_group.add_argument("--verify", action="store_true", 
                             help="Verify discovered subdomains (enabled by default with --all)")
    verify_group.add_argument("--no-verify", action="store_true",
                             help="Skip subdomain verification even with --all")
    verify_group.add_argument("--verify-method", choices=["dns", "http"], default="dns",
                             help="Verification method: dns (fast) or http (thorough)")
    
    # ===== REPORTING =====
    report_group = parser.add_argument_group('Reporting')
    report_group.add_argument("--report", choices=["txt", "json", "pdf"], 
                             help="Generate report (txt, json, pdf)")
    report_group.add_argument("--output", "-o", help="Custom output directory for reports")
    report_group.add_argument("--export-json", action="store_true",
                             help="Export active scan results to JSON")
    
    # ===== GENERAL OPTIONS =====
    general_group = parser.add_argument_group('General Options')
    general_group.add_argument("-v", "--verbose", action="count", default=0, 
                              help="Increase verbosity (-v, -vv, -vvv)")
    general_group.add_argument("--skip-disclaimer", action="store_true", 
                              help="Skip legal disclaimer")
    general_group.add_argument("--version", action="version", 
                              version="TEHQEEQ v2.0")
    
    args = parser.parse_args()
    
    # Use alternative target if specified
    target = args.target_alt if args.target_alt else args.target
    
    # Map verbosity levels (0=quiet, 1=normal, 2=verbose, 3=debug)
    verbosity = min(args.verbose, 3)
    
    # Create output formatter
    formatter = create_formatter(verbosity)
    
    # Set up logging
    setup_logging(verbose=(verbosity >= 3))
    logger = logging.getLogger(__name__)
    logger.info("=== Reconnaissance Tool Started ===")
    
    # Display banner
    formatter.print_banner()
    
    # Check if user specified at least one scan type
    if not (args.whois or args.dns or args.subdomains or args.ports or 
            args.banner or args.tech or args.all):
        formatter.print_error("Please specify at least one scan type!")
        print(f"\n{Fore.CYAN}Examples:{Style.RESET_ALL}")
        print("  python main.py example.com --all")
        print("  python main.py example.com --whois --dns -vv")
        print("  python main.py example.com --ports --use-nmap")
        print("  python main.py example.com --ports --scan-mode full")
        print("\nFor more help, use: python main.py --help\n")
        sys.exit(1)
    
    # Validate target
    try:
        target, target_type = parse_target(target)
        logger.info(f"Target validated: {target} (type: {target_type})")
    except ValueError as e:
        formatter.print_error(f"Invalid target: {e}")
        logger.error(f"Invalid target: {e}")
        sys.exit(1)
    
    # Show disclaimer
    if not args.skip_disclaimer:
        formatter.print_disclaimer()
    
    # Set custom output directory if specified
    if args.output:
        try:
            import config
            config.REPORTS_FOLDER = validate_output_path(args.output)
            logger.info(f"Custom output directory set: {config.REPORTS_FOLDER}")
        except ValueError as e:
            formatter.print_error(str(e))
            sys.exit(1)
    
    # Print target info
    formatter.print_target_info(target, verbosity, full_scan=args.all)
    
    # Print scan configuration
    if args.ports or args.all:
        print(f"{Fore.CYAN}Port Scan Configuration:{Style.RESET_ALL}")
        print(f"   Mode: {args.scan_mode}")
        print(f"   Method: {'Nmap' if args.use_nmap else 'Socket (concurrent)'}")
        if args.stealth and not args.use_nmap:
            print(f"   Stealth: Enabled (randomized, slower)")
        print()
    
    # Print scan started
    formatter.print_scan_started(target)
    
    # Initialize results dictionaries
    passive_results = {}
    active_results = {}
    
    # ===== PASSIVE RECONNAISSANCE =====
    if args.whois or args.dns or args.subdomains or args.all:
        p = PassiveRecon(target, formatter=formatter)
        
        if args.whois or args.all:
            passive_results['whois'] = p.whois_lookup()
        
        if args.dns or args.all:
            passive_results['dns'] = p.dns_enumeration()
        
        if args.subdomains or args.all:
            passive_results['subdomains'] = p.subdomain_enumeration()
            
            # Determine if we should verify subdomains
            should_verify = False
            if args.verify:
                should_verify = True
            elif args.all and not args.no_verify:
                # Default: verify when using --all unless --no-verify is specified
                should_verify = True
            
            # Run verification if enabled and subdomains were found
            if should_verify and passive_results.get('subdomains'):
                print(f"\n{Fore.CYAN}[INFO] Verifying discovered subdomains...{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[INFO] Using {args.verify_method.upper()} verification method{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[INFO] This may take a few minutes...{Style.RESET_ALL}\n")
                
                try:
                    verified_data = p.verify_subdomains(
                        verification_type=args.verify_method,
                        max_workers=20
                    )
                    
                    # Store verification results
                    passive_results['verified_subdomains'] = verified_data
                    
                except Exception as e:
                    logger.error(f"Verification failed: {e}")
                    print(f"{Fore.RED}[ERROR] Verification failed: {e}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[WARNING] Continuing without verification...{Style.RESET_ALL}\n")
        
        logger.info("Passive reconnaissance completed")
    
    # ===== ACTIVE RECONNAISSANCE =====
    if args.ports or args.banner or args.tech or args.all:
        a = ActiveRecon(target, formatter=formatter)
        
        if args.ports or args.all:
            a.port_scan(
                use_nmap=args.use_nmap,
                scan_mode=args.scan_mode,
                stealth=args.stealth
            )
        
        if args.banner or args.all:
            a.banner_grab()
        
        if args.tech or args.all:
            a.detect_technologies()
        
        active_results = a.results
        
        # Export JSON if requested
        if args.export_json:
            print(f"\n{Fore.CYAN}[INFO] Exporting active scan results...{Style.RESET_ALL}")
            json_file = a.export_results_json()
            if json_file:
                print(f"{Fore.GREEN}[✓] JSON export: {json_file}{Style.RESET_ALL}\n")
        
        logger.info("Active reconnaissance completed")
    
    # Print scan completed
    formatter.print_scan_completed(target)
    
    # ===== GENERATE REPORT =====
    if args.report:
        formatter.print_separator()
        print(f"\n{Fore.CYAN}Generating Reports...{Style.RESET_ALL}\n")
        
        # Pass both passive and active results (including verification data)
        r = Reporter(target, passive_results, active_results)
        report_path = r.generate_reports(format_type=args.report)
        
        if report_path:
            report_type = args.report.upper()
            formatter.print_report_saved(report_type, report_path)
            logger.info(f"Report generated: {report_path}")
    
    # ===== PRINT SUMMARY =====
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Summary:{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    if passive_results:
        total_subdomains = len(passive_results.get('subdomains', []))
        formatter.print_summary_line("Subdomains found", total_subdomains)
        
        # Show verification summary if available
        if 'verified_subdomains' in passive_results:
            verified = passive_results['verified_subdomains']
            total_live = len(verified.get('live', []))
            total_dead = len(verified.get('dead', []))
            total_internal = len(verified.get('internal', []))
            
            formatter.print_summary_line("   ├─ Verified live", total_live)
            formatter.print_summary_line("   ├─ Dead/unreachable", total_dead)
            if total_internal > 0:
                formatter.print_summary_line("   └─ Internal only", total_internal)
    
    if active_results:
        total_ports = len(active_results.get('open_ports', []))
        total_techs = len(active_results.get('technologies', []))
        total_os_hints = len(active_results.get('os_hints', []))
        
        formatter.print_summary_line("Open ports found", total_ports)
        formatter.print_summary_line("Technologies detected", total_techs)
        
        if total_os_hints > 0:
            formatter.print_summary_line("OS hints found", total_os_hints)
        
        # Show scan method used
        if args.use_nmap:
            print(f"{Fore.GREEN}   Scan method: Nmap (advanced){Style.RESET_ALL}")
        else:
            print(f"   Scan method: Socket (concurrent)")
    
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    # Helpful tips
    if args.use_nmap and total_ports > 0:
        print(f"{Fore.YELLOW}[TIP] Nmap provided service versions and OS detection{Style.RESET_ALL}")
    
    if not args.use_nmap and (args.ports or args.all):
        print(f"{Fore.YELLOW}[TIP] Use --use-nmap for more accurate service detection{Style.RESET_ALL}")
    
    if args.scan_mode == 'quick':
        print(f"{Fore.YELLOW}[TIP] Use --scan-mode normal or --scan-mode full for more thorough scanning{Style.RESET_ALL}")
    
    print()
    
    logger.info("=== Reconnaissance Tool Finished ===")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user. Exiting...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Goodbye!{Style.RESET_ALL}\n")
        sys.exit(0)
    except Exception as e:
        logging.exception("Fatal error occurred")
        print(f"\n{Fore.RED}[ERROR] Fatal error: {e}{Style.RESET_ALL}")
        print("Check the log file in ./logs/ for more details\n")
        sys.exit(1)