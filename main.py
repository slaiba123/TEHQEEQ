# """
# Modular Reconnaissance Tool v2.0
# Main entry point for the reconnaissance tool
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
# from utils import show_disclaimer, print_banner, parse_target


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
#             logging.StreamHandler() if verbose else logging.NullHandler()
#         ]
#     )


# def main():
#     # Display banner
#     print_banner()
    
#     # Parse arguments
#     parser = argparse.ArgumentParser(
#         description="Modular Reconnaissance Tool v2.0",
#         formatter_class=argparse.RawDescriptionHelpFormatter,
#         epilog="""
# Examples:
#   %(prog)s example.com --all --report txt
#   %(prog)s example.com --whois --dns
#   %(prog)s 192.168.1.1 --ports --banner
#   %(prog)s target.com --subdomains --report json
#   %(prog)s example.com --ports --tech --nmap
#         """
#     )
    
#     parser.add_argument("target", help="Target domain or IP address")
    
#     # Passive recon flags
#     parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
#     parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
#     parser.add_argument("--subdomains", action="store_true", help="Perform subdomain enumeration")
    
#     # Active recon flags
#     parser.add_argument("--ports", action="store_true", help="Perform port scanning")
#     parser.add_argument("--banner", action="store_true", help="Grab banners from open ports")
#     parser.add_argument("--tech", action="store_true", help="Detect web technologies")
#     parser.add_argument("--nmap", action="store_true", help="Use Nmap for port scanning (requires python-nmap)")
    
#     # Reporting
#     parser.add_argument("--report", choices=["txt", "json", "pdf"], help="Generate report in specified format")
#     parser.add_argument("--output", "-o", help="Custom output directory for reports")
    
#     # Miscellaneous
#     parser.add_argument("--all", action="store_true", help="Run all reconnaissance modules")
#     parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output (show debug logs)")
#     parser.add_argument("--skip-disclaimer", action="store_true", help="Skip legal disclaimer (not recommended)")
    
#     args = parser.parse_args()
    
#     # Set up logging
#     setup_logging(verbose=args.verbose)
#     logger = logging.getLogger(__name__)
#     logger.info("=== Reconnaissance Tool Started ===")
    
#     # Check if user specified at least one scan type
#     if not (args.whois or args.dns or args.subdomains or args.ports or 
#             args.banner or args.tech or args.all):
#         print(Fore.RED + "\n❌ Error: Please specify at least one scan type!\n")
#         print("Examples:")
#         print("  python main.py example.com --all")
#         print("  python main.py example.com --whois --dns")
#         print("  python main.py example.com --ports --tech")
#         print("\nFor more help, use: python main.py --help\n")
#         sys.exit(1)
    
#     # Validate target
#     try:
#         target, target_type = parse_target(args.target)
#         logger.info(f"Target validated: {target} (type: {target_type})")
#     except ValueError as e:
#         print(Fore.RED + f"\n❌ Invalid target: {e}\n")
#         logger.error(f"Invalid target: {e}")
#         sys.exit(1)
    
#     # Show disclaimer (unless skipped)
#     if not args.skip_disclaimer:
#         show_disclaimer()
    
#     # Set custom output directory if specified
#     if args.output:
#         import config
#         config.REPORTS_FOLDER = args.output
#         logger.info(f"Custom output directory set: {args.output}")
    
#     print(Fore.GREEN + f"\n[+] Starting reconnaissance on: {target}\n" + Style.RESET_ALL)
    
#     # Initialize results dictionaries
#     passive_results = {}
#     active_results = {}
    
#     # Run Passive Recon
#     if args.whois or args.dns or args.subdomains or args.all:
#         print(Fore.CYAN + "\n" + "="*60)
#         print("🔍 PASSIVE RECONNAISSANCE PHASE")
#         print("="*60 + Style.RESET_ALL)
        
#         p = PassiveRecon(target)
        
#         if args.whois or args.all:
#             passive_results['whois'] = p.whois_lookup()
        
#         if args.dns or args.all:
#             passive_results['dns'] = p.dns_enumeration()
        
#         if args.subdomains or args.all:
#             passive_results['subdomains'] = p.subdomain_enumeration()
        
#         logger.info("Passive reconnaissance completed")
    
#     # Run Active Recon
#     if args.ports or args.banner or args.tech or args.all:
#         print(Fore.CYAN + "\n" + "="*60)
#         print("🎯 ACTIVE RECONNAISSANCE PHASE")
#         print("="*60 + Style.RESET_ALL)
        
#         a = ActiveRecon(target)
        
#         if args.ports or args.all:
#             a.port_scan(use_nmap=args.nmap)
        
#         if args.banner or args.all:
#             a.banner_grab()
        
#         if args.tech or args.all:
#             a.detect_technologies()
        
#         active_results = a.results
#         logger.info("Active reconnaissance completed")
    
#     # Generate report if requested
#     if args.report:
#         r = Reporter(target, passive_results, active_results)
#         report_path = r.generate_reports(format_type=args.report)
        
#         if report_path:
#             print(Fore.GREEN + f"\n[✓] Report generated successfully!")
#             logger.info(f"Report generated: {report_path}")
    
#     # Final summary
#     print(Fore.GREEN + "\n" + "="*60)
#     print("✅ RECONNAISSANCE COMPLETE")
#     print("="*60)
    
#     if passive_results:
#         total_subdomains = len(passive_results.get('subdomains', []))
#         print(f"   • Subdomains found: {total_subdomains}")
    
#     if active_results:
#         total_ports = len(active_results.get('open_ports', []))
#         total_techs = len(active_results.get('technologies', []))
#         print(f"   • Open ports found: {total_ports}")
#         print(f"   • Technologies detected: {total_techs}")
    
#     print("="*60 + "\n" + Style.RESET_ALL)
    
#     logger.info("=== Reconnaissance Tool Finished ===")


# if __name__ == "__main__":
#     try:
#         main()
#     except KeyboardInterrupt:
#         print(Fore.YELLOW + "\n\n⚠️  Scan interrupted by user. Exiting gracefully...")
#         print(Fore.CYAN + "Goodbye!\n" + Style.RESET_ALL)
#         sys.exit(0)
#     except Exception as e:
#         logging.exception("Fatal error occurred")
#         print(Fore.RED + f"\n❌ Fatal error: {e}")
#         print("Check the log file in ./logs/ for more details\n" + Style.RESET_ALL)
#         sys.exit(1)


"""
TEHQEEQ - تحقیق
Advanced Network Reconnaissance Tool v2.0
For Authorized Security Testing Only
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
from utils import parse_target


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
  %(prog)s example.com --all --report pdf
  %(prog)s example.com --whois --dns -vv
  %(prog)s target.com --full --verify
  %(prog)s neduet.edu.pk --all -vv
  %(prog)s -d google.com --full -vvv --report html
        """
    )
    
    parser.add_argument("target", help="Target domain or IP address")
    parser.add_argument("-d", "--domain", dest="target_alt", help="Target domain (alternative)")
    
    # Scan options
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--dns", action="store_true", help="Perform DNS enumeration")
    parser.add_argument("--subdomains", action="store_true", help="Perform subdomain enumeration")
    parser.add_argument("--ports", action="store_true", help="Perform port scanning")
    parser.add_argument("--banner", action="store_true", help="Grab banners from open ports")
    parser.add_argument("--tech", action="store_true", help="Detect web technologies")
    parser.add_argument("--all", "--full", action="store_true", help="Run all reconnaissance modules")
    
    # Reporting
    parser.add_argument("--report", choices=["txt", "json", "pdf", "html"], help="Generate report")
    parser.add_argument("--output", "-o", help="Custom output directory for reports")
    
    # Verbosity
    parser.add_argument("-v", "--verbose", action="count", default=0, 
                       help="Increase verbosity (-v, -vv, -vvv)")
    parser.add_argument("--skip-disclaimer", action="store_true", help="Skip legal disclaimer")
    
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
        print("  python main.py example.com --ports --tech")
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
        import config
        config.REPORTS_FOLDER = args.output
        logger.info(f"Custom output directory set: {args.output}")
    
    # Print target info
    formatter.print_target_info(target, verbosity, full_scan=args.all)
    
    # Print scan started
    formatter.print_scan_started(target)
    
    # Initialize results dictionaries
    passive_results = {}
    active_results = {}
    
    # Run Passive Recon
    if args.whois or args.dns or args.subdomains or args.all:
        p = PassiveRecon(target, formatter=formatter)
        
        if args.whois or args.all:
            passive_results['whois'] = p.whois_lookup()
        
        if args.dns or args.all:
            passive_results['dns'] = p.dns_enumeration()
        
        if args.subdomains or args.all:
            passive_results['subdomains'] = p.subdomain_enumeration()
        
        logger.info("Passive reconnaissance completed")
    
    # Run Active Recon
    if args.ports or args.banner or args.tech or args.all:
        a = ActiveRecon(target, formatter=formatter)
        
        if args.ports or args.all:
            a.port_scan()
        
        if args.banner or args.all:
            a.banner_grab()
        
        if args.tech or args.all:
            a.detect_technologies()
        
        active_results = a.results
        logger.info("Active reconnaissance completed")
    
    # Print scan completed
    formatter.print_scan_completed(target)
    
    # Generate report if requested
    if args.report:
        formatter.print_separator()
        print(f"\n{Fore.CYAN}Generating Reports...{Style.RESET_ALL}\n")
        
        r = Reporter(target, passive_results, active_results)
        report_path = r.generate_reports(format_type=args.report)
        
        if report_path:
            report_type = args.report.upper()
            formatter.print_report_saved(report_type, report_path)
            logger.info(f"Report generated: {report_path}")
    
    # Print summary
    print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
    
    if passive_results:
        total_subdomains = len(passive_results.get('subdomains', []))
        formatter.print_summary_line("Subdomains found", total_subdomains)
    
    if active_results:
        total_ports = len(active_results.get('open_ports', []))
        total_techs = len(active_results.get('technologies', []))
        formatter.print_summary_line("Open ports found", total_ports)
        formatter.print_summary_line("Technologies detected", total_techs)
    
    print()
    logger.info("=== Reconnaissance Tool Finished ===")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user. Exiting gracefully...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Goodbye!{Style.RESET_ALL}\n")
        sys.exit(0)
    except Exception as e:
        logging.exception("Fatal error occurred")
        print(f"\n{Fore.RED}[ERROR] Fatal error: {e}{Style.RESET_ALL}")
        print("Check the log file in ./logs/ for more details\n")
        sys.exit(1)