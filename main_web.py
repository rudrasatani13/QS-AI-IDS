#!/usr/bin/env python3
# main_web.py - QS-AI-IDS Website Analysis Module

import os
import argparse
import sys
import signal
import time
from moniter.web_analyzer import WebTrafficAnalyzer
from moniter.sniffer import NetworkSniffer

# Global flag for graceful shutdown
shutdown_requested = False

def signal_handler(sig, frame):
    """Handle interrupt signals gracefully"""
    global shutdown_requested
    print("\n[CTRL+C] Shutdown requested. Please wait...")
    shutdown_requested = True

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)

def print_banner():
    """Display the system banner."""
    banner = """
 ██████╗ ███████╗       █████╗ ██╗    ██╗██████╗ ███████╗
██╔═══██╗██╔════╝      ██╔══██╗██║    ██║██╔══██╗██╔════╝
██║   ██║███████╗█████╗███████║██║    ██║██║  ██║███████╗
██║▄▄ ██║╚════██║╚════╝██╔══██║██║    ██║██║  ██║╚════██║
╚██████╔╝███████║      ██║  ██║██████╔╝███████║███████║
 ╚══▀▀═╝ ╚══════╝      ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝
                                                          
🔍 Website Security Analysis Module
"""
    print(banner)
    print("="*70)

def main():
    """Main entry point for website analysis."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="QS-AI-IDS Website Analysis")
    parser.add_argument("--interface", type=str, help="Network interface to monitor")
    parser.add_argument("--verify", type=str, help="URL to actively verify")
    parser.add_argument("--dashboard", action="store_true", help="Launch web dashboard")
    args = parser.parse_args()
    
    # Check if running as root for packet capture
    if not args.verify and os.geteuid() != 0:
        print("Error: This program must be run as root to capture network traffic.")
        print("Please run again with sudo or use --verify to check a specific website.")
        sys.exit(1)
    
    # Print banner
    print_banner()
    
    # Launch dashboard if requested
    if args.dashboard:
        print("[INFO] Launching web dashboard...")
        from dashboard.web_dashboard import WebSecurityDashboard
        dashboard = WebSecurityDashboard()
        dashboard.run_dashboard()
        return
    
    # Single website verification
    if args.verify:
        print(f"[INFO] Verifying website: {args.verify}")
        analyzer = WebTrafficAnalyzer()
        results = analyzer.verify_website(args.verify)
        
        # Print results
        print("\n" + "="*50)
        print(f"RESULTS FOR: {results.get('url', args.verify)}")
        print("="*50)
        
        if 'error' in results:
            print(f"ERROR: {results['error']}")
        else:
            print(f"IP Address: {results.get('ip', 'Unknown')}")
            print(f"HTTPS: {'Yes' if results.get('https') else 'No'}")
            
            if 'cipher' in results:
                print(f"\nTLS Version: {results['cipher']['version']}")
                print(f"Cipher: {results['cipher']['name']} ({results['cipher']['bits']} bits)")
            
            if 'certificate' in results:
                print("\nCertificate Information:")
                for key, value in results['certificate'].items():
                    print(f"  {key}: {value}")
            
            if results.get('security_issues'):
                print("\nSecurity Issues:")
                for i, issue in enumerate(results['security_issues'], 1):
                    print(f"  {i}. {issue}")
            else:
                print("\nNo security issues detected!")
                
        return
    
    # Initialize web analyzer
    analyzer = WebTrafficAnalyzer()
    packet_count = 0
    
    # Define packet handler
    def packet_handler(pkt):
        nonlocal packet_count
        packet_count += 1
        
        # Analyze for web traffic
        results = analyzer.analyze_packet(pkt)
        
        # If attack detected, print details
        if results and 'attack_types' in results:
            print(f"\n[ALERT] Potential web attack detected in packet {packet_count}:")
            print(f"  URL: {results['url']}")
            print(f"  Attack Types: {', '.join(results['attack_types'])}")
            print(f"  Severity: {results['severity']:.2f}")
            print("-"*50)
    
    # Start sniffer
    print(f"[INFO] Starting web traffic analysis on interface: {args.interface or 'default'}")
    sniffer = NetworkSniffer(iface=args.interface, packet_handler=packet_handler)
    sniffer.start()
    
    # Track statistics
    last_stats_time = time.time()
    stats_interval = 10  # seconds
    
    try:
        while not shutdown_requested:
            current_time = time.time()
            
            # Show statistics periodically
            if current_time - last_stats_time >= stats_interval:
                stats = analyzer.get_statistics()
                
                print("\n" + "="*50)
                print(f"WEB TRAFFIC STATISTICS (last {stats_interval} seconds)")
                print("="*50)
                print(f"Domains monitored: {stats['domains_count']}")
                print(f"URLs analyzed: {stats['analyzed_urls_count']}")
                print(f"HTTP methods: {dict(stats['http_methods'])}")
                
                if stats['attack_types_detected']:
                    print("\nAttack types detected:")
                    for attack, count in stats['attack_types_detected'].items():
                        print(f"  {attack}: {count}")
                
                if stats['top_suspicious_domains']:
                    print("\nTop suspicious domains:")
                    for domain, count in stats['top_suspicious_domains']:
                        print(f"  {domain}: {count} suspicious activities")
                
                print("-"*50)
                last_stats_time = current_time
            
            # Don't hog CPU
            time.sleep(0.1)
    
    finally:
        # Clean shutdown
        print("\n[SHUTDOWN] Stopping web analysis...")
        sniffer._stop_event.set()
        print("[✓] Web analysis stopped.")

if __name__ == "__main__":
    main()