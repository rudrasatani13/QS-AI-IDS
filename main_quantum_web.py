#!/usr/bin/env python3
# main_quantum_web.py - QS-AI-IDS Quantum Website Analysis Module (Target domain support)

import os
import argparse
import sys
import signal
import time
from moniter.quantum_web_analyzer import QuantumWebTrafficAnalyzer
from moniter.sniffer import NetworkSniffer

shutdown_requested = False

def signal_handler(sig, frame):
    global shutdown_requested
    print("\n[CTRL+C] Shutdown requested. Please wait...")
    shutdown_requested = True

signal.signal(signal.SIGINT, signal_handler)

def print_banner():
    banner = """
 ██████╗ ███████╗       █████╗ ██╗    ██╗██████╗ ███████╗
██╔═══██╗██╔════╝      ██╔══██╗██║    ██║██╔══██╗██╔════╝
██║   ██║███████╗█████╗███████║██║    ██║██║  ██║███████╗
██║▄▄ ██║╚════██║╚════╝██╔══██║██║    ██║██║  ██║╚════██║
╚██████╔╝███████║      ██║  ██║██████╔╝███████║███████║
 ╚══▀▀═╝ ╚══════╝      ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝

🧬 Quantum-Enhanced Website Security Analysis
"""
    print(banner)
    print("=" * 70)

def extract_domain(pkt):
    # HTTP packet (Scapy HTTP layer)
    if pkt.haslayer("HTTPRequest"):
        try:
            host = pkt["HTTPRequest"].Host.decode()
            return host
        except Exception:
            return None
    # TLS SNI extraction (Scapy's TLS layer)
    try:
        if pkt.haslayer("TLS Client Hello"):
            # Scapy TLS handshake SNI
            sni = pkt["TLS Client Hello"].ext_servername
            if isinstance(sni, bytes):
                sni = sni.decode(errors='ignore')
            return sni
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="QS-AI-IDS Quantum Website Analysis (Target domain support)")
    parser.add_argument("--interface", type=str, help="Network interface to monitor")
    parser.add_argument("--verify", type=str, help="URL to actively verify")
    parser.add_argument("--classical", action="store_true", help="Use classical algorithms only")
    parser.add_argument("--target", type=str, help="Target domain for focused analysis (e.g., example.com)")
    args = parser.parse_args()

    if not args.verify and os.geteuid() != 0:
        print("Error: This program must be run as root to capture network traffic.")
        print("Please run again with sudo or use --verify to check a specific website.")
        sys.exit(1)

    print_banner()
    if not args.classical:
        print("🔬 Quantum algorithms: ENABLED")
        print("Using Variational Quantum Circuit (VQC) with 8 qubits for analysis")
    else:
        print("🔬 Quantum algorithms: DISABLED (running in classical mode)")
    print("-" * 70)

    # Single website verify mode
    if args.verify:
        print(f"[INFO] Verifying website with quantum enhancement: {args.verify}")
        analyzer = QuantumWebTrafficAnalyzer(use_quantum=not args.classical)
        try:
            results = analyzer.verify_website(args.verify)
        except Exception as e:
            print(f"ERROR: Verification failed: {e}")
            sys.exit(1)

        print("\n" + "=" * 50)
        print(f"QUANTUM ANALYSIS RESULTS FOR: {results.get('url', args.verify)}")
        print("=" * 50)

        if 'error' in results:
            print(f"ERROR: {results['error']}")
        else:
            print(f"IP Address: {results.get('ip', 'Unknown')}")
            print(f"HTTPS: {'Yes' if results.get('https') else 'No'}")

            if 'quantum_analysis' in results and results['quantum_analysis']:
                print("\n=== QUANTUM SECURITY ANALYSIS ===")
                quantum_results = results['quantum_analysis']
                if quantum_results.get('is_malicious'):
                    print("⚠️  THREAT DETECTED: Quantum analysis indicates this site is potentially malicious")
                    print(f"Severity: {quantum_results['severity']:.2f}")
                    print("\nAttack Probabilities:")
                    for attack_type, data in quantum_results['predictions'].items():
                        status = "DETECTED" if data['detected'] else "Low Risk"
                        print(f"  {attack_type.replace('_', ' ').title()}: {data['probability']:.2f} ({status})")
                else:
                    print("✅ SECURE: Quantum analysis indicates this site is likely safe")

            if 'cipher' in results:
                print(f"\nTLS Version: {results['cipher']['version']}")
                print(f"Cipher: {results['cipher']['name']} ({results['cipher']['bits']} bits)")

            if results.get('security_issues'):
                print("\nSecurity Issues:")
                for i, issue in enumerate(results['security_issues'], 1):
                    print(f"  {i}. {issue}")
            else:
                print("\nNo classical security issues detected!")

            if 'risk_score' in results:
                print(f"\nRisk Assessment: {results['risk_level']} ({results['risk_score']:.2f})")
        return

    analyzer = QuantumWebTrafficAnalyzer(use_quantum=not args.classical)
    packet_count = 0

    def packet_handler(pkt):
        nonlocal packet_count
        packet_count += 1

        # Target filter logic
        if args.target:
            domain = extract_domain(pkt)
            if not domain or args.target not in domain:
                return  # Only analyze packets for target domain

        try:
            results = analyzer.analyze_packet(pkt)
            if results and 'attack_types' in results:
                print(f"\n[QUANTUM ALERT] Web attack detected in packet {packet_count}:")
                print(f"  URL: {results['url']}")
                print(f"  Attack Types: {', '.join(results['attack_types'])}")
                print(f"  Severity: {results['severity']:.2f}")
                if 'quantum_details' in results:
                    print("  Quantum Analysis Details:")
                    for attack_type, data in results['quantum_details'].items():
                        print(f"    {attack_type}: {data['probability']:.2f}")
                print("-" * 50)
        except Exception as e:
            print(f"[ERROR] Packet analysis failed: {e}")

    print(f"[INFO] Starting quantum web traffic analysis on interface: {args.interface or 'default'}")
    try:
        sniffer = NetworkSniffer(iface=args.interface, packet_handler=packet_handler)
        sniffer.start()
    except Exception as e:
        print(f"[ERROR] Could not start network sniffer: {e}")
        sys.exit(1)

    last_stats_time = time.time()
    stats_interval = 10

    try:
        while not shutdown_requested:
            current_time = time.time()
            if current_time - last_stats_time >= stats_interval:
                try:
                    stats = analyzer.get_statistics()
                    print("\n" + "=" * 50)
                    print(f"QUANTUM WEB TRAFFIC STATISTICS (last {stats_interval} seconds)")
                    print("=" * 50)
                    print(f"Domains monitored: {stats['domains_count']}")
                    print(f"URLs analyzed: {stats['analyzed_urls_count']}")
                    print(f"HTTP methods: {dict(stats['http_methods'])}")
                    print(f"Quantum confidence: {stats.get('average_quantum_confidence', 0):.2f}")
                    if stats['attack_types_detected']:
                        print("\nAttack types detected:")
                        for attack, count in stats['attack_types_detected'].items():
                            print(f"  {attack}: {count}")
                    if stats['top_suspicious_domains']:
                        print("\nTop suspicious domains:")
                        for domain, count in stats['top_suspicious_domains']:
                            print(f"  {domain}: {count} suspicious activities")
                    print("-" * 50)
                    last_stats_time = current_time
                except Exception as e:
                    print(f"[ERROR] Statistics display failed: {e}")
            time.sleep(0.1)
    finally:
        print("\n[SHUTDOWN] Stopping quantum web analysis...")
        try:
            sniffer._stop_event.set()
        except Exception:
            pass
        print("[✓] Quantum web analysis stopped.")

if __name__ == "__main__":
    main()