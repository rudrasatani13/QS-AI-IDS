#!/usr/bin/env python3
# main.py - QS-AI-IDS: Quantum-Safe AI Intrusion Detection System

import os
import time
import torch
import datetime
import threading
import random
import sys
import argparse
from typing import Dict, List

# Import core components
from core.encoder import QuantumFeatureEncoder
from core.hybrid_model import HybridAnomalyDetector
from moniter.feature_extractor import FeatureExtractor
from moniter.sniffer import NetworkSniffer
from crypto.logger import SecureLogger

# Set up command-line arguments
parser = argparse.ArgumentParser(description="Quantum-Safe AI Intrusion Detection System")
parser.add_argument("--mode", choices=["cli", "demo"], default="cli", help="Run mode: cli or demo")
parser.add_argument("--interface", type=str, help="Network interface to monitor (e.g., en0)")
parser.add_argument("--window", type=int, default=5, help="Analysis window size in seconds")
parser.add_argument("--simulate", action="store_true", help="Generate simulated traffic")
args = parser.parse_args()

class SimulatedTrafficGenerator:
    """Generates synthetic network traffic for testing and demonstration."""
    
    def __init__(self, packet_handler, interval_range=(0.1, 0.3)):
        self.packet_handler = packet_handler
        self.interval_range = interval_range
        self.running = False
        self.thread = None
        
        # Traffic pattern settings
        self.src_ips = ["192.168.1." + str(i) for i in range(1, 20)]
        self.dst_ips = ["10.0.0." + str(i) for i in range(1, 20)]
        self.common_ports = [80, 443, 8080, 53, 22, 25, 3389, 5900]
        
    def start(self):
        """Start generating simulated traffic."""
        if self.thread and self.thread.is_alive():
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._generation_loop, daemon=True)
        self.thread.start()
        print("[SIMULATOR] Started generating synthetic traffic")
        
    def stop(self):
        """Stop the traffic generator."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[SIMULATOR] Stopped traffic generator")
        
    def _generation_loop(self):
        """Main loop that generates packets at random intervals."""
        while self.running:
            # Create a random packet
            packet = self._create_random_packet()
            
            # Send to handler
            try:
                self.packet_handler(packet)
            except Exception as e:
                print(f"[ERROR] Failed to process simulated packet: {e}")
                
            # Wait random interval
            time.sleep(random.uniform(*self.interval_range))
            
    def _create_random_packet(self):
        """Create a randomized packet with realistic characteristics."""
        from scapy.layers.inet import IP, TCP, UDP
        
        src_ip = random.choice(self.src_ips)
        dst_ip = random.choice(self.dst_ips)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(self.common_ports)
        
        # Occasional anomalous traffic patterns (10% chance)
        if random.random() < 0.1:
            # Create port scan pattern (many ports, one IP)
            dst_port = random.randint(1, 65535)
            ttl = random.randint(30, 60)  # Lower TTL for suspect traffic
        else:
            ttl = random.randint(54, 64)  # Normal TTL range
        
        # Protocol selection (80% TCP, 20% UDP)
        if random.random() < 0.8:
            # TCP packet
            packet = IP(src=src_ip, dst=dst_ip, ttl=ttl)/TCP(sport=src_port, dport=dst_port)
            # Add random payload
            payload_size = random.randint(10, 200)
            payload = bytes([random.randint(32, 126) for _ in range(payload_size)])
            packet = packet/payload
        else:
            # UDP packet
            packet = IP(src=src_ip, dst=dst_ip, ttl=ttl)/UDP(sport=src_port, dport=dst_port)
            # Add random payload
            payload_size = random.randint(10, 100)
            payload = bytes([random.randint(32, 126) for _ in range(payload_size)])
            packet = packet/payload
            
        return packet


def print_banner():
    """Display the system banner."""
    banner = """
 ██████╗ ███████╗       █████╗ ██╗    ██╗██████╗ ███████╗
██╔═══██╗██╔════╝      ██╔══██╗██║    ██║██╔══██╗██╔════╝
██║   ██║███████╗█████╗███████║██║    ██║██║  ██║███████╗
██║▄▄ ██║╚════██║╚════╝██╔══██║██║    ██║██║  ██║╚════██║
╚██████╔╝███████║      ██║  ██║██║    ██║██████╔╝███████║
 ╚══▀▀═╝ ╚══════╝      ╚═╝  ╚═╝╚═╝    ╚═╝╚═════╝ ╚══════╝
                                                          
🔐 Quantum-Safe AI Intrusion Detection System 🛡️
"""
    print(banner)
    print("="*70)


def run_full_analysis(extractor, encoder, model, logger):
    """Run a complete analysis cycle."""
    features = extractor.get_feature_vector()
    if not features or features.get('packet_rate', 0) == 0:
        print("[!] No traffic captured in window. Waiting...")
        return False
    
    try:
        # Display analysis header
        print("\n" + "="*70)
        print(f"[ANALYSIS] Traffic analysis at {datetime.datetime.now().strftime('%H:%M:%S')}")
        print("-"*70)
        
        # Feature encoding
        print("[MODEL] Encoding network features to quantum angles...")
        angle_vector = encoder.encode(features)
        input_tensor = torch.tensor([angle_vector], dtype=torch.float32)
        
        # Model prediction
        print("[MODEL] Running hybrid quantum-classical detection...")
        score_tensor = model.predict(input_tensor)
        score = float(score_tensor.item())
        
        # Decision
        threshold = 0.7
        if score > threshold:
            label = "⚠️ ANOMALOUS"
        else:
            label = "✅ NORMAL"
        
        # Output fancy results
        print(f"\n[RESULT] Anomaly Score: {score:.4f} | Traffic: {label}")
        
        # Enhanced feature display
        print("\n┌─────────────────────────────────────────────────────────┐")
        print("│ Feature Analysis                                        │")
        print("├─────────────────┬───────────────────────────────────────┤")
        print(f"│ Packet Rate     │ {features['packet_rate']:.2f} pkts/s{' '*(28-len(str(int(features['packet_rate']))))}│")
        print(f"│ TTL Average     │ {features['avg_ttl']:.1f}{' '*(34-len(str(int(features['avg_ttl']))))}│")
        print(f"│ Unique IPs      │ {features['unique_src_ips']}{' '*(34-len(str(features['unique_src_ips'])))}│")
        print(f"│ Unique Ports    │ {features['unique_dst_ports']}{' '*(34-len(str(features['unique_dst_ports'])))}│")
        print(f"│ Byte Entropy    │ {features['byte_entropy']:.2f}{' '*(32-len(str(int(features['byte_entropy']))))}│")
        print(f"│ TCP/UDP Ratio   │ {features['tcp_udp_ratio']:.2f}{' '*(32-len(str(int(features['tcp_udp_ratio']))))}│")
        print("└─────────────────┴───────────────────────────────────────┘")
        
        # Log to secure file
        logger.log_event({
            "anomaly_score": round(score, 4),
            "features": features,
            "decision": label
        })
        
        return True
    except Exception as e:
        print(f"[ERROR] Processing exception: {e}")
        return False


def run_cli_mode(window_size: int = 5, interface: str = None, simulate: bool = False):
    """Run the IDS in command-line interface mode."""
    print_banner()
    
    if simulate:
        print("📡 Using simulated traffic for demonstration...")
    else:
        print("📡 Monitoring local interface and logging encrypted anomalies...")
    print()

    # Initialize components
    print("[INIT] Creating encoder...")
    encoder = QuantumFeatureEncoder()
    
    print("[INIT] Creating model...")
    model = HybridAnomalyDetector()
    
    print("[INIT] Creating feature extractor...")
    extractor = FeatureExtractor(window_size=window_size)
    
    print("[INIT] Creating secure logger...")
    logger = SecureLogger()
    
    # Debug packet count
    packet_count = 0
    last_analysis_packet_count = 0
    packets_before_analysis = 30  # Force analysis every 30 packets
    
    def handle_packet(pkt):
        nonlocal packet_count, last_analysis_packet_count
        packet_count += 1
        extractor.add_packet(pkt)
        if packet_count % 10 == 0:  # Log every 10 packets
            print(f"[DEBUG] Processed {packet_count} packets")
    
    # Start traffic collection
    if simulate:
        print("[INIT] Starting traffic simulator...")
        traffic_source = SimulatedTrafficGenerator(handle_packet)
        traffic_source.start()
    else:
        print("[INIT] Starting sniffer...")
        traffic_source = NetworkSniffer(iface=interface, packet_handler=handle_packet)
        traffic_source.start()
    
    print(f"[INFO] Started at {datetime.datetime.now().strftime('%H:%M:%S')}")
    
    if simulate:
        print("[INFO] Collecting initial traffic samples...")
        time.sleep(3)  # Allow time to collect initial packets
    else:
        print("[INFO] Waiting for first packet capture...")
    
    # Track when we last processed a full analysis
    last_analysis_time = time.time()
    last_debug_time = time.time()
    debug_interval = 2  # seconds
    analysis_interval = window_size  # seconds
    
    try:
        while True:
            current_time = time.time()
            
            # Show debug info periodically
            if current_time - last_debug_time > debug_interval:
                features = extractor.get_feature_vector()
                if features:
                    print(f"[DEBUG] Packets processed: {packet_count}")
                    print(f"[DEBUG] Features: {features}")
                last_debug_time = current_time
            
            # Process a full analysis based on either time or packet count
            if (current_time - last_analysis_time >= analysis_interval) or \
               (packet_count - last_analysis_packet_count >= packets_before_analysis):
                
                if run_full_analysis(extractor, encoder, model, logger):
                    last_analysis_time = current_time
                    last_analysis_packet_count = packet_count
                
            # Don't hog CPU
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[CTRL+C] Stopping system...")
        if isinstance(traffic_source, SimulatedTrafficGenerator):
            traffic_source.stop()
        else:
            traffic_source.stop()
        print("[✓] Shutdown complete.")


def main():
    """Main entry point for the application."""
    # Check if running as root if needed
    if not args.simulate and os.geteuid() != 0:
        print("Error: This program must be run as root to capture network traffic.")
        print("Please run again with sudo.")
        sys.exit(1)
    
    # Set up log directory
    os.makedirs("secure_logs", exist_ok=True)
    
    # Run in requested mode
    if args.mode == "cli":
        run_cli_mode(window_size=args.window, interface=args.interface, simulate=args.simulate)
    else:
        print("Demo mode not yet implemented. Please use CLI mode.")
        sys.exit(1)


if __name__ == "__main__":
    main()