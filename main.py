#!/usr/bin/env python3
# main.py - Advanced QS-AI-IDS (Quantum-Safe AI Intrusion Detection System)

import os
import sys
import time
import yaml
import torch
import logging
import argparse
import signal
import threading
from typing import Dict

# Core imports
from core.encoder import QuantumFeatureEncoder
from core.hybrid_model import HybridAnomalyDetector
from core.classical_model import ClassicalAnomalyDetector
from core.quantum_model import QuantumAnomalyDetector
from moniter.feature_extractor import FeatureExtractor
from moniter.sniffer import NetworkSniffer
from crypto.logger import SecureLogger

# Placeholder: for explainability module (SHAP/LIME integration)
# from explainability.explainer import ExplainabilityEngine

# Global flag for graceful shutdown
shutdown_requested = False

def signal_handler(sig, frame):
    """Handle interrupt signals gracefully."""
    global shutdown_requested
    print("\n[CTRL+C] Shutdown requested. Please wait...")
    shutdown_requested = True

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)

# Load config from YAML
def load_config(path="config/config.yaml"):
    if not os.path.exists(path):
        print(f"[ERROR] Config file not found: {path}")
        sys.exit(1)
    with open(path, "r") as f:
        config = yaml.safe_load(f)
    return config

# Setup logging (file + stdout)
def setup_logging(logfile="qsaiids.log", level="INFO"):
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[
            logging.FileHandler(logfile),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logging.info("Logging initialized.")

def print_banner():
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

def main():
    global shutdown_requested

    # CLI Arguments (override config if provided)
    parser = argparse.ArgumentParser(description="Quantum-Safe AI Intrusion Detection System")
    parser.add_argument("--simulate", action="store_true", help="Generate simulated traffic")
    parser.add_argument("--interface", type=str, help="Network interface to monitor")
    parser.add_argument("--window", type=int, help="Analysis window size in seconds")
    parser.add_argument("--config", type=str, default="config/config.yaml", help="Path to config file")
    args = parser.parse_args()

    # Load config
    config = load_config(args.config)

    # CLI > config (override)
    simulate = args.simulate or config.get("simulate", False)
    iface = args.interface if args.interface else config.get("interface", None)
    window_size = args.window if args.window else config.get("window", 5)
    threshold = config.get("threshold", 0.7)
    model_type = config.get("model_type", "hybrid")
    log_file = config.get("logging", {}).get("log_file", "qsaiids.log")
    log_level = config.get("logging", {}).get("log_level", "INFO")

    # Setup logging
    setup_logging(logfile=log_file, level=log_level)

    if not simulate and os.geteuid() != 0:
        logging.error("Run as root for live packet capture (sudo), or use --simulate.")
        sys.exit(1)

    os.makedirs("secure_logs", exist_ok=True)
    print_banner()
    logging.info(f"Simulation mode: {simulate}")
    logging.info(f"Monitoring interface: {iface}")
    logging.info(f"Analysis window: {window_size}s | Threshold: {threshold}")
    logging.info(f"Selected model: {model_type}")

    # Initialize model
    if model_type == "hybrid":
        model = HybridAnomalyDetector()
    elif model_type == "quantum":
        model = QuantumAnomalyDetector()
    else:
        model = ClassicalAnomalyDetector()
    encoder = QuantumFeatureEncoder()
    extractor = FeatureExtractor(window_size=window_size)
    logger = SecureLogger()
    # explainer = ExplainabilityEngine()  # Placeholder

    # Simulated traffic class (as before)
    class SimulatedTrafficGenerator:
        def __init__(self, packet_handler, interval_range=(0.1, 0.3)):
            self.packet_handler = packet_handler
            self.interval_range = interval_range
            self.running = False
            self.thread = None
            self.src_ips = ["192.168.1." + str(i) for i in range(1, 20)]
            self.dst_ips = ["10.0.0." + str(i) for i in range(1, 20)]
            self.common_ports = [80, 443, 8080, 53, 22, 25, 3389, 5900]

        def start(self):
            self.running = True
            self.thread = threading.Thread(target=self._generation_loop, daemon=True)
            self.thread.start()
            logging.info("[SIMULATOR] Started generating synthetic traffic")

        def stop(self):
            self.running = False
            logging.info("[SIMULATOR] Stopping traffic generator...")

        def _generation_loop(self):
            from scapy.layers.inet import IP, TCP, UDP
            import random
            while self.running:
                try:
                    src_ip = random.choice(self.src_ips)
                    dst_ip = random.choice(self.dst_ips)
                    src_port = random.randint(1024, 65535)
                    dst_port = random.choice(self.common_ports)
                    ttl = random.randint(54, 64)
                    if random.random() < 0.1:
                        dst_port = random.randint(1, 65535)
                        ttl = random.randint(30, 60)
                    if random.random() < 0.8:
                        pkt = IP(src=src_ip, dst=dst_ip, ttl=ttl)/TCP(sport=src_port, dport=dst_port)
                        payload = bytes([random.randint(32, 126) for _ in range(random.randint(10, 200))])
                        pkt = pkt/payload
                    else:
                        pkt = IP(src=src_ip, dst=dst_ip, ttl=ttl)/UDP(sport=src_port, dport=dst_port)
                        payload = bytes([random.randint(32, 126) for _ in range(random.randint(10, 100))])
                        pkt = pkt/payload
                    self.packet_handler(pkt)
                except Exception as e:
                    logging.error(f"Simulated packet processing error: {e}")
                time.sleep(random.uniform(*self.interval_range))

    # Packet handler
    packet_count = 0
    last_analysis_packet_count = 0
    packets_between_analyses = 25

    def handle_packet(pkt):
        nonlocal packet_count
        if shutdown_requested:
            return
        packet_count += 1
        try:
            extractor.add_packet(pkt)
            if packet_count % 10 == 0:
                logging.debug(f"Processed {packet_count} packets")
        except Exception as e:
            logging.error(f"Packet handling error: {e}")

    # Start traffic source
    traffic_source = None
    if simulate:
        traffic_source = SimulatedTrafficGenerator(handle_packet)
        traffic_source.start()
        logging.info("Using simulated traffic.")
    else:
        traffic_source = NetworkSniffer(iface=iface, packet_handler=handle_packet)
        traffic_source.start()
        logging.info("Started network sniffer.")

    # Main analysis loop
    last_analysis_time = time.time()
    last_feature_display_time = time.time()
    display_interval = 2  # seconds
    analysis_interval = window_size

    try:
        while not shutdown_requested:
            current_time = time.time()

            # Display features periodically (debug)
            if current_time - last_feature_display_time > display_interval:
                try:
                    features = extractor.get_feature_vector()
                    if features:
                        logging.debug(f"Packets processed: {packet_count} | Features: {features}")
                except Exception as e:
                    logging.error(f"Feature display error: {e}")
                last_feature_display_time = current_time

            # Run analysis based on time or packet count
            force_analysis = packet_count - last_analysis_packet_count >= packets_between_analyses
            time_for_analysis = current_time - last_analysis_time >= analysis_interval

            if force_analysis or time_for_analysis:
                try:
                    features = extractor.get_feature_vector()
                    if not features or features.get('packet_rate', 0) == 0:
                        logging.info("No significant traffic in current window.")
                    else:
                        print("\n" + "="*70)
                        print(f"[ANALYSIS] Traffic at {time.strftime('%H:%M:%S')}")
                        print("-"*70)
                        print(f"[MODEL] Encoding features...")
                        angle_vector = encoder.encode(features)
                        input_tensor = torch.tensor([angle_vector], dtype=torch.float32)
                        print("[MODEL] Running detection...")
                        score_tensor = model.predict(input_tensor)
                        score = float(score_tensor.item())
                        label = "⚠️ ANOMALOUS" if score > threshold else "✅ NORMAL"
                        print(f"\n[RESULT] Anomaly Score: {score:.4f} | Traffic: {label}")

                        # Placeholder for explainability
                        # explanation = explainer.explain(features)
                        # print(f"[EXPLAIN] {explanation}")

                        logger.log_event({
                            "anomaly_score": round(score, 4),
                            "features": features,
                            "decision": label
                        })

                    last_analysis_time = current_time
                    last_analysis_packet_count = packet_count

                except Exception as e:
                    logging.error(f"Analysis exception: {e}")

            time.sleep(0.1)

    finally:
        # Clean shutdown
        print("\n[SHUTDOWN] Stopping all components...")
        if traffic_source:
            try:
                traffic_source.stop()
            except:
                pass
        print("[✓] Shutdown complete - Thanks for using QS-AI-IDS!")

if __name__ == "__main__":
    main()