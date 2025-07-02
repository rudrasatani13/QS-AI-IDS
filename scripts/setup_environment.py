# scripts/setup_environment.py

import os
import platform
import subprocess
import sys
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

REQUIRED_PACKAGES = [
    "scapy",
    "torch",
    "pennylane[lightning]",
    "streamlit",
    "oqs",
    "psutil"
]

def check_python_version():
    logging.info("Checking Python version...")
    if sys.version_info < (3, 9):
        raise EnvironmentError("Python 3.9 or higher is required.")
    logging.info(f"✓ Python version: {platform.python_version()}")

def detect_mac_environment():
    logging.info("Checking OS and chip...")
    if platform.system().lower() != "darwin":
        raise EnvironmentError("This project is optimized for macOS (Darwin) only.")

    chip_info = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"]).decode()
    if "Apple" not in chip_info:
        raise EnvironmentError("Apple Silicon (M1/M2/M3) required for optimized execution.")
    logging.info(f"✓ Detected Apple chip: {chip_info.strip()}")

def install_packages():
    logging.info("Installing required Python packages...")
    for pkg in REQUIRED_PACKAGES:
        logging.info(f"  → {pkg}")
        subprocess.run([sys.executable, "-m", "pip", "install", pkg], check=True)

def check_liboqs_binding():
    try:
        import oqs
        logging.info("✓ liboqs binding available (quantum-safe crypto)")
    except ImportError:
        logging.warning("✗ liboqs not found — trying to install using pip...")
        subprocess.run([sys.executable, "-m", "pip", "install", "oqs"], check=True)

def enable_bpf_permissions():
    logging.info("Checking BPF permissions (for packet sniffing)...")
    bpf_path = "/dev/bpf0"
    if os.path.exists(bpf_path):
        try:
            os.chmod(bpf_path, 0o644)
            logging.info("✓ BPF permission updated (non-root sniffing enabled)")
        except PermissionError:
            logging.warning("⚠️ Could not change BPF permissions — consider running with sudo")
    else:
        logging.warning("⚠️ /dev/bpf0 not found — scapy may not capture packets without root")

def run_all_checks():
    logging.info("🚀 Starting QS-AI-IDS environment setup...")
    check_python_version()
    detect_mac_environment()
    install_packages()
    check_liboqs_binding()
    enable_bpf_permissions()
    logging.info("✅ Environment setup complete. You are ready to run QS-AI-IDS!")

if __name__ == "__main__":
    run_all_checks()
