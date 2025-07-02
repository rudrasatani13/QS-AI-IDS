# dashboard/app.py

import streamlit as st
import torch
import time
from moniter.feature_extractor import FeatureExtractor
from moniter.sniffer import NetworkSniffer
from core.encoder import QuantumFeatureEncoder
from core.hybrid_model import HybridAnomalyDetector
from crypto.logger import SecureLogger

st.set_page_config(page_title="QS-AI-IDS Dashboard", layout="wide")

st.title("🛡️ Quantum-Safe AI Intrusion Detection System")
st.markdown("**Monitoring your personal network in real-time with QNN and post-quantum cryptography.**")

placeholder = st.empty()
status_placeholder = st.sidebar.empty()

# Initialize components
encoder = QuantumFeatureEncoder()
model = HybridAnomalyDetector()
extractor = FeatureExtractor(window_size=5)
logger = SecureLogger()

latest_score = 0.0
latest_features = {}

def packet_handler(pkt):
    extractor.add_packet(pkt)

# Sniffer is started outside main loop
sniffer = NetworkSniffer(packet_handler=packet_handler)
sniffer.start()

try:
    while True:
        time.sleep(5)
        # Extract and encode features
        features = extractor.get_feature_vector()
        latest_features = features
        angles = encoder.encode(features)
        input_tensor = torch.tensor([angles], dtype=torch.float32)

        # Predict
        score = model.predict(input_tensor)
        score_val = float(score.item())
        latest_score = round(score_val, 4)

        # Decide and log
        label = "⚠️ Anomalous" if score_val > 0.7 else "✅ Normal"
        logger.log_event({
            "anomaly_score": latest_score,
            "features": features,
            "decision": label
        })

        # Streamlit display
        with placeholder.container():
            st.metric("🔍 Anomaly Score", f"{latest_score:.3f}", delta=None)
            st.progress(min(1.0, latest_score))

            col1, col2 = st.columns(2)
            with col1:
                st.subheader("🧬 Network Features")
                st.json(latest_features)

            with col2:
                st.subheader("📌 Decision")
                st.markdown(f"## {label}")

        status_placeholder.info(f"Last updated: {time.strftime('%H:%M:%S')}")
except KeyboardInterrupt:
    sniffer.stop()