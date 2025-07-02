# QS-AI-IDS

> **AI-Driven Intrusion Detection System** leveraging machine learning and network packet analysis.

---

## 📖 Overview
**QS-AI-IDS** is a proof-of-concept Intrusion Detection System designed to classify and detect anomalous network behaviour using deep learning techniques. It processes live or captured network traffic, extracts features, and applies trained AI models to flag suspicious activities in real time.

## ✨ Key Features
- **Real-time Traffic Monitoring**  
  Continuously captures network packets and analyzes them on the fly.
- **Deep Learning Classifier**  
  Utilizes neural networks (TensorFlow/PyTorch) to differentiate between benign and malicious traffic patterns.
- **Modular Architecture**  
  Easily extendable pipeline: packet capture → feature extraction → model inference → alerting.
- **Customizable Alerts**  
  Integrate with email, Slack, or logging systems to notify on detected threats.
- **Scalability**  
  Designed to handle high-throughput networks with multi-threaded capture and inference.

## 🛠️ Technology Stack
| Component             | Technology          |
|-----------------------|---------------------|
| Packet Capture        | Scapy               |
| Feature Extraction    | NumPy, Pandas       |
| Model Training        | TensorFlow / PyTorch|
| Visualization (Optional) | Matplotlib, Seaborn |
| Packaging & Deployment| Docker              |

## 🚀 Installation

1. Clone the repository  
   ```bash
   git clone https://github.com/rudrasatani13/QS-AI-IDS.git
   cd QS-AI-IDS
   ```

2. Create and activate a virtual environment  
   ```bash
   python3 -m venv venv
   source venv/bin/activate    # Linux/macOS
   venv\Scripts\activate       # Windows
   ```

3. Install dependencies  
   ```bash
   pip install -r requirements.txt
   ```

4. (Optional) Build Docker image  
   ```bash
   docker build -t qs-ai-ids .
   ```

## ⚙️ Configuration
- Review and modify parameters in `config.yaml`:  
  - `capture.interface` – network interface to listen on  
  - `model.path` – location of the serialized ML model  
  - `alert.method` – notification channel (e.g., email, webhook)

## ▶️ Usage

- **Live Monitoring**  
  ```bash
  python src/main.py --config config.yaml
  ```
- **Offline Analysis**  
  ```bash
  python src/main.py --pcap data/sample_traffic.pcap --config config.yaml
  ```

## 🏗️ Project Structure
```
QS-AI-IDS/
├── src/
│   ├── capture.py        # Packet capture logic
│   ├── features.py       # Feature extraction routines
│   ├── model.py          # Model loading & inference
│   └── main.py           # Entry point
├── config.yaml           # User configuration
├── requirements.txt      # Python dependencies
└── data/                 # Sample PCAP files
```

## 🤝 Contributing
Contributions are welcome! Please follow these steps:

1. Fork the repository  
2. Create a feature branch (`git checkout -b feature/YourFeature`)  
3. Commit your changes (`git commit -m "Add YourFeature"`)  
4. Push to your fork (`git push origin feature/YourFeature`)  
5. Open a Pull Request and describe your changes

## 📄 License
This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

## 📬 Contact
- **Author:** Rudra Satani  
- **Email:** rudrasatani13@example.com  
- **GitHub:** [@rudrasatani13](https://github.com/rudrasatani13)
