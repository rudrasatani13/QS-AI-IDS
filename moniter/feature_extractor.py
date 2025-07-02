import threading
import time
import math
from collections import Counter, defaultdict
from scapy.layers.inet import IP, TCP, UDP

class FeatureExtractor:
    """
    Extracts structured features from a stream of packets over a fixed time window.
    Features are used for real-time intrusion detection (QNN or classical model).
    """

    def __init__(self, window_size=5):
        """
        Initialize the feature extractor.
        
        Args:
            window_size (int): Time window in seconds for feature extraction
        """
        self.window_size = window_size
        self.lock = threading.Lock()
        self._snapshot = {}
        self.reset_stats()
        self._start_timer()

    def reset_stats(self):
        with self.lock:
            self.packet_count = 0
            self.byte_count = 0
            self.ttl_values = []
            self.src_ips = set()
            self.dst_ports = set()
            self.proto_counts = defaultdict(int)
            self.payload_bytes = []

    def _start_timer(self):
        def _reset_loop():
            while True:
                time.sleep(self.window_size)
                with self.lock:
                    self._snapshot = self._compute_features()
                    self.reset_stats()

        thread = threading.Thread(target=_reset_loop, daemon=True)
        thread.start()

    def add_packet(self, packet):
        """
        Add a packet to the statistics window.

        Args:
            packet: Scapy packet object
        """
        with self.lock:
            self.packet_count += 1
            self.byte_count += len(packet)

            if IP in packet:
                ip_layer = packet[IP]
                self.ttl_values.append(ip_layer.ttl)
                self.src_ips.add(ip_layer.src)

                if TCP in packet:
                    self.dst_ports.add(packet[TCP].dport)
                    self.proto_counts["TCP"] += 1
                    self.payload_bytes.append(bytes(packet[TCP].payload))
                elif UDP in packet:
                    self.dst_ports.add(packet[UDP].dport)
                    self.proto_counts["UDP"] += 1
                    self.payload_bytes.append(bytes(packet[UDP].payload))

    def get_feature_vector(self):
        """
        Returns:
            dict: Extracted features from the last completed window
        """
        with self.lock:
            return self._snapshot.copy() if self._snapshot else self._compute_features()

    def _compute_features(self):
        """
        Computes the full feature dictionary.

        Returns:
            dict: Network traffic features
        """
        packet_rate = self.packet_count / self.window_size
        avg_ttl = sum(self.ttl_values) / len(self.ttl_values) if self.ttl_values else 0
        unique_src_ips = len(self.src_ips)
        unique_dst_ports = len(self.dst_ports)
        tcp_count = self.proto_counts["TCP"]
        udp_count = self.proto_counts["UDP"]
        proto_ratio = tcp_count / (udp_count + 1e-5)

        byte_entropy = self._calc_byte_entropy(self.payload_bytes)

        return {
            "packet_rate": packet_rate,
            "avg_ttl": avg_ttl,
            "unique_src_ips": unique_src_ips,
            "unique_dst_ports": unique_dst_ports,
            "byte_entropy": byte_entropy,
            "tcp_udp_ratio": proto_ratio
        }

    def _calc_byte_entropy(self, payloads):
        """
        Computes Shannon entropy over all packet payloads in the window.

        Args:
            payloads (List[bytes]): Raw payloads

        Returns:
            float: Shannon entropy (0–8)
        """
        freq = [0] * 256
        total = 0

        for payload in payloads:
            for byte in payload:
                freq[byte] += 1
                total += 1

        if total == 0:
            return 0.0

        entropy = 0
        for count in freq:
            if count == 0:
                continue
            p = count / total
            entropy -= p * math.log2(p)

        return entropy