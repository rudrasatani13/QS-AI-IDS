# core/encoder.py

import numpy as np
from typing import List, Dict

class QuantumFeatureEncoder:

    def __init__(self, max_qubits: int = 6):

        self.max_qubits = max_qubits

    def normalize(self, features: Dict[str, float]) -> List[float]:

        # Define fixed order for consistency
        feature_order = [
            "packet_rate",
            "avg_ttl",
            "unique_src_ips",
            "unique_dst_ports",
            "byte_entropy",
            "tcp_udp_ratio"
        ]

        vector = []
        for key in feature_order[:self.max_qubits]:
            val = features.get(key, 0.0)
            vector.append(self._scale_feature(key, val))

        return vector

    def encode_to_angles(self, normalized_vector: List[float]) -> List[float]:

        return [np.pi * val for val in normalized_vector]

    def encode(self, features: Dict[str, float]) -> List[float]:

        norm_vec = self.normalize(features)
        return self.encode_to_angles(norm_vec)

    def _scale_feature(self, key: str, val: float) -> float:

        scaling_rules = {
            "packet_rate": (0, 2000),
            "avg_ttl": (0, 255),
            "unique_src_ips": (0, 100),
            "unique_dst_ports": (0, 100),
            "byte_entropy": (0, 8),
            "tcp_udp_ratio": (0, 10)
        }

        min_val, max_val = scaling_rules.get(key, (0, 1))
        val = max(min(val, max_val), min_val)  # clip
        return (val - min_val) / (max_val - min_val + 1e-8)  # normalized

