# core/quantum_web_detector.py

import pennylane as qml
import torch
import torch.nn as nn
from typing import List, Dict, Tuple
import numpy as np
import re
import urllib.parse


class QuantumWebSecurityCircuit:
    """
    Quantum circuit for detecting web security threats using variational quantum algorithms.
    Uses amplitude encoding for efficient representation of web traffic patterns.
    """

    def __init__(self, n_qubits: int = 8, n_layers: int = 3):
        """
        Initialize the quantum web security circuit.

        Args:
            n_qubits: Number of qubits (should be power of 2 for amplitude encoding)
            n_layers: Number of variational layers for pattern recognition
        """
        self.n_qubits = n_qubits
        self.n_layers = n_layers

        # Use lightning.qubit simulator for efficiency on classical hardware
        self.dev = qml.device("lightning.qubit", wires=n_qubits)

        # Define the quantum node with PyTorch interface
        self.qnode = qml.QNode(self._circuit, self.dev, interface="torch", diff_method="adjoint")

        # Pre-compute the feature map dimensions
        self.feature_dim = 2 ** n_qubits

        # Define variational parameters
        weight_shapes = {
            "weights": (n_layers, n_qubits, 3)  # Rotation angles for each qubit
        }

        # Create TorchLayer for PyTorch integration
        self.qlayer = qml.qnn.TorchLayer(self.qnode, weight_shapes)

    def _circuit(self, inputs: torch.Tensor, weights: torch.Tensor) -> torch.Tensor:
        """
        Quantum circuit definition for web security analysis.

        Args:
            inputs: Amplitude-encoded features (must be normalized)
            weights: Variational parameters for the quantum model

        Returns:
            Expected values of measurements that indicate security threats
        """
        # Amplitude encoding of features
        qml.AmplitudeEmbedding(inputs, wires=range(self.n_qubits), normalize=True)

        # Variational layers - structure optimized for pattern recognition
        for layer in range(self.n_layers):
            # Rotation layer
            for i in range(self.n_qubits):
                qml.Rot(weights[layer, i, 0],
                        weights[layer, i, 1],
                        weights[layer, i, 2],
                        wires=i)

            # Entanglement layer - fully connected for maximum correlation detection
            for i in range(self.n_qubits):
                for j in range(i + 1, self.n_qubits):
                    qml.CNOT(wires=[i, j])

        # Measure different observables for different types of threats
        return [
            qml.expval(qml.PauliZ(0)),  # SQL injection
            qml.expval(qml.PauliZ(1)),  # XSS
            qml.expval(qml.PauliZ(2)),  # Path traversal
            qml.expval(qml.PauliZ(3))  # Command injection
        ]

    def predict(self, features: torch.Tensor) -> torch.Tensor:
        """
        Run prediction using the quantum circuit.

        Args:
            features: Encoded web traffic features

        Returns:
            Tensor of threat scores for different attack types
        """
        return self.qlayer(features)


class WebFeatureQuantumEncoder:
    """
    Encodes web traffic features into quantum-ready format using amplitude encoding.
    Optimized for representing HTTP/HTTPS traffic patterns.
    """

    def __init__(self, max_features: int = 256):
        """
        Initialize the web feature encoder.

        Args:
            max_features: Maximum number of features to encode (must be power of 2)
        """
        self.max_features = max_features

        # Feature hash functions to create fixed-length representation
        self._feature_fns = [
            self._char_frequency,  # Character distribution (detects obfuscation)
            self._special_char_ratio,  # Special character patterns (SQL injection, XSS)
            self._path_depth,  # Path depth analysis (path traversal)
            self._parameter_analysis,  # Query parameter analysis
            self._entropy_calc,  # Shannon entropy (detect encryption/encoding)
            self._token_patterns  # Common attack token detection
        ]

        # Attack pattern dictionaries
        self.attack_tokens = {
            'sql': ['SELECT', 'UNION', 'INSERT', 'DROP', 'UPDATE', 'DELETE', 'FROM', 'WHERE'],
            'xss': ['script', 'alert', 'onerror', 'onload', 'eval', 'document', 'cookie'],
            'path': ['../', '..\\', '/etc/', 'C:\\', 'system32', 'passwd'],
            'cmd': [';', '&&', '||', '`', '$(', '${']
        }

        # Initialize the vector with zeros
        self.feature_vector = np.zeros(max_features)

    def encode(self, url: str, headers: Dict = None, body: str = None) -> torch.Tensor:
        """
        Encode web request data into quantum-ready amplitude vector.

        Args:
            url: URL to analyze
            headers: HTTP headers (optional)
            body: HTTP body content (optional)

        Returns:
            Tensor containing amplitude-encoded features
        """
        # Reset feature vector
        self.feature_vector = np.zeros(self.max_features)

        # URL decoding to analyze actual content
        decoded_url = urllib.parse.unquote(url)

        # Extract components from URL
        parsed = urllib.parse.urlparse(decoded_url)
        path = parsed.path
        query = parsed.query

        # Apply each feature extraction function
        position = 0
        for fn in self._feature_fns:
            # Each function returns a sub-vector
            sub_vector = fn(decoded_url, path, query, headers, body)
            sub_len = len(sub_vector)

            # Insert into main feature vector
            if position + sub_len <= self.max_features:
                self.feature_vector[position:position + sub_len] = sub_vector
                position += sub_len

        # Normalize the vector for amplitude encoding
        norm = np.linalg.norm(self.feature_vector)
        if norm > 0:
            self.feature_vector = self.feature_vector / norm

        # Convert to PyTorch tensor
        return torch.tensor(self.feature_vector, dtype=torch.float32)

    def _char_frequency(self, url, path, query, headers, body) -> np.ndarray:
        """Extract character frequency distribution."""
        freq = np.zeros(64)  # Reduced alphabet size

        for c in url:
            # Map ASCII characters to smaller space
            if ord('a') <= ord(c) <= ord('z'):
                idx = ord(c) - ord('a')
                freq[idx] += 1
            elif ord('A') <= ord(c) <= ord('Z'):
                idx = 26 + ord(c) - ord('A')
                freq[idx] += 1
            elif ord('0') <= ord(c) <= ord('9'):
                idx = 52 + ord(c) - ord('0')
                freq[idx] += 1
            elif c in '+-*/=':
                freq[62] += 1  # Math operators
            elif c in '<>{}[]()':
                freq[63] += 1  # Brackets

        # Normalize
        total = sum(freq)
        return freq / (total + 1e-10)

    def _special_char_ratio(self, url, path, query, headers, body) -> np.ndarray:
        """Calculate ratio of special characters indicating attacks."""
        result = np.zeros(16)

        # Count special characters
        special_chars = {
            '\'': 0, '"': 1, ';': 2, '=': 3, '<': 4, '>': 5, '&': 6, '|': 7,
            '!': 8, '(': 9, ')': 10, '{': 11, '}': 12, '[': 13, ']': 14, '/': 15
        }

        total_len = len(url)
        for c in url:
            if c in special_chars:
                result[special_chars[c]] += 1

        # Convert to ratios
        return result / (total_len + 1e-10)

    def _path_depth(self, url, path, query, headers, body) -> np.ndarray:
        """Analyze path structure for path traversal detection."""
        result = np.zeros(16)

        # Count path segments
        segments = path.split('/')
        depth = len(segments)
        result[0] = min(depth / 10, 1.0)  # Normalized path depth

        # Detect path traversal patterns
        for i, segment in enumerate(segments):
            if segment == '..':
                result[1] += 1
            if segment == '.':
                result[2] += 1
            if '.' in segment:  # File extension
                result[3] += 1
            if len(segment) > 20:  # Unusually long segment
                result[4] += 1
            if i < 15 and segment:
                result[i + 5] = min(len(segment) / 20, 1.0)  # Segment length

        return result

    def _parameter_analysis(self, url, path, query, headers, body) -> np.ndarray:
        """Analyze query parameters for injection patterns."""
        result = np.zeros(64)

        # Parse query parameters
        params = urllib.parse.parse_qs(query)

        # Suspicious parameter names
        suspicious_params = ['id', 'user', 'pass', 'key', 'admin', 'cmd', 'exec', 'query', 'file']

        # Parameter analysis
        for i, (name, values) in enumerate(params.items()):
            if i >= 8:
                break

            # Check for suspicious parameter names
            for j, susp in enumerate(suspicious_params):
                if susp in name.lower():
                    result[j] += 1

            # Parameter value analysis
            for value in values:
                offset = 16
                # Long values
                result[offset] += min(len(value) / 100, 1.0)
                # Special characters
                result[offset + 1] += sum(1 for c in value if c in '\'";=<>&|!(){}[]/')
                # Numbers
                result[offset + 2] += sum(1 for c in value if c.isdigit())
                # Uppercase
                result[offset + 3] += sum(1 for c in value if c.isupper())

                # Attack patterns
                if re.search(r"['\"]\s*OR\s*['\"]\s*=", value):
                    result[offset + 4] += 1  # SQL injection
                if re.search(r"<script", value):
                    result[offset + 5] += 1  # XSS
                if re.search(r"\.\.\/", value):
                    result[offset + 6] += 1  # Path traversal
                if re.search(r";\s*\w+", value):
                    result[offset + 7] += 1  # Command injection

        return result

    def _entropy_calc(self, url, path, query, headers, body) -> np.ndarray:
        """Calculate Shannon entropy for different URL components."""
        result = np.zeros(8)

        # Function to calculate entropy
        def shannon_entropy(data):
            if not data:
                return 0
            entropy = 0
            for x in range(256):
                p_x = float(data.count(chr(x))) / len(data)
                if p_x > 0:
                    entropy += - p_x * np.log2(p_x)
            return entropy / 8.0  # Normalize to [0,1]

        # Calculate entropy for different parts
        result[0] = shannon_entropy(url)
        result[1] = shannon_entropy(path)
        result[2] = shannon_entropy(query)

        # Check for encoded content
        if '%' in url:
            encoded_parts = re.findall(r'%[0-9A-Fa-f]{2}', url)
            result[3] = min(len(encoded_parts) / 10, 1.0)

        # Check for base64-like content
        base64_pattern = re.search(r'[A-Za-z0-9+/=]{16,}', url)
        if base64_pattern:
            result[4] = min(len(base64_pattern.group(0)) / 50, 1.0)
            result[5] = shannon_entropy(base64_pattern.group(0))

        # Additional entropy if body is available
        if body:
            result[6] = shannon_entropy(body[:1000])  # First 1000 chars

        # Header entropy if available
        if headers:
            header_str = str(headers)
            result[7] = shannon_entropy(header_str[:1000])

        return result

    def _token_patterns(self, url, path, query, headers, body) -> np.ndarray:
        """Detect known attack tokens in the request."""
        result = np.zeros(32)

        # Check entire URL for attack patterns
        full_text = url.lower()
        if body:
            full_text += " " + body.lower()
        if headers:
            full_text += " " + str(headers).lower()

        # Check SQL injection patterns
        for i, token in enumerate(self.attack_tokens['sql']):
            if i < 8 and token.lower() in full_text:
                result[i] += 1

        # Check XSS patterns
        for i, token in enumerate(self.attack_tokens['xss']):
            if i < 8 and token.lower() in full_text:
                result[i + 8] += 1

        # Check path traversal patterns
        for i, token in enumerate(self.attack_tokens['path']):
            if i < 8 and token.lower() in full_text:
                result[i + 16] += 1

        # Check command injection patterns
        for i, token in enumerate(self.attack_tokens['cmd']):
            if i < 8 and token in full_text:  # Case sensitive for command tokens
                result[i + 24] += 1

        return result


class QuantumWebSecurityDetector(nn.Module):
    """
    Hybrid quantum-classical model for web security threat detection.
    Combines quantum circuit for pattern recognition with classical post-processing.
    """

    def __init__(self, n_qubits: int = 8, n_layers: int = 3):
        """
        Initialize the quantum web security detector.

        Args:
            n_qubits: Number of qubits for the quantum circuit
            n_layers: Number of variational layers
        """
        super().__init__()

        # Initialize quantum circuit
        self.quantum_circuit = QuantumWebSecurityCircuit(n_qubits, n_layers)

        # Classical post-processing layers
        self.post_process = nn.Sequential(
            nn.Linear(4, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 4),
            nn.Sigmoid()
        )

        # Feature encoder
        self.encoder = WebFeatureQuantumEncoder(max_features=2 ** n_qubits)

        # Attack threshold values
        self.thresholds = {
            'sql_injection': 0.7,
            'xss': 0.75,
            'path_traversal': 0.65,
            'command_injection': 0.8
        }

        # Attack types mapping
        self.attack_types = ['sql_injection', 'xss', 'path_traversal', 'command_injection']

    def forward(self, url: str, headers: Dict = None, body: str = None) -> torch.Tensor:
        """
        Perform forward pass of the model.

        Args:
            url: URL to analyze
            headers: HTTP headers (optional)
            body: HTTP body content (optional)

        Returns:
            Tensor of attack probabilities for different attack types
        """
        # Encode features
        features = self.encoder.encode(url, headers, body)

        # Quantum circuit execution
        quantum_output = self.quantum_circuit.predict(features)

        # Classical post-processing
        return self.post_process(quantum_output)

    def predict_attack_types(self, url: str, headers: Dict = None, body: str = None) -> Dict:
        """
        Predict if the URL contains attack patterns.

        Args:
            url: URL to analyze
            headers: HTTP headers (optional)
            body: HTTP body content (optional)

        Returns:
            Dictionary with attack types and probabilities
        """
        # Get raw predictions
        with torch.no_grad():
            predictions = self.forward(url, headers, body)

        # Convert to attack probabilities
        results = {}
        for i, attack_type in enumerate(self.attack_types):
            prob = float(predictions[i].item())
            results[attack_type] = {
                'probability': prob,
                'detected': prob >= self.thresholds[attack_type]
            }

        # Calculate overall severity
        severity = max([prob for prob in predictions.tolist()])

        # Add detected attack types
        detected_attacks = [
            attack for attack, data in results.items() if data['detected']
        ]

        return {
            'url': url,
            'predictions': results,
            'severity': severity,
            'detected_attacks': detected_attacks,
            'is_malicious': len(detected_attacks) > 0
        }