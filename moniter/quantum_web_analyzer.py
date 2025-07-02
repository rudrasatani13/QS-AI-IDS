import threading
import time
import re
import socket
import ssl
import urllib.parse
import hashlib
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple, Optional, Any
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import TCP, IP
from scapy.packet import Packet

from core.quantum_web_detector import QuantumWebSecurityDetector


class QuantumWebTrafficAnalyzer:
    """
    Advanced web traffic analyzer using quantum algorithms for improved detection.
    Integrates with the QS\-AI\-IDS quantum\-safe framework.
    """

    def __init__(self, max_cache_size: int = 1000, use_quantum: bool = True):
        """
        Initialize the quantum web traffic analyzer.

        Args:
            max_cache_size: Maximum number of analyzed URLs to keep in memory
            use_quantum: Whether to use quantum algorithms for detection
        """
        self.lock = threading.Lock()
        self.max_cache_size = max_cache_size
        self.use_quantum = use_quantum

        # Initialize quantum detector
        self.quantum_detector = QuantumWebSecurityDetector(n_qubits=8, n_layers=3)

        # Tracking data structures
        self.analyzed_urls = {}
        self.domains = set()
        self.suspicious_patterns = defaultdict(int)
        self.http_methods = Counter()
        self.status_codes = Counter()

        # HTTP reconstruction data
        self.http_flows = {}
        self.flow_timeout = 30

        # Quantum analysis cache
        self.quantum_cache = {}
        self.last_cache_cleanup = time.time()
        self.cache_cleanup_interval = 300

        print("[QUANTUM] Initialized quantum web traffic analyzer")

    def analyze_packet(self, packet: Packet) -> Dict:
        """
        Analyze a packet for web traffic security threats using quantum algorithms.

        Args:
            packet: Scapy packet to analyze

        Returns:
            Dict of analysis results if web traffic, empty dict otherwise
        """
        results = {}

        try:
            if HTTPRequest in packet:
                with self.lock:
                    http_layer = packet[HTTPRequest]
                    host = http_layer.Host.decode() if hasattr(http_layer, 'Host') else ''
                    path = http_layer.Path.decode() if hasattr(http_layer, 'Path') else '/'
                    method = http_layer.Method.decode() if hasattr(http_layer, 'Method') else 'GET'

                    if host:
                        self.domains.add(host)
                    self.http_methods[method] += 1

                    url = f"http://{host}{path}"

                    headers = {}
                    for field in http_layer.fields:
                        if field not in ('Method', 'Path', 'Http\-Version'):
                            headers[field] = http_layer.fields[field]

                    body = None
                    if hasattr(packet, 'load'):
                        body = packet.load.decode('utf-8', errors='ignore')

                    if self.use_quantum:
                        url_hash = hashlib.md5(url.encode()).hexdigest()

                        if url_hash in self.quantum_cache:
                            quantum_results = self.quantum_cache[url_hash]
                        else:
                            quantum_results = self.quantum_detector.predict_attack_types(
                                url, headers, body
                            )
                            self.quantum_cache[url_hash] = quantum_results

                        if quantum_results['is_malicious']:
                            results = {
                                'url': url,
                                'attack_types': quantum_results['detected_attacks'],
                                'severity': quantum_results['severity'],
                                'quantum_details': quantum_results['predictions']
                            }

                            self.analyzed_urls[url] = {
                                'timestamp': time.time(),
                                'attack_types': quantum_results['detected_attacks'],
                                'severity': quantum_results['severity'],
                                'method': method,
                                'quantum_confidence': sum(
                                    data['probability']
                                    for _, data in quantum_results['predictions'].items()
                                ) / len(quantum_results['predictions'])
                            }

                    if len(self.analyzed_urls) > self.max_cache_size:
                        self._prune_old_entries()

                    current_time = time.time()
                    if current_time - self.last_cache_cleanup > self.cache_cleanup_interval:
                        self._clean_quantum_cache()
                        self.last_cache_cleanup = current_time

                return results

            elif HTTPResponse in packet:
                with self.lock:
                    http_layer = packet[HTTPResponse]
                    status_code = http_layer.Status_Code
                    if status_code:
                        self.status_codes[int(status_code)] += 1

            elif TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
                with self.lock:
                    if packet[TCP].dport == 443 and IP in packet:
                        server_ip = packet[IP].dst
                        if server_ip not in self.domains:
                            self.domains.add(f"https://{server_ip}")

        except Exception as e:
            print(f"[ERROR] Exception in quantum web analysis: {e}")

        return results

    def get_statistics(self) -> Dict:
        """
        Get current web traffic statistics with quantum analysis information.

        Returns:
            Dict containing summary statistics
        """
        with self.lock:
            return {
                'domains_count': len(self.domains),
                'analyzed_urls_count': len(self.analyzed_urls),
                'http_methods': dict(self.http_methods),
                'status_codes': dict(self.status_codes),
                'attack_types_detected': self._count_attack_types(),
                'top_suspicious_domains': self._get_top_suspicious_domains(5),
                'quantum_enabled': self.use_quantum,
                'quantum_cache_size': len(self.quantum_cache),
                'average_quantum_confidence': self._get_avg_quantum_confidence()
            }

    def get_domain_report(self, domain: str) -> Dict:
        """
        Generate a detailed report for a specific domain with quantum insights.

        Args:
            domain: Domain name to report on

        Returns:
            Dict containing domain\-specific analysis
        """
        with self.lock:
            domain_urls = {
                url: data for url, data in self.analyzed_urls.items()
                if domain in url
            }

            quantum_confidence = 0.0
            confidence_count = 0

            for data in domain_urls.values():
                if 'quantum_confidence' in data:
                    quantum_confidence += data['quantum_confidence']
                    confidence_count += 1

            avg_quantum_confidence = (
                quantum_confidence / confidence_count
                if confidence_count > 0 else 0.0
            )

            return {
                'domain': domain,
                'url_count': len(domain_urls),
                'first_seen': (
                    min(data['timestamp'] for data in domain_urls.values())
                    if domain_urls else None
                ),
                'last_seen': (
                    max(data['timestamp'] for data in domain_urls.values())
                    if domain_urls else None
                ),
                'attack_types': self._count_domain_attack_types(domain),
                'highest_severity': (
                    max(data['severity'] for data in domain_urls.values())
                    if domain_urls else 0
                ),
                'suspicious_urls': [
                    url for url, data in domain_urls.items()
                    if data['severity'] > 0.5
                ],
                'quantum_confidence': avg_quantum_confidence,
                'quantum_enabled': self.use_quantum
            }

    def verify_website(self, url: str, timeout: int = 10) -> Dict:
        """
        Actively check a website with quantum algorithm enhancement.

        Args:
            url: URL to check
            timeout: Connection timeout in seconds

        Returns:
            Dict with security findings
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.netloc
            is_https = parsed.scheme == 'https'
            port = 443 if is_https else 80

            results = {
                'url': url,
                'quantum_analysis': {},
                'security_issues': [],
                'scan_time': time.time()
            }

            if self.use_quantum:
                try:
                    quantum_results = self.quantum_detector.predict_attack_types(url)
                    results['quantum_analysis'] = quantum_results

                    if quantum_results['is_malicious']:
                        for attack_type in quantum_results['detected_attacks']:
                            prob = quantum_results['predictions'][attack_type]['probability']
                            results['security_issues'].append(
                                f"Quantum detected {attack_type} (confidence: {prob:.2f})"
                            )
                except Exception as e:
                    results['quantum_error'] = str(e)

            try:
                ip = socket.gethostbyname(hostname)
                results['ip'] = ip
            except socket.gaierror:
                results['dns_error'] = 'DNS resolution failed'
                results['security_issues'].append('DNS resolution failed')

            results['https'] = is_https
            if is_https:
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, port), timeout=timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            results['certificate'] = {
                                'subject': dict(x[0] for x in cert['subject']),
                                'issuer': dict(x[0] for x in cert['issuer']),
                                'version': cert['version'],
                                'expires': cert['notAfter']
                            }
                            cipher = ssock.cipher()
                            results['cipher'] = {
                                'name': cipher[0],
                                'version': cipher[1],
                                'bits': cipher[2]
                            }
                            if cipher[1] in ('TLSv1', 'TLSv1.1'):
                                results['security_issues'].append(
                                    f'Outdated TLS version: {cipher[1]}'
                                )
                except Exception as e:
                    results['tls_error'] = str(e)
                    results['security_issues'].append(f'TLS connection error: {str(e)}')

            try:
                import http.client
                conn_class = (
                    http.client.HTTPSConnection if is_https else http.client.HTTPConnection
                )
                conn = conn_class(hostname, timeout=timeout)
                conn.request('HEAD', '/')
                response = conn.getresponse()

                results['status_code'] = response.status
                results['headers'] = {k.lower(): v for k, v in response.getheaders()}

                security_headers = {
                    'strict-transport-security': 'Missing HSTS header',
                    'content-security-policy': 'Missing Content\-Security\-Policy',
                    'x-content-type-options': 'Missing X\-Content\-Type\-Options',
                    'x-frame-options': 'Missing X\-Frame\-Options'
                }

                for header, issue in security_headers.items():
                    if header not in results['headers']:
                        results['security_issues'].append(issue)

                sensitive_headers = ['server', 'x-powered-by']
                for header in sensitive_headers:
                    if header in results['headers']:
                        info_val = results['headers'][header]
                        results['security_issues'].append(
                            f'Information disclosure: {header}={info_val}'
                        )
            except Exception as e:
                results['request_error'] = str(e)
                results['security_issues'].append(f'HTTP request error: {str(e)}')

            risk_score = len(results['security_issues']) * 0.1

            if (
                'quantum_analysis' in results
                and results['quantum_analysis'].get('is_malicious')
            ):
                risk_score += results['quantum_analysis']['severity']

            results['risk_score'] = min(risk_score, 1.0)
            results['risk_level'] = self._calculate_risk_level(risk_score)

            return results

        except Exception as e:
            return {'error': str(e), 'url': url}

    def _clean_quantum_cache(self):
        """Clean up the quantum cache to prevent memory issues."""
        if len(self.quantum_cache) > self.max_cache_size:
            self.quantum_cache.clear()
            print(f"[QUANTUM] Cleared quantum analysis cache (size: {len(self.quantum_cache)})")

    def _prune_old_entries(self):
        """Remove oldest entries when cache gets too large."""
        if len(self.analyzed_urls) <= self.max_cache_size:
            return

        sorted_urls = sorted(
            self.analyzed_urls.items(),
            key=lambda x: x[1]['timestamp']
        )
        to_remove = int(len(sorted_urls) * 0.2)
        for i in range(to_remove):
            del self.analyzed_urls[sorted_urls[i][0]]

    def _count_attack_types(self) -> Dict[str, int]:
        """Count occurrences of each attack type."""
        counts = defaultdict(int)
        for data in self.analyzed_urls.values():
            for attack_type in data.get('attack_types', []):
                counts[attack_type] += 1
        return dict(counts)

    def _count_domain_attack_types(self, domain: str) -> Dict[str, int]:
        """Count attack types for a specific domain."""
        counts = defaultdict(int)
        for url, data in self.analyzed_urls.items():
            if domain in url:
                for attack_type in data.get('attack_types', []):
                    counts[attack_type] += 1
        return dict(counts)

    def _get_top_suspicious_domains(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Get domains with the most attacks detected."""
        domain_counts = defaultdict(int)
        for url, data in self.analyzed_urls.items():
            if data.get('attack_types'):
                parsed = urllib.parse.urlparse(url)
                domain = parsed.netloc
                domain_counts[domain] += len(data['attack_types'])
        return sorted(
            domain_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]

    def _get_avg_quantum_confidence(self) -> float:
        """Calculate average quantum confidence across all analyses."""
        total = 0.0
        count = 0
        for data in self.analyzed_urls.values():
            if 'quantum_confidence' in data:
                total += data['quantum_confidence']
                count += 1
        return total / count if count > 0 else 0.0

    def _calculate_risk_level(self, risk_score: float) -> str:
        """Convert risk score to human\-readable level."""
        if risk_score < 0.2:
            return "Low"
        elif risk_score < 0.5:
            return "Medium"
        elif risk_score < 0.8:
            return "High"
        else:
            return "Critical"