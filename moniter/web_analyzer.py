# moniter/web_analyzer.py

import re
import ssl
import socket
import threading
import time
import urllib.parse
from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple, Optional
import hashlib
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import TCP
from scapy.packet import Packet


class WebTrafficAnalyzer:
    """
    Specialized analyzer for HTTP/HTTPS traffic that can identify common web-based
    attacks, suspicious patterns, and security issues in websites.
    """

    def __init__(self, max_cache_size: int = 1000):
        """
        Initialize the web traffic analyzer.

        Args:
            max_cache_size: Maximum number of analyzed URLs to keep in memory
        """
        self.lock = threading.Lock()
        self.max_cache_size = max_cache_size
        
        # Tracking data structures
        self.analyzed_urls = {}  # URL -> analysis results
        self.domains = set()  # All domains seen
        self.suspicious_patterns = defaultdict(int)  # Pattern -> count
        self.payloads = []  # Raw HTTP payloads for analysis
        self.http_methods = Counter()  # HTTP method -> count
        self.status_codes = Counter()  # Status code -> count
        
        # Attack signatures
        self.attack_signatures = {
            'sql_injection': [
                r"['\"();].*OR.*['\"()]",
                r"UNION\s+SELECT",
                r"INSERT\s+INTO",
                r"DROP\s+TABLE",
                r"--\s+",
                r"\/\*.*\*\/"
            ],
            'xss': [
                r"<script>",
                r"javascript:",
                r"on\w+\s*=",
                r"<img[^>]*src=",
                r"eval\s*\(",
                r"document\.cookie"
            ],
            'path_traversal': [
                r"\.\.\/",
                r"\.\.\\",
                r"\/etc\/passwd",
                r"C:\\Windows",
                r"%2e%2e%2f"
            ],
            'command_injection': [
                r";\s*\w+",
                r"\|\s*\w+",
                r"`.*`",
                r"\$\([^)]*\)"
            ]
        }

    def analyze_packet(self, packet: Packet) -> Dict:
        """
        Analyze a packet for web traffic indicators.
        
        Args:
            packet: Scapy packet to analyze
            
        Returns:
            Dict of analysis results if web traffic, empty dict otherwise
        """
        results = {}
        
        # Check if this is HTTP traffic
        if HTTPRequest in packet:
            with self.lock:
                http_layer = packet[HTTPRequest]
                host = http_layer.Host.decode() if hasattr(http_layer, 'Host') else ''
                path = http_layer.Path.decode() if hasattr(http_layer, 'Path') else '/'
                method = http_layer.Method.decode() if hasattr(http_layer, 'Method') else 'GET'
                
                # Track domain and HTTP method
                if host:
                    self.domains.add(host)
                self.http_methods[method] += 1
                
                # Construct full URL
                url = f"http://{host}{path}"
                
                # Check for attack patterns in URL and headers
                attack_types = self._check_web_attacks(url, packet)
                if attack_types:
                    results['attack_types'] = attack_types
                    results['url'] = url
                    results['severity'] = self._calculate_severity(attack_types)
                    
                    # Store in analyzed URLs with timestamp
                    self.analyzed_urls[url] = {
                        'timestamp': time.time(),
                        'attack_types': attack_types,
                        'severity': results['severity'],
                        'method': method
                    }
                    
                    # Prune cache if needed
                    if len(self.analyzed_urls) > self.max_cache_size:
                        self._prune_old_entries()
                
                return results
        
        # Check if this is HTTP response
        elif HTTPResponse in packet:
            with self.lock:
                http_layer = packet[HTTPResponse]
                status_code = http_layer.Status_Code
                if status_code:
                    self.status_codes[int(status_code)] += 1
        
        # Look for potential HTTPS traffic (TCP port 443)
        elif TCP in packet and (packet[TCP].dport == 443 or packet[TCP].sport == 443):
            # Can't inspect encrypted content, but can track connection patterns
            with self.lock:
                if packet[TCP].dport == 443:
                    server_ip = packet.dst
                    if server_ip not in self.domains:
                        self.domains.add(f"https://{server_ip}")
        
        return results

    def get_statistics(self) -> Dict:
        """
        Get current web traffic statistics.
        
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
                'top_suspicious_domains': self._get_top_suspicious_domains(5)
            }
    
    def get_domain_report(self, domain: str) -> Dict:
        """
        Generate a detailed report for a specific domain.
        
        Args:
            domain: Domain name to report on
            
        Returns:
            Dict containing domain-specific analysis
        """
        with self.lock:
            domain_urls = {url: data for url, data in self.analyzed_urls.items() 
                          if domain in url}
            
            return {
                'domain': domain,
                'url_count': len(domain_urls),
                'first_seen': min([data['timestamp'] for data in domain_urls.values()]) 
                              if domain_urls else None,
                'last_seen': max([data['timestamp'] for data in domain_urls.values()]) 
                             if domain_urls else None,
                'attack_types': self._count_domain_attack_types(domain),
                'highest_severity': max([data['severity'] for data in domain_urls.values()]) 
                                   if domain_urls else 0,
                'suspicious_urls': [url for url, data in domain_urls.items() 
                                   if data['severity'] > 0.5]
            }
            
    def verify_website(self, url: str, timeout: int = 10) -> Dict:
        """
        Actively check a website by connecting to it and analyzing responses.
        Note: This performs active reconnaissance, use responsibly.
        
        Args:
            url: URL to check
            timeout: Connection timeout in seconds
            
        Returns:
            Dict with security findings
        """
        try:
            # Parse the URL
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.netloc
            is_https = parsed.scheme == 'https'
            port = 443 if is_https else 80
            
            # Check DNS
            try:
                ip = socket.gethostbyname(hostname)
            except socket.gaierror:
                return {'error': 'DNS resolution failed', 'url': url}
            
            # Prepare results
            results = {
                'url': url,
                'ip': ip,
                'https': is_https,
                'security_issues': []
            }
            
            # Connect to server and check TLS/SSL if HTTPS
            if is_https:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # Get certificate info
                        cert = ssock.getpeercert()
                        results['certificate'] = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert['version'],
                            'expires': cert['notAfter']
                        }
                        
                        # Check for weak ciphers
                        cipher = ssock.cipher()
                        results['cipher'] = {
                            'name': cipher[0],
                            'version': cipher[1],
                            'bits': cipher[2]
                        }
                        
                        # Check for security issues
                        if cipher[1] == 'TLSv1' or cipher[1] == 'TLSv1.1':
                            results['security_issues'].append('Outdated TLS version')
                
            # Try a HEAD request to check server headers
            conn = http.client.HTTPSConnection(hostname) if is_https else http.client.HTTPConnection(hostname)
            conn.request('HEAD', '/')
            response = conn.getresponse()
            
            # Get headers
            headers = {k.lower(): v for k, v in response.getheaders()}
            results['headers'] = headers
            
            # Check security headers
            security_headers = {
                'strict-transport-security': 'Missing HSTS header',
                'content-security-policy': 'Missing Content-Security-Policy',
                'x-content-type-options': 'Missing X-Content-Type-Options',
                'x-frame-options': 'Missing X-Frame-Options'
            }
            
            for header, issue in security_headers.items():
                if header not in headers:
                    results['security_issues'].append(issue)
            
            # Check for information disclosure
            sensitive_headers = ['server', 'x-powered-by']
            for header in sensitive_headers:
                if header in headers:
                    results['security_issues'].append(f'Information disclosure: {header}')
            
            return results
        
        except Exception as e:
            return {'error': str(e), 'url': url}

    def _check_web_attacks(self, url: str, packet: Packet) -> List[str]:
        """
        Check URL and packet content for common web attack patterns.
        
        Args:
            url: URL to check
            packet: Full packet to analyze
            
        Returns:
            List of detected attack types
        """
        detected_attacks = []
        
        # Decode URL to check for encoded attacks
        decoded_url = urllib.parse.unquote(url)
        
        # Check for each attack type
        for attack_type, patterns in self.attack_signatures.items():
            for pattern in patterns:
                if re.search(pattern, decoded_url, re.IGNORECASE):
                    detected_attacks.append(attack_type)
                    self.suspicious_patterns[pattern] += 1
                    break
        
        # Also check POST data if available
        if HTTPRequest in packet:
            http_layer = packet[HTTPRequest]
            if hasattr(http_layer, 'Method') and http_layer.Method == b'POST':
                if Raw in packet:
                    post_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    for attack_type, patterns in self.attack_signatures.items():
                        for pattern in patterns:
                            if re.search(pattern, post_data, re.IGNORECASE):
                                if attack_type not in detected_attacks:
                                    detected_attacks.append(attack_type)
                                    self.suspicious_patterns[pattern] += 1
                                break
        
        return detected_attacks

    def _calculate_severity(self, attack_types: List[str]) -> float:
        """
        Calculate severity score based on attack types.
        
        Args:
            attack_types: List of detected attack types
            
        Returns:
            Severity score from 0.0 to 1.0
        """
        # Severity weights for different attack types
        weights = {
            'sql_injection': 0.9,
            'xss': 0.8,
            'path_traversal': 0.7,
            'command_injection': 0.95
        }
        
        if not attack_types:
            return 0.0
            
        # Calculate highest severity
        return max([weights.get(attack, 0.5) for attack in attack_types])

    def _prune_old_entries(self):
        """Remove oldest entries when cache gets too large."""
        if len(self.analyzed_urls) <= self.max_cache_size:
            return
            
        # Sort by timestamp and remove oldest
        sorted_urls = sorted(self.analyzed_urls.items(), 
                            key=lambda x: x[1]['timestamp'])
        
        # Remove oldest 20%
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
                # Extract domain from URL
                parsed = urllib.parse.urlparse(url)
                domain = parsed.netloc
                domain_counts[domain] += len(data['attack_types'])
        
        # Sort by count descending and take top N
        return sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:limit]


# Import necessary modules
try:
    import http.client
except ImportError:
    pass

try:
    from scapy.layers.inet import Raw
except ImportError:
    pass