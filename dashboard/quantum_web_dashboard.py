import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import time
import threading
from typing import Dict, List
import urllib.parse
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from moniter.quantum_web_analyzer import QuantumWebTrafficAnalyzer
from moniter.sniffer import NetworkSniffer


class QuantumWebSecurityDashboard:
    """Interactive dashboard for QS-AI-IDS quantum web security analysis."""

    def __init__(self):
        """Initialize the dashboard and monitoring components."""
        self.web_analyzer = QuantumWebTrafficAnalyzer(use_quantum=True)
        self.should_stop = False
        self.last_update_time = time.time()
        self.statistics = {}
        self.domain_reports = {}
        self.verified_websites = {}

        # Initialize monitoring thread
        self.monitor_thread = None

    def start_monitoring(self, interface=None):
        """Start packet capture and quantum web traffic analysis."""

        def packet_handler(pkt):
            if self.should_stop:
                return

            # Analyze packet for web traffic
            self.web_analyzer.analyze_packet(pkt)

            # Update dashboard data periodically
            current_time = time.time()
            if current_time - self.last_update_time > 2:  # Update every 2 seconds
                self.statistics = self.web_analyzer.get_statistics()
                self.last_update_time = current_time

        # Create and start sniffer
        self.sniffer = NetworkSniffer(iface=interface, packet_handler=packet_handler)
        self.sniffer.start()

        print("[QUANTUM WEB DASHBOARD] Started monitoring web traffic with quantum enhancement")

    def stop_monitoring(self):
        """Stop all monitoring components."""
        self.should_stop = True
        if hasattr(self, 'sniffer'):
            self.sniffer.stop()
        print("[QUANTUM WEB DASHBOARD] Stopped monitoring")

    def verify_website(self, url):
        """Perform active security check on a website with quantum enhancement."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        results = self.web_analyzer.verify_website(url)
        self.verified_websites[url] = results
        return results

    def run_dashboard(self):
        """Run the Streamlit dashboard."""
        st.set_page_config(page_title="QS-AI-IDS Quantum Web Security", layout="wide")

        # Header
        st.title("🔬 QS-AI-IDS Quantum Web Security Analysis")
        st.markdown("**Real-time monitoring and analysis of web traffic security using quantum algorithms**")

        # Sidebar controls
        with st.sidebar:
            st.header("Controls")

            if st.button("Start Monitoring" if not hasattr(self, 'sniffer') else "Restart Monitoring"):
                if hasattr(self, 'sniffer'):
                    self.stop_monitoring()
                self.should_stop = False
                self.start_monitoring()

            if st.button("Stop Monitoring"):
                self.stop_monitoring()

            st.markdown("---")

            st.subheader("Website Verification")
            website_url = st.text_input("Enter website URL to verify:", "example.com")
            if st.button("Verify Website"):
                with st.spinner(f"Analyzing {website_url} with quantum algorithms..."):
                    results = self.verify_website(website_url)
                    st.success("Quantum analysis complete!")

        # Main content area - use tabs
        tab1, tab2, tab3, tab4 = st.tabs(["Overview", "Quantum Insights", "Domain Analysis", "Security Verification"])

        # Tab 1: Overview
        with tab1:
            # Statistics overview
            st.subheader("Web Traffic Overview")
            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric("Domains", self.statistics.get('domains_count', 0))

            with col2:
                st.metric("URLs Analyzed", self.statistics.get('analyzed_urls_count', 0))

            with col3:
                attack_count = sum(self.statistics.get('attack_types_detected', {}).values())
                st.metric("Attacks Detected", attack_count)

            with col4:
                avg_conf = self.statistics.get('average_quantum_confidence', 0)
                st.metric("Quantum Confidence", f"{avg_conf:.2f}")

            # HTTP methods chart
            st.subheader("HTTP Methods Distribution")
            if self.statistics.get('http_methods'):
                methods_df = pd.DataFrame({
                    'Method': list(self.statistics['http_methods'].keys()),
                    'Count': list(self.statistics['http_methods'].values())
                })
                fig = px.bar(methods_df, x='Method', y='Count', color='Method')
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No HTTP traffic detected yet.")

            # Attack types chart
            st.subheader("Detected Attack Types")
            if self.statistics.get('attack_types_detected'):
                attack_df = pd.DataFrame({
                    'Attack Type': list(self.statistics['attack_types_detected'].keys()),
                    'Count': list(self.statistics['attack_types_detected'].values())
                })
                fig = px.pie(attack_df, values='Count', names='Attack Type')
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No attacks detected yet.")

            # Status codes
            st.subheader("HTTP Status Codes")
            if self.statistics.get('status_codes'):
                status_df = pd.DataFrame({
                    'Status Code': list(self.statistics['status_codes'].keys()),
                    'Count': list(self.statistics['status_codes'].values())
                })
                fig = px.bar(status_df, x='Status Code', y='Count',
                             color='Status Code',
                             color_discrete_map={
                                 200: 'green',
                                 404: 'orange',
                                 500: 'red'
                             })
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No HTTP responses captured yet.")

        # Tab 2: Quantum Insights
        with tab2:
            st.subheader("Quantum Security Analysis")

            # Quantum status
            st.markdown("""
            ### Quantum Detection Status

            The system is currently using quantum algorithms to enhance web traffic security analysis.
            Quantum algorithms provide improved detection capabilities for:

            - **Complex pattern recognition** - Detecting subtle attack patterns
            - **Multi-dimensional correlation** - Finding relationships between attack vectors
            - **Superposition-based feature analysis** - Analyzing many traffic features simultaneously
            """)

            # Quantum metrics
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Quantum Cache Size", self.statistics.get('quantum_cache_size', 0))
            with col2:
                st.metric("Quantum Algorithm", "VQC-WebSec™")

            # Quantum advantage visualization
            st.subheader("Quantum Advantage in Attack Detection")

            # Create sample data for visualization if not available
            if not self.statistics.get('attack_types_detected'):
                # Sample data showing quantum vs classical
                detection_data = pd.DataFrame({
                    'Attack Type': ['SQL Injection', 'XSS', 'Path Traversal', 'Command Injection'],
                    'Classical Detection': [0.65, 0.70, 0.55, 0.75],
                    'Quantum Detection': [0.85, 0.90, 0.78, 0.95]
                })

                fig = go.Figure(data=[
                    go.Bar(name='Classical Detection', x=detection_data['Attack Type'],
                           y=detection_data['Classical Detection'], marker_color='lightblue'),
                    go.Bar(name='Quantum Detection', x=detection_data['Attack Type'],
                           y=detection_data['Quantum Detection'], marker_color='darkblue')
                ])
                fig.update_layout(barmode='group', title="Detection Capability Comparison",
                                  yaxis_title="Detection Confidence")
                st.plotly_chart(fig, use_container_width=True)

                st.info("This is a simulated comparison. Real comparison data will appear as attacks are detected.")
            else:
                # If we have real data
                st.info("Real quantum advantage metrics will be displayed as more attacks are analyzed.")

            # Technical explanation
            st.subheader("How Quantum Web Security Works")
            st.markdown("""
            The system uses a **Variational Quantum Circuit (VQC)** with 8 qubits to process web traffic features:

            1. **Amplitude Encoding** - Efficiently represents high-dimensional web traffic patterns
            2. **Variational Layers** - 3 entangled quantum layers for deep pattern recognition
            3. **Observable Measurement** - Optimized for different attack type signatures
            4. **Classical Post-processing** - Neural network for final attack classification

            This hybrid quantum-classical approach provides enhanced detection capabilities while
            maintaining compatibility with classical systems.
            """)

        # Tab 3: Domain Analysis
        with tab3:
            st.subheader("Top Suspicious Domains")

            # Display top suspicious domains
            if self.statistics.get('top_suspicious_domains'):
                suspicious_df = pd.DataFrame(
                    self.statistics['top_suspicious_domains'],
                    columns=['Domain', 'Attack Count']
                )
                st.dataframe(suspicious_df)

                # Allow detailed domain analysis
                st.subheader("Domain Detail Analysis")
                if suspicious_df.empty:
                    selected_domain = st.text_input("Enter domain to analyze:", "")
                else:
                    selected_domain = st.selectbox(
                        "Select domain to analyze:",
                        suspicious_df['Domain'].tolist()
                    )

                if selected_domain and st.button("Analyze Domain"):
                    report = self.web_analyzer.get_domain_report(selected_domain)

                    # Display domain report
                    st.markdown(f"### Analysis for: {report['domain']}")

                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("URLs", report['url_count'])
                    with col2:
                        st.metric("Highest Severity", f"{report['highest_severity']:.2f}")
                    with col3:
                        st.metric("Attack Types", len(report['attack_types']))
                    with col4:
                        st.metric("Quantum Confidence", f"{report.get('quantum_confidence', 0):.2f}")

                    # Show attack types
                    if report['attack_types']:
                        st.subheader("Attack Types")
                        attack_df = pd.DataFrame({
                            'Attack Type': list(report['attack_types'].keys()),
                            'Count': list(report['attack_types'].values())
                        })
                        fig = px.bar(attack_df, x='Attack Type', y='Count', color='Attack Type')
                        st.plotly_chart(fig, use_container_width=True)

                    # Show suspicious URLs
                    if report['suspicious_urls']:
                        st.subheader("Suspicious URLs")
                        for url in report['suspicious_urls']:
                            st.markdown(f"- `{url}`")
                    else:
                        st.info("No suspicious URLs detected for this domain.")
            else:
                st.info("No suspicious domains detected yet.")

        # Tab 4: Website Security Verification
        with tab4:
            st.subheader("Quantum-Enhanced Website Security Verification")

            if self.verified_websites:
                # Allow selecting from previously verified sites
                selected_url = st.selectbox(
                    "Select verified website:",
                    list(self.verified_websites.keys())
                )

                if selected_url:
                    results = self.verified_websites[selected_url]

                    # Display results
                    st.markdown(f"### Verification for: {results['url']}")
                    st.markdown(
                        f"*Scanned at: {datetime.fromtimestamp(results.get('scan_time', time.time())).strftime('%Y-%m-%d %H:%M:%S')}*")

                    # Handle error case
                    if 'error' in results:
                        st.error(f"Verification failed: {results['error']}")
                    else:
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric("IP Address", results.get('ip', 'Unknown'))
                        with col2:
                            st.metric("HTTPS", "Yes" if results.get('https') else "No")
                        with col3:
                            if 'risk_level' in results:
                                color = "green"
                                if results['risk_level'] == "Medium":
                                    color = "orange"
                                elif results['risk_level'] in ("High", "Critical"):
                                    color = "red"
                                st.markdown(f"<h3 style='color:{color}'>{results['risk_level']} Risk</h3>",
                                            unsafe_allow_html=True)
                                st.metric("Risk Score", f"{results.get('risk_score', 0):.2f}")

                        # Quantum analysis section
                        if 'quantum_analysis' in results and results['quantum_analysis']:
                            st.subheader("Quantum Security Analysis")

                            quantum_results = results['quantum_analysis']

                            if quantum_results.get('is_malicious'):
                                st.error("⚠️ Quantum analysis detected malicious patterns")

                                # Show attack probabilities
                                probs = []
                                for attack_type, data in quantum_results['predictions'].items():
                                    probs.append({
                                        'Attack Type': attack_type.replace('_', ' ').title(),
                                        'Probability': data['probability'],
                                        'Detected': 'Yes' if data['detected'] else 'No'
                                    })

                                prob_df = pd.DataFrame(probs)
                                st.dataframe(prob_df)

                                # Visualize probabilities
                                fig = px.bar(prob_df, x='Attack Type', y='Probability',
                                             color='Probability',
                                             color_continuous_scale='Reds')
                                st.plotly_chart(fig, use_container_width=True)
                            else:
                                st.success("✅ Quantum analysis indicates this site is likely safe")

                        # Security issues
                        if results.get('security_issues'):
                            st.subheader("Security Issues")
                            for issue in results['security_issues']:
                                st.warning(issue)
                        else:
                            st.success("No security issues detected!")

                        # Certificate info
                        if 'certificate' in results:
                            st.subheader("Certificate Information")
                            cert = results['certificate']

                            # Format certificate info
                            cert_info = {}
                            if 'subject' in cert:
                                subject = cert['subject']
                                if 'commonName' in subject:
                                    cert_info['Common Name'] = subject['commonName']
                                if 'organizationName' in subject:
                                    cert_info['Organization'] = subject['organizationName']

                            cert_info['Expires'] = cert.get('expires', 'Unknown')
                            cert_info['Version'] = f"v{cert.get('version', 'Unknown')}"

                            # Create a more readable certificate display
                            cert_df = pd.DataFrame({
                                'Property': list(cert_info.keys()),
                                'Value': list(cert_info.values())
                            })
                            st.dataframe(cert_df)

                        # TLS/Cipher info
                        if 'cipher' in results:
                            st.subheader("TLS Configuration")
                            st.markdown(f"""
                            - **TLS Version:** {results['cipher']['version']}
                            - **Cipher:** {results['cipher']['name']}
                            - **Key Strength:** {results['cipher']['bits']} bits
                            """)

                        # Headers
                        if 'headers' in results:
                            st.subheader("HTTP Headers")
                            headers_df = pd.DataFrame({
                                'Header': list(results['headers'].keys()),
                                'Value': list(results['headers'].values())
                            })
                            st.dataframe(headers_df)
            else:
                st.info("No websites have been verified yet. Use the sidebar to verify a website.")

        # Auto-refresh the dashboard
        time.sleep(2)
        st.rerun()


if __name__ == "__main__":
    dashboard = QuantumWebSecurityDashboard()
    try:
        dashboard.run_dashboard()
    except KeyboardInterrupt:
        dashboard.stop_monitoring()