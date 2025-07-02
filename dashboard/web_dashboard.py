import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import time
import threading
from typing import Dict, List
import urllib.parse
import plotly.express as px
import plotly.graph_objects as go

from moniter.web_analyzer import WebTrafficAnalyzer
from moniter.sniffer import NetworkSniffer


class WebSecurityDashboard:
    """Interactive dashboard for QS-AI-IDS web security analysis."""
    
    def __init__(self):
        """Initialize the dashboard and monitoring components."""
        self.web_analyzer = WebTrafficAnalyzer()
        self.should_stop = False
        self.last_update_time = time.time()
        self.statistics = {}
        self.domain_reports = {}
        self.verified_websites = {}
        
        # Initialize monitoring thread
        self.monitor_thread = None
    
    def start_monitoring(self, interface=None):
        """Start packet capture and web traffic analysis."""
        
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
        
        print("[WEB DASHBOARD] Started monitoring web traffic")
    
    def stop_monitoring(self):
        """Stop all monitoring components."""
        self.should_stop = True
        if hasattr(self, 'sniffer'):
            self.sniffer.stop()
        print("[WEB DASHBOARD] Stopped monitoring")
    
    def verify_website(self, url):
        """Perform active security check on a website."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        results = self.web_analyzer.verify_website(url)
        self.verified_websites[url] = results
        return results
    
    def run_dashboard(self):
        """Run the Streamlit dashboard."""
        st.set_page_config(page_title="QS-AI-IDS Web Security", layout="wide")
        
        # Header
        st.title("🔍 QS-AI-IDS Web Security Analysis")
        st.markdown("**Real-time monitoring and analysis of web traffic security**")
        
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
                with st.spinner(f"Analyzing {website_url}..."):
                    results = self.verify_website(website_url)
                    st.success("Analysis complete!")
        
        # Main content area - use tabs
        tab1, tab2, tab3 = st.tabs(["Overview", "Domain Analysis", "Security Verification"])
        
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
                methods = self.statistics.get('http_methods', {})
                post_count = methods.get('POST', 0)
                st.metric("POST Requests", post_count)
            
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
        
        # Tab 2: Domain Analysis
        with tab2:
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
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("URLs", report['url_count'])
                    with col2:
                        st.metric("Highest Severity", f"{report['highest_severity']:.2f}")
                    with col3:
                        st.metric("Attack Types", len(report['attack_types']))
                    
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
        
        # Tab 3: Website Security Verification
        with tab3:
            st.subheader("Website Security Verification Results")
            
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
                    
                    # Handle error case
                    if 'error' in results:
                        st.error(f"Verification failed: {results['error']}")
                    else:
                        col1, col2 = st.columns(2)
                        with col1:
                            st.metric("IP Address", results['ip'])
                            st.metric("HTTPS", "Yes" if results['https'] else "No")
                        
                        with col2:
                            issues_count = len(results.get('security_issues', []))
                            status = "Secure" if issues_count == 0 else f"{issues_count} Issues"
                            st.metric("Security Status", status)
                            
                            if 'cipher' in results:
                                st.metric("TLS Version", results['cipher']['version'])
                        
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
                            st.json(cert)
                        
                        # Headers
                        if 'headers' in results:
                            st.subheader("HTTP Headers")
                            st.json(results['headers'])
            else:
                st.info("No websites have been verified yet. Use the sidebar to verify a website.")
        
        # Auto-refresh the dashboard
        time.sleep(2)
        st.experimental_rerun()


if __name__ == "__main__":
    dashboard = WebSecurityDashboard()
    try:
        dashboard.run_dashboard()
    except KeyboardInterrupt:
        dashboard.stop_monitoring()