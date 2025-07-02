# monitor/sniffer.py

import os
import platform
import threading
import time
from scapy.all import sniff, conf, get_if_list
from typing import Callable, Optional


class NetworkSniffer:
    """
    Real-time packet sniffer for MacBook personal network interfaces using scapy.
    Captures packets and forwards them to a callback for live analysis.
    """

    def __init__(self, iface: Optional[str] = None, packet_handler: Optional[Callable] = None):
        """
        Initializes the sniffer.

        Args:
            iface (str): Network interface name (e.g., 'en0' or 'en1' on macOS)
            packet_handler (Callable): Callback function to process each sniffed packet
        """
        self.iface = iface or self._get_default_iface()
        self.packet_handler = packet_handler
        self._sniff_thread = None
        self._stop_event = threading.Event()

    def start(self):
        """Start packet sniffing in a background thread."""
        print(f"[SNIFFER] Listening on interface: {self.iface}")
        self._stop_event.clear()
        self._sniff_thread = threading.Thread(target=self._run_sniffer, daemon=True)
        self._sniff_thread.start()

    def stop(self):
        """Stop packet sniffing."""
        self._stop_event.set()
        if self._sniff_thread:
            self._sniff_thread.join()
            self._sniff_thread = None
        print("[SNIFFER] Stopped sniffing.")

    def _run_sniffer(self):
        """Internal thread target to run the sniffer."""
        try:
            sniff(
                iface=self.iface,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set()
            )
        except Exception as e:
            print(f"[ERROR] Failed to sniff on interface {self.iface}: {e}")

    def _packet_callback(self, packet):
        """Invoked for each captured packet."""
        if self.packet_handler:
            try:
                self.packet_handler(packet)
            except Exception as e:
                print(f"[HANDLER ERROR] {e}")

    def _get_default_iface(self) -> str:
        """
        Detects the default active network interface on macOS.

        Returns:
            str: Interface name (e.g., 'en0')
        """
        if platform.system().lower() != "darwin":
            raise EnvironmentError("This sniffer is optimized for macOS environments.")

        interfaces = get_if_list()
        preferred = ["en0", "en1", "bridge0", "utun0", "lo0"]

        for iface in preferred:
            if iface in interfaces:
                return iface

        if interfaces:
            return interfaces[0]

        raise RuntimeError("No network interface found.")
