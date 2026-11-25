import socket

import dns.exception
import dns.message
import dns.query


class ServiceDetector:
    ECHO_PAYLOAD: bytes = b"PING_PORT_SCANNER_ECHO_CHECK"

    def __init__(self, target_ip: str, timeout: float = 1.0) -> None:
        self.target_ip = target_ip
        self.timeout = timeout

    def detect_tcp(self, port: int) -> str | None:
        if self._check_echo_tcp(port):
            return "ECHO"
        if self._check_http_tcp(port):
            return "HTTP"
        if self._check_dns_tcp(port):
            return "DNS"
        return None

    def detect_udp(self, port: int) -> str | None:
        if self._check_echo_udp(port):
            return "ECHO"
        if self._check_http_udp(port):
            return "HTTP"
        if self._check_dns_udp(port):
            return "DNS"
        return None

    def _check_http_tcp(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
                client_sock.settimeout(self.timeout)
                client_sock.connect((self.target_ip, port))
                request = (
                    f"GET / HTTP/1.0\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"User-Agent: portscan\r\n\r\n"
                ).encode("ascii")
                client_sock.sendall(request)
                response = client_sock.recv(1024)
                return response.startswith(b"HTTP/")
        except OSError:
            return False

    def _check_http_udp(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_sock:
                client_sock.settimeout(self.timeout)
                request = (
                    f"GET / HTTP/1.0\r\n"
                    f"Host: {self.target_ip}\r\n"
                    f"User-Agent: portscan\r\n\r\n"
                ).encode("ascii")
                client_sock.sendto(request, (self.target_ip, port))
                response, _ = client_sock.recvfrom(1024)
                return response.startswith(b"HTTP/")
        except OSError:
            return False

    def _check_dns_tcp(self, port: int) -> bool:
        try:
            query = dns.message.make_query("example.com", dns.rdatatype.A)
            response = dns.query.tcp(query, self.target_ip, port=port, timeout=self.timeout)
            return response is not None and response.id == query.id
        except (OSError, dns.exception.DNSException):
            return False

    def _check_dns_udp(self, port: int) -> bool:
        try:
            query = dns.message.make_query("example.com", dns.rdatatype.A)
            response = dns.query.udp(query, self.target_ip, port=port, timeout=self.timeout)
            return response is not None and response.id == query.id
        except (OSError, dns.exception.DNSException):
            return False

    def _check_echo_tcp(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
                client_sock.settimeout(self.timeout)
                client_sock.connect((self.target_ip, port))
                client_sock.sendall(self.ECHO_PAYLOAD)
                response = client_sock.recv(1024)
                return self.ECHO_PAYLOAD in response
        except OSError:
            return False

    def _check_echo_udp(self, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_sock:
                client_sock.settimeout(self.timeout)
                client_sock.sendto(self.ECHO_PAYLOAD, (self.target_ip, port))
                response, _ = client_sock.recvfrom(1024)
                return self.ECHO_PAYLOAD in response
        except OSError:
            return False
