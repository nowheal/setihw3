import select
import socket
import time
from collections import deque

from portscan.constants import (
    MAX_PACKET_BUFFER_SIZE,
    SEND_BATCH_LIMIT,
)
from portscan.event_loop import EventLoop
from portscan.models import ScanResult


class UdpScanner:
    def __init__(
        self,
        target_ip: str,
        ports: list[int],
        event_loop: EventLoop,
        timeout: float = 2.0,
    ) -> None:
        self.target_ip = target_ip
        self.ports = ports
        self.event_loop = event_loop
        self.timeout = timeout

        self._socket: socket.socket | None = None
        self._sent_timestamps: dict[int, float] = {}
        self._unresolved_ports: set[int] = set(ports)
        self._send_queue: deque[int] = deque()
        self._results: dict[int, ScanResult] = {}
        self._deadline: float | None = None

    def start(self) -> None:
        if not self.ports:
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 10 * 1024 * 1024)
        self._socket = sock

        for port in self.ports:
            self._send_queue.append(port)

        self.event_loop.register(
            sock.fileno(),
            select.EPOLLIN | select.EPOLLOUT,
            self._on_socket_event,
        )
        self.event_loop.add_tick_callback(self._check_timeout)

    def _on_socket_event(self, fd: int, event: int) -> None:
        if self._socket is None or fd != self._socket.fileno():
            return

        if event & select.EPOLLOUT:
            self._send_pending_batch()

        if event & select.EPOLLIN:
            self._receive_incoming_packets()

    def _send_pending_batch(self) -> None:
        if self._socket is None:
            return

        sent_count = 0
        while self._send_queue and sent_count < SEND_BATCH_LIMIT:
            port = self._send_queue[0]
            try:
                self._socket.sendto(b"", (self.target_ip, port))
            except BlockingIOError:
                return
            except OSError:
                self._send_queue.popleft()
                self._unresolved_ports.discard(port)
                continue

            self._send_queue.popleft()
            self._sent_timestamps[port] = time.monotonic()
            sent_count += 1

        if not self._send_queue and self._socket is not None:
            self.event_loop.modify(self._socket.fileno(), select.EPOLLIN)
            self._deadline = time.monotonic() + self.timeout

    def _receive_incoming_packets(self) -> None:
        if self._socket is None:
            return

        while True:
            try:
                _, address = self._socket.recvfrom(MAX_PACKET_BUFFER_SIZE)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break

            response_ip, response_port = address[0], address[1]
            if response_ip != self.target_ip:
                continue

            sent_time = self._sent_timestamps.get(response_port)
            if sent_time is not None:
                response_time_ms = (time.monotonic() - sent_time) * 1000.0
                self._results[response_port] = ScanResult(
                    protocol="UDP",
                    port=response_port,
                    response_time_ms=response_time_ms,
                )
                self._unresolved_ports.discard(response_port)

    def _check_timeout(self) -> None:
        if self._send_queue:
            return

        is_all_answered = not self._unresolved_ports
        is_timed_out = self._deadline is not None and time.monotonic() >= self._deadline

        if is_all_answered or is_timed_out:
            self.stop()

    def stop(self) -> None:
        self.event_loop.remove_tick_callback(self._check_timeout)
        if self._socket is not None:
            self.event_loop.unregister(self._socket.fileno())
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None

    def get_results(self) -> list[ScanResult]:
        return [self._results[port] for port in self.ports if port in self._results]
