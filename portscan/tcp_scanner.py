import select
import socket
import time
from collections import deque
from dataclasses import dataclass

from portscan.constants import (
    MAX_PACKET_BUFFER_SIZE,
    SEND_BATCH_LIMIT,
)
from portscan.event_loop import EventLoop
from portscan.models import ScanResult
from portscan.network_utils import find_available_port
from portscan.packet_filter import PacketFilter
from portscan.tcp_packet import TcpSynPacket


@dataclass(frozen=True)
class SentProbeInfo:
    target_port: int
    client_port: int
    seq_num: int
    sent_time: float


class TcpScanner:
    def __init__(
        self,
        target_ip: str,
        ports: list[int],
        local_ip: str,
        event_loop: EventLoop,
        timeout: float = 2.0,
    ) -> None:
        self.target_ip = target_ip
        self.ports = ports
        self.local_ip = local_ip
        self.event_loop = event_loop
        self.timeout = timeout

        self._socket: socket.socket | None = None
        self._probes_by_port: dict[int, SentProbeInfo] = {}
        self._unresolved_ports: set[int] = set(ports)
        self._send_queue: deque[tuple[int, int, bytes, int]] = deque()
        self._results: dict[int, ScanResult] = {}
        self._deadline: float | None = None

    def start(self) -> None:
        if not self.ports:
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 10 * 1024 * 1024)
        self._socket = sock

        base_client_port = find_available_port()
        for idx, port in enumerate(self.ports):
            client_port = ((base_client_port + idx - 1024) % 64511) + 1024
            packet = TcpSynPacket(
                source_ip=self.local_ip,
                dest_ip=self.target_ip,
                source_port=client_port,
                dest_port=port,
            )
            self._send_queue.append((port, client_port, packet.to_bytes(), packet.seq_num))

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
            target_port, client_port, packet_bytes, seq_num = self._send_queue[0]
            try:
                self._socket.sendto(packet_bytes, (self.target_ip, target_port))
            except BlockingIOError:
                return
            except OSError:
                self._send_queue.popleft()
                self._unresolved_ports.discard(target_port)
                continue

            self._send_queue.popleft()
            self._probes_by_port[target_port] = SentProbeInfo(
                target_port=target_port,
                client_port=client_port,
                seq_num=seq_num,
                sent_time=time.monotonic(),
            )
            sent_count += 1

        if not self._send_queue and self._socket is not None:
            self.event_loop.modify(self._socket.fileno(), select.EPOLLIN)
            self._deadline = time.monotonic() + self.timeout

    def _receive_incoming_packets(self) -> None:
        if self._socket is None:
            return

        while True:
            try:
                data, address = self._socket.recvfrom(MAX_PACKET_BUFFER_SIZE)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break

            if address[0] != self.target_ip:
                continue

            tcp_segment = PacketFilter.extract_tcp_segment(data)
            if tcp_segment is None:
                continue

            source_port, _ = PacketFilter.unpack_tcp_ports(tcp_segment)
            probe = self._probes_by_port.get(source_port)
            if probe is None:
                continue

            if PacketFilter.is_valid_tcp_response(
                tcp_segment=tcp_segment,
                expected_server_port=probe.target_port,
                expected_client_port=probe.client_port,
                sent_seq_num=probe.seq_num,
            ):
                response_time_ms = (time.monotonic() - probe.sent_time) * 1000.0
                if PacketFilter.is_syn_ack(tcp_segment):
                    self._results[source_port] = ScanResult(
                        protocol="TCP",
                        port=source_port,
                        response_time_ms=response_time_ms,
                    )
                self._unresolved_ports.discard(source_port)

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
