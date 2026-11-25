import random
import socket
import struct

from portscan.constants import (
    DEFAULT_TCP_WINDOW_SIZE,
    STANDARD_TCP_HEADER_SIZE,
    TCP_FLAG_SYN,
)


def compute_internet_checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        data += b"\x00"

    checksum = 0
    for offset in range(0, len(data), 2):
        word = int.from_bytes(data[offset : offset + 2], byteorder="big")
        checksum += word

    while (checksum >> 16) > 0:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    return (~checksum) & 0xFFFF


class TcpSynPacket:
    def __init__(
        self,
        source_ip: str,
        dest_ip: str,
        source_port: int,
        dest_port: int,
        seq_num: int | None = None,
        window_size: int = DEFAULT_TCP_WINDOW_SIZE,
    ) -> None:
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.seq_num = seq_num if seq_num is not None else random.randint(0, 0xFFFFFFFF)
        self.window_size = window_size
        self._cached_packet: bytes | None = None

    def build_pseudo_header(self, tcp_length: int) -> bytes:
        source_ip_bytes = socket.inet_aton(self.source_ip)
        dest_ip_bytes = socket.inet_aton(self.dest_ip)
        reserved_byte = 0
        protocol_byte = socket.IPPROTO_TCP
        return struct.pack(
            "!4s4sBBH",
            source_ip_bytes,
            dest_ip_bytes,
            reserved_byte,
            protocol_byte,
            tcp_length,
        )

    def build_raw_segment(self, checksum: int = 0) -> bytes:
        data_offset_words = STANDARD_TCP_HEADER_SIZE // 4
        offset_and_flags = (data_offset_words << 12) | TCP_FLAG_SYN
        ack_num = 0
        urgent_pointer = 0

        return struct.pack(
            "!HHIIHHHH",
            self.source_port,
            self.dest_port,
            self.seq_num,
            ack_num,
            offset_and_flags,
            self.window_size,
            checksum,
            urgent_pointer,
        )

    def to_bytes(self) -> bytes:
        if self._cached_packet is not None:
            return self._cached_packet

        unchecksummed_segment = self.build_raw_segment(checksum=0)
        pseudo_header = self.build_pseudo_header(len(unchecksummed_segment))
        checksum = compute_internet_checksum(pseudo_header + unchecksummed_segment)

        segment_buffer = bytearray(unchecksummed_segment)
        struct.pack_into("!H", segment_buffer, 16, checksum)

        self._cached_packet = bytes(segment_buffer)
        return self._cached_packet
