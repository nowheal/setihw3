import struct

from portscan.constants import (
    STANDARD_TCP_HEADER_SIZE,
    TCP_FLAG_ACK,
    TCP_FLAG_RST,
    TCP_FLAG_SYN,
)


class PacketFilter:
    @staticmethod
    def extract_tcp_segment(ipv4_packet: bytes) -> bytes | None:
        if len(ipv4_packet) < 20:
            return None

        ip_version = ipv4_packet[0] >> 4
        if ip_version != 4:
            return None

        ip_header_length = (ipv4_packet[0] & 0x0F) * 4
        if len(ipv4_packet) < ip_header_length + STANDARD_TCP_HEADER_SIZE:
            return None

        return ipv4_packet[ip_header_length:]

    @staticmethod
    def unpack_tcp_ports(tcp_segment: bytes) -> tuple[int, int]:
        source_port, dest_port = struct.unpack("!HH", tcp_segment[:4])
        return source_port, dest_port

    @staticmethod
    def is_syn_ack(tcp_segment: bytes) -> bool:
        if len(tcp_segment) < STANDARD_TCP_HEADER_SIZE:
            return False
        flags = tcp_segment[13]
        return bool(flags & TCP_FLAG_SYN) and bool(flags & TCP_FLAG_ACK)

    @staticmethod
    def is_rst(tcp_segment: bytes) -> bool:
        if len(tcp_segment) < STANDARD_TCP_HEADER_SIZE:
            return False
        flags = tcp_segment[13]
        return bool(flags & TCP_FLAG_RST)

    @staticmethod
    def is_valid_tcp_response(
        tcp_segment: bytes,
        expected_server_port: int,
        expected_client_port: int,
        sent_seq_num: int,
    ) -> bool:
        if len(tcp_segment) < STANDARD_TCP_HEADER_SIZE:
            return False

        server_port, client_port = PacketFilter.unpack_tcp_ports(tcp_segment)
        if server_port != expected_server_port or client_port != expected_client_port:
            return False

        flags = tcp_segment[13]
        ack_number = struct.unpack("!I", tcp_segment[8:12])[0]
        expected_ack = (sent_seq_num + 1) & 0xFFFFFFFF

        if flags & TCP_FLAG_ACK:
            return ack_number == expected_ack

        if flags & TCP_FLAG_RST:
            rst_seq_number = struct.unpack("!I", tcp_segment[4:8])[0]
            return rst_seq_number in (expected_ack, 0)

        return False
