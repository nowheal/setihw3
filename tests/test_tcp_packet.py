import socket
import struct

from portscan.tcp_packet import TcpSynPacket, compute_internet_checksum


def test_pseudo_header_structure():
    packet = TcpSynPacket(
        source_ip="192.168.1.100",
        dest_ip="8.8.8.8",
        source_port=12345,
        dest_port=80,
    )
    pseudo_hdr = packet.build_pseudo_header(tcp_length=20)
    assert len(pseudo_hdr) == 12

    src_bytes, dst_bytes, zero, proto, length = struct.unpack("!4s4sBBH", pseudo_hdr)
    assert src_bytes == socket.inet_aton("192.168.1.100")
    assert dst_bytes == socket.inet_aton("8.8.8.8")
    assert zero == 0
    assert proto == socket.IPPROTO_TCP
    assert length == 20


def test_tcp_syn_packet_fields():
    packet = TcpSynPacket(
        source_ip="10.0.0.1",
        dest_ip="10.0.0.2",
        source_port=54321,
        dest_port=443,
        seq_num=1000,
        window_size=8192,
    )
    raw_packet = packet.to_bytes()
    assert len(raw_packet) == 20

    src_p, dst_p, seq, ack, offset_flags, win, chk, urg = struct.unpack(
        "!HHIIHHHH", raw_packet
    )
    assert src_p == 54321
    assert dst_p == 443
    assert seq == 1000
    assert ack == 0
    assert (offset_flags >> 12) == 5
    assert (offset_flags & 0x02) == 2
    assert win == 8192
    assert urg == 0


def test_checksum_verification():
    packet = TcpSynPacket(
        source_ip="1.2.3.4",
        dest_ip="5.6.7.8",
        source_port=30000,
        dest_port=80,
        seq_num=55555,
    )
    packet_bytes = packet.to_bytes()
    pseudo_hdr = packet.build_pseudo_header(len(packet_bytes))

    total_data = pseudo_hdr + packet_bytes
    assert compute_internet_checksum(total_data) == 0
