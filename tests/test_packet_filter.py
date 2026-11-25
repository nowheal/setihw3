import struct

from portscan.packet_filter import PacketFilter


def build_mock_ipv4_tcp_packet(
    source_port: int,
    dest_port: int,
    seq_num: int,
    ack_num: int,
    flags: int,
) -> bytes:
    # IPv4 header (20 bytes)
    ip_version_ihl = (4 << 4) | 5
    ip_tos = 0
    ip_total_len = 40
    ip_id = 1234
    ip_frag_off = 0
    ip_ttl = 64
    ip_proto = 6
    ip_checksum = 0
    ip_src = b"\x08\x08\x08\x08"
    ip_dst = b"\xc0\xa8\x01\x01"

    ipv4_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        ip_version_ihl,
        ip_tos,
        ip_total_len,
        ip_id,
        ip_frag_off,
        ip_ttl,
        ip_proto,
        ip_checksum,
        ip_src,
        ip_dst,
    )

    tcp_hdr = struct.pack(
        "!HHIIHHHH",
        source_port,
        dest_port,
        seq_num,
        ack_num,
        (5 << 12) | flags,
        8192,
        0,
        0,
    )

    return ipv4_hdr + tcp_hdr


def test_extract_tcp_segment():
    packet = build_mock_ipv4_tcp_packet(
        source_port=80,
        dest_port=12345,
        seq_num=200,
        ack_num=101,
        flags=0x12,
    )
    segment = PacketFilter.extract_tcp_segment(packet)
    assert segment is not None
    assert len(segment) == 20

    src_p, dst_p = PacketFilter.unpack_tcp_ports(segment)
    assert src_p == 80
    assert dst_p == 12345


def test_packet_filter_syn_ack_validation():
    sent_seq = 500
    expected_ack = sent_seq + 1
    server_port = 80
    client_port = 55555

    packet = build_mock_ipv4_tcp_packet(
        source_port=server_port,
        dest_port=client_port,
        seq_num=1000,
        ack_num=expected_ack,
        flags=0x12,
    )
    segment = PacketFilter.extract_tcp_segment(packet)
    assert segment is not None
    assert PacketFilter.is_syn_ack(segment) is True
    assert PacketFilter.is_rst(segment) is False

    is_valid = PacketFilter.is_valid_tcp_response(
        tcp_segment=segment,
        expected_server_port=server_port,
        expected_client_port=client_port,
        sent_seq_num=sent_seq,
    )
    assert is_valid is True


def test_packet_filter_rst_validation():
    sent_seq = 700
    server_port = 80
    client_port = 44444

    packet = build_mock_ipv4_tcp_packet(
        source_port=server_port,
        dest_port=client_port,
        seq_num=sent_seq + 1,
        ack_num=0,
        flags=0x04,
    )
    segment = PacketFilter.extract_tcp_segment(packet)
    assert segment is not None
    assert PacketFilter.is_rst(segment) is True

    is_valid = PacketFilter.is_valid_tcp_response(
        tcp_segment=segment,
        expected_server_port=server_port,
        expected_client_port=client_port,
        sent_seq_num=sent_seq,
    )
    assert is_valid is True


def test_packet_filter_mismatched_ports():
    packet = build_mock_ipv4_tcp_packet(
        source_port=81,
        dest_port=44444,
        seq_num=1000,
        ack_num=701,
        flags=0x12,
    )
    segment = PacketFilter.extract_tcp_segment(packet)
    assert segment is not None

    is_valid = PacketFilter.is_valid_tcp_response(
        tcp_segment=segment,
        expected_server_port=80,
        expected_client_port=44444,
        sent_seq_num=700,
    )
    assert is_valid is False
