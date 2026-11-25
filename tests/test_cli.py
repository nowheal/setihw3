import pytest

from portscan.cli import parse_cli_args


def test_parse_cli_args_desc_example():
    args = parse_cli_args(["1.1.1.1", "tcp/80", "tcp/12000-12002", "udp/3000-3001,3200"])
    assert args.target_ip == "1.1.1.1"
    assert args.tcp_ports == [80, 12000, 12001, 12002]
    assert args.udp_ports == [3000, 3001, 3200]
    assert args.timeout == 2.0
    assert args.verbose is False
    assert args.guess is False
    assert args.num_threads is None


def test_parse_cli_args_all_options_and_protocol_keyword():
    args = parse_cli_args([
        "-v",
        "-g",
        "--timeout",
        "4.5",
        "-j",
        "8",
        "8.8.8.8",
        "tcp",
        "udp/40000",
    ])
    assert args.target_ip == "8.8.8.8"
    assert len(args.tcp_ports) == 65535
    assert args.tcp_ports[0] == 1
    assert args.tcp_ports[-1] == 65535
    assert args.udp_ports == [40000]
    assert args.timeout == 4.5
    assert args.num_threads == 8
    assert args.verbose is True
    assert args.guess is True


def test_parse_cli_args_default_all_ports_when_empty_targets():
    args = parse_cli_args(["127.0.0.1"])
    assert args.target_ip == "127.0.0.1"
    assert len(args.tcp_ports) == 65535
    assert len(args.udp_ports) == 65535


def test_parse_cli_args_invalid_ip():
    with pytest.raises(ValueError, match="Invalid IP address"):
        parse_cli_args(["300.400.500.600", "tcp/80"])


def test_parse_cli_args_invalid_port_range():
    with pytest.raises(ValueError, match="out of valid boundaries"):
        parse_cli_args(["1.1.1.1", "tcp/70000"])

    with pytest.raises(ValueError, match="cannot exceed end port"):
        parse_cli_args(["1.1.1.1", "udp/100-50"])


def test_parse_cli_args_negative_timeout():
    with pytest.raises(ValueError, match="Timeout must be strictly positive"):
        parse_cli_args(["--timeout", "-1.0", "1.1.1.1", "tcp/80"])


def test_parse_cli_args_invalid_threads():
    with pytest.raises(ValueError, match="Thread count must be strictly positive"):
        parse_cli_args(["-j", "0", "1.1.1.1", "tcp/80"])
