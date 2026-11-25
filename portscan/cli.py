import argparse
import ipaddress

from portscan.constants import DEFAULT_SCAN_TIMEOUT
from portscan.models import ParsedArguments

ALL_PORT_RANGE: list[int] = list(range(1, 65536))


def parse_port_numbers(port_expression: str) -> list[int]:
    result_ports: list[int] = []
    seen_ports: set[int] = set()

    tokens = [token.strip() for token in port_expression.split(",") if token.strip()]
    for token in tokens:
        if "-" in token:
            parts = token.split("-", 1)
            try:
                start_port = int(parts[0])
                end_port = int(parts[1])
            except ValueError as err:
                raise ValueError(f"Port range '{token}' must contain valid integers") from err

            if start_port > end_port:
                raise ValueError(f"Invalid range '{token}': start port cannot exceed end port")
            if start_port < 1 or end_port > 65535:
                raise ValueError(f"Port range '{token}' out of valid boundaries (1-65535)")

            for port in range(start_port, end_port + 1):
                if port not in seen_ports:
                    seen_ports.add(port)
                    result_ports.append(port)
        else:
            try:
                port = int(token)
            except ValueError as err:
                raise ValueError(f"Port '{token}' must be an integer") from err

            if port < 1 or port > 65535:
                raise ValueError(f"Port '{token}' out of valid boundaries (1-65535)")

            if port not in seen_ports:
                seen_ports.add(port)
                result_ports.append(port)

    return result_ports


def parse_protocol_targets(target_tokens: list[str]) -> tuple[list[int], list[int]]:
    tcp_ports: list[int] = []
    udp_ports: list[int] = []
    seen_tcp: set[int] = set()
    seen_udp: set[int] = set()

    for item in target_tokens:
        token = item.strip()
        if not token:
            continue

        if "/" in token:
            protocol_name, ports_part = token.split("/", 1)
            protocol_name = protocol_name.lower()
            if protocol_name not in ("tcp", "udp"):
                raise ValueError(f"Unsupported protocol '{protocol_name}' in target '{token}'")

            parsed_ports = parse_port_numbers(ports_part)
        else:
            protocol_name = token.lower()
            if protocol_name not in ("tcp", "udp"):
                raise ValueError(f"Unsupported target specifier '{token}'")
            parsed_ports = list(ALL_PORT_RANGE)

        target_list = tcp_ports if protocol_name == "tcp" else udp_ports
        seen_set = seen_tcp if protocol_name == "tcp" else seen_udp

        for port in parsed_ports:
            if port not in seen_set:
                seen_set.add(port)
                target_list.append(port)

    return tcp_ports, udp_ports


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscan",
        description="TCP/UDP port scanner",
        usage="portscan [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_SCAN_TIMEOUT,
        help="Response timeout in seconds (default: 2.0)",
    )
    parser.add_argument(
        "-j",
        "--num-threads",
        type=int,
        default=None,
        dest="num_threads",
        help="Worker thread count for application protocol detection",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Display round-trip response time",
    )
    parser.add_argument(
        "-g",
        "--guess",
        action="store_true",
        default=False,
        help="Detect application layer protocol (HTTP, DNS, ECHO)",
    )
    parser.add_argument(
        "ip_address",
        help="Target IP address",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Target protocols and port ranges",
    )
    return parser


def parse_cli_args(raw_args: list[str] | None = None) -> ParsedArguments:
    parser = build_argument_parser()
    parsed = parser.parse_args(raw_args)

    try:
        ipaddress.ip_address(parsed.ip_address)
    except ValueError as err:
        raise ValueError(f"Invalid IP address: '{parsed.ip_address}'") from err

    if parsed.timeout <= 0:
        raise ValueError(f"Timeout must be strictly positive, got {parsed.timeout}")

    if parsed.num_threads is not None and parsed.num_threads <= 0:
        raise ValueError(f"Thread count must be strictly positive, got {parsed.num_threads}")

    tcp_ports, udp_ports = parse_protocol_targets(parsed.targets)

    if not parsed.targets:
        tcp_ports = list(ALL_PORT_RANGE)
        udp_ports = list(ALL_PORT_RANGE)

    return ParsedArguments(
        target_ip=parsed.ip_address,
        tcp_ports=tcp_ports,
        udp_ports=udp_ports,
        timeout=parsed.timeout,
        num_threads=parsed.num_threads,
        verbose=parsed.verbose,
        guess=parsed.guess,
    )
