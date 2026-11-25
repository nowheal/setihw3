import sys
from concurrent.futures import ThreadPoolExecutor

from portscan.cli import parse_cli_args
from portscan.event_loop import EventLoop
from portscan.formatter import print_scan_results
from portscan.models import ParsedArguments, ScanResult
from portscan.network_utils import get_local_ip
from portscan.service_detector import ServiceDetector
from portscan.tcp_scanner import TcpScanner
from portscan.udp_scanner import UdpScanner


def execute_scan(arguments: ParsedArguments) -> int:
    target_ip = arguments.target_ip
    local_ip = get_local_ip(target_ip)
    event_loop = EventLoop()

    tcp_scanner: TcpScanner | None = None
    udp_scanner: UdpScanner | None = None

    if arguments.tcp_ports:
        tcp_scanner = TcpScanner(
            target_ip=target_ip,
            ports=arguments.tcp_ports,
            local_ip=local_ip,
            event_loop=event_loop,
            timeout=arguments.timeout,
        )
        tcp_scanner.start()

    if arguments.udp_ports:
        udp_scanner = UdpScanner(
            target_ip=target_ip,
            ports=arguments.udp_ports,
            event_loop=event_loop,
            timeout=arguments.timeout,
        )
        udp_scanner.start()

    event_loop.run()

    scan_results: list[ScanResult] = []
    if tcp_scanner is not None:
        scan_results.extend(tcp_scanner.get_results())
    if udp_scanner is not None:
        scan_results.extend(udp_scanner.get_results())

    if arguments.guess and scan_results:
        detector = ServiceDetector(target_ip=target_ip, timeout=arguments.timeout)
        max_workers = arguments.num_threads or 10

        def detect_service(res: ScanResult) -> ScanResult:
            if res.protocol == "TCP":
                res.app_protocol = detector.detect_tcp(res.port)
            else:
                res.app_protocol = detector.detect_udp(res.port)
            return res

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            scan_results = list(pool.map(detect_service, scan_results))

    print_scan_results(scan_results, verbose=arguments.verbose, guess=arguments.guess)
    return 0


def main(args: list[str] | None = None) -> int:
    try:
        parsed_args = parse_cli_args(args)
    except (ValueError, SystemExit) as err:
        if isinstance(err, SystemExit):
            return err.code if isinstance(err.code, int) else 0
        print(f"Error: {err}", file=sys.stderr)
        return 1

    try:
        return execute_scan(parsed_args)
    except KeyboardInterrupt:
        return 130
    except PermissionError:
        print(
            "Error: Raw sockets require superuser privileges (run with sudo).",
            file=sys.stderr,
        )
        return 1
    except OSError as err:
        print(f"Network error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
