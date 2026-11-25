import socket


def get_local_ip(target_ip: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe_sock:
        probe_sock.connect((target_ip, 12345))
        return str(probe_sock.getsockname()[0])


def find_available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe_sock:
        probe_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe_sock.bind(("", 0))
        return probe_sock.getsockname()[1]
