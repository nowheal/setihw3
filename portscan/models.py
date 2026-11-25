from dataclasses import dataclass, field


@dataclass
class ScanResult:
    protocol: str
    port: int
    response_time_ms: float | None = None
    app_protocol: str | None = None


@dataclass
class ParsedArguments:
    target_ip: str
    tcp_ports: list[int] = field(default_factory=list)
    udp_ports: list[int] = field(default_factory=list)
    timeout: float = 2.0
    num_threads: int | None = None
    verbose: bool = False
    guess: bool = False
