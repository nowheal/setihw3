from portscan.models import ScanResult


def format_scan_result(result: ScanResult, verbose: bool = False, guess: bool = False) -> str:
    columns = [result.protocol.upper(), str(result.port)]

    if verbose:
        if result.response_time_ms is not None:
            columns.append(f"{result.response_time_ms:.1f}ms")
        else:
            columns.append("-")

    if guess:
        columns.append(result.app_protocol if result.app_protocol else "-")

    return " ".join(columns)


def print_scan_results(
    results: list[ScanResult],
    verbose: bool = False,
    guess: bool = False,
) -> None:
    for item in results:
        print(format_scan_result(item, verbose=verbose, guess=guess))
