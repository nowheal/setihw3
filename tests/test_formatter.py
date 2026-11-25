from portscan.formatter import format_scan_result
from portscan.models import ScanResult


def test_format_scan_result_basic():
    result = ScanResult(protocol="TCP", port=80)
    assert format_scan_result(result, verbose=False, guess=False) == "TCP 80"


def test_format_scan_result_verbose():
    result = ScanResult(protocol="TCP", port=443, response_time_ms=12.345)
    assert format_scan_result(result, verbose=True, guess=False) == "TCP 443 12.3ms"


def test_format_scan_result_guess():
    result = ScanResult(protocol="TCP", port=80, app_protocol="HTTP")
    assert format_scan_result(result, verbose=False, guess=True) == "TCP 80 HTTP"


def test_format_scan_result_verbose_and_guess():
    result = ScanResult(protocol="TCP", port=53, response_time_ms=2.1, app_protocol="DNS")
    assert format_scan_result(result, verbose=True, guess=True) == "TCP 53 2.1ms DNS"


def test_format_scan_result_guess_unknown_protocol():
    result = ScanResult(protocol="UDP", port=3000, response_time_ms=5.0, app_protocol=None)
    assert format_scan_result(result, verbose=True, guess=True) == "UDP 3000 5.0ms -"
