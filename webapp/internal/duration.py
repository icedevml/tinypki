import re

def parse_go_duration(s: str) -> float:
    """
    Parse a Go time.ParseDuration string into seconds (float).
    Supports: h, m, s, ms, us (µs), ns
    Examples: "24h", "2h45m", "300ms", "1.5h", "100s", "300us"
    """
    if s == "0":
        return 0.0

    units = {
        "h":  3600,
        "m":  60,
        "s":  1,
        "ms": 1e-3,
        "us": 1e-6,
        "µs": 1e-6,
        "ns": 1e-9,
    }

    pattern = re.compile(r'([+-]?\d+\.?\d*)(ns|µs|us|ms|[hms])')
    matches = pattern.findall(s)

    if not matches:
        raise ValueError(f"Invalid duration string: {s!r}")

    total = sum(float(value) * units[unit] for value, unit in matches)

    # handle leading negative sign e.g. "-1h30m"
    if s.lstrip().startswith("-"):
        total = -total

    return total


def days_to_go_duration(days: int) -> str:
    val = days * 24
    return f"{val}h"
