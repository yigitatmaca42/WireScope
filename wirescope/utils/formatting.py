"""Small, dependency-free formatting helpers used by the CLI and HTML report."""

from __future__ import annotations

from datetime import UTC, datetime

_SIZE_UNITS = ("B", "KB", "MB", "GB", "TB")


def human_bytes(num_bytes: float) -> str:
    """Format a byte count as e.g. '4.32 MB'."""
    value = float(num_bytes)
    for unit in _SIZE_UNITS:
        if value < 1024.0 or unit == _SIZE_UNITS[-1]:
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} {unit}"
        value /= 1024.0
    return f"{value:.2f} {_SIZE_UNITS[-1]}"


def human_duration(seconds: float) -> str:
    """Format a duration as HH:MM:SS (or MM:SS when under an hour)."""
    seconds = max(0, int(round(seconds)))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def human_timestamp(epoch: float | None) -> str:
    if epoch is None:
        return "-"
    return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def truncate(text: str, max_len: int = 60) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"
