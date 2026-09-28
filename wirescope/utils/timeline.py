"""Coarsen the analyzer's per-second timeline into a fixed number of
display buckets, sized to the capture's actual duration."""

from __future__ import annotations


def bucketize_timeline(
    timeline: dict[int, list[int]], num_buckets: int = 40
) -> list[tuple[float, int, int]]:
    """Returns a list of (bucket_start_offset_seconds, packet_count,
    byte_count), one entry per display bucket, oldest first. Empty buckets
    are included as zeros so the resulting series has a consistent length."""
    if not timeline:
        return []

    seconds = sorted(timeline)
    start, end = seconds[0], seconds[-1]
    span = max(1, end - start + 1)
    bucket_width = max(1, -(-span // num_buckets))  # ceil division

    buckets: list[list[int]] = [[0, 0] for _ in range(-(-span // bucket_width))]
    for sec, (packets, byte_count) in timeline.items():
        idx = (sec - start) // bucket_width
        idx = min(idx, len(buckets) - 1)
        buckets[idx][0] += packets
        buckets[idx][1] += byte_count

    return [(i * bucket_width, p, b) for i, (p, b) in enumerate(buckets)]
