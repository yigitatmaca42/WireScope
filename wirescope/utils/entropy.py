"""Shannon entropy helper, used as a weak signal for encrypted/compressed/
obfuscated payloads that aren't recognizable plaintext or standard TLS."""

from __future__ import annotations

import math
from collections import Counter

# Max bits of entropy per byte is 8 (uniformly random byte values).
HIGH_ENTROPY_THRESHOLD = 7.5
MIN_SAMPLE_SIZE = 64


def shannon_entropy(data: bytes) -> float:
    if len(data) < MIN_SAMPLE_SIZE:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def is_high_entropy(data: bytes) -> bool:
    return shannon_entropy(data) >= HIGH_ENTROPY_THRESHOLD
