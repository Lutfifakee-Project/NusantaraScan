"""
Entropy calculation utilities.
"""

import math
from collections import Counter


class EntropyCalculator:
    """Hitung Shannon entropy."""

    @staticmethod
    def calculate_entropy(filepath: str) -> float:
        counter = Counter()
        total = 0
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                counter.update(chunk)
                total += len(chunk)
        return EntropyCalculator._shannon(counter, total)

    @staticmethod
    def calculate_entropy_for_data(data: bytes) -> float:
        if not data:
            return 0.0
        return EntropyCalculator._shannon(Counter(data), len(data))

    @staticmethod
    def _shannon(counter: Counter, total: int) -> float:
        if total == 0:
            return 0.0
        entropy = 0.0
        for count in counter.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return entropy