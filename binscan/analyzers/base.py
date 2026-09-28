"""
Base analyzer class for binary analysis.
"""

import math
from abc import ABC, abstractmethod


class BaseAnalyzer(ABC):
    """Base class untuk semua binary analyzer."""

    def __init__(self, filepath: str, data: bytes = None):
        self.filepath = filepath
        if data is None:
            with open(filepath, "rb") as f:
                self.data = f.read()
        else:
            self.data = data

    @abstractmethod
    def get_sections(self) -> list:
        """Return list of section dicts."""
        ...

    @abstractmethod
    def get_imports(self) -> dict:
        """Return dict {library: [functions]}."""
        ...

    @abstractmethod
    def get_exports(self) -> dict:
        """Return dict {name: address}."""
        ...

    @staticmethod
    def get_entropy_for_section(data: bytes) -> float:
        """Hitung Shannon entropy untuk section."""
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy