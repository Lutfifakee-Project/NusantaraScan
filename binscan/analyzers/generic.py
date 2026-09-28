"""
Generic analyzer - fallback untuk file yang tidak dikenali.
"""

from .base import BaseAnalyzer


class GenericAnalyzer(BaseAnalyzer):
    """Analyzer generik untuk file apapun."""

    def get_sections(self) -> list:
        return [{
            "name": "raw",
            "virtual_address": 0,
            "virtual_size": len(self.data),
            "raw_size": len(self.data),
            "entropy": self.get_entropy_for_section(self.data),
        }]

    def get_imports(self) -> dict:
        return {}

    def get_exports(self) -> dict:
        return {}