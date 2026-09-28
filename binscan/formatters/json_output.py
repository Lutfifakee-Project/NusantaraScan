"""
JSON output formatter.
"""

import json


class JSONFormatter:
    """Format hasil analisis sebagai JSON."""

    @staticmethod
    def format(results: dict) -> str:
        return json.dumps(results, indent=2, default=str, ensure_ascii=False)

    @staticmethod
    def save(results: dict, filepath: str):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str, ensure_ascii=False)