"""
YARA scanner wrapper - dengan validasi path & recursive scan.
"""


from rich.console import Console

console = Console()
import glob
import os

from ..config import YARA_ALLOWED_EXTENSIONS
from ..utils.validators import validate_rule_path, ValidationError


class YaraScanner:
    """Wrapper untuk YARA scanning."""

    def __init__(self, rule_path: str, recursive: bool = False):
        self.rule_path = rule_path
        self.recursive = recursive
        self.rules = None
        self._compile_rules()

    def _collect_rule_files(self, directory) -> list:
        """Kumpulkan semua file rule di direktori (opsional recursive)."""
        rule_files = []
        pattern = "**/*" if self.recursive else "*"
        for ext in YARA_ALLOWED_EXTENSIONS:
            rule_files.extend(
                glob.glob(str(directory / f"{pattern}{ext}"), recursive=True)
            )
        return sorted(set(rule_files))

    def _compile_rules(self):
        try:
            import yara

            try:
                validated = validate_rule_path(
                    self.rule_path, base_dir=os.getcwd()
                )
            except ValidationError:
                validated = validate_rule_path(self.rule_path)

            if validated.is_file():
                if not str(validated).endswith(YARA_ALLOWED_EXTENSIONS):
                    console.print(f"[-] Ekstensi rule tidak didukung: {validated}")
                    self.rules = None
                    return
                self.rules = yara.compile(filepath=str(validated))

            elif validated.is_dir():
                rule_files = self._collect_rule_files(validated)
                if rule_files:
                    self.rules = yara.compile(
                        filepaths={
                            f"rule_{i}": f
                            for i, f in enumerate(rule_files)
                        }
                    )
                else:
                    console.print(f"[-] Tidak ada file rule di: {validated}")
                    self.rules = None
            else:
                self.rules = None

        except Exception as e:
            console.print(f"[-] YARA compile error: {e}")
            self.rules = None

    def scan(self, filepath: str) -> list:
        if not self.rules:
            return []
        try:
            matches = self.rules.match(filepath)
            return [m.rule for m in matches]
        except Exception as e:
            console.print(f"[-] YARA scan error: {e}")
            return []