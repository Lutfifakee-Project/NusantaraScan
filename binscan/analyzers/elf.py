"""
Linux ELF (Executable and Linkable Format) analyzer.
"""


from rich.console import Console

console = Console()
import io
from elftools.elf.elffile import ELFFile
from .base import BaseAnalyzer


class ELFAnalyzer(BaseAnalyzer):
    """Analyzer untuk file ELF (Linux)."""

    def __init__(self, filepath: str, data: bytes = None):
        super().__init__(filepath, data)
        try:
            self.elf = ELFFile(io.BytesIO(self.data))
        except Exception as e:
            self.elf = None
            console.print(f"[-] Error loading ELF file: {e}")

    def get_sections(self) -> list:
        if not self.elf:
            return []
        sections = []
        for section in self.elf.iter_sections():
            # Skip SHT_NULL dan section tanpa nama
            if not section.name or section["sh_type"] == "SHT_NULL":
                continue
            try:
                data = section.data()
            except Exception:
                data = b""
            sections.append({
                "name": section.name,
                "virtual_address": section["sh_addr"],
                "virtual_size": section["sh_size"],
                "raw_size": section["sh_size"],
                "entropy": self.get_entropy_for_section(data),
            })
        return sections

    def get_imports(self) -> dict:
        if not self.elf:
            return {}
        imports = {}
        try:
            dyn = self.elf.get_section_by_name(".dynamic")
            if dyn:
                for tag in dyn.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        imports[tag.needed] = ["(functions not parsed)"]
        except Exception:
            pass
        return imports

    def get_exports(self) -> dict:
        if not self.elf:
            return {}
        exports = {}
        try:
            symtab = self.elf.get_section_by_name(".symtab")
            if symtab:
                for symbol in symtab.iter_symbols():
                    if symbol["st_info"]["type"] == "STT_FUNC" and symbol.name:
                        exports[symbol.name] = symbol["st_value"]
        except Exception:
            pass
        return exports

    def get_elf_info(self) -> dict:
        if not self.elf:
            return {}
        return {
            "e_type": self.elf.header["e_type"],
            "e_machine": self.elf.header["e_machine"],
            "e_entry": hex(self.elf.header["e_entry"]),
        }

    def get_text_section_data(self) -> bytes:
        if not self.elf:
            return b""
        for section in self.elf.iter_sections():
            if section.name == ".text":
                try:
                    return section.data()
                except Exception:
                    return b""
        return b""