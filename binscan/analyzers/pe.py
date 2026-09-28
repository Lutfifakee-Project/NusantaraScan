"""
Windows PE (Portable Executable) analyzer.
"""


from rich.console import Console

console = Console()
import pefile
from .base import BaseAnalyzer


class PEAnalyzer(BaseAnalyzer):
    """Analyzer untuk file PE (Windows)."""

    def __init__(self, filepath: str, data: bytes = None):
        super().__init__(filepath, data)
        try:
            self.pe = pefile.PE(data=self.data, fast_load=True)
            self.pe.parse_data_directories()
        except Exception as e:
            self.pe = None
            if len(self.data) > 1024:
                console.print(f"[-] Bukan PE valid: {e}")

    def get_sections(self) -> list:
        if not self.pe:
            return []
        sections = []
        for section in self.pe.sections:
            name = section.Name.decode(errors="ignore").rstrip("\x00")
            sections.append({
                "name": name,
                "virtual_address": section.VirtualAddress,
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": self.get_entropy_for_section(section.get_data()),
            })
        return sections

    def get_imports(self) -> dict:
        if not self.pe:
            return {}
        imports = {}
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = (
                    entry.dll.decode(errors="ignore")
                    if isinstance(entry.dll, bytes) else entry.dll
                )
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        func = (
                            imp.name.decode(errors="ignore")
                            if isinstance(imp.name, bytes) else imp.name
                        )
                        functions.append(func)
                if functions:
                    imports[dll_name] = functions
        return imports

    def get_exports(self) -> dict:
        if not self.pe:
            return {}
        exports = {}
        if hasattr(self.pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = (
                        exp.name.decode(errors="ignore")
                        if isinstance(exp.name, bytes) else exp.name
                    )
                    exports[name] = exp.address
        return exports

    def get_pe_info(self) -> dict:
        if not self.pe:
            return {}
        return {
            "machine": pefile.MACHINE_TYPE.get(self.pe.FILE_HEADER.Machine, "Unknown"),
            "timestamp": self.pe.FILE_HEADER.TimeDateStamp,
            "characteristics": hex(self.pe.FILE_HEADER.Characteristics),
            "subsystem": pefile.SUBSYSTEM_TYPE.get(
                self.pe.OPTIONAL_HEADER.Subsystem, "Unknown"
            ),
        }

    def get_text_section_data(self) -> bytes:
        """Ambil byte dari .text section untuk disassembly."""
        if not self.pe:
            return b""
        for section in self.pe.sections:
            if b".text" in section.Name:
                return section.get_data()
        return b""