"""
macOS Mach-O analyzer.
Parsing header dasar - bukan full parser.
"""

import struct
from .base import BaseAnalyzer


class MachOAnalyzer(BaseAnalyzer):
    """Analyzer untuk file Mach-O (macOS)."""

    MAGIC_32 = 0xFEEDFACE
    MAGIC_64 = 0xFEEDFACF
    MAGIC_FAT = 0xCAFEBABE

    def __init__(self, filepath: str, data: bytes = None):
        super().__init__(filepath, data)
        self.magic = None
        self.is_64 = False
        self._parse_header()

    def _parse_header(self):
        if len(self.data) >= 4:
            self.magic = struct.unpack("<I", self.data[:4])[0]
            if self.magic == self.MAGIC_64:
                self.is_64 = True
            elif self.magic == self.MAGIC_32:
                self.is_64 = False
            elif self.magic == self.MAGIC_FAT:
                self.magic = "FAT"

    def get_sections(self) -> list:
        return [{
            "name": "Mach-O",
            "virtual_address": 0,
            "virtual_size": len(self.data),
            "raw_size": len(self.data),
            "entropy": self.get_entropy_for_section(self.data),
        }]

    def get_imports(self) -> dict:
        return {}

    def get_exports(self) -> dict:
        return {}

    def get_text_section_data(self) -> bytes:
        """Ambil data section __text (placeholder).

        Parsing Mach-O lengkap butuh library tambahan seperti macholib.
        Untuk saat ini kembalikan bytes kosong agar deep analysis
        tidak crash. Akan diimplementasikan di versi berikutnya.
        """
        return b""

    def get_macho_info(self) -> dict:
        if self.magic == "FAT":
            return {"magic": "FAT", "arch": "universal"}
        if self.magic == self.MAGIC_64:
            return {"magic": "0xFEEDFACF", "arch": "x86_64/arm64"}
        if self.magic == self.MAGIC_32:
            return {"magic": "0xFEEDFACE", "arch": "i386/arm"}
        return {"magic": hex(self.magic) if self.magic else "unknown"}