"""
Packer detector for binary files.
"""


class PackerDetector:
    """Deteksi packer dari signature & entropy."""

    # Signature packer — harus SPESIFIK, jangan generik.
    # Contoh: b"mpress" (lowercase) bisa match string "compress" di file normal.
    PACKER_SIGNATURES = {
        "UPX": [b"UPX0", b"UPX1", b"UPX!"],
        "ASPack": [b"ASPack", b".aspack"],
        "MPRESS": [b"MPRESS1", b"MPRESS2"],
        "PECompact": [b"PEC2", b"PECompact"],
        "Themida": [b"Themida", b"WinLicense"],
        "VMProtect": [b"VMProtect", b".vmp0", b".vmp1"],
        "Enigma": [b"Enigma Protector"],
        "Armadillo": [b"Armadillo", b"ArmAccess"],
        "Obsidium": [b"Obsidium"],
        "EXE32Pack": [b"EXE32Pack", b"Exe32Pack"],
    }

    # Section yang NORMAL punya entropy 0 (uninitialized data).
    # Tidak boleh dianggap indikator packing.
    ZERO_ENTROPY_WHITELIST = {
        ".bss", "bss",
        ".tbss", "tbss",
        ".sbss", "sbss",
    }

    @staticmethod
    def detect(data: bytes):
        for packer, signatures in PackerDetector.PACKER_SIGNATURES.items():
            for sig in signatures:
                if sig in data:
                    return packer
        return None

    @staticmethod
    def detect_by_entropy(sections: list):
        if not sections:
            return None

        # High entropy: minimal 2 section > 7.5 (indikator packed/encrypted)
        high = [s for s in sections if s.get("entropy", 0) > 7.5]
        if len(high) >= 2:
            return "Possible packed (high entropy sections)"

        # Zero entropy: skip section yang memang normal punya entropy 0 (.bss, dll)
        zero = []
        for s in sections:
            name = s.get("name", "").lower().strip()
            if name in PackerDetector.ZERO_ENTROPY_WHITELIST:
                continue
            if s.get("entropy", 0) < 0.5 and s.get("raw_size", 0) > 0:
                zero.append(s)

        if zero:
            return "Possible packed (zero entropy sections)"

        return None