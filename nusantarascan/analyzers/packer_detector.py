"""
Packer detector for binary files
"""

class PackerDetector:
    """Detect packers in binary files"""
    
    PACKER_SIGNATURES = {
        'UPX': [b'UPX0', b'UPX1', b'UPX!'],
        'ASPack': [b'ASPack', b'.aspack'],
        'MPRESS': [b'MPRESS', b'mpress'],
        'PECompact': [b'PEC2', b'PECompact'],
        'Themida': [b'Themida', b'WinLicense'],
        'VMProtect': [b'VMProtect', b'VMP'],
        'Enigma': [b'Enigma', b'Enigma Protector'],
        'Armadillo': [b'Armadillo', b'ArmAccess'],
        'Obsidium': [b'Obsidium', b'obsi'],
        'EXE32Pack': [b'EXE32Pack', b'Exe32Pack'],
    }
    
    @staticmethod
    def detect(data):
        """Detect packer by signature"""
        for packer, signatures in PackerDetector.PACKER_SIGNATURES.items():
            for sig in signatures:
                if sig in data:
                    return packer
        return None
    
    @staticmethod
    def detect_by_entropy(sections):
        """Detect packer by entropy pattern"""
        if not sections:
            return None
        
        high_entropy_sections = [s for s in sections if s.get('entropy', 0) > 7.5]
        if len(high_entropy_sections) >= 2:
            return 'Possible packed (high entropy sections)'
        
        zero_entropy_sections = [s for s in sections if s.get('entropy', 0) < 0.5 and s.get('raw_size', 0) > 0]
        if zero_entropy_sections:
            return 'Possible packed (zero entropy sections)'
        
        return None
