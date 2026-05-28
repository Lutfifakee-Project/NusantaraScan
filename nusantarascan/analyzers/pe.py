"""
Windows PE (Portable Executable) analyzer
"""

import pefile
import struct
from .base import BaseAnalyzer

class PEAnalyzer(BaseAnalyzer):
    """Analyzer for Windows PE files"""
    
    def __init__(self, filepath):
        super().__init__(filepath)
        try:
            self.pe = pefile.PE(filepath)
        except Exception as e:
            self.pe = None
            print(f"[-] Error loading PE file: {e}")
    
    def get_sections(self):
        """Get PE section information"""
        if not self.pe:
            return []
        
        sections = []
        for section in self.pe.sections:
            sections.append({
                'name': section.Name.decode().rstrip('\x00'),
                'virtual_address': section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': self.get_entropy_for_section(section.get_data())
            })
        
        return sections
    
    def get_imports(self):
        """Get imported DLLs and functions"""
        if not self.pe:
            return {}
        
        imports = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode() if isinstance(entry.dll, bytes) else entry.dll
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode() if isinstance(imp.name, bytes) else imp.name
                        functions.append(func_name)
                if functions:
                    imports[dll_name] = functions
        
        return imports
    
    def get_exports(self):
        """Get exported functions"""
        if not self.pe:
            return {}
        
        exports = {}
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode() if isinstance(exp.name, bytes) else exp.name
                    exports[name] = exp.address
        
        return exports
    
    def get_pe_info(self):
        """Get additional PE information"""
        if not self.pe:
            return {}
        
        info = {}
        info['machine'] = pefile.MACHINE_TYPE.get(self.pe.FILE_HEADER.Machine, 'Unknown')
        info['timestamp'] = self.pe.FILE_HEADER.TimeDateStamp
        info['characteristics'] = hex(self.pe.FILE_HEADER.Characteristics)
        info['subsystem'] = pefile.SUBSYSTEM_TYPE.get(self.pe.OPTIONAL_HEADER.Subsystem, 'Unknown')
        
        return info