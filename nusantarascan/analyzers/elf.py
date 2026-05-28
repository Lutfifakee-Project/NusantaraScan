"""
Linux ELF (Executable and Linkable Format) analyzer
"""

import struct
from elftools.elf.elffile import ELFFile
from .base import BaseAnalyzer

class ELFAnalyzer(BaseAnalyzer):
    """Analyzer for Linux ELF files"""
    
    def __init__(self, filepath):
        super().__init__(filepath)
        try:
            with open(filepath, 'rb') as f:
                self.elf = ELFFile(f)
        except Exception as e:
            self.elf = None
            print(f"[-] Error loading ELF file: {e}")
    
    def get_sections(self):
        """Get ELF section information"""
        if not self.elf:
            return []
        
        sections = []
        for section in self.elf.iter_sections():
            sections.append({
                'name': section.name,
                'virtual_address': section['sh_addr'],
                'virtual_size': section['sh_size'],
                'raw_size': section['sh_size'],
                'entropy': self.get_entropy_for_section(section.data())
            })
        
        return sections
    
    def get_imports(self):
        """Get imported functions (from dynamic section)"""
        if not self.elf:
            return {}
        
        imports = {}
        try:
            dyn = self.elf.get_section_by_name('.dynamic')
            if dyn:
                # Parse dynamic section for needed libraries
                needed_libs = []
                for tag in dyn.iter_tags():
                    if tag.entry.d_tag == 'DT_NEEDED':
                        needed_libs.append(tag.needed)
                
                for lib in needed_libs:
                    imports[lib] = ['(functions not parsed)']
        except Exception as e:
            pass
        
        return imports
    
    def get_exports(self):
        """Get exported functions"""
        if not self.elf:
            return {}
        
        exports = {}
        try:
            symtab = self.elf.get_section_by_name('.symtab')
            if symtab:
                for symbol in symtab.iter_symbols():
                    if symbol['st_info']['type'] == 'STT_FUNC' and symbol.name:
                        exports[symbol.name] = symbol['st_value']
        except Exception:
            pass
        
        return exports
    
    def get_elf_info(self):
        """Get additional ELF information"""
        if not self.elf:
            return {}
        
        info = {}
        info['e_type'] = self.elf.header['e_type']
        info['e_machine'] = self.elf.header['e_machine']
        info['e_entry'] = hex(self.elf.header['e_entry'])
        
        return info