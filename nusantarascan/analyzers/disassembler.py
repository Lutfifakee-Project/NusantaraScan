"""
Disassembly module using Capstone engine
Support x86/x64/ARM/ARM64
"""

from capstone import (
    Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64,
    CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB,
    CS_ARCH_ARM64, CS_MODE_ARM
)
from rich.console import Console
from rich.syntax import Syntax

console = Console()


class Disassembler:
    """Full disassembler with multiple architecture support"""
    
    ARCH_CONFIGS = {
        'x86_32': {'arch': CS_ARCH_X86, 'mode': CS_MODE_32},
        'x86_64': {'arch': CS_ARCH_X86, 'mode': CS_MODE_64},
        'arm': {'arch': CS_ARCH_ARM, 'mode': CS_MODE_ARM},
        'arm_thumb': {'arch': CS_ARCH_ARM, 'mode': CS_MODE_THUMB},
        'arm64': {'arch': CS_ARCH_ARM64, 'mode': CS_MODE_ARM},
    }
    
    def __init__(self, arch='x86_64'):
        self.arch = arch
        self._setup_disassembler()
    
    def _setup_disassembler(self):
        """Setup Capstone disassembler"""
        config = self.ARCH_CONFIGS.get(self.arch, self.ARCH_CONFIGS['x86_64'])
        self.md = Cs(config['arch'], config['mode'])
        self.md.detail = True
    
    def disassemble(self, data, start_address=0x1000, max_instructions=None):
        """
        Disassemble binary data
        
        Args:
            data: bytes to disassemble
            start_address: starting address for disassembly
            max_instructions: max number of instructions (None = all)
        
        Returns:
            list of instruction dicts
        """
        instructions = []
        
        for i, insn in enumerate(self.md.disasm(data, start_address)):
            if max_instructions is not None and i >= max_instructions:
                break
            
            instructions.append({
                'address': insn.address,
                'mnemonic': insn.mnemonic,
                'op_str': insn.op_str,
                'bytes': insn.bytes.hex(),
                'size': insn.size
            })
        
        return instructions
    
    def disassemble_to_asm(self, data, start_address=0x1000, max_instructions=None):
        """Disassemble and return as assembly string"""
        instructions = self.disassemble(data, start_address, max_instructions)
        
        asm_lines = []
        for insn in instructions:
            asm_lines.append(f"{insn['address']:08x}:  {insn['mnemonic']:10} {insn['op_str']}")
        
        return '\n'.join(asm_lines)
    
    def export_to_file(self, data, output_file, start_address=0x1000):
        """Export disassembly to .asm file"""
        asm_code = self.disassemble_to_asm(data, start_address, max_instructions=None)
        
        with open(output_file, 'w') as f:
            f.write(f"; Disassembly exported by NusantaraScan\n")
            f.write(f"; Architecture: {self.arch}\n")
            f.write(f"; Start address: 0x{start_address:x}\n\n")
            f.write(asm_code)
        
        console.print(f"    [green]✓ Disassembly exported to {output_file}[/green]")


def disassemble_binary(data, arch='x86_64', max_instructions=50):
    """
    Quick disassembly function (compatible with old code)
    """
    dis = Disassembler(arch)
    return dis.disassemble(data, max_instructions=max_instructions)