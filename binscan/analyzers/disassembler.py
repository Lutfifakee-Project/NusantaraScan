"""
Disassembly module using Capstone engine.
Support x86/x64/ARM/ARM64.
"""

from capstone import (
    Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64,
    CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB,
    CS_ARCH_ARM64,
)
from rich.console import Console

console = Console()


class Disassembler:
    """Disassembler dengan dukungan multi-arsitektur."""

    ARCH_CONFIGS = {
        "x86_32": {"arch": CS_ARCH_X86, "mode": CS_MODE_32},
        "x86_64": {"arch": CS_ARCH_X86, "mode": CS_MODE_64},
        "arm": {"arch": CS_ARCH_ARM, "mode": CS_MODE_ARM},
        "arm_thumb": {"arch": CS_ARCH_ARM, "mode": CS_MODE_THUMB},
        "arm64": {"arch": CS_ARCH_ARM64, "mode": CS_MODE_ARM},
    }

    def __init__(self, arch: str = "x86_64"):
        self.arch = arch
        self._setup_disassembler()

    def _setup_disassembler(self):
        config = self.ARCH_CONFIGS.get(self.arch, self.ARCH_CONFIGS["x86_64"])
        self.md = Cs(config["arch"], config["mode"])
        self.md.detail = False

    def disassemble(self, data: bytes, start_address: int = 0x1000,
                    max_instructions: int = None) -> list:
        instructions = []
        for i, insn in enumerate(self.md.disasm(data, start_address)):
            if max_instructions is not None and i >= max_instructions:
                break
            instructions.append({
                "address": insn.address,
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "bytes": insn.bytes.hex(),
                "size": insn.size,
            })
        return instructions

    def disassemble_to_asm(self, data: bytes, start_address: int = 0x1000,
                           max_instructions: int = None) -> str:
        instructions = self.disassemble(data, start_address, max_instructions)
        lines = [
            f"{insn['address']:08x}:  {insn['mnemonic']:10} {insn['op_str']}"
            for insn in instructions
        ]
        return "\n".join(lines)

    def export_to_file(self, data: bytes, output_file: str,
                       start_address: int = 0x1000):
        asm = self.disassemble_to_asm(data, start_address, max_instructions=None)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"; Disassembly exported by NusantaraScan\n")
            f.write(f"; Architecture: {self.arch}\n")
            f.write(f"; Start address: 0x{start_address:x}\n\n")
            f.write(asm)
        console.print(f"    [green]Disassembly exported to {output_file}[/green]")


def disassemble_binary(data: bytes, arch: str = "x86_64",
                       max_instructions: int = 50) -> list:
    return Disassembler(arch).disassemble(data, max_instructions=max_instructions)