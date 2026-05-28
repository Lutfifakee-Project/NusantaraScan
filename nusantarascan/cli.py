#!/usr/bin/env python3
"""
CLI handler for NusantaraScan
"""

import argparse
import sys
import os
from pathlib import Path
from colorama import init, Fore, Style
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.style import Style

init(autoreset=True)
console = Console()

from .analyzers.base import BaseAnalyzer
from .analyzers.pe import PEAnalyzer
from .analyzers.elf import ELFAnalyzer
from .analyzers.strings import StringAnalyzer
from .analyzers.packer_detector import PackerDetector
from .analyzers.disassembler import Disassembler
from .visualizers.entropy_graph import display_entropy_bars, export_entropy_graph
from .integrations.virustotal import VirusTotal
from .scanners.multi_file import MultiFileScanner
from .utils.hasher import FileHasher
from .utils.entropy import EntropyCalculator


def create_parser():
    """Create argument parser"""
    parser = argparse.ArgumentParser(
        prog="nusantarascan",
        description="NusantaraScan - Analisis mendalam untuk file binary (PE, ELF, Mach-O)",
        epilog="Dibangun dengan semangat Nusantara untuk keamanan siber Indonesia.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "target",
        help="File atau direktori target yang akan dianalisis"
    )
    
    parser.add_argument(
        "-d", "--deep",
        action="store_true",
        help="Analisis mendalam (termasuk disassembly dan YARA scan)"
    )
    
    parser.add_argument(
        "-y", "--yara",
        metavar="RULE_PATH",
        help="Path ke file atau direktori YARA rules"
    )
    
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Export hasil analisis ke file (JSON/HTML)"
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=["json", "html", "text"],
        default="text",
        help="Format output (default: text)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Tampilkan informasi detail"
    )
    
    parser.add_argument(
        "--packer",
        action="store_true",
        help="Deteksi packer pada file"
    )
    
    parser.add_argument(
        "--graph",
        action="store_true",
        help="Tampilkan visualisasi entropy bar graph"
    )
    
    parser.add_argument(
        "--full-disasm",
        action="store_true",
        help="Full disassembly (tidak terbatas 20 instruksi)"
    )
    
    parser.add_argument(
        "--disasm-arch",
        choices=["x86_32", "x86_64", "arm", "arm_thumb", "arm64"],
        default="x86_64",
        help="Arsitektur untuk disassembly (default: x86_64)"
    )
    
    parser.add_argument(
        "--export-asm",
        metavar="FILE",
        help="Export disassembly ke file .asm"
    )
    
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Scan semua file dalam direktori (recursive)"
    )
    
    parser.add_argument(
        "--vt", "--virustotal",
        action="store_true",
        help="Cek hash file ke VirusTotal API"
    )
    
    parser.add_argument(
        "--vt-api-key",
        metavar="KEY",
        help="VirusTotal API key (atau set env VT_API_KEY)"
    )
    
    return parser


def print_banner():
    banner_text = r"""
    _   _                       _                  ____                  
   | \ | |_   _ ___  __ _ _ __ | |_ __ _ _ __ __ _/ ___|  ___ __ _ _ __  
   |  \| | | | / __|/ _` | '_ \| __/ _` | '__/ _` \___ \ / __/ _` | '_ \ 
   | |\  | |_| \__ \ (_| | | | | || (_| | | | (_| |___) | (_| (_| | | | |
   |_| \_|\__,_|___/\__,_|_| |_|\__\__,_|_|  \__,_|____/ \___\__,_|_| |_| 0.2.2
                https://github.com/Lutfifakee-Project/
    """
    console.print(banner_text, highlight=False)
    console.print()


def detect_file_type(filepath):
    """Detect file type using magic numbers"""
    try:
        import magic
        return magic.from_file(filepath)
    except ImportError:
        ext = Path(filepath).suffix.lower()
        if ext in ['.exe', '.dll', '.sys']:
            return "PE32 executable"
        elif ext in ['.so', '.elf', '']:
            return "ELF binary"
        else:
            return "Unknown"


def get_analyzer(filepath, file_type):
    """Get appropriate analyzer based on file type"""
    if "PE32" in file_type or filepath.endswith(('.exe', '.dll', '.sys')):
        return PEAnalyzer(filepath)
    elif "ELF" in file_type or filepath.endswith(('.so', '.elf')):
        return ELFAnalyzer(filepath)
    elif "Mach-O" in file_type or filepath.endswith(('.dylib', '')):
        from .analyzers.macho import MachOAnalyzer
        return MachOAnalyzer(filepath)
    else:
        return BaseAnalyzer(filepath)


def scan_single_file(filepath, args):
    """Scan a single file with all requested features"""
    target_path = Path(filepath)
    
    # Basic file info
    file_size = target_path.stat().st_size
    file_size_formatted = f"{file_size:,} bytes"
    if file_size > 1024 * 1024:
        file_size_formatted += f" ({file_size / (1024*1024):.2f} MB)"
    elif file_size > 1024:
        file_size_formatted += f" ({file_size / 1024:.2f} KB)"
    
    console.print(f"[+] Target   : {target_path.name}", style="bold green")
    console.print(f"[+] Size     : {file_size_formatted}", style="green")
    
    # Calculate hashes
    hasher = FileHasher(filepath)
    md5_hash = hasher.md5()
    sha256_hash = hasher.sha256()
    console.print(f"[+] MD5      : {md5_hash}", style="green")
    console.print(f"[+] SHA1     : {hasher.sha1()}", style="green")
    console.print(f"[+] SHA256   : {sha256_hash}", style="green")
    
    # Calculate entropy
    entropy = EntropyCalculator.calculate_entropy(filepath)
    entropy_color = "green" if entropy < 6.5 else "yellow" if entropy < 7.5 else "red"
    console.print(f"[+] Entropy  : {entropy:.4f}", style=entropy_color)
    
    # Packer Detection
    if args.packer:
        from .analyzers.packer_detector import PackerDetector
        console.print("\n[bold #FFB6C1][!] Packer Detection:[/bold #FFB6C1]")
        data = open(filepath, 'rb').read()
        packer = PackerDetector.detect(data)
        if packer:
            console.print(f"    [!] Terdeteksi packer: [red]{packer}[/red]")
        else:
            entropy_packer = PackerDetector.detect_by_entropy(None)  # Would need sections
            if entropy_packer:
                console.print(f"    [!] {entropy_packer}", style="yellow")
            else:
                console.print("    [-] Tidak terdeteksi packer umum", style="dim")
    
    if entropy > 7.0:
        console.print(f"    [!] Entropy tinggi - kemungkinan file terenkripsi atau packed", style="yellow")
    
    # VirusTotal check
    if args.vt:
        console.print("\n[bold #FFB6C1][!] VirusTotal Check:[/bold #FFB6C1]")
        vt = VirusTotal(api_key=args.vt_api_key)
        vt_results = vt.check_hash(md5_hash)
        if vt_results:
            vt.display_results(vt_results)
    
    # Detect file type
    file_type = detect_file_type(filepath)
    console.print(f"[+] Type     : {file_type}", style="green")
    
    # Get analyzer
    analyzer = get_analyzer(filepath, file_type)
    
    # Analyze sections
    console.print("\n[bold #FFB6C1][*] Section Analysis:[/bold #FFB6C1]")
    sections = analyzer.get_sections()
    if sections:
        table = Table(show_header=True, header_style="bold #FFB6C1")
        table.add_column("Name", style="cyan")
        table.add_column("Virtual Address", style="green")
        table.add_column("Virtual Size", style="green")
        table.add_column("Raw Size", style="green")
        table.add_column("Entropy", style="yellow")
        
        for sec in sections:
            table.add_row(
                sec.get('name', 'Unknown'),
                hex(sec.get('virtual_address', 0)),
                hex(sec.get('virtual_size', 0)),
                hex(sec.get('raw_size', 0)),
                f"{sec.get('entropy', 0):.4f}"
            )
        console.print(table)
    else:
        console.print("    [-] Tidak ada section info", style="dim")
    
    # Entropy Graph
    if args.graph:
        console.print("\n[bold #FFB6C1][*] Entropy Visualization:[/bold #FFB6C1]")
        display_entropy_bars(sections)
        
        if args.output and args.format == 'text':
            graph_file = Path(args.output).stem + "_entropy.txt"
            export_entropy_graph(sections, graph_file)
    
    # Analyze imports
    console.print("\n[bold #FFB6C1][+] Imported Functions:[/bold #FFB6C1]")
    imports = analyzer.get_imports()
    if imports:
        for dll, functions in list(imports.items())[:10]:
            console.print(f"    [yellow]{dll}[/yellow]")
            for func in functions[:5]:
                console.print(f"      └─ {func}")
            if len(functions) > 5:
                console.print(f"      └─ ... dan {len(functions) - 5} lainnya")
    else:
        console.print("    [-] Tidak ada imports ditemukan", style="dim")
    
    # Analyze strings
    console.print("\n[bold #FFB6C1][+] String Analysis:[/bold #FFB6C1]")
    string_analyzer = StringAnalyzer(filepath)
    suspicious = string_analyzer.find_suspicious()
    
    if suspicious:
        console.print("    [!] String mencurigakan ditemukan:", style="yellow")
        for s in suspicious[:15]:
            console.print(f"      • {s}")
        if len(suspicious) > 15:
            console.print(f"      • ... dan {len(suspicious) - 15} lainnya")
    else:
        console.print("    [-] Tidak ada string mencurigakan", style="dim")
    
    # YARA scanning
    if args.yara or args.deep:
        console.print("\n[bold #FFB6C1][!] YARA Scan:[/bold #FFB6C1]")
        try:
            import yara
            from .signatures.yara_scanner import YaraScanner
            
            rule_path = args.yara or "./nusantarascan/signatures/yara_rules"
            scanner = YaraScanner(rule_path)
            matches = scanner.scan(filepath)
            
            if matches:
                console.print(f"    [!] {len(matches)} YARA rule(s) matched:", style="red")
                for match in matches[:10]:
                    console.print(f"      • {match}")
            else:
                console.print("    [-] Tidak ada YARA rules yang match", style="dim")
        except Exception as e:
            console.print(f"    [-] YARA scan error: {e}", style="dim")
    
    # Deep analysis / Disassembly
    if args.deep or args.full_disasm:
        console.print("\n[bold #FFB6C1][*] Deep Analysis:[/bold #FFB6C1]")
        
        max_instructions = None if args.full_disasm else 20
        
        if isinstance(analyzer, PEAnalyzer) and analyzer.pe:
            text_section = None
            for section in analyzer.pe.sections:
                if b'.text' in section.Name:
                    text_section = section
                    break
            
            if text_section:
                data = text_section.get_data()
                if args.full_disasm:
                    data = data[:4096]  # Limit for full disasm to avoid huge output
                
                console.print(f"    [cyan]Disassembly (.text section, arch={args.disasm_arch}):[/cyan]")
                dis = Disassembler(arch=args.disasm_arch)
                instructions = dis.disassemble(data, max_instructions=max_instructions)
                
                for insn in instructions[:50]:  # Show first 50 in terminal
                    console.print(f"      0x{insn['address']:x}: {insn['mnemonic']:10} {insn['op_str']}")
                
                if len(instructions) > 50:
                    console.print(f"      ... dan {len(instructions) - 50} instruksi lainnya")
                
                # Export to .asm if requested
                if args.export_asm:
                    dis.export_to_file(data, args.export_asm)
                    
        elif isinstance(analyzer, ELFAnalyzer) and analyzer.elf:
            text_section = None
            for section in analyzer.elf.iter_sections():
                if section.name == '.text':
                    text_section = section
                    break
            
            if text_section:
                data = text_section.data()
                if args.full_disasm:
                    data = data[:4096]
                
                console.print(f"    [cyan]Disassembly (.text section, arch={args.disasm_arch}):[/cyan]")
                dis = Disassembler(arch=args.disasm_arch)
                instructions = dis.disassemble(data, max_instructions=max_instructions)
                
                for insn in instructions[:50]:
                    console.print(f"      0x{insn['address']:x}: {insn['mnemonic']:10} {insn['op_str']}")
                
                if len(instructions) > 50:
                    console.print(f"      ... dan {len(instructions) - 50} instruksi lainnya")
                
                if args.export_asm:
                    dis.export_to_file(data, args.export_asm)
    
    console.print("\n[bold green][+] Scan completed![/bold green]")
    
    # Prepare results (always, not just on export)
    results = {
        'target': filepath,
        'md5': md5_hash,
        'sha256': sha256_hash,
        'entropy': entropy,
        'sections': sections,
        'imports': imports,
        'suspicious_strings': suspicious
    }
    
    # Export if requested
    if args.output:
        console.print(f"\n[+] Exporting to {args.output}...", style="green")
        
        if args.format == 'json':
            from .formatters.json_output import JSONFormatter
            JSONFormatter.save(results, args.output)
        elif args.format == 'html':
            from .formatters.html_output import HTMLFormatter
            HTMLFormatter.save(results, args.output)
        
        console.print(f"    [green]✓ Exported to {args.output}[/green]")
    
    return results


def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    print_banner()
    
    # Check if target exists
    target_path = Path(args.target)
    if not target_path.exists():
        console.print(f"[!] Error: File/directory '{args.target}' tidak ditemukan", style="bold red")
        sys.exit(1)
    
    # Multi-file scanning
    if args.recursive or target_path.is_dir():
        console.print(f"[cyan][*] Scanning directory: {target_path}[/cyan]")
        
        scanner = MultiFileScanner(
            str(target_path), 
            recursive=args.recursive,
            extensions=['.exe', '.dll', '.elf', '.so', '.dylib', '']
        )
        
        def scan_wrapper(filepath):
            # Create a clean args copy for each file
            file_args = argparse.Namespace(**vars(args))
            # Disable recursive for sub-files
            file_args.recursive = False
            return scan_single_file(filepath, file_args)
        
        results = scanner.scan_all(scan_wrapper)
        scanner.display_summary(results)
        
    else:
        # Single file scan
        scan_single_file(args.target, args)


if __name__ == "__main__":
    main()