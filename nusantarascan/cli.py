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
        help="File target yang akan dianalisis"
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
    
    return parser

def print_banner():
    banner_text = r"""
    _   _                       _                  ____                  
   | \ | |_   _ ___  __ _ _ __ | |_ __ _ _ __ __ _/ ___|  ___ __ _ _ __  
   |  \| | | | / __|/ _` | '_ \| __/ _` | '__/ _` \___ \ / __/ _` | '_ \ 
   | |\  | |_| \__ \ (_| | | | | || (_| | | | (_| |___) | (_| (_| | | | |
   |_| \_|\__,_|___/\__,_|_| |_|\__\__,_|_|  \__,_|____/ \___\__,_|_| |_| v0.1.0
                https://github.com/Lutfifakee-Project/
    """
    
    # Print dengan hyperlink dinonaktifkan
    console.print(banner_text, highlight=False)
    console.print()

def detect_file_type(filepath):
    """Detect file type using magic numbers"""
    try:
        import magic
        return magic.from_file(filepath)
    except ImportError:
        # Fallback: use file extension
        ext = Path(filepath).suffix.lower()
        if ext in ['.exe', '.dll', '.sys']:
            return "PE32 executable"
        elif ext in ['.so', '.elf', '']:
            return "ELF binary"
        else:
            return "Unknown"

def get_analyzer(filepath, file_type):
    """Get appropriate analyzer based on file type"""
    if "PE32" in file_type or "PE" in file_type or filepath.endswith(('.exe', '.dll', '.sys')):
        return PEAnalyzer(filepath)
    elif "ELF" in file_type or filepath.endswith(('.so', '.elf')):
        return ELFAnalyzer(filepath)
    else:
        return BaseAnalyzer(filepath)

def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    # Check if target file exists
    target_path = Path(args.target)
    if not target_path.exists():
        console.print(f"[!] Error: File '{args.target}' tidak ditemukan", style="bold red")
        sys.exit(1)
    
    print_banner()
    
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
    hasher = FileHasher(args.target)
    console.print(f"[+] MD5      : {hasher.md5()}", style="green")
    console.print(f"[+] SHA1     : {hasher.sha1()}", style="green")
    console.print(f"[+] SHA256   : {hasher.sha256()}", style="green")
    
    # Calculate entropy
    entropy = EntropyCalculator.calculate_entropy(args.target)
    entropy_color = "green" if entropy < 6.5 else "yellow" if entropy < 7.5 else "red"
    console.print(f"[+] Entropy  : {entropy:.4f}", style=entropy_color)
    
    if entropy > 7.0:
        console.print(f"    [!] Entropy tinggi - kemungkinan file terenkripsi atau packed", style="yellow")
    
    # Detect file type
    file_type = detect_file_type(args.target)
    console.print(f"[+] Type     : {file_type}", style="green")
    
    # Get analyzer
    analyzer = get_analyzer(args.target, file_type)
    
    # Analyze sections
    console.print("\n[bold #FFB6C1]📊 Section Analysis:[/bold #FFB6C1]")
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
    
    # Analyze imports
    console.print("\n[bold #FFB6C1]🔗 Imported Functions:[/bold #FFB6C1]")
    imports = analyzer.get_imports()
    if imports:
        for dll, functions in list(imports.items())[:10]:  # Show first 10
            console.print(f"    [yellow]{dll}[/yellow]")
            for func in functions[:5]:  # Show first 5 per dll
                console.print(f"      └─ {func}")
            if len(functions) > 5:
                console.print(f"      └─ ... dan {len(functions) - 5} lainnya")
    else:
        console.print("    [-] Tidak ada imports ditemukan", style="dim")
    
    # Analyze strings
    console.print("\n[bold #FFB6C1]📝 String Analysis:[/bold #FFB6C1]")
    string_analyzer = StringAnalyzer(args.target)
    suspicious = string_analyzer.find_suspicious()
    
    if suspicious:
        console.print("    [!] String mencurigakan ditemukan:", style="yellow")
        for s in suspicious[:15]:
            console.print(f"      • {s}")
        if len(suspicious) > 15:
            console.print(f"      • ... dan {len(suspicious) - 15} lainnya")
    else:
        console.print("    [-] Tidak ada string mencurigakan", style="dim")
    
    # YARA scanning if requested
    if args.yara or args.deep:
        console.print("\n[bold #FFB6C1]🦠 YARA Scan:[/bold #FFB6C1]")
        try:
            import yara
            from .signatures.yara_scanner import YaraScanner
            
            rule_path = args.yara or "./nusantarascan/signatures/yara_rules"
            scanner = YaraScanner(rule_path)
            matches = scanner.scan(args.target)
            
            if matches:
                console.print(f"    [!] {len(matches)} YARA rule(s) matched:", style="red")
                for match in matches[:10]:
                    console.print(f"      • {match}")
            else:
                console.print("    [-] Tidak ada YARA rules yang match", style="dim")
        except Exception as e:
            console.print(f"    [-] YARA scan error: {e}", style="dim")
    
    # Deep analysis
    if args.deep:
        console.print("\n[bold #FFB6C1]🔬 Deep Analysis:[/bold #FFB6C1]")
        # TODO: Add disassembly with capstone
        console.print("    [*] Disassembly feature coming soon...", style="dim")
    
    console.print("\n[bold green]✅ Scan completed![/bold green]")
    
    # Export if requested
    if args.output:
        console.print(f"\n[+] Exporting to {args.output}...", style="green")
        # TODO: Implement export functionality
        console.print("    [*] Export feature coming soon...", style="dim")

if __name__ == "__main__":
    main()