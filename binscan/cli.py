#!/usr/bin/env python3
"""
CLI handler for NusantaraScan.
"""

import argparse
import os
import sys
from pathlib import Path

from colorama import init
from rich.console import Console
from rich.table import Table

init(autoreset=True)
console = Console()

from . import __version__
from .config import (
    MAX_SUSPICIOUS_DISPLAY,
    MAX_INSTRUCTIONS_PREVIEW,
    MAX_DISASM_BYTES,
    MAX_DISASM_BYTES_PREVIEW,
    ENTROPY_HIGH,
)
from .analyzers.pe import PEAnalyzer
from .analyzers.elf import ELFAnalyzer
from .analyzers.macho import MachOAnalyzer
from .analyzers.generic import GenericAnalyzer
from .analyzers.strings import StringAnalyzer
from .analyzers.packer_detector import PackerDetector
from .analyzers.disassembler import Disassembler
from .visualizers.entropy_graph import display_entropy_bars, export_entropy_graph
from .integrations.virustotal import VirusTotal
from .scanners.multi_file import MultiFileScanner
from .utils.hasher import FileHasher
from .utils.entropy import EntropyCalculator
from .utils.validators import (
    ValidationError,
    validate_file,
    validate_directory,
)
from .utils.scoring import RiskScorer


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="binscan",
        description="NusantaraScan - Analisis mendalam untuk file binary (PE, ELF, Mach-O)",
        epilog="Dibangun dengan semangat Nusantara untuk keamanan siber Indonesia.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="File atau direktori target")
    parser.add_argument("-d", "--deep", action="store_true",
                        help="Analisis mendalam (disassembly + YARA)")
    parser.add_argument("-y", "--yara", metavar="RULE_PATH",
                        help="Path ke file atau direktori YARA rules")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Export hasil ke file (JSON/HTML)")
    parser.add_argument("-f", "--format", choices=["json", "html", "text"],
                        default="text", help="Format output (default: text)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Tampilkan informasi detail")
    parser.add_argument("--packer", action="store_true",
                        help="Deteksi packer pada file")
    parser.add_argument("--graph", action="store_true",
                        help="Tampilkan visualisasi entropy bar graph")
    parser.add_argument("--full-disasm", action="store_true",
                        help="Full disassembly (tidak terbatas preview)")
    parser.add_argument("--disasm-arch",
                        choices=["x86_32", "x86_64", "arm", "arm_thumb", "arm64"],
                        default="x86_64", help="Arsitektur disassembly (default: x86_64)")
    parser.add_argument("--export-asm", metavar="FILE",
                        help="Export disassembly ke file .asm")
    parser.add_argument("--recursive", action="store_true",
                        help="Scan semua file dalam direktori (recursive)")
    parser.add_argument("--vt", "--virustotal", action="store_true",
                        help="Cek hash file ke VirusTotal API (butuh env VT_API_KEY)")
    parser.add_argument("--all", action="store_true", dest="scan_all",
                        help="Aktifkan semua fitur analisis (packer + graph + deep + VT + export HTML)")
    return parser


def print_banner():
    banner = r"""
    _   _                       _                  ____
   | \ | |_   _ ___  __ _ _ __ | |_ __ _ _ __ __ _/ ___|  ___ __ _ _ __
   |  \| | | | / __|/ _` | '_ \| __/ _` | '__/ _` \___ \ / __/ _` | '_ \
   | |\  | |_| \__ \ (_| | | | | || (_| | | | (_| |___) | (_| (_| | | | |
   |_| \_|\__,_|___/\__,_|_| |_|\__\__,_|_|  \__,_|____/ \___\__,_|_| |_| {ver}
                https://github.com/Lutfifakee-Project/
    """.format(ver=__version__)
    console.print(banner, highlight=False)
    console.print()


def detect_file_type(filepath: str) -> str:
    try:
        import magic
        return magic.from_file(filepath)
    except ImportError:
        ext = Path(filepath).suffix.lower()
        if ext in (".exe", ".dll", ".sys"):
            return "PE32 executable"
        if ext in (".so", ".elf", ""):
            return "ELF binary"
        if ext in (".dylib", ".macho"):
            return "Mach-O binary"
        return "Unknown"


def detect_binary_type_from_magic(data: bytes) -> str:
    """Deteksi tipe binary dari magic number - lebih akurat dari string match."""
    if not data or len(data) < 4:
        return "Unknown"
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    if data[:4] in (
        b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
    ):
        return "Mach-O"
    return "Unknown"


def get_analyzer(filepath: str, file_type: str, data: bytes = None):
    magic_type = detect_binary_type_from_magic(data) if data else "Unknown"

    if magic_type == "PE" or "PE32" in file_type or filepath.lower().endswith((".exe", ".dll", ".sys")):
        return PEAnalyzer(filepath, data)
    if magic_type == "ELF" or "ELF" in file_type or filepath.lower().endswith((".so", ".elf")):
        return ELFAnalyzer(filepath, data)
    if magic_type == "Mach-O" or "Mach-O" in file_type or filepath.lower().endswith((".dylib", ".macho")):
        return MachOAnalyzer(filepath, data)
    return GenericAnalyzer(filepath, data)


def scan_single_file(filepath: str, args) -> dict:
    target_path = Path(filepath)

    try:
        validated_path = validate_file(filepath)
    except ValidationError as e:
        console.print(f"[!] Validasi gagal: {e}", style="bold red")
        return {"file": filepath, "error": str(e)}

    file_size = validated_path.stat().st_size
    size_formatted = f"{file_size:,} bytes"
    if file_size > 1024 * 1024:
        size_formatted += f" ({file_size / (1024*1024):.2f} MB)"
    elif file_size > 1024:
        size_formatted += f" ({file_size / 1024:.2f} KB)"

    console.print(f"[+] Target   : {target_path.name}", style="bold green")
    console.print(f"[+] Size     : {size_formatted}", style="green")

    hasher = FileHasher(str(validated_path))
    hashes = hasher.all_hashes()
    console.print(f"[+] MD5      : {hashes['md5']}", style="green")
    console.print(f"[+] SHA1     : {hashes['sha1']}", style="green")
    console.print(f"[+] SHA256   : {hashes['sha256']}", style="green")

    entropy = EntropyCalculator.calculate_entropy(str(validated_path))
    entropy_color = (
        "green" if entropy < 6.5 else "yellow" if entropy < 7.5 else "red"
    )
    console.print(f"[+] Entropy  : {entropy:.4f}", style=entropy_color)

    with open(validated_path, "rb") as f:
        file_data = f.read()

    file_type = detect_file_type(str(validated_path))
    console.print(f"[+] Type     : {file_type}", style="green")
    analyzer = get_analyzer(str(validated_path), file_type, file_data)

    # ── Section Analysis ─────────────────────────────────────
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
                str(sec.get("name", "Unknown")),
                hex(sec.get("virtual_address", 0)),
                hex(sec.get("virtual_size", 0)),
                hex(sec.get("raw_size", 0)),
                f"{sec.get('entropy', 0):.4f}",
            )
        console.print(table)
    else:
        console.print("    [-] Tidak ada section info", style="dim")

    # ── Packer Detection ──────────────────────────────────────
    packer_detected = None
    if args.packer:
        console.print("\n[bold #FFB6C1][!] Packer Detection:[/bold #FFB6C1]")
        packer = PackerDetector.detect(file_data)
        if packer:
            packer_detected = packer
            console.print(f"    [!] Terdeteksi packer: [red]{packer}[/red]")
        else:
            entropy_packer = PackerDetector.detect_by_entropy(sections)
            if entropy_packer:
                packer_detected = entropy_packer
                console.print(f"    [!] {entropy_packer}", style="yellow")
            else:
                console.print("    [-] Tidak terdeteksi packer umum", style="dim")

    if entropy > ENTROPY_HIGH:
        console.print(
            "    [!] Entropy tinggi - kemungkinan file terenkripsi atau packed",
            style="yellow",
        )

    # ── VirusTotal ────────────────────────────────────────────
    if args.vt:
        console.print("\n[bold #FFB6C1][!] VirusTotal Check:[/bold #FFB6C1]")
        vt = VirusTotal()
        vt_results = vt.check_hash(hashes["sha256"])
        if vt_results:
            vt.display_results(vt_results)

    # ── Imports ───────────────────────────────────────────────
    console.print("\n[bold #FFB6C1][+] Imported Functions:[/bold #FFB6C1]")
    imports = analyzer.get_imports()
    if imports:
        for dll, functions in list(imports.items())[:10]:
            console.print(f"    [yellow]{dll}[/yellow]")
            for func in functions[:5]:
                console.print(f"      - {func}", markup=False, highlight=False)
            if len(functions) > 5:
                console.print(f"      - ... dan {len(functions) - 5} lainnya")
    else:
        console.print("    [-] Tidak ada imports ditemukan", style="dim")

    # ── String Analysis ───────────────────────────────────────
    console.print("\n[bold #FFB6C1][+] String Analysis:[/bold #FFB6C1]")
    string_analyzer = StringAnalyzer(str(validated_path), file_data)
    suspicious = string_analyzer.find_suspicious()
    if suspicious:
        console.print("    [!] String mencurigakan ditemukan:", style="yellow")
        for s in suspicious[:MAX_SUSPICIOUS_DISPLAY]:
            console.print(f"      - {s}", markup=False, highlight=False)
        if len(suspicious) > MAX_SUSPICIOUS_DISPLAY:
            console.print(f"      - ... dan {len(suspicious) - MAX_SUSPICIOUS_DISPLAY} lainnya")
    else:
        console.print("    [-] Tidak ada string mencurigakan", style="dim")

    # ── YARA Scan (selalu jalan) ──────────────────────────────
    yara_matches = []
    console.print("\n[bold #FFB6C1][!] YARA Scan:[/bold #FFB6C1]")
    try:
        from .scanners.yara_scanner import YaraScanner
        if args.yara:
            rule_path = args.yara
        else:
            cli_dir = os.path.dirname(os.path.abspath(__file__))
            rule_path = os.path.join(cli_dir, "signatures", "yara_rules")
        scanner = YaraScanner(rule_path, recursive=True)
        yara_matches = scanner.scan(str(validated_path))
        if yara_matches:
            console.print(f"    [!] {len(yara_matches)} YARA rule(s) matched:", style="red")
            for match in yara_matches[:10]:
                console.print(f"      - {match}", markup=False, highlight=False)
        else:
            console.print("    [-] Tidak ada YARA rules yang match", style="dim")
    except Exception as e:
        console.print(f"    [-] YARA scan error: {e}", style="dim")

    # ── Deep Analysis ─────────────────────────────────────────
    if args.deep or args.full_disasm:
        console.print("\n[bold #FFB6C1][*] Deep Analysis:[/bold #FFB6C1]")
        text_data = b""
        if isinstance(analyzer, (PEAnalyzer, ELFAnalyzer)):
            text_data = analyzer.get_text_section_data()
        elif isinstance(analyzer, MachOAnalyzer):
            text_data = analyzer.get_text_section_data()
            if not text_data:
                console.print(
                    "    [-] Deep analysis belum didukung untuk Mach-O",
                    style="dim",
                )
        if text_data:
            if args.full_disasm:
                text_data = text_data[:MAX_DISASM_BYTES]
            else:
                text_data = text_data[:MAX_DISASM_BYTES_PREVIEW]
            console.print(f"    [cyan]Disassembly (.text, arch={args.disasm_arch}):[/cyan]")
            dis = Disassembler(arch=args.disasm_arch)
            instructions = dis.disassemble(
                text_data,
                max_instructions=None if args.full_disasm else MAX_INSTRUCTIONS_PREVIEW,
            )
            for insn in instructions[:MAX_INSTRUCTIONS_PREVIEW]:
                console.print(
                    f"      0x{insn['address']:x}: {insn['mnemonic']:10} {insn['op_str']}",
                    markup=False,
                    highlight=False,
                )
            if len(instructions) > MAX_INSTRUCTIONS_PREVIEW:
                console.print(
                    f"      ... dan {len(instructions) - MAX_INSTRUCTIONS_PREVIEW} instruksi lainnya"
                )
            if args.export_asm:
                dis.export_to_file(text_data, args.export_asm)

    # ── Entropy Graph ─────────────────────────────────────────
    if args.graph:
        console.print("\n[bold #FFB6C1][*] Entropy Visualization:[/bold #FFB6C1]")
        display_entropy_bars(sections)
        if args.output and args.format == "text":
            graph_file = Path(args.output).stem + "_entropy.txt"
            export_entropy_graph(sections, graph_file)

    # ── Risk Scoring ──────────────────────────────────────────
    results = {
        "target": str(validated_path),
        "size": file_size,
        "md5": hashes["md5"],
        "sha1": hashes["sha1"],
        "sha256": hashes["sha256"],
        "entropy": entropy,
        "file_type": file_type,
        "sections": sections,
        "imports": imports,
        "suspicious_strings": suspicious,
        "yara_matches": yara_matches,
        "packer_detected": packer_detected,
    }

    scoring = RiskScorer.score(results)
    results["risk_score"] = scoring["score"]
    results["risk_level"] = scoring["level"]
    results["risk_reasons"] = scoring["reasons"]

    console.print("\n[bold #FFB6C1][*] Risk Assessment:[/bold #FFB6C1]")
    console.print(f"    Level: {RiskScorer.format_display(scoring)}")
    if scoring["reasons"]:
        console.print("    Alasan:")
        for reason in scoring["reasons"]:
            console.print(f"      - {reason}")
    else:
        console.print("    [-] Tidak ada indikasi mencurigakan", style="dim")

    console.print("\n[bold green][+] Scan completed![/bold green]")

    # ── Export ────────────────────────────────────────────────
    if args.output:
        console.print(f"\n[+] Exporting to {args.output}...", style="green")
        if args.format == "json":
            from .formatters.json_output import JSONFormatter
            JSONFormatter.save(results, args.output)
        elif args.format == "html":
            from .formatters.html_output import HTMLFormatter
            HTMLFormatter.save(results, args.output)
        console.print(f"    [green]Exported to {args.output}[/green]")

    return results


def main():
    """Entry point CLI dengan Ctrl+C handler."""
    try:
        parser = create_parser()
        args = parser.parse_args()

        # Handle --all: nyalakan semua flag
        if getattr(args, "scan_all", False):
            args.packer = True
            args.graph = True
            args.deep = True
            args.vt = True
            if not args.output:
                args.output = "report.html"
                args.format = "html"

        print_banner()

        target = Path(args.target)
        if not target.exists():
            console.print(
                f"[!] Error: '{args.target}' tidak ditemukan", style="bold red"
            )
            sys.exit(1)

        if args.recursive or target.is_dir():
            try:
                validated = validate_directory(str(target))
            except ValidationError as e:
                console.print(f"[!] {e}", style="bold red")
                sys.exit(1)

            console.print(f"[cyan][*] Scanning directory: {validated}[/cyan]")
            scanner = MultiFileScanner(str(validated), recursive=args.recursive)

            def scan_wrapper(filepath):
                file_args = argparse.Namespace(**vars(args))
                file_args.recursive = False
                return scan_single_file(filepath, file_args)

            results = scanner.scan_all(scan_wrapper)
            scanner.display_summary(results)
        else:
            scan_single_file(args.target, args)

    except KeyboardInterrupt:
        console.print(
            "\n[yellow][!] Program dihentikan oleh user (Ctrl+C)[/yellow]"
        )
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red][!] Error tidak terduga: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()