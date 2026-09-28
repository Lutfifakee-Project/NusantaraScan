"""
Multi-file scanner - dengan batas jumlah file & Ctrl+C handler.
"""

from pathlib import Path

from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table

from ..config import MAX_FILES_PER_SCAN, MAX_FILE_SIZE, SUPPORTED_EXTENSIONS

console = Console()


class MultiFileScanner:
    """Scan banyak file dalam direktori."""

    def __init__(self, filepath: str, recursive: bool = False, extensions=None):
        self.filepath = Path(filepath)
        self.recursive = recursive
        self.extensions = extensions or SUPPORTED_EXTENSIONS
        self.files = []
        self._collect_files()

    def _collect_files(self):
        if self.filepath.is_file():
            self.files.append(self.filepath)
        elif self.filepath.is_dir():
            pattern = "**/*" if self.recursive else "*"
            seen = set()
            for ext in self.extensions:
                if ext:
                    for f in self.filepath.glob(f"{pattern}{ext}"):
                        if f.is_file() and f not in seen:
                            seen.add(f)
                            self.files.append(f)
            for f in self.filepath.glob(pattern):
                if f.is_file() and f.suffix == "" and f not in seen:
                    seen.add(f)
                    self.files.append(f)

        # Filter file kosong dan file yang terlalu besar
        filtered_files = []
        skipped_large = 0
        skipped_empty = 0
        for f in self.files:
            try:
                size = f.stat().st_size
            except OSError:
                continue
            if size == 0:
                skipped_empty += 1
                continue
            if size > MAX_FILE_SIZE:
                skipped_large += 1
                continue
            filtered_files.append(f)

        if skipped_empty > 0:
            console.print(
                f"[!] {skipped_empty} file kosong di-skip",
                style="yellow",
            )
        if skipped_large > 0:
            console.print(
                f"[!] {skipped_large} file terlalu besar di-skip "
                f"(> {MAX_FILE_SIZE:,} bytes)",
                style="yellow",
            )

        self.files = filtered_files

        if len(self.files) > MAX_FILES_PER_SCAN:
            console.print(
                f"[!] Dibatasi {MAX_FILES_PER_SCAN} file pertama "
                f"(dari {len(self.files)} total)",
                style="yellow",
            )
            self.files = self.files[:MAX_FILES_PER_SCAN]

    def scan_all(self, scan_function) -> list:
        if not self.files:
            console.print("    [-] Tidak ada file ditemukan", style="dim")
            return []

        results = []
        interrupted = False

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "[cyan]Scanning files...", total=len(self.files)
            )
            for filepath in self.files:
                try:
                    result = scan_function(str(filepath))
                    results.append({"file": str(filepath), "result": result})
                except KeyboardInterrupt:
                    interrupted = True
                    break
                except Exception as e:
                    results.append({"file": str(filepath), "error": str(e)})
                progress.advance(task)

        if interrupted:
            console.print(
                "\n[yellow][!] Scan dibatalkan oleh user (Ctrl+C)[/yellow]"
            )
            console.print(
                f"[yellow][i] {len(results)} file berhasil di-scan "
                f"sebelum dibatalkan[/yellow]"
            )

        return results

    def display_summary(self, results: list):
        if not results:
            console.print("    [-] Tidak ada hasil", style="dim")
            return
        table = Table(title="Multi-File Scan Summary", header_style="bold cyan")
        table.add_column("File", style="green")
        table.add_column("Status", style="yellow")
        for r in results:
            if "result" in r:
                status = "OK Success"
            elif "error" in r:
                status = f"ERROR: {r['error'][:40]}"
            else:
                status = "ERROR: Unknown"
            table.add_row(Path(r["file"]).name[:50], status)
        console.print(table)
        console.print(f"\n[bold green]Scanned {len(results)} files[/bold green]")