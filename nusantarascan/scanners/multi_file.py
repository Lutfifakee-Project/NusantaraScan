"""
Multi-file scanner for recursive directory scanning
"""

import os
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn
from rich.table import Table

console = Console()


class MultiFileScanner:
    """Scan multiple files in directory"""
    
    def __init__(self, filepath, recursive=False, extensions=None):
        self.filepath = Path(filepath)
        self.recursive = recursive
        self.extensions = extensions or ['.exe', '.dll', '.elf', '.so', '.dylib']
        self.files = []
        self._collect_files()
    
    def _collect_files(self):
        """Collect all files to scan"""
        if self.filepath.is_file():
            self.files.append(self.filepath)
        elif self.filepath.is_dir():
            if self.recursive:
                pattern = '**/*'
            else:
                pattern = '*'
            
            for ext in self.extensions:
                self.files.extend(self.filepath.glob(f"{pattern}{ext}"))
            
            # Also include files without extension
            for file in self.filepath.glob(f"{pattern}"):
                if file.is_file() and file.suffix == '':
                    self.files.append(file)
            
            # Remove duplicates
            self.files = list(set(self.files))
    
    def scan_all(self, scan_function):
        """Scan all collected files with given scan function"""
        if not self.files:
            console.print("    [-] Tidak ada file ditemukan untuk di-scan", style="dim")
            return []
        
        results = []
        
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning files...", total=len(self.files))
            
            for filepath in self.files:
                try:
                    result = scan_function(str(filepath))
                    results.append({
                        'file': str(filepath),
                        'result': result
                    })
                except Exception as e:
                    results.append({
                        'file': str(filepath),
                        'error': str(e)
                    })
                
                progress.advance(task)
        
        return results
    
    def display_summary(self, results):
        """Display scan summary"""
        if not results:
            return
        
        table = Table(title="Multi-File Scan Summary", header_style="bold cyan")
        table.add_column("File", style="green")
        table.add_column("Status", style="yellow")
        
        for r in results:
            status = "✅ Success" if 'result' in r else f"❌ Error: {r.get('error', 'Unknown')}"
            table.add_row(r['file'][:50], status)
        
        console.print(table)
        console.print(f"\n[bold green]✅ Scanned {len(results)} files[/bold green]")