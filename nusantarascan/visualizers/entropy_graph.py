"""
Entropy visualization module
"""

from rich.console import Console
from rich.table import Table

console = Console()


def display_entropy_bars(sections):
    """Display entropy as bar graph in terminal"""
    if not sections:
        console.print("    [-] Tidak ada section data", style="dim")
        return
    
    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Section", style="cyan")
    table.add_column("Entropy Graph", style="green")
    table.add_column("Value", style="yellow")
    
    for section in sections:
        entropy = section.get('entropy', 0)
        bar_length = int(entropy / 8 * 20)
        bar = '█' * bar_length + '░' * (20 - bar_length)
        color = "green" if entropy < 6 else "yellow" if entropy < 7 else "red"
        
        table.add_row(
            section.get('name', 'Unknown'),
            f"[{color}]{bar}[/{color}]",
            f"{entropy:.2f}"
        )
    
    console.print(table)


def export_entropy_graph(sections, output_file):
    """Export entropy graph to text file"""
    if not sections:
        return
    
    with open(output_file, 'w') as f:
        f.write("Entropy Visualization Report\n")
        f.write("=" * 50 + "\n\n")
        
        for section in sections:
            entropy = section.get('entropy', 0)
            bar_length = int(entropy / 8 * 40)
            bar = '█' * bar_length + '░' * (40 - bar_length)
            
            f.write(f"{section.get('name', 'Unknown'):15} {bar} {entropy:.2f}\n")
    
    console.print(f"    [green]✓ Entropy graph exported to {output_file}[/green]")
