"""
VirusTotal API integration
"""

import requests
import json
import os
from rich.console import Console
from rich.table import Table

console = Console()


class VirusTotal:
    """VirusTotal API wrapper"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get('VT_API_KEY')
        self.headers = {"x-apikey": self.api_key} if self.api_key else None
        self.cache = {}
    
    def check_hash(self, file_hash):
        """Check file hash against VirusTotal"""
        if not self.api_key:
            console.print("    [-] VirusTotal API key tidak ditemukan", style="dim")
            return None
        
        # Check cache first
        if file_hash in self.cache:
            return self.cache[file_hash]
        
        try:
            url = f"{self.BASE_URL}/files/{file_hash}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                self.cache[file_hash] = data
                return data
            elif response.status_code == 404:
                console.print("    [-] Hash tidak ditemukan di VirusTotal", style="dim")
                return None
            else:
                console.print(f"    [-] VirusTotal API error: {response.status_code}", style="dim")
                return None
                
        except Exception as e:
            console.print(f"    [-] VirusTotal error: {e}", style="dim")
            return None
    
    def display_results(self, results):
        """Display VirusTotal results in table"""
        if not results:
            return
        
        try:
            attributes = results.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            total = sum(stats.values())
            
            if total > 0:
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                
                table = Table(title="VirusTotal Report", header_style="bold red")
                table.add_column("Status", style="cyan")
                table.add_column("Count", style="yellow")
                
                table.add_row("Malicious", str(malicious))
                table.add_row("Suspicious", str(suspicious))
                table.add_row("Undetected", str(stats.get('undetected', 0)))
                table.add_row("Harmless", str(stats.get('harmless', 0)))
                
                console.print(table)
                
                if malicious > 0:
                    console.print(f"    [red]⚠️  {malicious}/{total} engines detected as malicious![/red]")
                else:
                    console.print(f"    [green]✓ Clean - {malicious}/{total} detections[/green]")
                    
        except Exception as e:
            console.print(f"    [-] Error parsing VirusTotal response: {e}", style="dim")