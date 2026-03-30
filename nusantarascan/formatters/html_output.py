"""
HTML output formatter
"""

class HTMLFormatter:
    """Format analysis results as HTML"""
    
    @staticmethod
    def format(results):
        """Convert results to HTML string"""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>NusantaraScan Report</title>
            <style>
                body { font-family: monospace; margin: 20px; background: #0a0a0a; color: #00ff00; }
                .container { max-width: 1200px; margin: auto; }
                .section { margin: 20px 0; padding: 10px; border: 1px solid #00ff00; }
                .section h2 { margin-top: 0; color: #00ff00; }
                .suspicious { color: #ff0000; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #00ff00; padding: 8px; text-align: left; }
                th { background: #1a1a1a; }
            </style>
        </head>
        <body>
        <div class="container">
            <h1>🌏 NusantaraScan Report</h1>
            <div class="section">
                <h2>File Information</h2>
                <pre>{file_info}</pre>
            </div>
            <div class="section">
                <h2>Suspicious Strings</h2>
                <pre>{suspicious_strings}</pre>
            </div>
            <div class="section">
                <h2>YARA Matches</h2>
                <pre>{yara_matches}</pre>
            </div>
        </div>
        </body>
        </html>
        """
        
        file_info = f"Target: {results.get('target', 'Unknown')}\n"
        file_info += f"MD5: {results.get('md5', 'Unknown')}\n"
        file_info += f"SHA256: {results.get('sha256', 'Unknown')}\n"
        file_info += f"Entropy: {results.get('entropy', 0):.4f}"
        
        suspicious = "\n".join(results.get('suspicious_strings', []))
        yara = "\n".join(results.get('yara_matches', []))
        
        return html.format(
            file_info=file_info,
            suspicious_strings=suspicious or "None",
            yara_matches=yara or "None"
        )
    
    @staticmethod
    def save(results, filepath):
        """Save results to HTML file"""
        html = HTMLFormatter.format(results)
        with open(filepath, 'w') as f:
            f.write(html)