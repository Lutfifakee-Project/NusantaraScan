"""
HTML output formatter
"""

class HTMLFormatter:
    """Format analysis results as HTML"""
    
    @staticmethod
    def format(results):
        """Convert results to HTML string"""
        # Versi paling sederhana - tanpa CSS rumit
        html = "<html><head><title>NusantaraScan Report</title></head><body>"
        html += "<h1>NusantaraScan Report</h1>"
        html += "<h2>File Information</h2><pre>{file_info}</pre>"
        html += "<h2>Suspicious Strings</h2><pre>{suspicious_strings}</pre>"
        html += "<h2>YARA Matches</h2><pre>{yara_matches}</pre>"
        html += "</body></html>"
        
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
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)