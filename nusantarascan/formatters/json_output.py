"""
JSON output formatter
"""

import json

class JSONFormatter:
    """Format analysis results as JSON"""
    
    @staticmethod
    def format(results):
        """Convert results to JSON string"""
        return json.dumps(results, indent=2, default=str)
    
    @staticmethod
    def save(results, filepath):
        """Save results to JSON file"""
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2, default=str)