"""
Entropy calculation utilities
"""

import math

class EntropyCalculator:
    """Calculate entropy for binary data"""
    
    @staticmethod
    def calculate_entropy(filepath):
        """Calculate Shannon entropy of a file"""
        with open(filepath, 'rb') as f:
            data = f.read()
        
        if not data:
            return 0.0
        
        # Count frequency of each byte
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(data)
        
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def calculate_entropy_for_data(data):
        """Calculate Shannon entropy for bytes data"""
        if not data:
            return 0.0
        
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        entropy = 0.0
        length = len(data)
        
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        
        return entropy