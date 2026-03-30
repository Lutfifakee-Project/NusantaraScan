"""
Base analyzer class for binary analysis
"""

import math
import struct
from abc import ABC, abstractmethod

class BaseAnalyzer(ABC):
    """Base class for binary analyzers"""
    
    def __init__(self, filepath):
        self.filepath = filepath
        self.data = None
        self._load_file()
    
    def _load_file(self):
        """Load file into memory"""
        with open(self.filepath, 'rb') as f:
            self.data = f.read()
    
    @abstractmethod
    def get_sections(self):
        """Get section information"""
        pass
    
    @abstractmethod
    def get_imports(self):
        """Get imported functions"""
        pass
    
    @abstractmethod
    def get_exports(self):
        """Get exported functions"""
        pass
    
    def get_entropy_for_section(self, data):
        """Calculate entropy for a section"""
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
                entropy -= p * math.log2(p)  # Lebih akurat
        
        return entropy