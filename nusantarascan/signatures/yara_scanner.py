"""
YARA scanner wrapper
"""

import os
import glob

class YaraScanner:
    """Wrapper for YARA scanning"""
    
    def __init__(self, rule_path):
        self.rule_path = rule_path
        self.rules = None
        self._compile_rules()
    
    def _compile_rules(self):
        """Compile YARA rules from path"""
        try:
            import yara
            
            if os.path.isfile(self.rule_path):
                # Single file
                self.rules = yara.compile(filepath=self.rule_path)
            elif os.path.isdir(self.rule_path):
                # Directory - compile all .yar and .yara files
                rule_files = glob.glob(os.path.join(self.rule_path, "*.yar")) + \
                             glob.glob(os.path.join(self.rule_path, "*.yara"))
                if rule_files:
                    self.rules = yara.compile(filepaths={f"rule_{i}": f for i, f in enumerate(rule_files)})
            else:
                self.rules = None
        except Exception as e:
            print(f"[-] YARA compile error: {e}")
            self.rules = None
    
    def scan(self, filepath):
        """Scan file with compiled rules"""
        if not self.rules:
            return []
        
        try:
            matches = self.rules.match(filepath)
            return [match.rule for match in matches]
        except Exception as e:
            print(f"[-] YARA scan error: {e}")
            return []