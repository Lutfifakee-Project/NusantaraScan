#!/usr/bin/env python3
"""
NusantaraScan - Advanced Binary Analysis Tool
Run script for NusantaraScan
"""

import sys
import os

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import and run
try:
    from nusantarascan.cli import main
    main()
except ImportError as e:
    print(f"[!] Error: {e}")
    print("[!] Pastikan struktur folder sudah benar:")
    print("    NusantaraScan/")
    print("    ├── run.py")
    print("    └── nusantarascan/")
    print("        ├── __init__.py")
    print("        ├── cli.py")
    print("        └── ...")
    sys.exit(1)