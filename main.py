#!/usr/bin/env python3
"""
NusantaraScan - Advanced Binary Analysis Tool
Entry point utama.
"""

import sys
import os

current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

try:
    from binscan.cli import main
    main()
except ImportError as e:
    print(f"[!] Error: {e}")
    print("[!] Pastikan struktur folder sudah benar:")
    print("    NusantaraScan/")
    print("    ├── main.py")
    print("    └── binscan/")
    print("        ├── __init__.py")
    print("        ├── cli.py")
    print("        └── ...")
    sys.exit(1)