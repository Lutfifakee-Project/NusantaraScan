# NusantaraScan

> *"An open-source binary analysis tool for modern security workflows."*

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-GPLv3-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)]()
[![PyPI version](https://badge.fury.io/py/nusantarascan.svg)](https://pypi.org/project/nusantarascan/)

---

## 📌 About The Project

**NusantaraScan** is an open-source binary analysis tool designed for modern malware analysis and reverse engineering workflows.

It supports:
- Malware analysis
- RAT (Remote Access Trojan) detection
- Binary reverse engineering
- Packer detection
- Entropy visualization
- Multi-platform executable analysis

Designed to be:
- Powerful for professional analysts
- Simple enough for beginners

---

## ✨ Features (v0.2.0)

- Static Analysis (PE, ELF, Mach-O)
- RAT Detection (DarkComet, NanoCore, NjRAT, Gh0st, etc.)
- String Extraction (URLs, IPs, API calls)
- Entropy Analysis
- Section Analysis
- YARA Integration
- Disassembly (x86/x64/ARM/ARM64)
- Multi-format Export (JSON, HTML)
- Packer Detection (UPX, ASPack, MPRESS)
- Entropy Visualization
- Multi-file Scanning
- VirusTotal Integration

---

## ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/Lutfifakee-Project/NusantaraScan.git
cd NusantaraScan
pip install -r requirements.txt
python main.py --help
```

### Install from PyPI

```bash
pip install nusantarascan
```

---

## 🛡️ RAT Detection Examples

```bash
python main.py suspicious_file.exe --yara nusantarascan/signatures/yara_rules/rat_rules

python main.py suspicious_file.exe --deep \
--yara nusantarascan/signatures/yara_rules/rat_rules
```

---

## 🚀 Usage Examples

```bash
# Basic analysis
python main.py notepad.exe

# Detect packers
python main.py malware.exe --packer

# Entropy graph visualization
python main.py malware.exe --graph

# Full disassembly
python main.py malware.exe --full-disasm

# Scan all files recursively
python main.py ./malware_samples/ --recursive

# Check file on VirusTotal (requires API key)
python main.py malware.exe --vt --vt-api-key YOUR_API_KEY

# Combine multiple features
python main.py malware.exe --deep --packer --graph --vt

# Export report to HTML/JSON
python main.py file.exe --output report.html --format html
```

---

## 📊 Example Output

```text
    _   _                       _                  ____
   | \ | |_   _ ___  __ _ _ __ | |_ __ _ _ __ __ _/ ___|  ___ __ _ _ __
   |  \| | | | / __|/ _` | '_ \| __/ _` | '__/ _` \___ \ / __/ _` | '_ \
   | |\  | |_| \__ \ (_| | | | | || (_| | | | (_| |___) | (_| (_| | | | |
   |_| \_|\__,_|___/\__,_|_| |_|\__\__,_|_|  \__,_|____/ \___\__,_|_| |_| 0.2.0
                https://github.com/Lutfifakee-Project/

[+] Target   : malware_simulator.exe
[+] Size     : 8,456,064 bytes (8.06 MB)
[+] MD5      : 1a2b3c4d5e6f7g8h9i0j
[+] Entropy  : 6.8521

[*] Section Analysis:
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┓
┃ Name   ┃ Virtual Address ┃ Virtual Size ┃ Raw Size ┃ Entropy ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━┩
│ .text  │ 0x1000          │ 0x2448f      │ 0x24600  │ 6.2747  │
│ .rdata │ 0x26000         │ 0x9288       │ 0x9400   │ 5.9296  │
└────────┴─────────────────┴──────────────┴──────────┴─────────┘

[+] Imported Functions:
    KERNEL32.dll
      └─ CreateRemoteThread
      └─ VirtualAllocEx
      └─ WriteProcessMemory
      └─ RegSetValueExW

[+] String Analysis:
    [!] Suspicious strings detected:
      • DarkComet
      • CreateRemoteThread
      • VirtualAllocEx

[!] YARA Scan:
    [!] 2 YARA rule(s) matched:
      • DarkComet_RAT
      • Suspicious_RAT_APIs

[+] Scan completed!
```

---

## 📦 Requirements

- Python 3.8 or newer

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Main Dependencies

- `pefile` — Windows PE analysis
- `pyelftools` — Linux ELF analysis
- `capstone` — Disassembly engine
- `yara-python` — YARA integration
- `rich` — CLI formatting
- `requests` — VirusTotal API integration

---

## 📁 Project Structure

```text
NusantaraScan/
├── main.py                  # Main entry point
├── requirements.txt         # Python dependencies
├── setup.py                 # Package installer
├── README.md                # Documentation
└── nusantarascan/
    ├── cli.py               # CLI handler
    ├── analyzers/           # Binary analyzers (PE, ELF, Mach-O)
    ├── visualizers/         # Entropy graph visualization
    ├── integrations/        # VirusTotal integration
    ├── scanners/            # Multi-file scanner
    ├── utils/               # Utilities (hashing, entropy, etc.)
    ├── signatures/          # YARA scanner & rules
    │   └── yara_rules/
    │       └── rat_rules/   # RAT detection rules
    └── formatters/          # JSON/HTML exporters
```

---

## 🧩 Using Community YARA Rules

To significantly improve detection capabilities, you can integrate community-maintained YARA rules from the `Yara-Rules/rules` repository.

This repository contains thousands of signatures for:
- Malware detection
- Packer detection
- Exploit kits
- Malicious documents
- Anti-debugging techniques
- Threat actor indicators

---

## 📥 Integrating Community Rules

### Clone the Repository

```bash
git clone https://github.com/Yara-Rules/rules.git \
nusantarascan/signatures/yara_rules/community
```

### Directory Structure

```text
nusantarascan/signatures/yara_rules/
├── rat_rules/          # Custom RAT rules
└── community/          # Community YARA rules
    ├── malware/
    ├── packers/
    ├── maldocs/
    └── ...
```

---

## 🔍 Using Community Rules

### Scan with All Community Rules

```bash
python main.py suspicious_file.exe \
--yara nusantarascan/signatures/yara_rules/community
```

### Scan with Malware Category Only

```bash
python main.py suspicious_file.exe \
--yara nusantarascan/signatures/yara_rules/community/malware
```

### Combine Custom RAT Rules + Community Rules

```bash
python main.py suspicious_file.exe \
--yara nusantarascan/signatures/yara_rules/
```

---

## ⚠️ Disclaimer

This project is intended for:
- Security research
- Malware analysis
- Educational purposes
- Authorized penetration testing

The developer is **not responsible** for:
- Illegal activities
- Unauthorized system access
- Misuse of this software
- Damage caused by improper usage

Use this tool responsibly and only in environments where you have explicit permission.

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**.

See the <a href='https://github.com/Lutfifakee-Project/NusantaraScan/blob/main/LICENSE'>LICENSE</a> file for more information.

---