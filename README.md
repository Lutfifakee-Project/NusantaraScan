# 🌏 NusantaraScan

> *"An open-source binary analysis tool for modern security workflows."*

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-GPLv3-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)]()
[![PyPI](https://img.shields.io/pypi/v/nusantarascan)](https://pypi.org/project/nusantarascan/)

---

## 🧠 Tentang Proyek

**NusantaraScan** adalah tool open-source untuk analisis binary, mencakup malware analysis dan reverse engineering, dengan output yang terstruktur dan mudah dipahami.

Dirancang agar:
- Powerful untuk analis profesional
- Tetap simpel untuk pemula

---

## 🗡️ Fitur

- ✅ **Static Analysis** — Informasi lengkap file binary (PE, ELF, Mach-O)
- ✅ **String Extraction** — Deteksi string mencurigakan (URL, IP, API calls)
- ✅ **Entropy Analysis** — Deteksi file terenkripsi atau packed
- ✅ **Section Analysis** — Analisis struktur internal binary
- ✅ **YARA Integration** — Scan dengan custom YARA rules
- 🚧 **Disassembly** — (Coming soon) dengan Capstone Engine
- ✅ **Multi-format Export** — JSON, HTML, Text

---

## 🚀 Instalasi

```bash
git clone https://github.com/Lutfifakee-Project/NusantaraScan.git
cd NusantaraScan
pip install -r requirements.txt
python main.py --help
```

---

## 💻 Contoh Penggunaan

```bash
# Analisis dasar
python main.py notepad.exe

# Analisis mendalam dengan YARA scan
python main.py malware.exe --deep

# Scan dengan custom YARA rules
python main.py suspicious.dll --yara rules/malware.yara

# Export hasil ke HTML
python main.py file.exe --output report.html --format html
```

---

## 📊 Contoh Output

```text
    _   _                       _                  ____
   | \ | |_   _ ___  __ _ _ __ | |_ __ _ _ __ __ _/ ___|  ___ __ _ _ __
   |  \| | | | / __|/ _` | '_ \| __/ _` | '__/ _` \___ \ / __/ _` | '_ \
   | |\  | |_| \__ \ (_| | | | | || (_| | | | (_| |___) | (_| (_| | | | |
   |_| \_|\__,_|___/\__,_|_| |_|\__\__,_|_|  \__,_|____/ \___\__,_|_| |_| v0.1.0
                https://github.com/Lutfifakee-Project/

[+] Target   : notepad.exe
[+] Size     : 200,704 bytes (196.00 KB)
[+] MD5      : 6f51bcabf1b2b34ad7e670aee6da451f
[+] Entropy  : 6.3093

📊 Section Analysis:
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┓
┃ Name   ┃ Virtual Address ┃ Virtual Size ┃ Raw Size ┃ Entropy ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━┩
│ .text  │ 0x1000          │ 0x2448f      │ 0x24600  │ 6.2747  │
│ .rdata │ 0x26000         │ 0x9288       │ 0x9400   │ 5.9296  │
└────────┴─────────────────┴──────────────┴──────────┴─────────┘

✅ Scan completed!
```

---

## 📦 Requirements

- Python 3.8 atau lebih baru

Install dependencies:

```bash
pip install -r requirements.txt
```

Dependencies:
- `pefile` — Analisis file PE Windows
- `pyelftools` — Analisis file ELF Linux
- `capstone` — Disassembly engine (coming soon)
- `yara-python` — YARA integration
- `rich` — CLI output formatting

---

## 📁 Struktur Proyek

```text
NusantaraScan/
├── main.py                  # Entry point utama
├── requirements.txt        # Dependencies
├── setup.py                # Installer
├── README.md               # Dokumentasi
└── nusantarascan/
    ├── cli.py              # CLI handler
    ├── analyzers/          # Binary analyzers (PE, ELF)
    ├── utils/              # Utilities (hash, entropy)
    ├── signatures/         # YARA scanner
    └── formatters/         # JSON/HTML export
```

---


## 📜 Lisensi

Proyek ini menggunakan lisensi **GNU General Public License v3.0**

---
