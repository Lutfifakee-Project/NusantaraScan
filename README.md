<div align="center">

# NusantaraScan

**Advanced Binary Analysis Tool for Modern Security Workflows**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-GPLv3-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Version](https://img.shields.io/badge/Version-0.3.0-green.svg)]()
[![Status](https://img.shields.io/badge/Status-Beta-yellow.svg)]()

**Static Binary Analysis • Malware Analysis • Reverse Engineering**

</div>

---

## About

**NusantaraScan** adalah alat analisis binary open-source yang dirancang untuk **malware analysis**, **reverse engineering**, dan **security research**.

NusantaraScan ditujukan untuk:

- Security Analyst
- Incident Responder
- Malware Researcher
- Reverse Engineer
- Security Researcher

Tool ini menyediakan berbagai fitur analisis binary secara lokal, mulai dari identifikasi format file, section analysis, import/export analysis, string extraction, entropy analysis, YARA scanning, packer detection, hingga disassembly.

> **Current Version:** `v0.3.0 Beta`

---

## Features

### Static Analysis

- **PE Analysis** — Windows executable (`.exe`, `.dll`, `.sys`)
- **ELF Analysis** — Linux binary (`.elf`, `.so`)
- **Mach-O Analysis** — macOS binary (`.dylib`, `.macho`)
- **Section Analysis** — Struktur section dan entropy per section
- **Import Analysis** — DLL dan fungsi yang di-import
- **Export Analysis** — Fungsi yang di-export
- **File Hashing** — MD5 dan SHA256
- **File Type Detection** — Identifikasi tipe binary

### Threat Detection

- **RAT Detection**
  - DarkComet
  - NanoCore
  - NjRAT
  - Gh0st
  - dan signature lainnya
- **YARA Integration** — Rule-based detection
- **Packer Detection**
  - UPX
  - ASPack
  - MPRESS
  - Themida
  - VMProtect
  - dan lainnya
- **String Analysis**
  - URL
  - IP Address
  - API Calls
  - Registry Indicators
  - C2 Indicators
  - Suspicious Strings
- **Entropy Analysis** — Membantu mengidentifikasi binary yang packed atau encrypted

### Advanced Analysis

- **Disassembly**
  - x86
  - x64
  - ARM
  - ARM64
- **Deep Analysis** — Analisis `.text` section dan disassembly
- **Full Disassembly** — Disassembly seluruh instruksi yang tersedia
- **Risk Scoring** — Skor risiko `0–100`
- **Whitelist Filter** — Mengurangi false positive dari software/vendor yang dikenal

### Output & Integration

- **JSON Report** — Untuk integrasi dengan tool lain
- **HTML Report** — Report berbasis browser
- **VirusTotal Integration** — Hash lookup melalui VirusTotal API
- **Multi-File Scan** — Scan directory secara recursive
- **Custom YARA Rules** — Mendukung rule YARA eksternal
- **`--all` Flag** — Menjalankan beberapa fitur analisis sekaligus

---

## Installation

### Requirements

- Python `3.8` atau lebih baru
- Windows
- Linux
- macOS

### Clone Repository

```bash
git clone https://github.com/Lutfifakee-Project/NusantaraScan.git
cd NusantaraScan
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Install NusantaraScan

```bash
pip install -e .
```

### Dependencies

| Package | Purpose |
|---|---|
| `pefile` | Windows PE analysis |
| `pyelftools` | Linux ELF analysis |
| `capstone` | Disassembly engine |
| `yara-python` | YARA integration |
| `rich` | CLI formatting |
| `colorama` | Cross-platform terminal color |
| `python-magic` | File type detection |
| `requests` | HTTP client / VirusTotal API |

---

## PyPI

> **Status:** Coming Soon

NusantaraScan belum tersedia di PyPI pada versi `0.3.0`.

Target package:

```bash
pip install binscan
```

Package PyPI direncanakan tersedia bersamaan dengan release `v1.0.0`.

---

## Usage

### Basic Analysis

Scan satu file:

```bash
binscan suspicious.exe
```

Scan directory secara recursive:

```bash
binscan ./samples/ --recursive
```

### Packer Detection

```bash
binscan malware.exe --packer
```

### Entropy Graph

```bash
binscan malware.exe --graph
```

### YARA Scan

Menggunakan rule bawaan:

```bash
binscan suspicious.exe
```

Menggunakan custom YARA rules:

```bash
binscan suspicious.exe --yara ./my_rules/
```

### Deep Analysis

Deep analysis dengan disassembly dan YARA:

```bash
binscan malware.exe --deep
```

Full disassembly:

```bash
binscan malware.exe --full-disasm --disasm-arch x86_64
```

### Export Report

HTML:

```bash
binscan malware.exe --output report.html --format html
```

JSON:

```bash
binscan malware.exe --output report.json --format json
```

Export disassembly:

```bash
binscan malware.exe --deep --export-asm output.asm
```

---

## VirusTotal Integration

VirusTotal integration bersifat **opsional**.

Set API key melalui environment variable.

### Linux / macOS

```bash
export VT_API_KEY="your_api_key_here"
```

### Windows CMD

```cmd
set VT_API_KEY=your_api_key_here
```

### Windows PowerShell

```powershell
$env:VT_API_KEY = "your_api_key_here"
```

Kemudian jalankan:

```bash
binscan malware.exe --vt
```

API key dapat diperoleh melalui [VirusTotal](https://www.virustotal.com/).

> **Security Note:** Jangan commit API key ke repository atau menuliskannya langsung di source code.

---

## Scan with All Features

Gunakan flag `--all` untuk mengaktifkan fitur analisis yang tersedia dalam satu command:

```bash
binscan malware.exe --all
```

Secara konseptual, `--all` mengaktifkan fitur seperti:

```bash
binscan malware.exe --packer --graph --deep --vt
```

Output dapat diarahkan ke report HTML:

```bash
binscan malware.exe --all --output report.html --format html
```

---

## Example Output

```text
    _   _                       _                  ____
   | \ | |_   _ ___  __ _ _ __ |_|_ __ _ _ __ __ _/ ___|  ___ __ _ _ __
   |  \| | | | / __|/ _` | '_ \| __/ _` | '__/ _` \___ \ / __/ _` | '_ \
   | |\  | |_| \__ \ (_| | | | | || (_| | | | (_| |___) | (_| (_| | | | |
   |_| \_|\__,_|___/\__,_|_| |_|\__\__,_|_|  \__,_|____/ \___\__,_|_| |_| 0.3.0

                https://github.com/Lutfifakee-Project/NusantaraScan

[+] Target   : malware_simulator.exe
[+] Size     : 8,456,064 bytes (8.06 MB)
[+] MD5      : 1a2b3c4d5e6f7g8h9i0j
[+] SHA256   : 9k8l7m6n5o4p3q2r1s0t...
[+] Entropy  : 6.8521
[+] Type     : PE32 executable

[*] Section Analysis:

+----------+-----------------+--------------+----------+---------+
| Name     | Virtual Address | Virtual Size | Raw Size | Entropy |
+----------+-----------------+--------------+----------+---------+
| .text    | 0x1000          | 0x2448f      | 0x24600  | 6.2747  |
| .rdata   | 0x26000         | 0x9288       | 0x9400   | 5.9296  |
| .data    | 0x30000         | 0x2718       | 0xe00    | 1.8068  |
+----------+-----------------+--------------+----------+---------+

[+] Imported Functions:

    KERNEL32.dll
      - CreateRemoteThread
      - VirtualAllocEx
      - WriteProcessMemory

[+] String Analysis:

    [!] Suspicious strings detected:
      - DarkComet
      - CreateRemoteThread
      - VirtualAllocEx

[!] YARA Scan:

    [!] 2 YARA rule(s) matched:
      - DarkComet_RAT
      - Suspicious_RAT_APIs

[*] Risk Assessment:

    Level: HIGH (62/100)

    Reasons:
      - 2 YARA rule matches (+60)
      - API combination: CreateRemoteThread... (+15)

[+] Scan completed!
```

---

## Project Structure

```text
NusantaraScan/
├── main.py
├── setup.py
├── requirements.txt
├── README.md
├── SECURITY.md
├── DISCLAIMER.md
├── ROADMAP.md
├── LICENSE
├── .gitignore
│
└── binscan/
    ├── __init__.py
    ├── cli.py
    ├── config.py
    │
    ├── analyzers/
    │   ├── base.py
    │   ├── generic.py
    │   ├── pe.py
    │   ├── elf.py
    │   ├── macho.py
    │   ├── strings.py
    │   ├── packer_detector.py
    │   └── disassembler.py
    │
    ├── formatters/
    │   ├── json_output.py
    │   └── html_output.py
    │
    ├── integrations/
    │   └── virustotal.py
    │
    ├── scanners/
    │   ├── multi_file.py
    │   └── yara_scanner.py
    │
    ├── signatures/
    │   └── yara_rules/
    │       └── rat_rules/
    │           └── rat_rules.yar
    │
    ├── utils/
    │   ├── hasher.py
    │   ├── entropy.py
    │   ├── validators.py
    │   └── scoring.py
    │
    └── visualizers/
        └── entropy_graph.py
```

---

## CLI Reference

```text
usage: binscan [-h] [-d] [-y RULE_PATH] [-o FILE] [-f {json,html,text}]
               [-v] [--packer] [--graph] [--full-disasm]
               [--disasm-arch {x86_32,x86_64,arm,arm_thumb,arm64}]
               [--export-asm FILE] [--recursive] [--vt] [--all]
               target

positional arguments:
  target                File atau direktori target

options:
  -h, --help            Show help
  -d, --deep            Deep analysis (disassembly + YARA)
  -y, --yara RULE_PATH  Path ke file atau direktori YARA rules
  -o, --output FILE     Export hasil ke file
  -f, --format FORMAT   Format output: json, html, text
  -v, --verbose         Tampilkan informasi detail
  --packer              Deteksi packer pada file
  --graph               Tampilkan visualisasi entropy bar graph
  --full-disasm         Full disassembly
  --disasm-arch ARCH    Arsitektur:
                        x86_32
                        x86_64
                        arm
                        arm_thumb
                        arm64
  --export-asm FILE     Export disassembly ke file .asm
  --recursive           Scan folder secara recursive
  --vt, --virustotal    Cek hash ke VirusTotal API
  --all                 Aktifkan semua fitur sekaligus
```

---

## Security

NusantaraScan menerapkan beberapa mekanisme keamanan untuk mengurangi risiko saat melakukan analisis file.

### Security Controls

- Input path validation
- Path traversal protection
- Symlink validation
- File size limit
- Maximum scan count
- Maximum string extraction limit
- HTML escaping untuk report
- Timeout untuk API eksternal
- Rate limiting untuk API eksternal
- Validasi YARA rule path
- Tidak menggunakan `eval()`
- Tidak menggunakan `exec()`
- Tidak menggunakan `os.system()`
- API key hanya dibaca dari environment variable

### Analysis Limits

| Limit | Value |
|---|---:|
| Maximum file size | 500 MB |
| Maximum files per scan | 1,000 |
| Maximum extracted strings | 100,000 |

Untuk melaporkan security vulnerability, lihat:

[SECURITY.md](SECURITY.md)

---

## Disclaimer

NusantaraScan dibuat untuk:

- Security research
- Malware analysis
- Reverse engineering
- Education
- Authorized security testing

Gunakan tool ini hanya pada file atau sistem yang **kamu miliki atau memiliki izin untuk menganalisis**.

Pengguna bertanggung jawab atas penggunaan tool ini dan wajib mematuhi hukum serta peraturan yang berlaku.

Untuk informasi lebih lanjut, lihat:

[DISCLAIMER.md](DISCLAIMER.md)

---

## Roadmap

Roadmap lengkap tersedia di:

[ROADMAP.md](ROADMAP.md)

### Planned Releases

| Version | Status | Focus |
|---|---|---|
| `v0.3.0` | Released | Current beta release |
| `v0.3.1` | Planned | Bug fixes & polish |
| `v0.4.0` | Planned | Refactor & plugin system |
| `v0.5.0` | Planned | REST API & integrations |
| `v1.0.0` | Planned | Stable release |

---

## Contributing

Kontribusi sangat terbuka.

Beberapa area yang dapat dikembangkan:

- Bug reports
- Bug fixes
- Documentation
- Testing pada Linux dan macOS
- Binary analyzers baru
- YARA rules
- Performance improvements
- CLI improvements
- HTML report improvements
- UI/UX improvements

### Contribution Workflow

1. Fork repository
2. Buat branch baru

```bash
git checkout -b feature/AmazingFeature
```

3. Commit perubahan

```bash
git commit -m "Add AmazingFeature"
```

4. Push branch

```bash
git push origin feature/AmazingFeature
```

5. Buat Pull Request

---

## License

NusantaraScan menggunakan:

**GNU General Public License v3.0 (GPLv3)**

Lihat [LICENSE](LICENSE) untuk informasi lengkap.

---

## Acknowledgments

NusantaraScan menggunakan dan terinspirasi oleh berbagai open-source project dan security tools:

- [YARA](https://virustotal.github.io/yara/) — Pattern matching engine
- [Capstone](https://www.capstone-engine.org/) — Disassembly framework
- [pefile](https://github.com/erocarrera/pefile) — PE parser
- [pyelftools](https://github.com/eliben/pyelftools) — ELF parser
- [Rich](https://github.com/Textualize/rich) — CLI formatting
- Komunitas security dan open-source Indonesia

---

## Contact

### GitHub

[github.com/Lutfifakee-Project/NusantaraScan](https://github.com/Lutfifakee-Project/NusantaraScan)

### Issues

[Report an Issue](https://github.com/Lutfifakee-Project/NusantaraScan/issues)

### Email

`lutfifakeeproject@proton.me`

---

<div align="center">

**NusantaraScan v0.3.0**

*Dibangun dengan semangat Nusantara untuk keamanan siber Indonesia.*

</div>