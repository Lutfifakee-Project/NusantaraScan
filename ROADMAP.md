# Roadmap NusantaraScan

> Rencana pengembangan jangka panjang untuk NusantaraScan.
> Dokumen ini hidup - akan diperbarui seiring feedback dan kebutuhan.

---

## Status Versi

| Versi | Status | Tanggal | Highlights |
|-------|--------|---------|------------|
| **v0.3.0** | [DONE] Released | 2026-09-28 | Cross-platform tested (Windows + Linux + macOS), fix false positives, add tests |
| **v0.3.1** | [WIP] Planned | TBD | Bug fixes dari user feedback |
| **v0.4.0** | [WIP] Planned | TBD | Refactor engine/display + test coverage |
| **v0.5.0** | [WIP] Planned | TBD | REST API + plugin system |
| **v1.0.0** | [TARGET] Target | TBD | Stable release + publish PyPI |

---

## Filosofi Pengembangan

1. **Security first** - setiap fitur harus aman (no RCE, no path traversal, no DoS)
2. **Analyst-friendly** - output jelas, false positive minimal
3. **Extensible** - mudah tambah analyzer/rule baru tanpa sentuh core
4. **Testable** - setiap fitur punya test
5. **Cross-platform** - Windows, Linux, macOS

---

## v0.3.1 - Bug Fix & Polish (Target: 2-4 minggu)

**Fokus:** stabilitas, polish, feedback dari user v0.3.0.

### Bug Fix
- [ ] Perbaiki false positive yang masih muncul dari user feedback
- [ ] Perbaiki edge case yang belum ter-handle
- [ ] Perbaiki compatibility issue di Linux/macOS (belum ditest)
- [ ] Perbaiki YARA rule yang belum lengkap

### Polish
- [ ] Refactor `scan_single_file` yang 217 baris jadi sub-fungsi
- [ ] Tambah type hints lengkap di semua modul
- [ ] Tambah docstring yang konsisten di semua fungsi public
- [ ] Perbaiki pesan error agar lebih informatif

### Dokumentasi
- [ ] Tambah screenshot output di README
- [ ] Tambah GIF demo di README
- [ ] Tambah FAQ di README
- [ ] Tambah tutorial penggunaan di `docs/`

### Testing
- [ ] Buat folder `tests/` dengan pytest
- [ ] Test minimal 50% coverage untuk core module
- [ ] Setup GitHub Actions CI (Windows + Linux + macOS)
- [ ] Setup codecov untuk tracking coverage

---

## v0.4.0 - Refactor & Extensibility (Target: 1-2 bulan)

**Fokus:** maintainability, engine/display separation, plugin system.

### Refactor Fundamental
- [ ] Pisahkan **engine** (analisis) dari **display** (print terminal)
- [ ] Pisahkan **engine** dari **formatter** (export file)
- [ ] Refactor `scan_single_file` jadi pipeline: `prepare → analyze → display → export`
- [ ] Buat `ScanResult` dataclass untuk konsistensi output

### Plugin System
- [ ] Buat decorator `@register_analyzer` untuk auto-register analyzer
- [ ] Buat decorator `@register_formatter` untuk auto-register formatter
- [ ] Buat decorator `@register_integration` untuk auto-register integrasi
- [ ] Buat dokumentasi cara buat plugin sendiri

### Analyzer Baru
- [ ] Analyzer PDF (untuk deteksi malicious PDF)
- [ ] Analyzer Office (docx, xlsx, pptx - deteksi macro)
- [ ] Analyzer APK (Android)
- [ ] Analyzer JAR (Java)
- [ ] Analyzer Script (VBS, PS1, JS, Python)

### Whitelist & Scoring
- [ ] Buat whitelist database yang bisa di-update (JSON/YAML)
- [ ] Buat scoring model yang lebih sophisticated (ML-based nanti)
- [ ] Buat opsi `--whitelist custom.json` untuk user-defined whitelist
- [ ] Buat opsi `--scoring config.json` untuk user-defined scoring

### YARA
- [ ] Auto-update YARA rules dari Yara-Rules/rules
- [ ] Buat rule builder GUI (opsional)
- [ ] Buat rule generator dari sample malware

---

## v0.5.0 - API & Integrasi (Target: 3-6 bulan)

**Fokus:** integrasi dengan tool lain, mode library.

### REST API
- [ ] Buat folder `api/` dengan FastAPI
- [ ] Endpoint `POST /scan` (upload file, return JSON)
- [ ] Endpoint `GET /scan/{id}` (ambil hasil)
- [ ] Endpoint `POST /batch` (scan multiple files)
- [ ] Rate limiting + API key authentication
- [ ] Docker support untuk deployment

### Library Mode
- [ ] Buat `from binscan import scan` untuk programmatic use
- [ ] Buat `from binscan import scan_file, scan_directory`
- [ ] Buat `from binscan import Analyzer, ScanResult`
- [ ] Publish library API di dokumentasi

### Integrasi Pihak Ketiga
- [ ] Integrasi MISP (Malware Information Sharing Platform)
- [ ] Integrasi AlienVault OTX
- [ ] Integrasi AbuseIPDB
- [ ] Integrasi MalwareBazaar
- [ ] Integrasi Shodan (untuk IP di string)
- [ ] Integrasi Hybrid Analysis

### Database
- [ ] Buat folder `db/` dengan SQLite
- [ ] Simpan riwayat scan
- [ ] Buat command `binscan --history`
- [ ] Buat command `binscan --diff` (bandingkan 2 scan)
- [ ] Buat command `binscan --stats` (statistik scan)

---

## v1.0.0 - Stable Release (Target: 6-12 bulan)

**Fokus:** stabil, matang, siap produksi.

### Stability
- [ ] Freeze API public
- [ ] Test coverage minimal 80%
- [ ] Fuzz testing untuk analyzer
- [ ] Performance benchmark
- [ ] Security audit oleh pihak ketiga

### Documentation
- [ ] Situs dokumentasi di ReadTheDocs
- [ ] Video tutorial
- [ ] Contoh use case lengkap
- [ ] API reference lengkap

### Distribution
- [ ] Publish ke PyPI (final)
- [ ] Buat Windows installer (`.msi`)
- [ ] Buat Linux package (`.deb`, `.rpm`)
- [ ] Buat macOS package (`.dmg`)
- [ ] Buat Docker image di Docker Hub
- [ ] Buat Homebrew formula

### Community
- [ ] Buat `CONTRIBUTING.md`
- [ ] Buat `CODE_OF_CONDUCT.md`
- [ ] Buat issue template di GitHub
- [ ] Buat PR template di GitHub
- [ ] Buat Discord/Telegram community

---

## v1.x - Maintenance & Fitur Baru (Ongoing)

### Fitur yang Mungkin
- [ ] Web UI (React/Vue) untuk visualisasi
- [ ] Machine learning untuk deteksi malware
- [ ] Threat intelligence feed integration
- [ ] Sandbox integration (Cuckoo, CAPE)
- [ ] Binary diff viewer
- [ ] Decompiler integration (Ghidra, IDA)
- [ ] Real-time monitoring (file system watcher)
- [ ] Remote scan (scan file dari URL)
- [ ] Cloud deployment (AWS, GCP, Azure)
- [ ] Mobile app (Android/iOS) untuk cek file

---

## Fitur yang Diminta User

Bagian ini akan diisi berdasarkan feedback dari user. Setiap request akan di-review dan dikategorikan.

### Kategori
- [CRITICAL] **Critical** - bug yang menghalangi penggunaan
- [IMPORTANT] **Important** - fitur yang sangat dibutuhkan
- [NICE] **Nice-to-have** - fitur tambahan

*Belum ada request. Silakan buat issue di GitHub.*

---

## Tidak Akan Diimplementasikan

Beberapa fitur yang **tidak akan** diimplementasikan untuk menjaga fokus & keamanan:

- [NO] **Auto-execute file** - NusantaraScan hanya analisis statis, tidak eksekusi
- [NO] **Bypass antivirus** - alat ini untuk analisis, bukan untuk evasion
- [NO] **Crack software** - tidak untuk reverse engineering ilegal
- [NO] **Auto-exploit** - tidak untuk penetration testing otomatis
- [NO] **Cloud upload file** - hanya hash yang dikirim ke VirusTotal, bukan file
- [NO] **Telemetry** - tidak ada tracking penggunaan

---

## Kontribusi

Kami menyambut kontribusi! Lihat `CONTRIBUTING.md` untuk panduan.

### Area yang Butuh Bantuan
- [BUG] Bug reports & fixes
- [DOC] Dokumentasi
- [TEST] Testing di platform berbeda (Linux, macOS)
- [I18N] Terjemahan (English, Indonesia, dll)
- [TOOL] Analyzer baru
- [RULE] YARA rules
- [UI] UI/UX improvements

---

## Lisensi

GPLv3 - lihat [LICENSE](LICENSE).

---

## Kontak

- **GitHub Issues:** https://github.com/Lutfifakee-Project/NusantaraScan/issues
- **Email:** lutfifakeeproject@proton.me

---

*Dokumen ini terakhir diperbarui: 2026*

**Catatan:** Roadmap ini bersifat **indikatif**, bukan komitmen. Prioritas bisa berubah berdasarkan feedback user dan kebutuhan komunitas.