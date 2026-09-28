"""
Konfigurasi global NusantaraScan.
Semua konstanta keamanan, limit, whitelist & scoring ada di sini.
"""

# ── Limit file ────────────────────────────────────────────────
MAX_FILE_SIZE = 500 * 1024 * 1024          # 500 MB
MAX_FILES_PER_SCAN = 1000
MAX_STRINGS_EXTRACT = 100_000
MAX_SUSPICIOUS_DISPLAY = 15
MAX_INSTRUCTIONS_PREVIEW = 50

# ── Disassembly limits ────────────────────────────────────────
MAX_DISASM_BYTES = 1024 * 1024             # 1 MB untuk --full-disasm
MAX_DISASM_BYTES_PREVIEW = 4096            # 4 KB untuk mode preview biasa

# ── VirusTotal ────────────────────────────────────────────────
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_TIMEOUT = 10
VT_RATE_LIMIT_SLEEP = 60

# ── YARA ──────────────────────────────────────────────────────
YARA_ALLOWED_EXTENSIONS = (".yar", ".yara")

# ── Entropy threshold ─────────────────────────────────────────
ENTROPY_LOW = 6.5
ENTROPY_HIGH = 7.5

# ── Ekstensi binary yang didukung ─────────────────────────────
SUPPORTED_EXTENSIONS = (
    ".exe", ".dll", ".sys",
    ".elf", ".so",
    ".dylib", ".macho",
    "",
)

# ── Whitelist: domain yang dianggap aman ──────────────────────
WHITELIST_DOMAINS = (
    # Microsoft & Windows
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    # Certificate authorities
    "verisign.com",
    "symantec.com",
    "symcb.com",
    "symcd.com",
    "digicert.com",
    "globalsign.com",
    "godaddy.com",
    "letsencrypt.org",
    "thawte.com",
    "comodo.com",
    "sectigo.com",
    "entrust.net",
    "amazontrust.com",
    # Vendor umum
    "apple.com",
    "google.com",
    "mozilla.org",
    # Linux distro
    "ubuntu.com",
    "debian.org",
    "archlinux.org",
    "fedoraproject.org",
    "redhat.com",
    "centos.org",
    "opensuse.org",
    "linux.org",
    # GNU & Free Software Foundation
    "gnu.org",
    "fsf.org",
    # Kernel & desktop environment
    "kernel.org",
    "freedesktop.org",
    "gnome.org",
    "kde.org",
    # Media & misc legal
    "xiph.org",
    "translationproject.org",
)

# ── Whitelist: API yang normal di aplikasi ────────────────────
WHITELIST_APIS = (
    "RegOpenKeyExW", "RegOpenKeyExA",
    "RegSetValueExW", "RegSetValueExA",
    "RegQueryValueExW", "RegQueryValueExA",
    "CreateProcessA", "CreateProcessW",
    "CreateFileA", "CreateFileW",
    "ReadFile", "WriteFile",
    "ShellExecuteW", "ShellExecuteA",
    "ShellExecuteExW", "ShellExecuteExA",
    "GetProcAddress",
    "LoadLibraryA", "LoadLibraryW",
    "GetModuleHandleA", "GetModuleHandleW",
    "FindFirstFileW", "FindNextFileW",
    "GetFileAttributesW",
    "SetFileAttributesW",
    "DuplicateEncryptionInfoFile",
    # Windows CRT & runtime normal (false positive dari /bin/ls)
    "WaitForThreadpoolTimerCallbacks",
    "_register_thread_local_exe_atexit_callback",
)

# ── Whitelist: string yang normal (XML manifest, URL legal, dll) ──
WHITELIST_STRING_PATTERNS = (
    # XML manifest (Windows)
    "<?xml",
    "<assembly",
    "manifestVersion",
    "xmlns=",
    "<assemblyIdentity",
    "<dependentAssembly",
    "<trustInfo",
    "<requestedPrivileges",
    "<application",
    "<windowsSettings",
    "<compatibility",
    "Microsoft.Windows",
    "publicKeyToken",
    "processorArchitecture",
    # URL legal (GNU/FSF & Linux)
    "https://gnu.org",
    "http://gnu.org",
    "https://www.gnu.org",
    "http://www.gnu.org",
    "https://fsf.org",
    "https://www.fsf.org",
    "bug-coreutils@",
    "bug-gnu-utils@",
    "translationproject.org",
    "wiki.xiph.org",
    "kernel.org",
    "freedesktop.org",
)

# ── Risk scoring ──────────────────────────────────────────────
# Bobot untuk setiap indikasi mencurigakan
RISK_WEIGHTS = {
    "suspicious_string": 2,
    "yara_match": 30,
    "packer_detected": 20,
    "high_entropy": 10,
    "api_combo": 15,
}

# Batas skor untuk kategori
RISK_LEVELS = (
    (0,   "CLEAN"),
    (10,  "LOW"),
    (30,  "MEDIUM"),
    (60,  "HIGH"),
    (100, "CRITICAL"),
)

# ── Kombinasi API yang mencurigakan (RAT indicator) ───────────
SUSPICIOUS_API_COMBOS = (
    # Proses injection
    ("CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory"),
    ("NtCreateThreadEx", "VirtualAllocEx", "WriteProcessMemory"),
    # Keylogger
    ("SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState"),
    # Persistence + download
    ("RegSetValueExW", "URLDownloadToFileW", "ShellExecuteW"),
)
