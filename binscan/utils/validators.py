"""
Validasi input untuk mencegah path traversal & DoS.
"""

from pathlib import Path

from ..config import MAX_FILE_SIZE, MAX_FILES_PER_SCAN


class ValidationError(Exception):
    """Error saat validasi input gagal."""
    pass


def validate_file(filepath: str, max_size: int = MAX_FILE_SIZE) -> Path:
    path = Path(filepath).resolve()

    if not path.exists():
        raise ValidationError(f"File tidak ditemukan: {filepath}")

    if not path.is_file():
        raise ValidationError(f"Bukan file biasa: {filepath}")

    if Path(filepath).is_symlink():
        raise ValidationError(f"Symlink ditolak: {filepath}")

    size = path.stat().st_size
    if size > max_size:
        raise ValidationError(
            f"File terlalu besar: {size:,} bytes (max {max_size:,})"
        )

    if size == 0:
        raise ValidationError(f"File kosong: {filepath}")

    return path


def validate_directory(dirpath: str) -> Path:
    path = Path(dirpath).resolve()
    if not path.exists():
        raise ValidationError(f"Direktori tidak ditemukan: {dirpath}")
    if not path.is_dir():
        raise ValidationError(f"Bukan direktori: {dirpath}")
    return path


def validate_rule_path(rule_path: str, base_dir: str = None) -> Path:
    path = Path(rule_path).resolve()
    if not path.exists():
        raise ValidationError(f"Rule path tidak ditemukan: {rule_path}")

    if base_dir:
        base = Path(base_dir).resolve()
        try:
            path.relative_to(base)
        except ValueError:
            raise ValidationError(
                f"Rule path di luar base directory: {rule_path}"
            )

    return path


def cap_file_list(files: list, max_files: int = MAX_FILES_PER_SCAN) -> list:
    if len(files) > max_files:
        return files[:max_files]
    return files