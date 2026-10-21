import os
import secrets
from pathlib import Path
from typing import Union

CHUNK_SIZE = 64 * 1024  # 64 KB chunks to match crypto_engine

SSD_WEAR_LEVELING_WARNING = (
    "SECURITY NOTICE (SSD / NVMe Storage): Modern solid-state drives use Flash "
    "Translation Layers (FTL) and wear-leveling algorithms that redirect block "
    "writes to new physical NAND cells rather than overwriting existing sectors "
    "in-place. Consequently, OS-level file shredding on an SSD is best-effort "
    "and cannot be forensically guaranteed. For full forensic protection on SSDs, "
    "enable full-disk encryption (e.g., BitLocker) alongside File Safe."
)


class FileLockedError(Exception):
    """Raised when the target file is locked by another process or lacks write permissions."""
    pass


class ShredderError(Exception):
    """Raised when the shredding or unlinking process fails."""
    pass


def is_file_locked(filepath: Union[str, Path]) -> bool:
    """
    Checks if a file is locked by another process or read-only.
    On Windows, opening a file in 'r+b' mode and attempting to rename it to
    itself reliably detects sharing violations (WinError 32 / PermissionError).
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")

    try:
        with open(path, "r+b"):
            pass
        os.replace(path, path)
        return False
    except OSError:
        return True


def shred_file(
    filepath: Union[str, Path],
    is_ssd: bool = True
) -> str:
    """
    Destroys a target file after encryption:
    1. Verifies the file is not locked by another process.
    2. Overwrites exact byte length with os.urandom() in 64 KB chunks (if not skipped by SSD toggle).
    3. Flushes OS buffers to physical storage via os.fsync().
    4. Renames the file to an anonymous random name to scrub directory entry metadata.
    5. Unlinks the file from the filesystem.

    Args:
        filepath: Path to the plaintext file to destroy.
        is_ssd: Set True if the target drive is an SSD. Regardless of the toggle,
                this module performs best-effort overwrite unless configured otherwise,
                and returns the appropriate forensic notice for the GUI to display.

    Returns:
        A status/warning string suitable for displaying in the GUI status log.
    """
    target = Path(filepath)

    if not target.is_file():
        raise FileNotFoundError(f"Target file does not exist: {target}")

    # 1. Verify file is not locked before modifying any bytes
    if is_file_locked(target):
        raise FileLockedError(
            f"Cannot shred '{target.name}': The file is currently open in another "
            "application or marked read-only."
        )

    file_size = target.stat().st_size

    try:
        # 2. Overwrite in-place with cryptographically secure random bytes
        with open(target, "r+b", buffering=0) as f:
            f.seek(0)
            remaining = file_size
            while remaining > 0:
                write_len = min(CHUNK_SIZE, remaining)
                f.write(os.urandom(write_len))
                remaining -= write_len

            # 3. Flush Python and OS file buffers to disk
            f.flush()
            os.fsync(f.fileno())

        # 4. Rename to a random 16-character hex name to obscure original filename in MFT
        random_name = f".{secrets.token_hex(8)}.tmp"
        obfuscated_path = target.with_name(random_name)
        os.replace(target, obfuscated_path)

        # 5. Unlink the obfuscated file
        obfuscated_path.unlink()

    except Exception as exc:
        raise ShredderError(f"Failed to securely shred '{target.name}': {exc}") from exc

    if is_ssd:
        return SSD_WEAR_LEVELING_WARNING
    return f"Successfully shredded '{target.name}' (1-pass CSPRNG overwrite + fsync + unlink)."