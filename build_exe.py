import hashlib
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


def run_security_tests() -> None:
    """Runs all unit tests before allowing a release build."""
    print("[1/4] Running cryptographic and shredder unit tests...")
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=".", pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if not result.wasSuccessful():
        print("\n[!] ABORTING BUILD: Unit tests failed.")
        sys.exit(1)


def clean_previous_builds() -> None:
    """Purges stale build/ and dist/ artifacts."""
    print("[2/4] Cleaning previous build artifacts...")
    for folder in ("build", "dist"):
        path = Path(folder)
        if path.exists():
            shutil.rmtree(path)


def run_pyinstaller() -> None:
    """Invokes PyInstaller with the hardened FileSafe.spec configuration."""
    print("[3/4] Building standalone executable via PyInstaller...")
    cmd = [sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", "FileSafe.spec"]
    subprocess.run(cmd, check=True)


def generate_sha256_manifest() -> None:
    """Computes SHA-256 digest of the compiled executable for integrity verification."""
    print("[4/4] Generating SHA-256 integrity manifest...")
    exe_path = Path("dist") / "FileSafe" / "FileSafe.exe"
    if not exe_path.is_file():
        raise FileNotFoundError(f"Expected executable not found at {exe_path}")

    sha256 = hashlib.sha256()
    with open(exe_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)

    digest = sha256.hexdigest()
    manifest_path = Path("dist") / "FileSafe" / "FileSafe.exe.sha256"
    manifest_path.write_text(f"{digest}  FileSafe.exe\n", encoding="utf-8")

    print("\n" + "=" * 60)
    print(f"BUILD SUCCESSFUL: {exe_path.resolve()}")
    print(f"SHA-256 Digest  : {digest}")
    print(f"Manifest File   : {manifest_path.resolve()}")
    print("=" * 60)


if __name__ == "__main__":
    run_security_tests()
    clean_previous_builds()
    run_pyinstaller()
    generate_sha256_manifest()