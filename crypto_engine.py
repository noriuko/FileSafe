import os
import tempfile
from pathlib import Path
from typing import Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# Security & Format Constants
SALT_SIZE = 16
IV_SIZE = 12
TAG_SIZE = 16
HEADER_SIZE = SALT_SIZE + IV_SIZE + TAG_SIZE  # 44 bytes total
KEY_SIZE = 32  # 256 bits
KDF_ITERATIONS = 600_000
CHUNK_SIZE = 64 * 1024  # 64 KB


class DecryptionError(Exception):
    """Raised when file authentication fails or the file is malformed."""
    pass


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit key from a password and 16-byte salt using PBKDF2-HMAC-SHA256."""
    if not password:
        raise ValueError("Master password cannot be empty.")
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be exactly {SALT_SIZE} bytes.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    password: str
) -> None:
    """
    Streams encryption of a file in 64 KB chunks using AES-256-GCM.
    File layout: [Salt (16B)] + [IV (12B)] + [Auth Tag (16B)] + [Ciphertext]
    """
    in_path = Path(input_path)
    out_path = Path(output_path)

    if not in_path.is_file():
        raise FileNotFoundError(f"Source file not found: {in_path}")

    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    key = derive_key(password, salt)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()

    try:
        with open(in_path, "rb") as f_in, open(out_path, "wb") as f_out:
            # Write Salt (16B), IV (12B), and a 16-byte placeholder for the GCM Auth Tag
            f_out.write(salt)
            f_out.write(iv)
            f_out.write(b"\x00" * TAG_SIZE)

            # Stream and encrypt in 64 KB chunks
            while chunk := f_in.read(CHUNK_SIZE):
                ciphertext_chunk = encryptor.update(chunk)
                if ciphertext_chunk:
                    f_out.write(ciphertext_chunk)

            # Finalize GCM state and compute the authentication tag
            f_out.write(encryptor.finalize())
            tag = encryptor.tag

            # Seek back to offset 28 (after Salt + IV) and write the actual 16-byte tag
            f_out.seek(SALT_SIZE + IV_SIZE)
            f_out.write(tag)

    except Exception:
        # Clean up partial ciphertext output on failure
        if out_path.exists():
            out_path.unlink(missing_ok=True)
        raise
    finally:
        # Drop reference to derived key
        del key


def decrypt_file(
    input_path: Union[str, Path],
    output_path: Union[str, Path],
    password: str
) -> None:
    """
    Streams decryption of an AES-256-GCM encrypted file in 64 KB chunks.
    Verifies the authentication tag before exposing the output file.
    """
    in_path = Path(input_path)
    out_path = Path(output_path)

    if not in_path.is_file():
        raise FileNotFoundError(f"Encrypted file not found: {in_path}")

    if in_path.stat().st_size < HEADER_SIZE:
        raise DecryptionError("File is smaller than the minimum valid header size (44 bytes).")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_output = tempfile.mkstemp(dir=out_path.parent, prefix=".tmp_dec_")
    os.close(fd)
    temp_path = Path(temp_output)

    key = None
    try:
        with open(in_path, "rb") as f_in, open(temp_path, "wb") as f_out:
            # Extract header components: [Salt (16B)] + [IV (12B)] + [Auth Tag (16B)]
            salt = f_in.read(SALT_SIZE)
            iv = f_in.read(IV_SIZE)
            tag = f_in.read(TAG_SIZE)

            key = derive_key(password, salt)

            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
            ).decryptor()

            # Stream ciphertext in 64 KB chunks
            while chunk := f_in.read(CHUNK_SIZE):
                plaintext_chunk = decryptor.update(chunk)
                if plaintext_chunk:
                    f_out.write(plaintext_chunk)

            # Verify the GCM Authentication Tag (raises InvalidTag if tampered or wrong key)
            f_out.write(decryptor.finalize())

        # Atomically replace destination only after tag verification succeeds
        os.replace(temp_path, out_path)

    except InvalidTag as exc:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise DecryptionError("Authentication failed: Invalid master password or corrupted file.") from exc
    except Exception:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise
    finally:
        if key is not None:
            del key

MAX_MEMORY_PREVIEW_SIZE = 50 * 1024 * 1024  # 50 MB safety cap for in-RAM preview


def decrypt_to_memory(
    input_path: Union[str, Path],
    password: str,
    max_bytes: int = MAX_MEMORY_PREVIEW_SIZE,
) -> bytearray:
    """
    Streams decryption of an AES-256-GCM encrypted file strictly into a mutable
    in-memory bytearray without touching disk.
    Caller is responsible for zeroing the returned bytearray when finished.
    """
    in_path = Path(input_path)

    if not in_path.is_file():
        raise FileNotFoundError(f"Encrypted file not found: {in_path}")

    file_size = in_path.stat().st_size
    if file_size < HEADER_SIZE:
        raise DecryptionError("File is smaller than the minimum valid header size (44 bytes).")

    ciphertext_size = file_size - HEADER_SIZE
    if ciphertext_size > max_bytes:
        raise ValueError(
            f"File is too large for safe in-memory preview ({ciphertext_size / (1024 * 1024):.1f} MB). "
            f"Maximum allowed is {max_bytes / (1024 * 1024):.0f} MB."
        )

    key = None
    buffer = bytearray()
    try:
        with open(in_path, "rb") as f_in:
            salt = f_in.read(SALT_SIZE)
            iv = f_in.read(IV_SIZE)
            tag = f_in.read(TAG_SIZE)

            key = derive_key(password, salt)
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
            ).decryptor()

            while chunk := f_in.read(CHUNK_SIZE):
                plaintext_chunk = decryptor.update(chunk)
                if plaintext_chunk:
                    buffer.extend(plaintext_chunk)

            buffer.extend(decryptor.finalize())

        return buffer

    except InvalidTag as exc:
        for i in range(len(buffer)):
            buffer[i] = 0
        buffer.clear()
        raise DecryptionError("Authentication failed: Invalid master password or corrupted file.") from exc
    except Exception:
        for i in range(len(buffer)):
            buffer[i] = 0
        buffer.clear()
        raise
    finally:
        if key is not None:
            del key