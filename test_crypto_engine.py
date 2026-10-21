import os
import unittest
from pathlib import Path
import tempfile
from crypto_engine import (
    encrypt_file,
    decrypt_file,
    DecryptionError,
    HEADER_SIZE,
    CHUNK_SIZE,
)


class TestCryptoEngine(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)
        self.password = "CorrectHorseBatteryStaple!99"

    def tearDown(self):
        self.test_dir.cleanup()

    def test_encrypt_decrypt_multi_chunk_file(self):
        """Verifies streaming encryption/decryption across multiple 64 KB chunks."""
        src_file = self.base_path / "sample.bin"
        enc_file = self.base_path / "sample.bin.enc"
        dec_file = self.base_path / "sample.dec.bin"

        # Generate 200 KB of random payload (spans > 3 chunks of 64 KB)
        original_data = os.urandom(CHUNK_SIZE * 3 + 12345)
        src_file.write_bytes(original_data)

        encrypt_file(src_file, enc_file, self.password)

        # Verify exact file size: [44-byte Header] + [Ciphertext length == Plaintext length]
        self.assertEqual(enc_file.stat().st_size, len(original_data) + HEADER_SIZE)

        decrypt_file(enc_file, dec_file, self.password)
        self.assertEqual(dec_file.read_bytes(), original_data)

    def test_wrong_password_rejection_and_cleanup(self):
        """Verifies wrong passwords raise DecryptionError and leave no unverified files."""
        src_file = self.base_path / "secret.txt"
        enc_file = self.base_path / "secret.txt.enc"
        dec_file = self.base_path / "secret.txt.dec"

        src_file.write_bytes(b"Classified payload data.")
        encrypt_file(src_file, enc_file, self.password)

        with self.assertRaises(DecryptionError):
            decrypt_file(enc_file, dec_file, "WrongPassword123!")

        # Ensure output file was never created and no temp files remain
        self.assertFalse(dec_file.exists())
        temp_files = list(self.base_path.glob(".tmp_dec_*"))
        self.assertEqual(len(temp_files), 0)

    def test_ciphertext_tampering_rejection(self):
        """Verifies bit-flipping in the ciphertext invalidates the GCM Auth Tag."""
        src_file = self.base_path / "document.pdf"
        enc_file = self.base_path / "document.pdf.enc"
        dec_file = self.base_path / "document.pdf.dec"

        src_file.write_bytes(os.urandom(1024))
        encrypt_file(src_file, enc_file, self.password)

        # Flip a bit in the last byte of the ciphertext
        enc_bytes = bytearray(enc_file.read_bytes())
        enc_bytes[-1] ^= 0x01
        enc_file.write_bytes(enc_bytes)

        with self.assertRaises(DecryptionError):
            decrypt_file(enc_file, dec_file, self.password)

        self.assertFalse(dec_file.exists())

    def test_unique_salt_and_iv_per_encryption(self):
        """Verifies encrypting identical files with the same password yields unique headers and ciphertexts."""
        src_file = self.base_path / "data.txt"
        enc_file_1 = self.base_path / "data1.enc"
        enc_file_2 = self.base_path / "data2.enc"

        src_file.write_bytes(b"Repeatable plaintext block.")
        encrypt_file(src_file, enc_file_1, self.password)
        encrypt_file(src_file, enc_file_2, self.password)

        bytes_1 = enc_file_1.read_bytes()
        bytes_2 = enc_file_2.read_bytes()

        self.assertNotEqual(bytes_1[:16], bytes_2[:16], "Salts must be unique")
        self.assertNotEqual(bytes_1[16:28], bytes_2[16:28], "IVs must be unique")
        self.assertNotEqual(bytes_1[44:], bytes_2[44:], "Ciphertexts must be unique")


if __name__ == "__main__":
    unittest.main()