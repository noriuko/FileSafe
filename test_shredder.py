import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from shredder import (
    shred_file,
    is_file_locked,
    FileLockedError,
    SSD_WEAR_LEVELING_WARNING,
    CHUNK_SIZE,
)


class TestShredder(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_shred_removes_file_and_returns_ssd_warning(self):
        """Verifies a multi-chunk file is overwritten, renamed, and unlinked."""
        secret_file = self.base_path / "financials.xlsx"
        original_size = CHUNK_SIZE * 2 + 500
        secret_file.write_bytes(b"A" * original_size)

        msg = shred_file(secret_file, is_ssd=True)

        self.assertFalse(secret_file.exists())
        self.assertEqual(len(list(self.base_path.iterdir())), 0)
        self.assertEqual(msg, SSD_WEAR_LEVELING_WARNING)

    def test_overwrite_occurs_before_unlink(self):
        """Verifies exact file length is overwritten with random bytes before unlinking."""
        secret_file = self.base_path / "notes.txt"
        original_payload = b"SensitivePlaintextData" * 100
        secret_file.write_bytes(original_payload)

        overwritten_Snapshot = None
        original_unlink = Path.unlink

        def capture_before_unlink(path_self, *args, **kwargs):
            nonlocal overwritten_Snapshot
            overwritten_Snapshot = path_self.read_bytes()
            return original_unlink(path_self, *args, **kwargs)

        with patch.object(Path, "unlink", capture_before_unlink):
            shred_file(secret_file, is_ssd=False)

        self.assertIsNotNone(overwritten_Snapshot)
        self.assertEqual(len(overwritten_Snapshot), len(original_payload))
        self.assertNotEqual(overwritten_Snapshot, original_payload)

    def test_locked_file_raises_error_without_modifying(self):
        """Verifies that a locked/read-only file raises FileLockedError before destruction."""
        locked_file = self.base_path / "locked_doc.pdf"
        payload = b"Important data that is currently locked."
        locked_file.write_bytes(payload)

        # Make the file read-only to simulate an OS-level lock across platforms
        os.chmod(locked_file, 0o444)
        try:
            self.assertTrue(is_file_locked(locked_file))
            with self.assertRaises(FileLockedError):
                shred_file(locked_file)
            # Confirm original contents are untouched
            self.assertEqual(locked_file.read_bytes(), payload)
        finally:
            os.chmod(locked_file, 0o666)


if __name__ == "__main__":
    unittest.main()