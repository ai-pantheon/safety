"""
Self-hosted chain connector.
Authority #7 — the insurance policy. Runs on infrastructure we control.

This is the simplest connector: an HTTP API backed by encrypted file storage.
No blockchain needed. Direct control. Always available as long as the server runs.
"""

import hashlib
import hmac
import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from safety.connectors.base import ChainConnector
from safety.shamir import Share


class SelfHostedConnector(ChainConnector):
    """
    Self-hosted seal authority.
    Stores the encrypted share locally or on a controlled server.
    Verifies HMAC-signed proof requests before releasing.
    """

    def __init__(
        self,
        storage_dir: str | Path,
        auth_secret: bytes = None,
        share_index: int = 7,
    ):
        """
        Args:
            storage_dir: Directory to store the encrypted share.
            auth_secret: Shared secret for HMAC verification of requests.
            share_index: This authority's Shamir share index.
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.auth_secret = auth_secret or os.urandom(32)
        self.share_index = share_index
        self._encryption_key = None

    @property
    def _share_file(self) -> Path:
        return self.storage_dir / f"share-{self.share_index}.enc"

    @property
    def _meta_file(self) -> Path:
        return self.storage_dir / f"share-{self.share_index}.meta.json"

    def store_share(self, share: Share, encryption_key: bytes) -> dict:
        """Encrypt and store the share to local filesystem."""
        self._encryption_key = encryption_key

        # Encrypt with AES-256-GCM
        nonce = os.urandom(12)
        aesgcm = AESGCM(encryption_key)
        plaintext = share.to_hex().encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Write encrypted share
        self._share_file.write_bytes(nonce + ciphertext)

        # Write metadata
        meta = {
            "share_index": share.index,
            "chain": "self-hosted",
            "stored_at": int(time.time()),
            "encrypted": True,
        }
        self._meta_file.write_text(json.dumps(meta, indent=2))

        return {
            "chain": "self-hosted",
            "location": str(self._share_file),
            "share_index": share.index,
            "success": True,
        }

    def request_share(self, proof_digest: bytes, signature: bytes) -> Share | None:
        """
        Verify HMAC signature and return the decrypted share.

        Args:
            proof_digest: SHA-256 hash of the CloakProof fields.
            signature: HMAC-SHA256 of proof_digest using the auth_secret.

        Returns:
            Decrypted Share if valid, None otherwise.
        """
        # Verify HMAC
        expected = hmac.new(self.auth_secret, proof_digest, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return None

        # Read and decrypt
        if not self._share_file.exists():
            return None

        if not self._encryption_key:
            return None

        encrypted = self._share_file.read_bytes()
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]

        aesgcm = AESGCM(self._encryption_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return Share.from_hex(plaintext.decode())

    def is_available(self) -> bool:
        """Self-hosted is available if the share file exists."""
        return self._share_file.exists()

    def get_info(self) -> dict:
        """Get self-hosted authority info."""
        info = {
            "chain": "self-hosted",
            "share_index": self.share_index,
            "storage_dir": str(self.storage_dir),
            "has_share": self._share_file.exists(),
        }

        if self._meta_file.exists():
            meta = json.loads(self._meta_file.read_text())
            info["stored_at"] = meta.get("stored_at")

        return info
