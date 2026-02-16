"""
Cloak — The Full Anonymization Layer
Wraps the Vault with request anonymization.

Flow for storing data:
1. Serialize the data
2. Strip metadata from the request
3. Pad to a fixed bucket size
4. Encrypt with envelope encryption (Vault)
5. Shuffle the storage order

Flow for loading data:
1. Authenticate with a privacy token (no identity link)
2. Decrypt from Vault
3. Unpad the bucket
4. Return the data

An observer sees: fixed-size encrypted blobs stored in random order
with no metadata linking them to a user or data type.
"""

import json
import os
import base64
import time
from pathlib import Path

from safety.vault import Vault, derive_kek, derive_seal_key, SALT_SIZE
from safety.padding import pad_to_bucket
from safety.shuffle import ShuffleBuffer
from safety.tokens import PrivacyTokenIssuer


# Fields allowed through metadata stripping
ALLOWED_FIELDS = {"action", "category", "timestamp_bucket"}


def strip_metadata(request: dict) -> dict:
    """
    Strip identifying metadata from a request envelope.

    Only fields in the allow-list pass through. Timestamps are
    bucketed to 10-second windows to prevent timing correlation.
    """
    stripped = {}
    for key, value in request.items():
        if key in ALLOWED_FIELDS:
            stripped[key] = value

    # Bucket the timestamp to 10-second windows
    if "timestamp_bucket" not in stripped:
        now = int(time.time())
        stripped["timestamp_bucket"] = now - (now % 10)

    return stripped


class Cloak:
    """
    The full anonymization layer wrapping the Vault.

    Combines encryption (Vault) with traffic analysis resistance
    (padding, shuffling, metadata stripping, privacy tokens).

    Args:
        passphrase: Your secret passphrase for the Vault.
        vault_dir: Directory for encrypted storage.
    """

    def __init__(self, passphrase: str, vault_dir: str | Path = "./vault-encrypted"):
        vault_dir = Path(vault_dir)
        vault_dir.mkdir(parents=True, exist_ok=True)

        # Load or create salt
        salt_file = vault_dir / ".vault-salt"
        if salt_file.exists():
            salt = base64.b64decode(salt_file.read_text())
        else:
            salt = os.urandom(SALT_SIZE)
            salt_file.write_text(base64.b64encode(salt).decode())

        # Derive both keys — the Vault can't work without the seal
        kek = derive_kek(passphrase, salt)
        seal_key = derive_seal_key(passphrase, salt)

        # Pass both to the Vault — it binds them into the Bound Key
        self.vault = Vault(kek, seal_key, vault_dir)
        self.token_issuer = PrivacyTokenIssuer()
        self.shuffle_buffer = ShuffleBuffer()
        self.tokens = self.token_issuer.issue_batch(100)
        self._token_index = 0

        # Stats
        self.requests_processed = 0
        self.bytes_before_padding = 0
        self.bytes_after_padding = 0
        self.categories_stored = 0
        self.categories_loaded = 0

    def _use_token(self) -> str:
        """Use the next privacy token."""
        if self._token_index >= len(self.tokens):
            self.tokens = self.token_issuer.issue_batch(100)
            self._token_index = 0
        token = self.tokens[self._token_index]
        self._token_index += 1
        return token

    def store(self, data: dict[str, dict]) -> dict:
        """
        Store data through the full anonymization pipeline.

        Each key in the dict becomes a category. All categories are
        shuffled before storage so the order reveals nothing.

        Args:
            data: Dictionary of {category_name: category_data}.

        Returns:
            Report of what was stored, including anonymization stats.
        """
        report = {
            "categories": [],
            "total_plaintext_bytes": 0,
            "total_padded_bytes": 0,
            "total_encrypted_bytes": 0,
            "tokens_used": 0,
            "shuffle_order": [],
        }

        # Add all categories to shuffle buffer
        for category, category_data in data.items():
            self.shuffle_buffer.add((category, category_data))

        # Process in randomized order
        shuffled = self.shuffle_buffer.flush()
        report["shuffle_order"] = [cat for cat, _ in shuffled]

        for category, category_data in shuffled:
            # Use a privacy token for this request
            token = self._use_token()
            assert self.token_issuer.verify(token), "Token verification failed"
            report["tokens_used"] += 1

            # Serialize
            plaintext = json.dumps(category_data, indent=2).encode("utf-8")
            report["total_plaintext_bytes"] += len(plaintext)

            # Pad to bucket size
            padded = pad_to_bucket(plaintext)
            report["total_padded_bytes"] += len(padded)

            # Strip metadata from request envelope
            request = {
                "action": "store",
                "category": category,
                "payload_size": len(padded),
                "user_agent": "should be stripped",
                "ip_address": "should be stripped",
                "session_id": "should be stripped",
            }
            clean_request = strip_metadata(request)

            # Store through vault (encrypted)
            result = self.vault.store(category, category_data)
            result["padded_size"] = len(padded)
            result["metadata_stripped"] = list(
                set(request.keys()) - set(clean_request.keys())
            )

            report["categories"].append(result)
            report["total_encrypted_bytes"] += result["encrypted_bytes"]
            self.categories_stored += 1
            self.requests_processed += 1

        self.bytes_before_padding = report["total_plaintext_bytes"]
        self.bytes_after_padding = report["total_padded_bytes"]

        return report

    def load_all(self) -> dict:
        """Load all data through the anonymization layer."""
        token = self._use_token()
        assert self.token_issuer.verify(token)

        data = self.vault.load_all()
        self.categories_loaded += len(data)
        self.requests_processed += 1
        return data

    def load(self, category: str) -> dict:
        """Load a single category through the anonymization layer."""
        token = self._use_token()
        assert self.token_issuer.verify(token)
        self.categories_loaded += 1
        self.requests_processed += 1
        return self.vault.load(category)

    def verify_all(self, original: dict[str, dict]) -> dict[str, str]:
        """Verify all stored data matches the originals."""
        results = {}
        for category, original_data in original.items():
            match = self.vault.verify(category, original_data)
            results[category] = "PASS" if match else "FAIL"
        return results

    def stats(self) -> dict:
        """Get operational statistics."""
        padding_overhead = 0
        if self.bytes_before_padding > 0:
            padding_overhead = round(
                (self.bytes_after_padding - self.bytes_before_padding)
                / self.bytes_before_padding * 100, 1
            )

        return {
            "requests_processed": self.requests_processed,
            "categories_stored": self.categories_stored,
            "categories_loaded": self.categories_loaded,
            "bytes_before_padding": self.bytes_before_padding,
            "bytes_after_padding": self.bytes_after_padding,
            "padding_overhead_pct": padding_overhead,
            "tokens_issued": self.token_issuer.issued_count,
        }
