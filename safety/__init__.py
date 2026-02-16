"""
Safety — The Cloak
Client-side encryption and request anonymization for private data stores.

Safety provides two cryptographically bound layers:
1. Vault — AES-256-GCM envelope encryption (the lock)
2. Cloak — Request anonymization: padding, stripping, shuffling, tokens (the cloak)

These layers are cryptographically bound: the Vault's encryption key requires
a seal that only the Cloak can derive. You MUST use the Cloak to access the Vault.
Attempting to use the Vault directly will fail — not by policy, but by math.

Usage:
    from safety import Cloak
    cloak = Cloak("my-passphrase")
    cloak.store({"category": {"key": "value"}})
"""

from safety.cloak import Cloak
from safety.padding import pad_to_bucket, unpad_from_bucket, BUCKET_SIZES
from safety.shuffle import ShuffleBuffer
from safety.tokens import PrivacyTokenIssuer
from safety.shamir import split as shamir_split, combine as shamir_combine, Share
from safety.seal import SealAuthority, CloakProof, ChainType

__version__ = "0.3.0"
__all__ = [
    "Cloak",
    "ShuffleBuffer",
    "PrivacyTokenIssuer",
    "pad_to_bucket",
    "unpad_from_bucket",
    "BUCKET_SIZES",
    "shamir_split",
    "shamir_combine",
    "Share",
    "SealAuthority",
    "CloakProof",
    "ChainType",
]
