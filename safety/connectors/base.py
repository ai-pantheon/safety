"""
Base class for all chain connectors.
Every blockchain authority implements this interface.
"""

from abc import ABC, abstractmethod
from safety.shamir import Share


class ChainConnector(ABC):
    """Abstract base class for blockchain seal authority connectors."""

    @abstractmethod
    def store_share(self, share: Share, encryption_key: bytes) -> dict:
        """
        Store an encrypted Shamir share on this chain.

        Args:
            share: The Shamir share to store.
            encryption_key: AES key to encrypt the share before storage.

        Returns:
            Deployment receipt (tx hash, address, etc.)
        """

    @abstractmethod
    def request_share(self, proof_digest: bytes, signature: bytes) -> Share | None:
        """
        Request this authority's share after presenting a valid Cloak proof.

        Args:
            proof_digest: SHA-256 hash of the CloakProof fields.
            signature: ECDSA signature of the proof digest.

        Returns:
            The decrypted Share, or None if verification fails.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this authority is reachable."""

    @abstractmethod
    def get_info(self) -> dict:
        """Get metadata about this authority (chain, address, status)."""
