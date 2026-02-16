"""
Filecoin connector.
Authority #6 — decentralized storage with architectural diversity.

Filecoin stores data across a network of independent storage providers.
The encrypted share is stored as a Filecoin deal, replicated across
multiple miners for redundancy.

Implementation approach:
  - Store encrypted share via Filecoin deal (web3.storage or Lighthouse)
  - Retrieve via CID on IPFS/Filecoin gateway
  - The share is encrypted — public retrieval doesn't compromise security
  - Proof verification happens client-side (the authority is the storage network)

Dependencies (not yet installed):
  - web3.storage or lighthouse SDK for deal creation
  - FIL tokens for storage deals (or free tier via web3.storage)
"""

from safety.connectors.base import ChainConnector
from safety.shamir import Share


class FilecoinConnector(ChainConnector):
    """
    Filecoin decentralized storage seal authority.

    STATUS: Interface defined. Blockchain interaction not yet implemented.
    """

    def __init__(self, api_token: str = None, gateway: str = "https://w3s.link"):
        self.api_token = api_token
        self.gateway = gateway
        self._available = False

    def store_share(self, share: Share, encryption_key: bytes) -> dict:
        raise NotImplementedError(
            "Filecoin connector not yet implemented. "
            "Requires web3.storage SDK or Lighthouse."
        )

    def request_share(self, proof_digest: bytes, signature: bytes) -> Share | None:
        raise NotImplementedError("Filecoin connector not yet implemented.")

    def is_available(self) -> bool:
        return self._available

    def get_info(self) -> dict:
        return {
            "chain": "filecoin",
            "gateway": self.gateway,
            "status": "not_implemented",
            "note": "Decentralized storage — architectural diversity from EVM chains",
        }
