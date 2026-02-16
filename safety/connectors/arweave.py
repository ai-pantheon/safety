"""
Arweave connector.
Authority #3 — permanent storage.

Arweave stores data forever with a single upfront payment.
The encrypted share is stored as a transaction's data field.
Once confirmed, it cannot be deleted or modified — ever.

Implementation approach:
  - Upload encrypted share as Arweave transaction data
  - Tag with seal authority metadata for retrieval
  - Verification: the Arweave gateway returns data, but the
    share is encrypted — only valid Cloak proofs can use it
  - Retrieval via Arweave gateway (arweave.net/TX_ID)

Dependencies (not yet installed):
  - arweave-python-client for transaction construction
  - AR tokens for storage payment
"""

from safety.connectors.base import ChainConnector
from safety.shamir import Share


class ArweaveConnector(ChainConnector):
    """
    Arweave permanent storage seal authority.

    STATUS: Interface defined. Blockchain interaction not yet implemented.
    """

    def __init__(self, wallet_path: str = None, gateway: str = "https://arweave.net"):
        self.wallet_path = wallet_path
        self.gateway = gateway
        self._available = False

    def store_share(self, share: Share, encryption_key: bytes) -> dict:
        raise NotImplementedError(
            "Arweave connector not yet implemented. "
            "Requires arweave-python-client and AR tokens."
        )

    def request_share(self, proof_digest: bytes, signature: bytes) -> Share | None:
        raise NotImplementedError("Arweave connector not yet implemented.")

    def is_available(self) -> bool:
        return self._available

    def get_info(self) -> dict:
        return {
            "chain": "arweave",
            "gateway": self.gateway,
            "status": "not_implemented",
            "note": "Permanent storage — pay once, stored forever",
        }
