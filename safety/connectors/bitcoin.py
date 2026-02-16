"""
Bitcoin Taproot connector.
Authority #2 — the indestructible one.

Stores the encrypted Shamir share in a Taproot script path.
The Bitcoin network is the most resilient blockchain — if this goes down,
civilization has bigger problems.

Implementation approach:
  - Embed encrypted share in a Taproot script-path spend
  - Use OP_RETURN or witness data for the ciphertext
  - Verification via Bitcoin script (signature check)
  - Retrieval via spending the UTXO with valid Cloak proof signature

Dependencies (not yet installed):
  - python-bitcoinlib or bitcoinutils for transaction construction
  - A Bitcoin Signet/Testnet node or API (Blockstream, Mempool.space)
"""

from safety.connectors.base import ChainConnector
from safety.shamir import Share


class BitcoinConnector(ChainConnector):
    """
    Bitcoin Taproot seal authority.

    STATUS: Interface defined. Blockchain interaction not yet implemented.
    Uses local file fallback for now.
    """

    def __init__(self, network: str = "signet", rpc_url: str = None):
        self.network = network
        self.rpc_url = rpc_url
        self._available = False

    def store_share(self, share: Share, encryption_key: bytes) -> dict:
        raise NotImplementedError(
            "Bitcoin Taproot connector not yet implemented. "
            "Requires python-bitcoinlib and a Signet/Testnet node."
        )

    def request_share(self, proof_digest: bytes, signature: bytes) -> Share | None:
        raise NotImplementedError("Bitcoin Taproot connector not yet implemented.")

    def is_available(self) -> bool:
        return self._available

    def get_info(self) -> dict:
        return {
            "chain": "bitcoin",
            "network": self.network,
            "status": "not_implemented",
            "note": "Taproot script-path storage planned",
        }
