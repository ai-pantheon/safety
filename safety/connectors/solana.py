"""
Solana connector.
Authority #4 — the daily workhorse.

Solana's speed (~400ms finality) and low cost make it ideal for
high-frequency seal requests. The encrypted share is stored in a
Solana program account.

Implementation approach:
  - Deploy a Solana program (Anchor/native) that mirrors SealAuthority.sol
  - Store encrypted share in a program-derived account
  - Verification: Ed25519 signature check on Cloak proof
  - Retrieval via Solana RPC (getAccountInfo)

Dependencies (not yet installed):
  - solders or solana-py for transaction construction
  - Anchor for program deployment (Rust side)
  - SOL tokens for rent + transactions
"""

from safety.connectors.base import ChainConnector
from safety.shamir import Share


class SolanaConnector(ChainConnector):
    """
    Solana program-based seal authority.

    STATUS: Interface defined. Blockchain interaction not yet implemented.
    """

    def __init__(self, rpc_url: str = "https://api.devnet.solana.com", keypair_path: str = None):
        self.rpc_url = rpc_url
        self.keypair_path = keypair_path
        self._available = False

    def store_share(self, share: Share, encryption_key: bytes) -> dict:
        raise NotImplementedError(
            "Solana connector not yet implemented. "
            "Requires solana-py and an Anchor program."
        )

    def request_share(self, proof_digest: bytes, signature: bytes) -> Share | None:
        raise NotImplementedError("Solana connector not yet implemented.")

    def is_available(self) -> bool:
        return self._available

    def get_info(self) -> dict:
        return {
            "chain": "solana",
            "rpc_url": self.rpc_url,
            "status": "not_implemented",
            "note": "Fast + cheap — daily workhorse for seal requests",
        }
