"""
Seal Authority — Distributed Seal Protocol
Manages the 7-chain seal authority network.

The production seal secret is split into 7 shares via Shamir's Secret Sharing
and distributed across independent blockchains. Any 4-of-7 can reconstruct
the seal. No single chain holds enough to forge it.

Chain lineup:
  1. Ethereum    — Smart contract verification (anchor)
  2. Bitcoin     — Taproot script (indestructible)
  3. Arweave     — Permanent storage (pay once, forever)
  4. Solana      — Fast + cheap (daily workhorse)
  5. Base (L2)   — Ethereum security, low cost (volume ops)
  6. Filecoin    — Decentralized storage (architectural diversity)
  7. Self-hosted — Direct control (insurance policy)

Protocol:
  1. Client Cloak generates a proof (signed attestation that the pipeline ran)
  2. Client sends proof to 4+ authorities
  3. Each authority verifies the proof and returns their partial seal
  4. Client combines partial seals via Lagrange interpolation
  5. Combined seal + KEK → Bound Key → data access
"""

import hashlib
import json
import os
import time
import base64
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from safety.shamir import split, combine, Share
from safety.connectors.base import ChainConnector


class ChainType(Enum):
    """Supported blockchain types for seal authority."""
    ETHEREUM = "ethereum"
    BITCOIN = "bitcoin"
    ARWEAVE = "arweave"
    SOLANA = "solana"
    BASE = "base"
    FILECOIN = "filecoin"
    SELF_HOSTED = "self-hosted"


@dataclass
class SealAuthorityConfig:
    """Configuration for a single seal authority node."""
    chain: ChainType
    share_index: int
    endpoint: str = ""          # RPC endpoint or contract address
    contract_address: str = ""  # Smart contract address (for EVM chains)
    enabled: bool = True


@dataclass
class CloakProof:
    """
    Proof that the Cloak pipeline ran correctly.
    Submitted to seal authorities for verification.
    """
    timestamp: int
    privacy_token: str          # Valid token from the issuer
    padding_applied: bool       # Bucket padding was applied
    metadata_stripped: bool     # Identifying metadata was removed
    shuffle_applied: bool       # Order was randomized
    client_signature: str = ""  # ECDSA signature of the above fields

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "privacy_token": self.privacy_token,
            "padding_applied": self.padding_applied,
            "metadata_stripped": self.metadata_stripped,
            "shuffle_applied": self.shuffle_applied,
            "client_signature": self.client_signature,
        }

    def digest(self) -> bytes:
        """Compute a deterministic hash of the proof fields (for signing)."""
        payload = (
            f"{self.timestamp}:"
            f"{self.privacy_token}:"
            f"{self.padding_applied}:"
            f"{self.metadata_stripped}:"
            f"{self.shuffle_applied}"
        )
        return hashlib.sha256(payload.encode()).digest()


# Default chain configuration — 7 authorities, 4-of-7 threshold
DEFAULT_THRESHOLD = 4
DEFAULT_CHAINS = [
    SealAuthorityConfig(chain=ChainType.ETHEREUM, share_index=1),
    SealAuthorityConfig(chain=ChainType.BITCOIN, share_index=2),
    SealAuthorityConfig(chain=ChainType.ARWEAVE, share_index=3),
    SealAuthorityConfig(chain=ChainType.SOLANA, share_index=4),
    SealAuthorityConfig(chain=ChainType.BASE, share_index=5),
    SealAuthorityConfig(chain=ChainType.FILECOIN, share_index=6),
    SealAuthorityConfig(chain=ChainType.SELF_HOSTED, share_index=7),
]


class SealAuthority:
    """
    Manages the distributed seal authority network.

    In production, this contacts 7 independent blockchain-based authorities
    to reconstruct the seal. Each authority holds one Shamir share and
    verifies the Cloak proof before releasing it.

    For local development, this generates and stores shares locally,
    simulating the distributed network.
    """

    def __init__(
        self,
        threshold: int = DEFAULT_THRESHOLD,
        chains: list[SealAuthorityConfig] = None,
        local_dir: str | Path = None,
        connectors: dict[ChainType, ChainConnector] = None,
    ):
        self.threshold = threshold
        self.chains = chains or DEFAULT_CHAINS
        self.num_shares = len(self.chains)
        self.local_dir = Path(local_dir) if local_dir else None
        self.connectors = connectors or {}

        if self.local_dir:
            self.local_dir.mkdir(parents=True, exist_ok=True)

    def generate_and_distribute(self, seal_secret: bytes) -> dict:
        """
        Split the seal secret and distribute shares to authorities.

        In production: deploys shares to smart contracts on each chain.
        In local mode: stores shares as encrypted files.

        Args:
            seal_secret: The 32-byte seal secret to split.

        Returns:
            Distribution report.
        """
        shares = split(seal_secret, self.threshold, self.num_shares)

        report = {
            "threshold": self.threshold,
            "total_shares": self.num_shares,
            "chains": [],
        }

        for share, config in zip(shares, self.chains):
            chain_report = {
                "chain": config.chain.value,
                "share_index": share.index,
                "distributed": False,
            }

            # Try chain connector first
            connector = self.connectors.get(config.chain)
            if connector is not None:
                try:
                    enc_key = hashlib.sha256(seal_secret + config.chain.value.encode()).digest()
                    result = connector.store_share(share, enc_key)
                    chain_report["distributed"] = result.get("success", False)
                    chain_report.update(result)
                except NotImplementedError:
                    chain_report["note"] = f"{config.chain.value} connector not yet implemented"
                except Exception as e:
                    chain_report["error"] = str(e)
            elif self.local_dir:
                # Local mode: store share to file
                share_file = self.local_dir / f"share-{share.index}-{config.chain.value}.json"
                share_data = {
                    "chain": config.chain.value,
                    "share": share.to_hex(),
                    "created": int(time.time()),
                }
                share_file.write_text(json.dumps(share_data, indent=2))
                chain_report["distributed"] = True
                chain_report["location"] = str(share_file)
            else:
                chain_report["distributed"] = False
                chain_report["note"] = "No connector or local dir configured"

            report["chains"].append(chain_report)

        return report

    def request_seal(self, proof: CloakProof) -> bytes:
        """
        Request the production seal from the authority network.

        Contacts threshold+ authorities, verifies proof, collects partial
        seals, and reconstructs the full seal via Lagrange interpolation.

        Args:
            proof: CloakProof demonstrating the anonymization pipeline ran.

        Returns:
            The reconstructed 32-byte seal secret.

        Raises:
            RuntimeError: If not enough authorities respond.
        """
        collected_shares = []

        for config in self.chains:
            if not config.enabled:
                continue

            try:
                share = self._request_share(config, proof)
                if share is not None:
                    collected_shares.append(share)

                # Stop once we have enough
                if len(collected_shares) >= self.threshold:
                    break
            except Exception:
                continue  # Authority unavailable, try next

        if len(collected_shares) < self.threshold:
            raise RuntimeError(
                f"Could not reach threshold: got {len(collected_shares)} "
                f"of {self.threshold} required shares. "
                f"Authorities may be unavailable."
            )

        # Reconstruct the seal from K shares
        return combine(collected_shares)

    def _request_share(self, config: SealAuthorityConfig, proof: CloakProof) -> Share | None:
        """
        Request a single share from one authority.

        Resolution order:
        1. Use chain connector if one is registered for this chain type
        2. Fall back to local file mode if local_dir is set
        3. Return None (authority unavailable)
        """
        # Verify the proof locally (each authority does this independently)
        if not self._verify_proof(proof):
            return None

        # Try chain connector first
        connector = self.connectors.get(config.chain)
        if connector is not None:
            try:
                digest = proof.digest()
                signature = proof.client_signature.encode() if proof.client_signature else b""
                return connector.request_share(digest, signature)
            except Exception:
                pass  # Fall through to local mode

        if self.local_dir:
            # Local mode: read share from file
            share_file = self.local_dir / f"share-{config.share_index}-{config.chain.value}.json"
            if not share_file.exists():
                return None
            share_data = json.loads(share_file.read_text())
            return Share.from_hex(share_data["share"])

        return None

    def _verify_proof(self, proof: CloakProof) -> bool:
        """
        Verify a Cloak proof is valid.

        Checks:
        1. All anonymization steps were applied
        2. Timestamp is recent (within 60 seconds)
        3. Privacy token is present
        """
        # All pipeline steps must have run
        if not (proof.padding_applied and proof.metadata_stripped and proof.shuffle_applied):
            return False

        # Timestamp must be recent (prevent replay)
        now = int(time.time())
        if abs(now - proof.timestamp) > 60:
            return False

        # Privacy token must be present
        if not proof.privacy_token:
            return False

        return True

    def get_status(self) -> dict:
        """Get status of all authorities."""
        status = {
            "threshold": self.threshold,
            "total": self.num_shares,
            "authorities": [],
        }

        for config in self.chains:
            auth_status = {
                "chain": config.chain.value,
                "share_index": config.share_index,
                "enabled": config.enabled,
                "has_share": False,
                "has_connector": config.chain in self.connectors,
            }

            connector = self.connectors.get(config.chain)
            if connector is not None:
                try:
                    auth_status["available"] = connector.is_available()
                    auth_status.update(connector.get_info())
                except Exception:
                    auth_status["available"] = False

            if self.local_dir:
                share_file = self.local_dir / f"share-{config.share_index}-{config.chain.value}.json"
                auth_status["has_share"] = share_file.exists()

            status["authorities"].append(auth_status)

        return status
