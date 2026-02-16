"""
Ethereum / EVM chain connector.
Works for Ethereum mainnet, Sepolia testnet, and Base L2.
"""

import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from safety.connectors.base import ChainConnector
from safety.shamir import Share


class EthereumConnector(ChainConnector):
    """
    Connects to a SealAuthority smart contract on an EVM chain.

    Supports: Ethereum (mainnet/Sepolia), Base L2, or any EVM-compatible chain.
    """

    def __init__(
        self,
        rpc_url: str,
        contract_address: str = None,
        contract_abi: list = None,
        private_key: str = None,
        chain_name: str = "ethereum",
    ):
        self.rpc_url = rpc_url
        self.contract_address = contract_address
        self.chain_name = chain_name
        self._private_key = private_key
        self._abi = contract_abi
        self._w3 = None
        self._contract = None
        self._account = None

    def _connect(self):
        """Lazy connection to the chain."""
        if self._w3 is not None:
            return

        from web3 import Web3
        from web3.middleware import ExtraDataToPoa

        self._w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self._w3.middleware_onion.inject(ExtraDataToPoa, layer=0)

        if self._private_key:
            self._account = self._w3.eth.account.from_key(self._private_key)

        if self.contract_address and self._abi:
            self._contract = self._w3.eth.contract(
                address=Web3.to_checksum_address(self.contract_address),
                abi=self._abi,
            )

    def _encrypt_share(self, share: Share, key: bytes) -> bytes:
        """Encrypt a share with AES-256-GCM before on-chain storage."""
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        plaintext = share.to_hex().encode()
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext

    def _decrypt_share(self, encrypted: bytes, key: bytes) -> Share:
        """Decrypt an on-chain share."""
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return Share.from_hex(plaintext.decode())

    def store_share(self, share: Share, encryption_key: bytes) -> dict:
        """Deploy encrypted share to the SealAuthority contract."""
        self._connect()

        if not self._contract or not self._account:
            raise RuntimeError("Contract and account must be configured to store shares")

        encrypted = self._encrypt_share(share, encryption_key)

        tx = self._contract.functions.setShare(encrypted).build_transaction({
            "from": self._account.address,
            "nonce": self._w3.eth.get_transaction_count(self._account.address),
            "gasPrice": self._w3.eth.gas_price,
            "chainId": self._w3.eth.chain_id,
        })
        gas_estimate = self._w3.eth.estimate_gas(tx)
        tx["gas"] = int(gas_estimate * 1.2)

        signed = self._account.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

        return {
            "chain": self.chain_name,
            "tx_hash": receipt.transactionHash.hex(),
            "block": receipt.blockNumber,
            "gas_used": receipt.gasUsed,
            "success": receipt.status == 1,
        }

    def request_share(self, proof_digest: bytes, signature: bytes) -> Share | None:
        """
        Request share from the on-chain authority.

        In the full protocol, this calls requestSeal() on the contract.
        The contract verifies the signature and returns the encrypted share.
        We decrypt it client-side with the authority encryption key.

        For now, this reads the encrypted share directly (admin read)
        since the full ECDSA signing flow requires the Cloak to have
        a registered signer key on the contract.
        """
        self._connect()

        if not self._contract:
            return None

        try:
            encrypted_share = self._contract.functions.encryptedShare().call()
            if not encrypted_share:
                return None
            # In production, we'd decrypt with the authority's encryption key
            # For now, return the raw encrypted bytes as a placeholder
            return encrypted_share
        except Exception:
            return None

    def is_available(self) -> bool:
        """Check if the chain is reachable and contract is deployed."""
        try:
            self._connect()
            if not self._w3.is_connected():
                return False
            if self.contract_address:
                code = self._w3.eth.get_code(
                    self._w3.to_checksum_address(self.contract_address)
                )
                return len(code) > 0
            return True
        except Exception:
            return False

    def get_info(self) -> dict:
        """Get chain and contract info."""
        self._connect()

        info = {
            "chain": self.chain_name,
            "rpc_url": self.rpc_url,
            "contract_address": self.contract_address,
            "connected": self._w3.is_connected() if self._w3 else False,
        }

        if self._contract:
            try:
                on_chain = self._contract.functions.info().call()
                info.update({
                    "share_index": on_chain[0],
                    "threshold": on_chain[1],
                    "total_shares": on_chain[2],
                    "active": on_chain[3],
                    "has_share": on_chain[4],
                })
            except Exception as e:
                info["error"] = str(e)

        return info

    @classmethod
    def from_deployment(cls, deployment_file: str | Path, private_key: str = None) -> "EthereumConnector":
        """Create a connector from a saved deployment JSON file."""
        data = json.loads(Path(deployment_file).read_text())

        # Load ABI from adjacent file
        abi_file = Path(deployment_file).parent / "SealAuthority.abi.json"
        abi = json.loads(abi_file.read_text()) if abi_file.exists() else None

        return cls(
            rpc_url=data.get("rpc_url", os.environ.get("SEPOLIA_RPC_URL", "")),
            contract_address=data["contract_address"],
            contract_abi=abi,
            private_key=private_key,
            chain_name=data.get("network", "ethereum"),
        )
