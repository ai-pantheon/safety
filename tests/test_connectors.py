"""Tests for chain connectors."""

import hashlib
import hmac
import os
import tempfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from safety.shamir import split, combine, Share
from safety.connectors.self_hosted import SelfHostedConnector
from safety.connectors.bitcoin import BitcoinConnector
from safety.connectors.arweave import ArweaveConnector
from safety.connectors.solana import SolanaConnector
from safety.connectors.filecoin import FilecoinConnector


def test_self_hosted_store_and_retrieve():
    """Self-hosted connector: store a share, retrieve with valid HMAC."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth_secret = os.urandom(32)
        enc_key = os.urandom(32)
        connector = SelfHostedConnector(
            storage_dir=tmpdir,
            auth_secret=auth_secret,
            share_index=7,
        )

        # Generate a test share
        secret = os.urandom(32)
        shares = split(secret, 2, 3)
        share = shares[0]

        # Store
        result = connector.store_share(share, enc_key)
        assert result["success"]
        assert result["chain"] == "self-hosted"

        # Set encryption key for retrieval
        connector._encryption_key = enc_key

        # Valid HMAC request
        proof_digest = hashlib.sha256(b"valid-proof").digest()
        signature = hmac.new(auth_secret, proof_digest, hashlib.sha256).digest()

        recovered = connector.request_share(proof_digest, signature)
        assert recovered is not None
        assert recovered.index == share.index
        assert recovered.value == share.value
        print("  [PASS] Self-hosted store + retrieve")


def test_self_hosted_rejects_bad_hmac():
    """Self-hosted connector: reject requests with wrong HMAC."""
    with tempfile.TemporaryDirectory() as tmpdir:
        auth_secret = os.urandom(32)
        enc_key = os.urandom(32)
        connector = SelfHostedConnector(
            storage_dir=tmpdir,
            auth_secret=auth_secret,
            share_index=7,
        )

        secret = os.urandom(32)
        shares = split(secret, 2, 3)
        connector.store_share(shares[0], enc_key)
        connector._encryption_key = enc_key

        # Bad HMAC (wrong secret)
        proof_digest = hashlib.sha256(b"valid-proof").digest()
        bad_sig = hmac.new(os.urandom(32), proof_digest, hashlib.sha256).digest()

        result = connector.request_share(proof_digest, bad_sig)
        assert result is None
        print("  [PASS] Self-hosted rejects bad HMAC")


def test_self_hosted_availability():
    """Self-hosted connector: available when share file exists."""
    with tempfile.TemporaryDirectory() as tmpdir:
        connector = SelfHostedConnector(storage_dir=tmpdir, share_index=7)

        assert not connector.is_available()

        secret = os.urandom(32)
        shares = split(secret, 2, 3)
        connector.store_share(shares[0], os.urandom(32))

        assert connector.is_available()
        print("  [PASS] Self-hosted availability check")


def test_self_hosted_info():
    """Self-hosted connector: get_info returns correct metadata."""
    with tempfile.TemporaryDirectory() as tmpdir:
        connector = SelfHostedConnector(storage_dir=tmpdir, share_index=7)
        info = connector.get_info()

        assert info["chain"] == "self-hosted"
        assert info["share_index"] == 7
        assert not info["has_share"]
        print("  [PASS] Self-hosted get_info")


def test_self_hosted_full_shamir_roundtrip():
    """Full roundtrip: split secret, store in self-hosted, retrieve, reconstruct."""
    with tempfile.TemporaryDirectory() as tmpdir:
        secret = os.urandom(32)
        auth_secret = os.urandom(32)
        enc_key = os.urandom(32)

        # Split into 4-of-7
        shares = split(secret, 4, 7)

        # Store share #7 in self-hosted
        connector = SelfHostedConnector(
            storage_dir=tmpdir,
            auth_secret=auth_secret,
            share_index=7,
        )
        connector.store_share(shares[6], enc_key)  # shares[6] has index 7
        connector._encryption_key = enc_key

        # Retrieve
        proof_digest = hashlib.sha256(b"test-proof").digest()
        signature = hmac.new(auth_secret, proof_digest, hashlib.sha256).digest()
        recovered_share = connector.request_share(proof_digest, signature)

        # Combine with 3 other shares (we need 4 total)
        all_shares = [shares[0], shares[1], shares[2], recovered_share]
        reconstructed = combine(all_shares)

        assert reconstructed == secret
        print("  [PASS] Full Shamir roundtrip through self-hosted")


def test_stub_connectors_not_implemented():
    """Stub connectors raise NotImplementedError."""
    stubs = [
        BitcoinConnector(),
        ArweaveConnector(),
        SolanaConnector(),
        FilecoinConnector(),
    ]

    for conn in stubs:
        try:
            conn.store_share(None, None)
            assert False, f"{conn.__class__.__name__} should raise"
        except NotImplementedError:
            pass

        try:
            conn.request_share(None, None)
            assert False, f"{conn.__class__.__name__} should raise"
        except NotImplementedError:
            pass

        assert not conn.is_available()
        info = conn.get_info()
        assert info["status"] == "not_implemented"

    print("  [PASS] Stub connectors raise NotImplementedError correctly")


if __name__ == "__main__":
    print("Testing chain connectors...\n")
    test_self_hosted_store_and_retrieve()
    test_self_hosted_rejects_bad_hmac()
    test_self_hosted_availability()
    test_self_hosted_info()
    test_self_hosted_full_shamir_roundtrip()
    test_stub_connectors_not_implemented()
    print(f"\n{'='*50}")
    print("All 6 connector tests passed!")
