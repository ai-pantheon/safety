"""
Tests for Shamir's Secret Sharing and the Seal Authority Network.
"""

import os
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from safety.shamir import split, combine, verify_shares, Share
from safety.seal import SealAuthority, CloakProof, DEFAULT_THRESHOLD


TEST_DIR = Path(__file__).parent / "test-seal-authority"


def setup():
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)


def test_split_and_combine_basic():
    """Test basic split and reconstruct."""
    print("Testing Shamir split/combine (basic)...", end=" ")
    secret = os.urandom(32)
    shares = split(secret, threshold=3, num_shares=5)

    assert len(shares) == 5
    for s in shares:
        assert s.threshold == 3
        assert s.total == 5

    # Reconstruct with exactly threshold shares
    reconstructed = combine(shares[:3])
    assert reconstructed == secret
    print("PASS")


def test_combine_any_k_shares():
    """Test that ANY K shares can reconstruct."""
    print("Testing any K shares reconstruct...", end=" ")
    secret = os.urandom(32)
    shares = split(secret, threshold=4, num_shares=7)

    # Try different combinations of 4 shares
    import itertools
    combinations_tested = 0
    for combo in itertools.combinations(shares, 4):
        reconstructed = combine(list(combo))
        assert reconstructed == secret, f"Failed with shares {[s.index for s in combo]}"
        combinations_tested += 1

    # 7 choose 4 = 35 combinations
    assert combinations_tested == 35
    print(f"PASS ({combinations_tested} combinations)")


def test_insufficient_shares_fail():
    """Test that fewer than K shares can't reconstruct."""
    print("Testing insufficient shares fail...", end=" ")
    secret = os.urandom(32)
    shares = split(secret, threshold=4, num_shares=7)

    # Try with only 3 shares (need 4)
    try:
        combine(shares[:3])
        print("FAIL (should have raised ValueError)")
        return
    except ValueError:
        pass
    print("PASS")


def test_wrong_shares_wrong_secret():
    """Test that wrong combination produces wrong result."""
    print("Testing wrong shares = wrong secret...", end=" ")
    secret1 = os.urandom(32)
    secret2 = os.urandom(32)

    shares1 = split(secret1, threshold=3, num_shares=5)
    shares2 = split(secret2, threshold=3, num_shares=5)

    # Mix shares from different secrets
    mixed = [shares1[0], shares2[1], shares1[2]]
    reconstructed = combine(mixed)
    assert reconstructed != secret1
    assert reconstructed != secret2
    print("PASS")


def test_share_serialization():
    """Test share hex serialization round-trip."""
    print("Testing share serialization...", end=" ")
    secret = os.urandom(32)
    shares = split(secret, threshold=4, num_shares=7)

    for share in shares:
        hex_str = share.to_hex()
        restored = Share.from_hex(hex_str)
        assert restored.index == share.index
        assert restored.value == share.value
        assert restored.threshold == share.threshold
        assert restored.total == share.total

    # Reconstruct from serialized shares
    serialized = [s.to_hex() for s in shares[:4]]
    restored_shares = [Share.from_hex(h) for h in serialized]
    reconstructed = combine(restored_shares)
    assert reconstructed == secret
    print("PASS")


def test_verify_shares():
    """Test share verification helper."""
    print("Testing verify_shares...", end=" ")
    secret = os.urandom(32)
    shares = split(secret, threshold=3, num_shares=5)

    assert verify_shares(shares[:3], secret)
    assert verify_shares(shares, secret)

    # Wrong secret should fail verification
    wrong_secret = os.urandom(32)
    assert not verify_shares(shares[:3], wrong_secret)
    print("PASS")


def test_4_of_7_scheme():
    """Test the exact scheme we use: 4-of-7."""
    print("Testing 4-of-7 scheme (production config)...", end=" ")
    seal_secret = os.urandom(32)
    shares = split(seal_secret, threshold=4, num_shares=7)

    assert len(shares) == 7

    # Any 4 can reconstruct
    import itertools
    for combo in itertools.combinations(shares, 4):
        assert combine(list(combo)) == seal_secret

    # No 3 can reconstruct (probabilistically — they produce wrong results)
    for combo in itertools.combinations(shares, 3):
        try:
            result = combine(list(combo))
            # Should not equal the real secret (with overwhelming probability)
            assert result != seal_secret
        except ValueError:
            pass  # Also acceptable — not enough shares

    print("PASS")


def test_seal_authority_local():
    """Test the seal authority in local mode."""
    print("Testing seal authority (local mode)...", end=" ")
    setup()

    seal_secret = os.urandom(32)
    authority = SealAuthority(
        threshold=DEFAULT_THRESHOLD,
        local_dir=TEST_DIR,
    )

    # Distribute shares
    report = authority.generate_and_distribute(seal_secret)
    assert report["threshold"] == 4
    assert report["total_shares"] == 7
    assert all(c["distributed"] for c in report["chains"])

    # Check status
    status = authority.get_status()
    assert all(a["has_share"] for a in status["authorities"])

    # Request seal with valid proof
    proof = CloakProof(
        timestamp=int(time.time()),
        privacy_token="valid-token-abc123",
        padding_applied=True,
        metadata_stripped=True,
        shuffle_applied=True,
    )

    reconstructed = authority.request_seal(proof)
    assert reconstructed == seal_secret
    print("PASS")


def test_seal_authority_rejects_bad_proof():
    """Test that authority rejects invalid proofs."""
    print("Testing seal authority rejects bad proof...", end=" ")
    setup()

    seal_secret = os.urandom(32)
    authority = SealAuthority(threshold=DEFAULT_THRESHOLD, local_dir=TEST_DIR)
    authority.generate_and_distribute(seal_secret)

    # Missing padding
    bad_proof = CloakProof(
        timestamp=int(time.time()),
        privacy_token="token",
        padding_applied=False,  # Pipeline didn't run!
        metadata_stripped=True,
        shuffle_applied=True,
    )

    try:
        authority.request_seal(bad_proof)
        print("FAIL (should have raised RuntimeError)")
        return
    except RuntimeError:
        pass

    # Stale timestamp
    stale_proof = CloakProof(
        timestamp=int(time.time()) - 300,  # 5 minutes old
        privacy_token="token",
        padding_applied=True,
        metadata_stripped=True,
        shuffle_applied=True,
    )

    try:
        authority.request_seal(stale_proof)
        print("FAIL (should have rejected stale timestamp)")
        return
    except RuntimeError:
        pass

    print("PASS")


def test_seal_authority_survives_failures():
    """Test that seal works even when some authorities are down."""
    print("Testing seal authority (chain failures)...", end=" ")
    setup()

    seal_secret = os.urandom(32)
    authority = SealAuthority(threshold=DEFAULT_THRESHOLD, local_dir=TEST_DIR)
    authority.generate_and_distribute(seal_secret)

    # Disable 3 chains (max tolerable for 4-of-7)
    authority.chains[0].enabled = False  # Ethereum down
    authority.chains[2].enabled = False  # Arweave down
    authority.chains[5].enabled = False  # Filecoin down

    proof = CloakProof(
        timestamp=int(time.time()),
        privacy_token="token",
        padding_applied=True,
        metadata_stripped=True,
        shuffle_applied=True,
    )

    # Should still work with 4 remaining
    reconstructed = authority.request_seal(proof)
    assert reconstructed == seal_secret

    # Disable one more (4 down = only 3 left, below threshold)
    authority.chains[1].enabled = False  # Bitcoin down too

    try:
        authority.request_seal(proof)
        print("FAIL (should have failed with only 3 authorities)")
        return
    except RuntimeError as e:
        assert "threshold" in str(e).lower()

    print("PASS")


def main():
    setup()
    print("=" * 50)
    print("  Shamir + Seal Authority Tests")
    print("  (4-of-7 distributed seal network)")
    print("=" * 50)
    print()

    tests = [
        test_split_and_combine_basic,
        test_combine_any_k_shares,
        test_insufficient_shares_fail,
        test_wrong_shares_wrong_secret,
        test_share_serialization,
        test_verify_shares,
        test_4_of_7_scheme,
        test_seal_authority_local,
        test_seal_authority_rejects_bad_proof,
        test_seal_authority_survives_failures,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"FAIL: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print()
    print(f"Results: {passed} passed, {failed} failed")

    setup()  # Cleanup
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
