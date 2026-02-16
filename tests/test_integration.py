"""
Safety — Integration Tests
Tests the full encrypt/pad/shuffle/verify pipeline.
Tests cryptographic binding (Vault cannot operate without Cloak).
"""

import json
import shutil
import sys
from pathlib import Path

# Add parent to path for local development
sys.path.insert(0, str(Path(__file__).parent.parent))

from safety import Cloak, pad_to_bucket, unpad_from_bucket, BUCKET_SIZES
from safety import ShuffleBuffer, PrivacyTokenIssuer
from safety.vault import Vault, derive_kek, derive_seal_key, SALT_SIZE
import os, base64

TEST_PASSPHRASE = "test-passphrase-do-not-use-in-production"
TEST_CLOAK_DIR = Path(__file__).parent / "test-cloak"
TEST_BINDING_DIR = Path(__file__).parent / "test-binding"


def setup():
    """Clean up test directories."""
    for d in [TEST_CLOAK_DIR, TEST_BINDING_DIR]:
        if d.exists():
            shutil.rmtree(d)


def test_padding():
    """Test bucket padding round-trip."""
    print("Testing padding...", end=" ")
    for size in [10, 100, 1000, 5000, 20000, 100000]:
        data = b"x" * size
        padded = pad_to_bucket(data)
        assert len(padded) in BUCKET_SIZES, f"Padded to {len(padded)}, not a bucket size"
        recovered = unpad_from_bucket(padded)
        assert recovered == data, f"Round-trip failed for size {size}"
    print("PASS")


def test_shuffle():
    """Test shuffle buffer randomization."""
    print("Testing shuffle...", end=" ")
    buf = ShuffleBuffer()
    items = list(range(100))
    for i in items:
        buf.add(i)
    assert buf.size == 100
    result = buf.flush()
    assert buf.size == 0
    assert sorted(result) == items
    assert result != items  # Statistically certain with 100 items
    print("PASS")


def test_tokens():
    """Test privacy token issue and verify."""
    print("Testing tokens...", end=" ")
    issuer = PrivacyTokenIssuer()
    tokens = issuer.issue_batch(10)
    assert len(tokens) == 10
    for t in tokens:
        assert issuer.verify(t), "Valid token failed verification"
    assert not issuer.verify("not-a-valid-token")
    assert issuer.issued_count == 10
    print("PASS")


def test_cloak_store_load():
    """Test full cloak pipeline: store, load, verify."""
    print("Testing cloak (full pipeline)...", end=" ")
    cloak = Cloak(TEST_PASSPHRASE, vault_dir=TEST_CLOAK_DIR)

    data = {
        "notes": {"entries": [{"text": "Private note 1"}, {"text": "Private note 2"}]},
        "config": {"theme": "dark", "lang": "en"},
        "contacts": {"people": [{"name": "Alice"}, {"name": "Bob"}]},
    }

    # Store
    report = cloak.store(data)
    assert report["tokens_used"] == 3
    assert len(report["shuffle_order"]) == 3
    assert report["total_plaintext_bytes"] > 0
    assert report["total_padded_bytes"] >= report["total_plaintext_bytes"]
    assert report["total_encrypted_bytes"] > 0

    # Metadata was stripped
    for cat_report in report["categories"]:
        assert "ip_address" in cat_report["metadata_stripped"]
        assert "user_agent" in cat_report["metadata_stripped"]
        assert "session_id" in cat_report["metadata_stripped"]

    # Load all
    loaded = cloak.load_all()
    assert len(loaded) == 3
    for cat in data:
        assert cat in loaded
        assert loaded[cat] == data[cat]

    # Load individual
    notes = cloak.load("notes")
    assert notes == data["notes"]

    # Verify
    results = cloak.verify_all(data)
    for cat, status in results.items():
        assert status == "PASS", f"Verification failed for {cat}"

    # Stats
    stats = cloak.stats()
    assert stats["requests_processed"] > 0
    assert stats["categories_stored"] == 3

    print("PASS")


def test_cloak_multi_category():
    """Test cloak with multiple categories and reload."""
    print("Testing cloak (multi-category reload)...", end=" ")
    cloak = Cloak(TEST_PASSPHRASE, vault_dir=TEST_CLOAK_DIR / "multi")

    data = {
        "alpha": {"items": [1, 2, 3]},
        "beta": {"items": [4, 5, 6]},
        "gamma": {"items": [7, 8, 9]},
    }

    cloak.store(data)

    # Create a NEW Cloak instance (simulates restart) — same passphrase
    cloak2 = Cloak(TEST_PASSPHRASE, vault_dir=TEST_CLOAK_DIR / "multi")
    loaded = cloak2.load_all()

    for cat in data:
        assert cat in loaded, f"Category {cat} missing after reload"
        assert loaded[cat] == data[cat], f"Category {cat} data mismatch"

    print("PASS")


def test_wrong_passphrase():
    """Test that wrong passphrase fails to decrypt."""
    print("Testing wrong passphrase...", end=" ")
    cloak1 = Cloak("correct-passphrase", vault_dir=TEST_BINDING_DIR / "wrong-pass")
    cloak1.store({"secret": {"data": "sensitive"}})

    try:
        cloak2 = Cloak("wrong-passphrase", vault_dir=TEST_BINDING_DIR / "wrong-pass")
        cloak2.load("secret")
        print("FAIL (should have raised an exception)")
        return
    except Exception:
        pass  # Expected — wrong passphrase = wrong bound key = decryption fails
    print("PASS")


def test_vault_no_seal_rejected():
    """Test that Vault rejects initialization without a seal key."""
    print("Testing vault rejects no seal...", end=" ")
    try:
        Vault(kek=b"x" * 32, seal_key=None, vault_dir=TEST_BINDING_DIR / "no-seal")
        print("FAIL (should have raised ValueError)")
        return
    except ValueError as e:
        assert "seal_key" in str(e)
    print("PASS")


def test_vault_wrong_seal_cant_decrypt():
    """Test that Vault with wrong seal produces wrong key — can't decrypt data."""
    print("Testing wrong seal = can't decrypt...", end=" ")
    test_dir = TEST_BINDING_DIR / "wrong-seal"

    # Store via Cloak (correct seal)
    cloak = Cloak(TEST_PASSPHRASE, vault_dir=test_dir)
    cloak.store({"private": {"msg": "you can't read this without the cloak"}})

    # Now try to access the vault with correct KEK but WRONG seal
    salt_file = test_dir / ".vault-salt"
    salt = base64.b64decode(salt_file.read_text())
    kek = derive_kek(TEST_PASSPHRASE, salt)
    wrong_seal = os.urandom(32)  # Random seal — not the real one

    vault_direct = Vault(kek=kek, seal_key=wrong_seal, vault_dir=test_dir)

    try:
        vault_direct.load("private")
        print("FAIL (should have raised an exception — wrong bound key)")
        return
    except Exception:
        pass  # Expected — wrong seal = wrong bound key = AES-GCM auth tag fails
    print("PASS")


def test_vault_correct_seal_works():
    """Test that Vault with correct seal (from Cloak derivation) works."""
    print("Testing correct seal = can decrypt...", end=" ")
    test_dir = TEST_BINDING_DIR / "correct-seal"

    # Store via Cloak
    cloak = Cloak(TEST_PASSPHRASE, vault_dir=test_dir)
    cloak.store({"private": {"msg": "this should be readable"}})

    # Derive the correct seal (same way Cloak does it)
    salt_file = test_dir / ".vault-salt"
    salt = base64.b64decode(salt_file.read_text())
    kek = derive_kek(TEST_PASSPHRASE, salt)
    seal = derive_seal_key(TEST_PASSPHRASE, salt)

    vault_direct = Vault(kek=kek, seal_key=seal, vault_dir=test_dir)
    loaded = vault_direct.load("private")
    assert loaded == {"msg": "this should be readable"}
    print("PASS")


def main():
    setup()
    print("=" * 50)
    print("  Safety Integration Tests")
    print("  (with cryptographic binding)")
    print("=" * 50)
    print()

    tests = [
        test_padding,
        test_shuffle,
        test_tokens,
        test_cloak_store_load,
        test_cloak_multi_category,
        test_wrong_passphrase,
        test_vault_no_seal_rejected,
        test_vault_wrong_seal_cant_decrypt,
        test_vault_correct_seal_works,
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

    # Cleanup
    setup()

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
