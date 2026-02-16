"""
Safety — Basic Usage Example

Demonstrates encrypting and anonymizing a personal data store.
The Vault and Cloak are cryptographically bound — you MUST use the
Cloak to access your data. The Vault cannot operate alone.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from safety import Cloak


def main():
    # Your passphrase — the only key to your data
    passphrase = "my-secret-passphrase-change-this"

    print("=" * 50)
    print("  Safety — Encrypted + Anonymized Storage")
    print("=" * 50)

    cloak = Cloak(passphrase, vault_dir="./example-vault")

    # A data store with multiple categories
    my_data = {
        "journal": {
            "entries": [
                {"date": "2026-02-10", "text": "Had a breakthrough idea today."},
                {"date": "2026-02-11", "text": "Built the prototype. It works."},
            ]
        },
        "bookmarks": {
            "links": [
                {"url": "https://example.com", "tag": "reference"},
                {"url": "https://docs.python.org", "tag": "python"},
            ]
        },
        "settings": {
            "theme": "dark",
            "language": "en",
        },
    }

    # Store through the full pipeline:
    # strip metadata → pad to buckets → shuffle order → encrypt → disk
    report = cloak.store(my_data)

    print(f"\nStored {len(report['categories'])} categories")
    print(f"Shuffle order: {report['shuffle_order']}")
    print(f"(Original order was: {list(my_data.keys())})")
    print(f"Privacy tokens used: {report['tokens_used']}")
    print(f"Plaintext: {report['total_plaintext_bytes']} bytes")
    print(f"Padded:    {report['total_padded_bytes']} bytes")
    print(f"Encrypted: {report['total_encrypted_bytes']} bytes")

    for cat in report["categories"]:
        print(f"  {cat['category']}: {cat['plaintext_bytes']}B -> padded {cat['padded_size']}B -> encrypted {cat['encrypted_bytes']}B")
        print(f"    Metadata stripped: {cat['metadata_stripped']}")

    # Load everything back through the Cloak
    loaded_data = cloak.load_all()
    print(f"\nLoaded {len(loaded_data)} categories: {list(loaded_data.keys())}")

    # Verify integrity
    results = cloak.verify_all(my_data)
    for category, status in results.items():
        print(f"  [{status}] {category}")

    # Try loading with wrong passphrase
    print("\nAttempting load with wrong passphrase...")
    bad_cloak = Cloak("wrong-passphrase", vault_dir="./example-vault")
    try:
        bad_cloak.load("journal")
        print("  ERROR: Should have failed!")
    except Exception:
        print("  Correctly rejected — wrong passphrase = wrong key = can't decrypt")

    # Cleanup
    import shutil
    shutil.rmtree("./example-vault", ignore_errors=True)
    print("\nCleaned up example files.")


if __name__ == "__main__":
    main()
