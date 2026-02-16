# Safety

## In Plain English

You know how you put your valuables in a safe at home? You set the combination. Nobody else knows it. Even the company that made the safe doesn't know your combination.

**Safety is that safe, but for your digital life.**

It does two things:

1. **It locks your stuff.** Your data gets scrambled with a password only you know. Even if someone broke into the server and stole every file, all they'd see is random nonsense. Without your password, it's useless.

2. **It hides *how* you use it.** Imagine if someone couldn't read your diary, but they could still see that you opened it at 3am on a Tuesday and wrote 4 pages. That's still information. Safety erases even those clues. It makes every request look the same size, in random order, with no fingerprints.

**What does "open source" mean?** It means the blueprints are public. Anyone can read the code, check our work, and verify that we did what we said. No hidden doors. No shortcuts. Just a safe you can trust because you can see how it's built.

Part of the **[You Own You](https://ai-pantheon.ai)** initiative by **[AI Pantheon](https://ai-pantheon.ai)**.

---

## The Technical Version

**Client-side encryption and request anonymization for private data stores.**

Your data. Your keys. Your control. Safety gives you two cryptographically bound layers of protection:

| Layer | What It Does |
|-------|-------------|
| **Vault** | AES-256-GCM envelope encryption. Each data category gets its own key. The master key is derived from your passphrase and never stored. |
| **Cloak** | Request anonymization. Bucket padding, metadata stripping, order shuffling, and privacy tokens. An observer sees fixed-size encrypted blobs in random order with no identifying metadata. |

**These layers are cryptographically bound.** The Vault's encryption key requires a seal that only the Cloak can derive. You cannot use the Vault without the Cloak. This isn't a policy — it's math. Bypass the anonymizer and the encryption key is wrong.

Part of the **[You Own You](https://ai-pantheon.ai)** initiative by **[AI Pantheon](https://ai-pantheon.ai)**.

---

## Install

```bash
pip install safety-cloak
```

Or from source:

```bash
git clone https://github.com/ai-pantheon/safety.git
cd safety
pip install -e .
```

Requires Python 3.10+ and the `cryptography` library.

---

## Quick Start

```python
from safety import Cloak

cloak = Cloak("my-secret-passphrase", vault_dir="./my-vault")

# Store multiple categories through the full pipeline:
# strip metadata → pad to buckets → shuffle order → encrypt → disk
report = cloak.store({
    "journal": {"entries": [{"date": "2026-02-11", "text": "It works."}]},
    "bookmarks": {"links": [{"url": "https://example.com"}]},
    "settings": {"theme": "dark"},
})

print(f"Shuffle order: {report['shuffle_order']}")
print(f"Padding overhead: {report['total_padded_bytes'] - report['total_plaintext_bytes']} bytes")
print(f"Metadata stripped from each request")

# Load everything back
data = cloak.load_all()

# Verify integrity
results = cloak.verify_all(data)
```

That's it. One class. One passphrase. Full encryption + anonymization.

---

## How It Works

### Vault: Envelope Encryption with Cryptographic Binding

```
Your Passphrase
    ↓ PBKDF2-SHA256 (600K iterations)
    ├── KEK (Key Encryption Key)
    └── Seal Key (via HKDF, separate context)
            ↓
        KEK + Seal → HKDF → Bound Key ← requires BOTH components
            ↓ encrypts
        DEK (one per category, stored encrypted)
            ↓ encrypts
        Your Data → AES-256-GCM → ciphertext on disk
```

- Each data category gets its own DEK (Data Encryption Key)
- DEKs are encrypted by the **Bound Key** (not the KEK alone)
- The Bound Key requires both the KEK and the Cloak's seal — derived via HKDF with separate contexts
- Only the Cloak can derive the seal. No seal = wrong Bound Key = can't decrypt DEKs
- The KEK and Bound Key exist only in memory, never on disk
- Wrong passphrase OR missing Cloak = decryption fails. No backdoors.

### Cloak: Traffic Analysis Resistance

Even with encryption, an observer could learn from *patterns*: how big is the data? What order is it accessed? How often? The Cloak eliminates these side channels:

| Technique | What It Prevents |
|-----------|-----------------|
| **Bucket Padding** | Size fingerprinting. All payloads are padded to fixed sizes (1KB, 4KB, 16KB, 64KB, 256KB, 1MB). An observer can't tell a 100-byte config from a 3KB document. |
| **Metadata Stripping** | Identity correlation. IP addresses, user agents, session IDs, and timestamps are stripped. Timestamps are bucketed to 10-second windows. |
| **Shuffle Buffer** | Order correlation. Categories are stored in random order. The sequence reveals nothing about the data structure. |
| **Privacy Tokens** | Request linking. Each operation uses a single-use HMAC token that proves authorization without linking requests together. |

---

## Architecture

```
Your Application
    ↓
┌──────────────── Cloak ─────────────────┐
│  Derive KEK + Seal Key (PBKDF2 + HKDF) │
│  Strip metadata                         │
│  Pad to bucket size                     │
│  Shuffle order                          │
│  Use privacy token                      │
│  ┌─────────── Vault ─────────────────┐ │
│  │  Bind Key = HKDF(KEK, Seal)       │ │
│  │  Get/create DEK (encrypted by BK) │ │
│  │  AES-256-GCM encrypt data         │ │
│  │  Write to disk                    │ │
│  └───────────────────────────────────┘ │
└─────────────────────────────────────────┘
    ↓
Encrypted, padded, shuffled files on disk
(Vault is inaccessible without the Cloak's seal)
```

---

## API Reference

### `Cloak(passphrase, vault_dir="./vault-encrypted")`

The single entry point. Creates and manages the bound Vault internally.

| Method | Description |
|--------|-------------|
| `store(data_dict)` | Store through full anonymization pipeline |
| `load_all()` | Load all categories |
| `load(category)` | Load a single category |
| `verify_all(original_dict)` | Verify all categories |
| `stats()` | Get operational statistics |

The `Vault` class is internal. It requires a seal key that only the Cloak can derive. Attempting to instantiate it directly without a seal raises `ValueError`. Attempting to use it with a wrong seal produces a wrong encryption key — decryption fails silently via AES-GCM authentication.

### Utilities

| Function/Class | Description |
|---------------|-------------|
| `pad_to_bucket(data)` | Pad bytes to next bucket size |
| `unpad_from_bucket(padded)` | Remove padding |
| `ShuffleBuffer` | Collect and randomize items |
| `PrivacyTokenIssuer` | Issue and verify unlinkable tokens |

---

## Running Tests

```bash
cd tests
python test_integration.py
```

---

## Security Notes

- **Passphrase strength matters.** Safety uses PBKDF2 with 600K iterations, but a weak passphrase is still a weak passphrase.
- **Privacy tokens are simplified.** Production multi-user deployments should use blind-signed RSA tokens per RFC 9576-9578 (Privacy Pass protocol). The HMAC implementation here is suitable for single-user or trusted environments.
- **This is not a replacement for TLS.** Safety protects data at rest and against server-side access. Use TLS for data in transit.
- **Audit the code.** That's why it's open source.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Built by **[AI Pantheon](https://ai-pantheon.ai)** as part of the **You Own You** initiative.
