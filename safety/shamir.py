"""
Shamir's Secret Sharing
Split a secret into N shares where any K can reconstruct it.

Used by the Seal Authority Network to distribute the production seal
across multiple independent blockchains. No single chain holds enough
to forge a seal. Any K-of-N chains can reconstruct it.

This is the same math that powers the inheritance model —
your digital self survives because no single point of failure can kill it.
"""

import os
import secrets
from dataclasses import dataclass

# 256-bit prime field (NIST P-256 order, widely used in cryptography)
# This is larger than our 256-bit secrets, which is required for security.
PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclass
class Share:
    """A single share of a split secret."""
    index: int      # The x-coordinate (1-indexed, never 0)
    value: int      # The y-coordinate (the share value)
    threshold: int  # K — how many shares needed to reconstruct
    total: int      # N — total number of shares

    def to_hex(self) -> str:
        """Serialize to a portable hex string."""
        return f"{self.index}:{self.value:064x}:{self.threshold}:{self.total}"

    @classmethod
    def from_hex(cls, hex_str: str) -> "Share":
        """Deserialize from hex string."""
        parts = hex_str.split(":")
        return cls(
            index=int(parts[0]),
            value=int(parts[1], 16),
            threshold=int(parts[2]),
            total=int(parts[3]),
        )


def _mod_inverse(a: int, p: int) -> int:
    """Modular multiplicative inverse using Fermat's little theorem."""
    return pow(a, p - 2, p)


def _eval_polynomial(coefficients: list[int], x: int, prime: int) -> int:
    """Evaluate a polynomial at x in the prime field."""
    result = 0
    for i, coeff in enumerate(coefficients):
        result = (result + coeff * pow(x, i, prime)) % prime
    return result


def split(secret: bytes, threshold: int, num_shares: int) -> list[Share]:
    """
    Split a secret into shares using Shamir's Secret Sharing.

    Args:
        secret: The secret bytes to split (max 32 bytes / 256 bits).
        threshold: Minimum shares needed to reconstruct (K).
        num_shares: Total shares to generate (N).

    Returns:
        List of N Share objects. Any K can reconstruct the secret.

    Raises:
        ValueError: If parameters are invalid.
    """
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")
    if threshold > num_shares:
        raise ValueError("Threshold cannot exceed number of shares")
    if len(secret) > 32:
        raise ValueError("Secret must be 32 bytes or less")

    # Convert secret to integer
    secret_int = int.from_bytes(secret, "big")
    if secret_int >= PRIME:
        raise ValueError("Secret too large for the prime field")

    # Generate random polynomial: f(x) = secret + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
    # The secret is the constant term (f(0) = secret)
    coefficients = [secret_int]
    for _ in range(threshold - 1):
        coefficients.append(secrets.randbelow(PRIME))

    # Evaluate polynomial at points 1, 2, ..., N
    shares = []
    for i in range(1, num_shares + 1):
        value = _eval_polynomial(coefficients, i, PRIME)
        shares.append(Share(index=i, value=value, threshold=threshold, total=num_shares))

    return shares


def combine(shares: list[Share]) -> bytes:
    """
    Reconstruct a secret from K or more shares using Lagrange interpolation.

    Args:
        shares: At least K shares (where K is the threshold).

    Returns:
        The reconstructed secret bytes.

    Raises:
        ValueError: If not enough shares provided.
    """
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares")

    threshold = shares[0].threshold
    if len(shares) < threshold:
        raise ValueError(f"Need at least {threshold} shares, got {len(shares)}")

    # Use only threshold number of shares (any K will do)
    shares = shares[:threshold]

    # Lagrange interpolation at x=0 to recover f(0) = secret
    secret_int = 0
    for i, share_i in enumerate(shares):
        xi = share_i.index
        yi = share_i.value

        # Compute Lagrange basis polynomial at x=0
        numerator = 1
        denominator = 1
        for j, share_j in enumerate(shares):
            if i == j:
                continue
            xj = share_j.index
            numerator = (numerator * (-xj)) % PRIME
            denominator = (denominator * (xi - xj)) % PRIME

        lagrange = (yi * numerator * _mod_inverse(denominator, PRIME)) % PRIME
        secret_int = (secret_int + lagrange) % PRIME

    # Convert back to bytes
    return secret_int.to_bytes(32, "big")


def verify_shares(shares: list[Share], secret: bytes) -> bool:
    """Verify that a set of shares correctly reconstructs the secret."""
    try:
        reconstructed = combine(shares)
        return reconstructed == secret.rjust(32, b'\x00')
    except Exception:
        return False
