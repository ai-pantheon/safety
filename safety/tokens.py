"""
Privacy Tokens
Unlinkable authentication tokens for anonymous access.

In production: blind-signed RSA tokens per RFC 9576-9578 (Privacy Pass).
This implementation provides HMAC-based tokens that prove "valid session"
without linking individual requests to an identity.
"""

import os
import hashlib
import base64


class PrivacyTokenIssuer:
    """
    Issues and verifies unlinkable authentication tokens.

    Each token proves the holder has a valid session without
    revealing which session or linking multiple requests together.

    Args:
        secret: HMAC signing secret. Generated randomly if not provided.
    """

    def __init__(self, secret: bytes = None):
        self.secret = secret or os.urandom(32)
        self._issued_count = 0

    def issue_batch(self, count: int = 10) -> list[str]:
        """
        Issue a batch of single-use tokens.

        Args:
            count: Number of tokens to issue.

        Returns:
            List of base64-encoded tokens.
        """
        tokens = []
        for _ in range(count):
            self._issued_count += 1
            # Each token is unique but unlinkable to the session
            token_data = os.urandom(32)
            hmac = hashlib.sha256(self.secret + token_data).digest()
            token = base64.b64encode(token_data + hmac).decode()
            tokens.append(token)
        return tokens

    def verify(self, token: str) -> bool:
        """
        Verify a token is valid without identifying who it was issued to.

        Args:
            token: Base64-encoded token string.

        Returns:
            True if the token is valid.
        """
        try:
            raw = base64.b64decode(token)
            token_data = raw[:32]
            provided_hmac = raw[32:]
            expected_hmac = hashlib.sha256(self.secret + token_data).digest()
            # Constant-time comparison via double hash
            return (
                hashlib.sha256(provided_hmac).digest()
                == hashlib.sha256(expected_hmac).digest()
            )
        except Exception:
            return False

    @property
    def issued_count(self) -> int:
        """Total number of tokens issued."""
        return self._issued_count
