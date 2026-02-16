"""
Bucket Padding
Pad all payloads to fixed bucket sizes to prevent size-based fingerprinting.

An observer cannot determine the type or content of data by its size.
All data appears as one of a small number of fixed sizes.
"""

import os


# Fixed bucket sizes — every payload gets padded to one of these
BUCKET_SIZES = [
    1024,       # 1 KB
    4096,       # 4 KB
    16384,      # 16 KB
    65536,      # 64 KB
    262144,     # 256 KB
    1048576,    # 1 MB
]


def pad_to_bucket(data: bytes) -> bytes:
    """
    Pad data to the next fixed bucket size.

    Prepends a 4-byte length header, then pads with random bytes
    to fill the bucket. An observer sees only fixed-size blobs.

    Args:
        data: The raw bytes to pad.

    Returns:
        Padded bytes with length header.
    """
    original_len = len(data)

    # Find the smallest bucket that fits
    bucket_size = BUCKET_SIZES[-1]  # Default to largest
    for size in BUCKET_SIZES:
        if original_len + 4 <= size:  # 4 bytes for length header
            bucket_size = size
            break

    # Prepend 4-byte length header, then pad with random bytes
    padded = original_len.to_bytes(4, "big") + data
    padding_needed = bucket_size - len(padded)
    if padding_needed > 0:
        padded += os.urandom(padding_needed)

    return padded


def unpad_from_bucket(padded: bytes) -> bytes:
    """
    Remove bucket padding and extract original data.

    Reads the 4-byte length header to determine the original size,
    then extracts exactly that many bytes.

    Args:
        padded: The padded bytes (with length header).

    Returns:
        The original unpadded data.
    """
    original_len = int.from_bytes(padded[:4], "big")
    return padded[4:4 + original_len]
