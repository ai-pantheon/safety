"""
Shuffle Buffer
Batch operations and process them in random order.

Prevents an observer from correlating the order of operations
to the structure of the underlying data.
"""

import random


class ShuffleBuffer:
    """
    Collects items and releases them in randomized order.

    Use this to decouple the order in which data is prepared
    from the order in which it is stored or transmitted.

    Args:
        min_batch: Minimum items before flush is effective (advisory).
        max_wait_ms: Maximum wait before auto-flush in async contexts (advisory).
    """

    def __init__(self, min_batch: int = 2, max_wait_ms: int = 200):
        self.buffer = []
        self.min_batch = min_batch
        self.max_wait_ms = max_wait_ms

    def add(self, item):
        """Add an item to the buffer."""
        self.buffer.append(item)

    def flush(self) -> list:
        """Return all items in randomized order and clear the buffer."""
        items = list(self.buffer)
        random.shuffle(items)
        self.buffer.clear()
        return items

    @property
    def size(self):
        """Number of items currently in the buffer."""
        return len(self.buffer)
