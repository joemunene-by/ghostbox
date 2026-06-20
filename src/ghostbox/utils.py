"""Shared helpers: entropy, safe slicing, logging."""

from __future__ import annotations

import logging
import math
from collections import Counter

logger = logging.getLogger("ghostbox")


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of a byte string in bits per byte (0.0 to 8.0)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def human_size(num_bytes: int) -> str:
    """Render a byte count as a human-readable string."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def safe_slice(data: bytes, start: int, length: int) -> bytes:
    """Return data[start:start+length], clamped to the buffer, never raising."""
    if start < 0 or start >= len(data) or length <= 0:
        return b""
    return data[start : start + length]


def configure_logging(verbose: bool) -> None:
    """Configure the package logger level."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger.setLevel(level)
