import math
from pathlib import Path


# ==============================
# CONSTANTS
# ==============================
CHUNK_SIZE = 1024  # Sliding window chunk size (bytes)


# ==============================
# CORE ENTROPY CALCULATION
# ==============================
def calculate_entropy(data) -> float:
    """
    Shannon Entropy calculate karta hai.

    Input : bytes ya string
    Output: float (0.0 to 8.0)

    0.0 → Completely uniform data
    8.0 → Perfectly random data
    """
    # String hai toh bytes mein convert karo
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')

    if not data:
        return 0.0

    # Har byte ki frequency count karo
    frequency = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1

    # Shannon entropy formula:
    # H = -sum(p * log2(p))
    total = len(data)
    entropy = 0.0

    for count in frequency.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


# ==============================
# BYTE FREQUENCY ANALYSIS
# ==============================
def byte_frequency(data: bytes) -> dict:
    """
    Har byte (0-255) ki frequency
    percentage mein return karta hai.

    Flat distribution → Encryption
    Skewed distribution → Plaintext
    """
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')

    total = len(data)
    if total == 0:
        return {}

    freq = {}
    for i in range(256):
        freq[i] = 0

    for byte in data:
        freq[byte] += 1

    # Percentage mein convert karo
    return {
        byte: round((count / total) * 100, 4)
        for byte, count in freq.items()
    }


def is_flat_distribution(data: bytes,
                          threshold: float = 0.8) -> bool:
    """
    Byte distribution flat hai?
    (Encryption ka strong signal)

    Threshold: Kitne % bytes active hone chahiye
    Default  : 80% bytes ka use hona chahiye
    """
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')

    freq = byte_frequency(data)

    # Kitne unique bytes hain
    active_bytes = sum(1 for v in freq.values() if v > 0)

    # 256 possible bytes mein se
    # threshold % active hain?
    return (active_bytes / 256) >= threshold


# ==============================
# SLIDING WINDOW ENTROPY
# ==============================
def sliding_window_entropy(data: bytes,
                            chunk_size: int = CHUNK_SIZE) -> list:
    """
    File ko chunks mein scan karke
    har chunk ka entropy nikalta hai.

    Large files mein encrypted blobs
    locate karne ke liye use hota hai.

    Returns: list of dicts
    [
        {
            'offset'  : 0,
            'size'    : 1024,
            'entropy' : 7.94,
            'label'   : 'encrypted'
        },
        ...
    ]
    """
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')

    if not data:
        return []

    results = []
    total = len(data)

    for offset in range(0, total, chunk_size):
        chunk = data[offset: offset + chunk_size]

        if not chunk:
            continue

        entropy = calculate_entropy(chunk)
        label   = classify_entropy(entropy)

        results.append({
            'offset'  : offset,
            'size'    : len(chunk),
            'entropy' : entropy,
            'label'   : label
        })

    return results


# ==============================
# ENTROPY CLASSIFIER
# ==============================
def classify_entropy(entropy: float) -> str:
    """
    Entropy value ko human-readable
    label mein classify karta hai.

    DB ke entropy_profiles se match
    karne se pehle quick classification.
    """
    if entropy < 1.0:
        return 'uniform'          # Same bytes repeat
    elif entropy < 3.5:
        return 'low'              # Highly structured
    elif entropy < 5.0:
        return 'plaintext'        # Normal text
    elif entropy < 6.5:
        return 'structured'       # Code, JSON, XML
    elif entropy < 7.2:
        return 'encoded'          # Base64, etc
    elif entropy < 7.7:
        return 'compressed'       # ZIP, LZMA
    elif entropy < 7.85:
        return 'high'             # Compressed or encrypted
    else:
        return 'encrypted'        # AES, strong encryption


# ==============================
# SUMMARY REPORT
# ==============================
def entropy_summary(data) -> dict:
    """
    Complete entropy analysis
    ek dict mein return karta hai.

    Pillar C ismein directly use karega.
    """
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')

    entropy      = calculate_entropy(data)
    label        = classify_entropy(entropy)
    flat         = is_flat_distribution(data)
    windows      = sliding_window_entropy(data)

    # High entropy windows count karo
    high_entropy_chunks = [
        w for w in windows
        if w['entropy'] >= 7.7
    ]

    return {
        'entropy'            : entropy,
        'label'              : label,
        'is_flat_dist'       : flat,
        'total_chunks'       : len(windows),
        'high_entropy_chunks': len(high_entropy_chunks),
        'chunk_details'      : windows
    }