import math


# ==============================
# CONSTANTS
# ==============================

# Agar sab 256 bytes equally distribute
# hon toh expected frequency ye hogi
EXPECTED_FREQUENCY = 1.0 / 256  # 0.00390625

# Chi-Square critical values
# (Degrees of freedom = 255)
# p-value thresholds:
CHI_CRITICAL = {
    'p_0.001': 310.457,   # 99.9% confidence
    'p_0.01' : 293.248,   # 99% confidence
    'p_0.05' : 280.000,   # 95% confidence
}


# ==============================
# CORE CHI-SQUARE TEST
# ==============================
def chi_square_test(data) -> dict:
    """
    Chi-Square test run karta hai data pe.

    Ye test differentiate karta hai:
    → Truly Random  (Encryption)
    → Pseudo Random (Compression)
    → Structured    (Plaintext)

    Returns dict:
    {
        'chi_square'   : float,
        'result'       : str,
        'distribution' : str,
        'confidence'   : str
    }
    """
    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')

    if not data:
        return {
            'chi_square'   : 0.0,
            'result'       : 'unknown',
            'distribution' : 'unknown',
            'confidence'   : 'none'
        }

    total = len(data)

    # Har byte (0-255) ki observed frequency
    observed = [0] * 256
    for byte in data:
        observed[byte] += 1

    # Expected frequency har byte ke liye
    expected = total * EXPECTED_FREQUENCY

    # Chi-Square formula:
    # X² = sum((observed - expected)² / expected)
    chi_square = 0.0
    for obs in observed:
        diff = obs - expected
        chi_square += (diff * diff) / expected

    chi_square = round(chi_square, 4)

    # Result classify karo
    result       = classify_chi_square(chi_square)
    distribution = get_distribution_type(chi_square)
    confidence   = get_confidence_level(chi_square)

    return {
        'chi_square'   : chi_square,
        'result'       : result,
        'distribution' : distribution,
        'confidence'   : confidence
    }


# ==============================
# CLASSIFIERS
# ==============================
def classify_chi_square(chi_sq: float) -> str:
    """
    Chi-Square value ko classification
    mein convert karta hai.

    Low value  → Truly random (Encrypted)
    High value → Not random (Compressed/Plain)
    """
    if chi_sq <= CHI_CRITICAL['p_0.001']:
        return 'truly_random'      # Encryption signal
    elif chi_sq <= CHI_CRITICAL['p_0.01']:
        return 'near_random'       # Possibly encrypted
    elif chi_sq <= CHI_CRITICAL['p_0.05']:
        return 'pseudo_random'     # Compression signal
    elif chi_sq <= 500:
        return 'structured'        # Encoded data
    else:
        return 'non_random'        # Plaintext


def get_distribution_type(chi_sq: float) -> str:
    """
    Distribution type return karta hai —
    CLI output ke liye.
    """
    if chi_sq <= CHI_CRITICAL['p_0.001']:
        return 'flat'             # Encryption
    elif chi_sq <= CHI_CRITICAL['p_0.05']:
        return 'near_flat'        # Compression
    elif chi_sq <= 500:
        return 'mixed'            # Encoded
    else:
        return 'skewed'           # Plaintext


def get_confidence_level(chi_sq: float) -> str:
    """
    Confidence level string return karta hai.
    """
    if chi_sq <= CHI_CRITICAL['p_0.001']:
        return '99.9%'
    elif chi_sq <= CHI_CRITICAL['p_0.01']:
        return '99%'
    elif chi_sq <= CHI_CRITICAL['p_0.05']:
        return '95%'
    else:
        return 'low'


# ==============================
# COMBINED ANALYSIS
# ==============================
def full_randomness_analysis(data) -> dict:
    """
    Entropy + Chi-Square dono combine
    karke final verdict deta hai.

    Pillar C directly ye use karega.

    Returns:
    {
        'verdict'      : str,
        'chi_square'   : float,
        'result'       : str,
        'distribution' : str,
        'confidence'   : str,
        'explanation'  : str
    }
    """
    from utils.entropy import calculate_entropy, classify_entropy

    if isinstance(data, str):
        data = data.encode('utf-8', errors='replace')

    # Entropy calculate karo
    entropy       = calculate_entropy(data)
    entropy_label = classify_entropy(entropy)

    # Chi-Square test karo
    chi_result = chi_square_test(data)

    # Dono combine karke verdict do
    verdict, explanation = combine_signals(
        entropy_label,
        chi_result['result']
    )

    return {
        'verdict'      : verdict,
        'entropy'      : entropy,
        'entropy_label': entropy_label,
        'chi_square'   : chi_result['chi_square'],
        'chi_result'   : chi_result['result'],
        'distribution' : chi_result['distribution'],
        'confidence'   : chi_result['confidence'],
        'explanation'  : explanation
    }


def combine_signals(entropy_label: str,
                    chi_result: str) -> tuple:
    """
    Entropy + Chi-Square dono signals
    ko combine karke final verdict deta hai.

    Returns: (verdict, explanation)
    """

    # Encryption signals
    if entropy_label in ('encrypted', 'high') and \
       chi_result in ('truly_random', 'near_random'):
        return (
            'encrypted',
            'High entropy + truly random distribution → Strong encryption signal'
        )

    # Compression signals
    if entropy_label in ('compressed', 'high') and \
       chi_result in ('pseudo_random', 'structured'):
        return (
            'compressed',
            'High entropy + pseudo random distribution → Compression signal'
        )

    # Encoded signals
    if entropy_label == 'encoded':
        return (
            'encoded',
            'Moderate entropy → Encoding detected (Base64/similar)'
        )

    # Plaintext signals
    if entropy_label in ('plaintext', 'low', 'structured'):
        return (
            'plaintext',
            'Low entropy + skewed distribution → Plaintext or structured data'
        )

    # Ambiguous
    return (
        'unknown',
        f'Inconclusive — Entropy: {entropy_label}, Chi-Sq: {chi_result}'
    )