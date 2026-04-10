import re
import math
import codecs
from utils.db_connector import fetch_all


# ==============================
# CONSTANTS
# ==============================
MIN_TEXT_LENGTH = 20

ENGLISH_WORDS = {
    'the', 'and', 'is', 'in', 'it', 'of', 'to', 'a', 'that', 'was', 'for', 'on', 'are', 'with',
    'this', 'be', 'as', 'at', 'by', 'from', 'or', 'an', 'but', 'not', 'have', 'had', 'they',
    'you', 'he', 'she', 'we', 'his', 'her', 'their', 'test', 'message', 'hello', 'world',
    'quick', 'brown', 'fox', 'jumps', 'lazy', 'dog', 'over', 'moon', 'cipher', 'secret',
    'hidden', 'flag', 'text', 'plain', 'code', 'data', 'security', 'analyst', 'found'
}

ROT13_WORDS = {
    'gur', 'naq', 'vf', 'bs', 'gb', 'be',
    'jbeyq', 'uryyb', 'grfg', 'zrffntr',
    'guvf', 'sbe', 'ebg', 'guvegrra',
    'n', 'va', 'ba', 'ng', 'ol', 'fb'
}


# ==============================
# PLAIN ENGLISH CHECK
# ==============================
def _is_plain_english(text: str) -> bool:
    """
    Text plain English hai?
    Common words ratio check.
    """
    words = re.findall(r'[a-zA-Z]+', text.lower())

    if len(words) < 3:
        return False

    match_count = sum(
        1 for w in words
        if w in ENGLISH_WORDS
    )

    ratio = match_count / len(words)
    return ratio >= 0.35  # 35%+ words English


# ==============================
# CORE DETECTION
# ==============================
def detect_cipher(input_data: str) -> dict:
    try:
        input_data = input_data.strip()
    except AttributeError:
        return _empty_result()

    if not input_data:
        return _empty_result()

    # 1. 🛡️ Candidate check (Ab 10 chars allow karta hai)
    if not _is_cipher_candidate(input_data):
        return _empty_result()

    # 2. 🛡️ Plain English early exit
    if _is_plain_english(input_data):
        return _empty_result()

    # ==========================================
    # PHASE 1: DIRECT SIGNATURE CHECKS (Length >= 10)
    # ==========================================
    # Ye word-matching par base hain, isliye statistics ki tension nahi hai
    
    # ROT13 Check
    rot13_result = _direct_rot13_check(input_data)
    if rot13_result: return _build_result([rot13_result])
    
    # Atbash Check
    atbash_result = _direct_atbash_check(input_data)
    if atbash_result: return _build_result([atbash_result])
    
    # Caesar / Rotation Check
    caesar_result = _direct_caesar_check(input_data)
    if caesar_result: return _build_result([caesar_result])


    # ==========================================
    # PHASE 2: STATISTICAL HEURISTICS (Length >= 25)
    # ==========================================
    # Vigenere, Substitution aur Transposition ke liye statistics chahiye
    
    if len(input_data) >= 25:
        try:
            ic = calculate_ic(input_data)
            freq_pattern = _get_frequency_pattern(input_data)

            # DB se profiles match karo
            candidates = _match_cipher_profiles(ic, freq_pattern)

            if candidates:
                # Confidence adjust aur Filter
                candidates = _adjust_confidence(input_data, ic, candidates)
                candidates = _filter_plain_english(candidates)

                if candidates:
                    candidates.sort(key=lambda x: x['confidence'], reverse=True)
                    return _build_result(candidates)
        except Exception:
            pass

    return _empty_result()
    # return _build_result(candidates)

ATBASH_MAP = str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba'
)

def _direct_atbash_check(input_data: str):
    """
    Atbash decode karke English check karta hai.
    A=Z, B=Y, C=X ... Z=A
    """
    try:
        decoded    = input_data.translate(ATBASH_MAP)
        is_english = _is_plain_english(decoded)
    except Exception:
        return None

    if not is_english:
        return None

    ic = calculate_ic(input_data)

    return {
        'name'        : 'Atbash Cipher',
        'confidence'  : 0.92,
        'ic'          : ic,
        'ic_min'      : 0.060,
        'ic_max'      : 0.070,
        'freq_pattern': 'reversed_english',
        'keyspace'    : '26',
        'description' : 'Atbash reverses alphabet: A=Z, B=Y.',
        'example'     : 'Svool → Hello',
        'reasons'     : [
            'Atbash decode → valid English confirmed'
        ]
    }

# ==============================
# CIPHER CANDIDATE CHECK
# ==============================
def _is_cipher_candidate(input_data: str) -> bool:
    if len(input_data) < 10:
        return False

    alpha_count = sum(1 for c in input_data if c.isalpha())
    total       = len(input_data)

    if (alpha_count / total) < 0.60:
        return False

    # ✅ Base32 charset → cipher nahi hai
    if re.match(r'^[A-Z2-7=\s]+$', input_data) and bool(re.search(r'[2-7=]', input_data)):
        return False

    # ✅ Pure Hex → cipher nahi hai
    if re.match(r'^[0-9a-fA-F\s]+$', input_data):
        return False

    return True

# ==============================
# ROT13 DIRECT CHECK
# ==============================
def _direct_rot13_check(input_data: str):
    """
    2 methods se ROT13 check karta hai:
    1. Known ROT13 word patterns
    2. Decode karke English check
    """
    text_lower = input_data.lower()

    # ✅ Pehle Atbash check karo
    # Agar Atbash words hain toh ROT13 nahi hai
    atbash_decoded = input_data.translate(ATBASH_MAP)
    if _is_plain_english(atbash_decoded):
        return None  # Atbash hai, ROT13 nahi

    # Method 1: ROT13 word patterns
    rot13_count = sum(
        1 for w in ROT13_WORDS
        if w in text_lower
    )

    # Method 2: Decode karke English check
    try:
        decoded     = codecs.decode(input_data, 'rot_13')
        is_english  = _is_plain_english(decoded)
    except Exception:
        is_english  = False

    # Dono confirm karein → High confidence
    if rot13_count >= 2 and is_english:
        confidence = 0.97
        reasons    = [
            f'ROT13 word patterns: {rot13_count}',
            'ROT13 decode → valid English confirmed'
        ]

    elif is_english:
        confidence = 0.88
        reasons    = ['ROT13 decode → valid English']

    # ✅ Ab — threshold 2 se 3 karo
    elif rot13_count >= 3:
        confidence = 0.82
        reasons    = [f'ROT13 word patterns: {rot13_count}']

    else:
        return None

    ic = calculate_ic(input_data)

    return {
        'name'        : 'ROT13',
        'confidence'  : confidence,
        'ic'          : ic,
        'ic_min'      : 0.060,
        'ic_max'      : 0.070,
        'freq_pattern': 'shifted_english',
        'keyspace'    : '13',
        'description' : 'ROT13 is Caesar cipher with shift 13.',
        'example'     : 'Uryyb → Hello',
        'reasons'     : reasons
    }


# Famous Rotation Shifts Mapping
FAMOUS_ROTATIONS = {
    1:  "ROT-1 (Caesar Variant)",
    3:  "Caesar Cipher (Classic ROT-3)",
    13: "ROT-13 (Standard)",
    5:  "ROT-5 (Commonly for Digits)",
    47: "ROT-47 (ASCII Rotation)" 
}


def _direct_caesar_check(input_data: str):
    """
    Caesar cipher — saare 25 shifts try karo
    aur check karo decoded English hai?
    """
    def caesar_decode(text: str, shift: int) -> str:
        result = []
        for char in text:
            if char.isalpha():
                base  = ord('A') if char.isupper() else ord('a')
                decoded = chr((ord(char) - base - shift) % 26 + base)
                result.append(decoded)
            else:
                result.append(char)
        return ''.join(result)

    best_shift      = None
    best_confidence = 0.0
    best_decoded    = ''

    for shift in range(1, 26):
        # ROT13 already handle hua
        if shift == 13:
            continue

        decoded = caesar_decode(input_data, shift)

        # decoded text ko check karo
        if _is_plain_english(decoded):
            #  NAYA FILTER: Playfair aur 2-letter garbage ko rokne ke liye
            words = decoded.split()
            short_words = sum(1 for w in words if len(w) <= 2)
            if short_words / len(words) > 0.5:
                continue
            # Agar average word length 2.1 se kam hai, toh ye real English nahi hai
            avg_len = sum(len(w) for w in words) / len(words) if words else 0
            
            if avg_len <= 2.1:
                continue # Ye likely Playfair ya random data ka false match hai

            # IC check karo decoded text ka
            ic_decoded = calculate_ic(decoded)

            # English IC range mein hai?
            if ic_decoded >= 0.040:
                confidence = 0.85 + (0.12 * (ic_decoded - 0.040))
                confidence = min(round(confidence, 4), 0.98)

                if confidence > best_confidence:
                    best_confidence = confidence
                    best_shift      = shift
                    best_decoded    = decoded

    if best_shift is None:
        return None
    
    # Famous naam check karo, agar nahi mile toh generic ROT-N rakho
    display_name = FAMOUS_ROTATIONS.get(best_shift, f"Rotation Cipher (ROT-{best_shift})")

    ic = calculate_ic(input_data)

    return {
        'name'        : display_name, # 🔥 DB ke naye naam se match karo
        'confidence'  : best_confidence,
        'ic'          : ic,
        'ic_min'      : 0.055,
        'ic_max'      : 0.095,
        'freq_pattern': 'shifted_english',
        'keyspace'    : '1-25',
        'description' : f'Detected a rotation cipher with a shift of {best_shift}.', # 🔥 Shift number batao!
        'example'     : f'ROT-{best_shift} detected',
        'reasons'     : [
            f'Brute-force found valid English at ROT-{best_shift}',
            f'Decoded IC: {calculate_ic(best_decoded):.4f}'
        ]
    }



# ==============================
# IC CALCULATION
# ==============================
def calculate_ic(text: str) -> float:
    text = re.sub(r'[^a-zA-Z]', '', text.upper())
    n    = len(text)

    if n < 2:
        return 0.0

    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    numerator   = sum(c * (c - 1) for c in freq.values())
    denominator = n * (n - 1)

    if denominator == 0:
        return 0.0

    return round(numerator / denominator, 6)


# ==============================
# FREQUENCY ANALYSIS
# ==============================
def _get_frequency_pattern(text: str) -> str:
    alpha = re.sub(r'[^a-zA-Z]', '', text.upper())
    if len(alpha) < MIN_TEXT_LENGTH: return 'unknown'
    
    words = text.split()
    # 🕵️‍♂️ Playfair ka sabse bada saboot: Words are pairs
    is_digraph_form = all(len(w) == 2 for w in words) if len(words) >= 5 else False
    
    ic = calculate_ic(text)
    total = len(alpha)
    freq = {c: alpha.count(c) / total * 100 for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'}
    most_common = max(freq, key=freq.get)
    top3 = sorted(freq, key=freq.get, reverse=True)[:3]

    # Rule 1: Visual Digraphs (Bypass IC)
    if is_digraph_form: return 'digraph'

    # Rule 2: Atbash Specific
    if set(top3).issubset(set('ZYXWVU')): return 'reversed_english'

    # Rule 3: High IC (Monoalphabetic)
    if 0.058 <= ic <= 0.095:
        if most_common in 'ETA' and not _is_plain_english(text): return 'scrambled'
        return 'substituted'
        
    # Rule 4: Low IC (Polyalphabetic)
    return 'polyalphabetic'

# ==============================
# DB PROFILE MATCHING
# ==============================
def _match_cipher_profiles(ic: float,
                            freq_pattern: str) -> list:
    query = '''
        SELECT name, ic_min, ic_max, charset,
               freq_pattern, keyspace,
               confidence, priority,
               description, example
        FROM cipher_profiles
        WHERE ic_min <= ?
        AND   ic_max >= ?
        ORDER BY priority ASC, confidence DESC
    '''
    rows = fetch_all(query, (ic, ic))

    candidates = []
    for row in rows:
        if row['name'] in ('Plain English', 'Random Data'):
            continue

        # ROT13 already direct check se handle hua
        if row['name'] == 'ROT13':
            continue

        candidate = {
            'name'        : row['name'],
            'confidence'  : row['confidence'],
            'ic'          : ic,
            'ic_min'      : row['ic_min'],
            'ic_max'      : row['ic_max'],
            'freq_pattern': row['freq_pattern'],
            'keyspace'    : row['keyspace'],
            'description' : row['description'],
            'example'     : row['example'],
            'reasons'     : [
                f'IC: {ic:.4f} '
                f'(range: {row["ic_min"]}-{row["ic_max"]})'
            ]
        }

        if freq_pattern == row['freq_pattern']:
            candidate['confidence'] = round(
                min(candidate['confidence'] + 0.08, 0.99),
                4
            )
            candidate['reasons'].append(
                f'Freq pattern: {freq_pattern}'
            )

        candidates.append(candidate)

    return candidates


# ==============================
# CONFIDENCE ADJUSTMENT
# ==============================
def _adjust_confidence(input_data: str,
                        ic: float,
                        candidates: list) -> list:
    text_len = len(re.sub(r'[^a-zA-Z]', '', input_data))

    for candidate in candidates:
        if text_len > 100:
            candidate['confidence'] = round(
                min(candidate['confidence'] + 0.05, 0.99),
                4
            )

        ic_center = (candidate['ic_min'] +
                     candidate['ic_max']) / 2
        distance  = abs(ic - ic_center)
        ic_range  = (candidate['ic_max'] -
                     candidate['ic_min']) / 2

        if ic_range > 0:
            closeness = 1 - (distance / ic_range)
            boost     = 0.05 * closeness
            candidate['confidence'] = round(
                min(candidate['confidence'] + boost, 0.99),
                4
            )

    return candidates


# ==============================
# FALSE POSITIVE FILTER
# ==============================
def _filter_plain_english(candidates: list) -> list:
    return [
        c for c in candidates
        if c['confidence'] >= 0.55
    ]


# ==============================
# HELPERS
# ==============================
def _build_result(candidates: list) -> dict:
    if not candidates:
        return _empty_result()

    top       = candidates[0]
    ambiguous = len(candidates) > 1

    return {
        'detected'   : True,
        'candidates' : candidates,
        'top'        : top,
        'ambiguous'  : ambiguous,
    }


def _empty_result() -> dict:
    return {
        'detected'   : False,
        'candidates' : [],
        'top'        : None,
        'ambiguous'  : False,
    }


# ==============================
# OUTPUT FORMATTER
# ==============================
def format_cipher_result(result: dict) -> str:
    lines = []
    sep   = "─" * 54

    if not result['detected']:
        return ""

    lines.append(sep)
    lines.append("  PILLAR D — CLASSICAL CIPHER DETECTION")
    lines.append(sep)

    top = result['top']

    if not result['ambiguous']:
        lines.append(f"  Type       : {top['name']}")
        lines.append(
            f"  Confidence : {int(top['confidence'] * 100)}%"
        )
        lines.append(f"  IC Value   : {top['ic']:.4f}")
        lines.append(
            f"  Reason     : {', '.join(top['reasons'])}"
        )
        if top.get('keyspace'):
            lines.append(f"  Keyspace   : {top['keyspace']}")
        if top.get('description'):
            lines.append(
                f"  Description: {top['description']}"
            )
    else:
        lines.append("  [!] Multiple Candidates:")
        lines.append("")
        lines.append(
            f"  {'Type':<25} {'Confidence':<12} {'IC'}"
        )
        lines.append(
            f"  {'─'*25} {'─'*12} {'─'*8}"
        )
        for c in result['candidates']:
            conf = f"{int(c['confidence'] * 100)}%"
            lines.append(
                f"  {c['name']:<25} {conf:<12} {c['ic']:.4f}"
            )
        lines.append("")
        lines.append(
            f"  Reason : {', '.join(top['reasons'])}"
        )

    lines.append(sep)
    return "\n".join(lines)