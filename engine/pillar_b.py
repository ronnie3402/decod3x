import re
from utils.db_connector import fetch_all, fetch_one


# ==============================
# CONSTANTS
# ==============================
HASH_CHARSETS = {
    'lowercase_hex' : r'^[a-f0-9]+$',
    'uppercase_hex' : r'^[A-F0-9]+$',
    'mixed_hex'     : r'^[a-fA-F0-9]+$',
    'base64_custom' : r'^[A-Za-z0-9+/=]+$',
    'modular_crypt' : r'^\$[a-z0-9]+\$',
}


# ==============================
# CORE DETECTION
# ==============================
def detect_hash(input_data: str) -> dict:
    """
    Input string ko analyze karke
    hash type identify karta hai.

    Returns:
    {
        'detected'   : bool,
        'candidates' : list,
        'top'        : dict,
        'ambiguous'  : bool,
        'input_len'  : int
    }
    """
    try:
        input_data = input_data.strip()
    except AttributeError:
        return _empty_result()

    if not input_data:
        return _empty_result()

    # Step 1: Prefix based check (KDFs)
    # bcrypt, argon2, scrypt — 100% confidence
    try:
        prefix_result = _check_prefix(input_data)
        if prefix_result:
            return _build_result([prefix_result])

    except Exception:
        pass  # Prefix fail → continue to length check

    # Step 2: Hex charset validate karo
    try:
        if not _is_valid_hash_charset(input_data):
            return _empty_result()
    except Exception:
        return _empty_result()

    # Step 3: Length based candidates
    try:
        candidates = _get_candidates_by_length(input_data)

        if not candidates:
            return _empty_result()

        # Step 4: Charset refine karo

        candidates = _adjust_confidence(input_data, candidates)

        candidates = _refine_by_charset(input_data, candidates)
        candidates = _add_context_hints(input_data, candidates)

        # Step 4 ke baad add karo
       
        

        # Step 5: Confidence adjust karo
        

        # Step 6: Sort by confidence
        candidates.sort(
            key=lambda x: x['confidence'],
            reverse=True
        )

    except Exception:
        return _empty_result()


    return _build_result(candidates)


# ==============================
# STEP 1: PREFIX CHECK
# ==============================
def _check_prefix(input_data: str):
    # ✅ GROUP BY name,prefix karo
    # Taaki saare prefixes milein
    query = '''
        SELECT name, hex_length, prefix, charset,
               category, MAX(base_confidence) as base_confidence,
               MIN(priority) as priority,
               output_format, collision_risk,
               ambiguous_with, description,
               example, next_step
        FROM hash_formats
        WHERE prefix IS NOT NULL
        GROUP BY name, prefix
        ORDER BY priority ASC
    '''
    rows = fetch_all(query)

    for row in rows:
        if row['prefix'] and \
           input_data.startswith(row['prefix']):
            return {
                'name'          : row['name'],
                'confidence'    : row['base_confidence'],
                'category'      : row['category'],
                'charset'       : row['charset'],
                'output_format' : row['output_format'],
                'collision_risk': row['collision_risk'],
                'ambiguous_with': row['ambiguous_with'],
                'description'   : row['description'],
                'example'       : row['example'],
                'next_step'     : row['next_step'],
                'match_reason'  : f'Prefix match: {row["prefix"]}'
            }
    return None


# ==============================
# STEP 2: CHARSET VALIDATION
# ==============================
def _is_valid_hash_charset(input_data: str) -> bool:
    """
    Hash valid hex charset mein hai?
    KDF prefixes already handled —
    ye sirf hex hashes ke liye hai.
    """
    # Modular crypt format already prefix
    # se handle ho gaya
    if input_data.startswith('$'):
        return False

    # Hex charset check
    hex_pattern = r'^[a-fA-F0-9]+$'
    return bool(re.match(hex_pattern, input_data))


# ==============================
# STEP 3: LENGTH BASED LOOKUP
# ==============================
def _get_candidates_by_length(input_data: str) -> list:
    length = len(input_data)

    query = '''
        SELECT name, hex_length, prefix, charset,
               category, MAX(base_confidence) as base_confidence,
               MIN(priority) as priority,
               output_format, collision_risk,
               ambiguous_with, description,
               example, next_step
        FROM hash_formats
        WHERE hex_length = ?
        AND   prefix IS NULL
        GROUP BY name
        ORDER BY priority ASC, base_confidence DESC
    '''
    rows = fetch_all(query, (length,))

    candidates = []
    for row in rows:
        candidates.append({
            'name'          : row['name'],
            'confidence'    : row['base_confidence'],
            'category'      : row['category'],
            'charset'       : row['charset'],
            'output_format' : row['output_format'],
            'collision_risk': row['collision_risk'],
            'ambiguous_with': row['ambiguous_with'],
            'description'   : row['description'],
            'example'       : row['example'],
            'next_step'     : row['next_step'],
            'match_reason'  : f'Length match: {length} chars'
        })

    return candidates


# ==============================
# STEP 4: CHARSET REFINEMENT
# ==============================
def _refine_by_charset(input_data: str,
                        candidates: list) -> list:
    is_lower = input_data == input_data.lower()
    is_upper = input_data == input_data.upper()

    refined = []
    for candidate in candidates:
        # ✅ Fix: charset candidate dict se lo
        charset = candidate.get('charset', '') or ''
        boost   = 0.0

        if charset == 'lowercase_hex' and is_lower:
            boost = 0.08
        elif charset == 'uppercase_hex' and is_upper:
            boost = 0.08
        elif charset == 'mixed_hex': # 🔥 NAYA LOGIC: Case matter nahi karta
            boost = 0.08
        elif charset == 'lowercase_hex' and is_upper:
            boost = -0.10
        elif charset == 'uppercase_hex' and is_lower:
            boost = -0.10

        candidate['confidence'] = round(
            min(candidate['confidence'] + boost, 0.99),
            4
        )
        # ✅ Fix: charset value bhi show karo
        if charset:
            candidate['match_reason'] += f', Charset: {charset}'

        refined.append(candidate)

    return refined

def _add_context_hints(input_data: str,
                       candidates: list) -> list:
    """
    Context clues se disambiguation karo.
    SM3, Keccak-256, SHA3-256 sab 64 hex hain.
    """
    # Koi hard rule nahi — sirf description add karo
    # Analyst ko context se decide karna hoga

    ambiguous_64 = {
        'SHA-256', 'SHA3-256', 'SM3',
        'Keccak-256', 'BLAKE2s', 'BLAKE3',
        'RIPEMD-256', 'Streebog-256'
    }

    names = [c['name'] for c in candidates]
    overlap = set(names) & ambiguous_64

    if len(overlap) > 1:
        for candidate in candidates:
            if candidate['name'] in overlap:
                candidate['reasons'] = candidate.get(
                    'reasons', []
                ) + [
                    'Context needed: multiple 64-char '
                    'hash algorithms share this length'
                ]

    return candidates


# ==============================
# STEP 5: CONFIDENCE ADJUSTMENT
# ==============================
# ==============================
# STEP 5: CONFIDENCE ADJUSTMENT
# ==============================
def _adjust_confidence(input_data: str, candidates: list) -> list:
    # 1. Ambiguous Lengths Definition
    AMBIGUOUS_LENGTHS = {2: 0.60, 4: 0.72,8: 0.72, 16: 0.72, 32: 0.75, 40: 0.75, 56: 0.75, 64: 0.75, 96: 0.75, 128: 0.75}
    
    # 2. Priority Map (Standard vs Specialized)
    # Rank 1: Jo hum hamesha pehle dekhna chahte hain
    PRIORITY_MAP = {
        'SHA-256': 1, 'SM3': 1, 'MD5': 1, 'SHA-1': 1, 'NTLM': 1, 'SHA-512': 1,'ssdeep (Fuzzy Hash)': 1,'yescrypt': 1,
        'SHA3-256': 2, 'Keccak-256': 2, 'Keccak-512': 2,'BLAKE2s': 2,'MD6': 2,'BLAKE2b': 2,'SHA3-512': 2,'SHA3-384': 2,'Keccak-384': 2, 'Keccak-224': 2,
        'HMAC-SHA256': 2, 'HMAC-MD5': 2, 'HMAC-SHA1': 2, 'HMAC-SHA512': 2, 'CMAC-AES128': 2,'scrypt': 2, 'Yescrypt': 2,'CMAC-AES (64-bit)': 2,
        'RIPEMD-256': 3, 'SHA-224': 3,'SHA-0': 3,'MD2': 3,'MD4': 2,'LM Hash': 3,'RIPEMD-160': 3,'SHA-0': 3,
        'RIPEMD-320': 3, 'RIPEMD-128': 3,'SHA-224': 3,'Whirlpool': 3, 'Streebog-512': 3,'SHAKE256 (XOF)': 3, 'SHAKE128 (XOF)': 3,'HAS-160': 3,
        'Snefru-256': 3, 'Snefru-128': 3,'GOST R 34.11-94': 3, 'Streebog-256': 3,'HMAC-MD4': 3, 'HMAC-RIPEMD160': 3,
        # Rank 4: Checksums
        'CRC8': 4, 'Fletcher-8': 4, 'XOR-8 / Checksum-8': 4, 'CRC16': 4,'Fletcher-16': 4,'Fletcher-64': 4, 'Fletcher-32': 4,'CRC16': 4,
        'CRC32': 4,'CRC64': 4,'Adler-32': 4,'TCP/IP Checksum': 4

    }

    input_len = len(input_data)

    for candidate in candidates:
        name = candidate['name']

        # 🔥 STEP A: EQUALIZER (The Fix)
        # Agar length 64 (ya any ambiguous) hai, toh DB ka purana score hatao 
        # aur sabko 0.70 se shuru karo. Isse "Noise" khatam ho jayegi.
        if input_len in AMBIGUOUS_LENGTHS:
            candidate['confidence'] = 0.70 
        
        # STEP B: STRUCTURAL BOOST
        candidate['confidence'] += 0.10 # Sab 0.80 par aa gaye

        # STEP C: COMMON HASH BOOST
        # SHA-256 aur SM3 ko extra edge do
        if name in ['SHA-256', 'SM3', 'MD5', 'SHA-1']:
            candidate['confidence'] += 0.05 # Ab ye 0.85 ho gaye

        # STEP D: APPLY STRICT CAP
        if input_len in AMBIGUOUS_LENGTHS:
            max_conf = AMBIGUOUS_LENGTHS[input_len]
            if candidate['confidence'] > max_conf:
                candidate['confidence'] = max_conf # Sab 0.75 par tie ho gaye!

        # Final rounding
        candidate['confidence'] = round(max(0.40, min(candidate['confidence'], 0.99)), 4)

    # 🔥 STEP E: FINAL SORTING (No Rounding needed here now)
    # 1. Confidence (Highest first)
    # 2. Priority Map (Lower rank first: 1 > 2)
    # 3. Name (Alphabetical)
    candidates.sort(key=lambda x: (
        -x['confidence'], 
        PRIORITY_MAP.get(x['name'], 99), 
        x['name']
    ))
    
    return candidates


# ==============================
# HELPERS
# ==============================

import re

import re


                
def _build_result(candidates: list) -> dict:
    """
    Final result dict build karta hai.
    """
    if not candidates:
        return _empty_result()

    top       = candidates[0]
    ambiguous = len(candidates) > 1

    return {
        'detected'   : True,
        'candidates' : candidates,
        'top'        : top,
        'ambiguous'  : ambiguous,
        'input_len'  : 0
    }


def _empty_result() -> dict:
    return {
        'detected'   : False,
        'candidates' : [],
        'top'        : None,
        'ambiguous'  : False,
        'input_len'  : 0
    }


# ==============================
# OUTPUT FORMATTER
# ==============================
def format_hash_result(result: dict,
                        input_data: str) -> str:
    """
    Hash detection result ko
    CLI output format mein convert karta hai.
    """
    lines = []
    sep   = "─" * 54

    if not result['detected']:
        return ""

    lines.append(sep)
    lines.append("  PILLAR B — HASH DETECTION")
    lines.append(sep)

    top = result['top']

    if not result['ambiguous']:
        # Single result
        lines.append(f"  Type        : {top['name']}")
        lines.append(f"  Category    : {top['category']}")
        lines.append(f"  Confidence  : "
                     f"{int(top['confidence'] * 100)}%")
        lines.append(f"  Reason      : {top['match_reason']}")

        if top['collision_risk'] and \
           top['collision_risk'] != 'low':
            lines.append(
                f"  ⚠ Risk      : "
                f"Collision risk — {top['collision_risk'].upper()}"
            )

        if top['next_step']:
            lines.append(f"  Next Step   : {top['next_step']}")

    else:
        # Multiple candidates
        lines.append("  [!] Ambiguous — Multiple Candidates:")
        lines.append("")
        lines.append(
            f"  {'Type':<20} {'Confidence':<12} {'Risk'}"
        )
        lines.append(f"  {'─'*20} {'─'*12} {'─'*8}")

        for c in result['candidates']:
            conf = f"{int(c['confidence'] * 100)}%"
            risk = c.get('collision_risk') or 'N/A'
            lines.append(
                f"  {c['name']:<20} {conf:<12} {risk}"
            )

        lines.append("")
        lines.append(
            f"  Reason    : {top['match_reason']}"
        )
        lines.append(
            "  Next Step : Context check karo — "
            "source application kya hai?"
        )

    lines.append(sep)
    return "\n".join(lines)