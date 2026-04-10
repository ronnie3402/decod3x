from engine.pillar_a import detect_encoding
from engine.pillar_b import detect_hash
from engine.pillar_c import detect_encryption
from engine.pillar_d import detect_cipher


# ==============================
# CONSTANTS
# ==============================
CONFIDENCE_HIGH   = 0.80   # Green
CONFIDENCE_MEDIUM = 0.60   # Yellow
CONFIDENCE_LOW    = 0.40   # Red

# Category priority order
# (Pehle kaunsa pillar check ho)
PILLAR_PRIORITY = [
    'encryption',   # Magic bytes → instant, reliable
    'hash',         # Prefix/length → fast, reliable
    'encoding',     # Regex → moderate
    'cipher',       # IC/stats → slowest
]


# ==============================
# MAIN SCORER
# ==============================
def run_all_pillars(input_data) -> dict:
    """
    Saare pillars run karta hai aur
    best result return karta hai.

    Returns:
    {
        'category'    : str,
        'result'      : dict,
        'confidence'  : float,
        'confidence_label': str,
        'all_results' : dict,
        'ambiguous'   : bool,
    }
    """
    all_results = {}

    # String input ke liye
    try:
        if isinstance(input_data, str):
            input_str = input_data.strip()
            input_bytes = input_str.encode(
                'utf-8', errors='replace'
            )
        else:
            input_str   = None
            input_bytes = input_data

    except Exception:
        return _unknown_result(input_data)

    # ── Pillar C: Encryption (Magic bytes → fast) ──
    try:
        enc_result = detect_encryption(input_bytes)
        if enc_result['detected']:
            all_results['encryption'] = enc_result
    except Exception:
        pass

    # ── Pillar B: Hash ──
    try:
        if input_str:
            hash_result = detect_hash(input_str)
            if hash_result['detected']:
                all_results['hash'] = hash_result
    except Exception:
        pass   

    # ── Pillar A: Encoding ──
    try:
        if input_str:
            enc_result2 = detect_encoding(input_str)
            if enc_result2['detected']:
                all_results['encoding'] = enc_result2
    except Exception:
        pass            

    # ── Pillar D: Classical Cipher ──
    try:
        if input_str:
            cipher_result = detect_cipher(input_str)
            if cipher_result['detected']:
                all_results['cipher'] = cipher_result
    except Exception:
        pass

    # Koi bhi detect nahi hua
    if not all_results:
        return _unknown_result(input_data)
    
    
    try:
        if input_str:
            all_results = resolve_conflicts(
                all_results, input_str
            )
    except Exception:
        pass
    # Best result choose karo
    try:
        best = _choose_best(all_results)
    except Exception:
        return _unknown_result(input_data)

    return best


# ==============================
# BEST RESULT SELECTOR
# ==============================
def _choose_best(all_results: dict) -> dict:
    """
    Sare pillars mein se best match dhoondhta hai aur 
    ambiguity check karta hai.
    """
    if not all_results:
        return {'category': 'unknown', 'confidence': 0.0, 'result': None, 'ambiguous': False}

    # 1. Sabhi pillars ke top candidates ki ek list banao
    pillar_tops = []
    for cat, res in all_results.items():
        top_cand = res['top']
        top_cand['category'] = cat
        pillar_tops.append(top_cand)

    # 2. Confidence ke hisaab se sort karo
    pillar_tops.sort(key=lambda x: x['confidence'], reverse=True)

    top_winner = pillar_tops[0]
    ambiguous  = False

    # 3. AMBIGUITY CHECK (The Secret Sauce)
    # Agar 2 ya usse zyada candidates ka confidence gap < 0.15 hai, 
    # toh wo ambiguous hai.
    if len(pillar_tops) > 1:
        gap = abs(pillar_tops[0]['confidence'] - pillar_tops[1]['confidence'])
        if gap < 0.15:
            ambiguous = True
    
    # 4. Intra-Pillar Ambiguity Check 
    # (Agar winning pillar ke andar hi multiple close candidates hain)
    winning_cat = top_winner['category']
    win_pillar_res = all_results[winning_cat]
    if len(win_pillar_res.get('candidates', [])) > 1:
        p_gap = abs(win_pillar_res['candidates'][0]['confidence'] - 
                    win_pillar_res['candidates'][1]['confidence'])
        if p_gap < 0.10:
            ambiguous = True

    return {
        'category'   : winning_cat,
        'confidence' : top_winner['confidence'],
        'result'     : win_pillar_res,
        'ambiguous'  : ambiguous,
        'all_results': all_results
    }


# ==============================
# CONFIDENCE HELPERS
# ==============================
def get_confidence_label(confidence: float) -> str:
    """
    Confidence score ko label mein convert karo.
    """
    if confidence >= CONFIDENCE_HIGH:
        return 'HIGH'
    elif confidence >= CONFIDENCE_MEDIUM:
        return 'MEDIUM'
    else:
        return 'LOW'


def get_confidence_color(confidence: float) -> str:
    """
    Confidence ke basis pe color return karo.
    Colors.py se match karta hai.
    """
    label = get_confidence_label(confidence)
    color_map = {
        'HIGH'  : 'green',
        'MEDIUM': 'yellow',
        'LOW'   : 'red'
    }
    return color_map.get(label, 'white')


# ==============================
# UNKNOWN RESULT
# ==============================
def _unknown_result(input_data) -> dict:
    """
    Kuch bhi detect nahi hua.
    """
    return {
        'category'        : 'unknown',
        'result'          : None,
        'confidence'      : 0.0,
        'confidence_label': 'LOW',
        'all_results'     : {},
        'ambiguous'       : False,
    }


# ==============================
# CONFLICT RESOLVER
# ==============================
# ==============================
# CONFLICT RESOLVER
# ==============================
def resolve_conflicts(all_results: dict, input_str: str) -> dict:
    if 'hash' not in all_results or 'encoding' not in all_results:
        return all_results

    input_len = len(input_str.strip())
    hash_lengths = {8, 32, 40, 48, 56, 64, 96, 128}

    # KDF Check
    if all_results['hash']['top'].get('category') == 'kdf':
        all_results['hash']['top']['confidence'] = 0.99
        del all_results['encoding']
        return all_results

    # Global Hash-Length Cap for Encodings
    if input_len in hash_lengths:
        top_enc = all_results['encoding']['top']
        # Agar exact hash length hai, toh encoding ko 0.70 par le aao
        # Isse Hash (jo 0.72-0.78 ke beech hoga) hamesha winner banega
        if top_enc['name'] in ['Hex', 'Base64']:
            all_results['encoding']['top']['confidence'] = 0.70
            all_results['encoding']['top']['reasons'].append("De-prioritized against Hash length")

    return all_results