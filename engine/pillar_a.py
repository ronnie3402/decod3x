import re
import math
from utils.db_connector import fetch_all


# ==============================
# CONSTANTS
# ==============================
MIN_PRINTABLE_RATIO = 0.85  # Decoded output mein
                             # kitne % printable chars
                             # hone chahiye


# ==============================
# CORE DETECTION
# ==============================
def detect_encoding(input_data: str) -> dict:
    """
    Input string ko analyze karke
    encoding type identify karta hai.

    Returns:
    {
        'detected'   : bool,
        'candidates' : list,
        'top'        : dict,
        'ambiguous'  : bool,
    }
    """
    try:
        input_data = input_data.strip()

    except AttributeError:
        return _empty_result()

    if not input_data:
        return _empty_result()

    # Step 1: DB se saare patterns load karo
    try:
        patterns = _load_patterns()

    except Exception:
        return _empty_result()

    if not patterns:
        return _empty_result()

    # Step 2: Har pattern ke against match karo
    candidates = []
    for pattern in patterns:
        try:
            result = _match_pattern(input_data, pattern)
            if result:
                candidates.append(result)

        except Exception:
            continue  # ← Ek pattern fail → skip, crash nahi

    if not candidates:
        return _empty_result()

    # Step 3: Silent decode validation
    try:
        candidates = _validate_candidates(input_data, candidates)
        candidates = _filter_false_positives(candidates)

    except Exception:
        return _empty_result()

    if not candidates:
        return _empty_result()

    # Step 5: Sort by confidence
    candidates.sort(
        key=lambda x: x['confidence'],
        reverse=True
    )

    return _build_result(candidates)


# ==============================
# STEP 1: LOAD PATTERNS FROM DB
# ==============================
def _load_patterns() -> list:
    query = '''
        SELECT name, regex, min_length, max_length,
               padding_char, length_multiple,
               MAX(base_confidence) as base_confidence,
               MIN(priority) as priority,
               description, example, notes
        FROM encoding_signatures
        GROUP BY name
        ORDER BY priority ASC, base_confidence DESC
    '''
    rows = fetch_all(query)

    patterns = []
    for row in rows:
        patterns.append({
            'name'           : row['name'],
            'regex'          : row['regex'],
            'min_length'     : row['min_length'],
            'max_length'     : row['max_length'],
            'padding_char'   : row['padding_char'],
            'length_multiple': row['length_multiple'],
            'confidence'     : row['base_confidence'],
            'priority'       : row['priority'],
            'description'    : row['description'],
            'example'        : row['example'],
            'notes'          : row['notes']
        })

    return patterns


# ==============================
# STEP 2: PATTERN MATCHING
# ==============================
def _match_pattern(input_data: str, pattern: dict):

    name    = pattern['name']
    reasons = []
    boost   = 0.0

 
    check_data = input_data.strip()
    
    if name == 'Base32':
        check_data = check_data.replace(' ', '')
    elif name == 'Binary':
        import re
        check_data = re.sub(r'[\s,:;]+', '', check_data)
    elif name == 'Hex':
        import re
        # Bulletproof Stripper: Galti se bhi asli characters nahi udayega
        check_data = check_data.replace('0x', '').replace('0X', '')
        check_data = check_data.replace('\\x', '').replace('\\X', '')
        check_data = check_data.replace('%', '')
        check_data = re.sub(r'[\s,:;]+', '', check_data)
    
    if name == 'HTML Entity':
        check_data = check_data.strip()

    # Check 1: Min length
    if len(check_data) < (pattern['min_length'] or 1):
        return None

    # Check 2: Max length
    if pattern['max_length'] and len(check_data) > pattern['max_length']:
        return None
    
   
    try:
        import re
        # DB se regex lekar uske anchors (^ aur $) hatao taaki fullmatch confuse na ho
        clean_regex = pattern['regex'].strip('^$')
        
        if name == 'HTML Entity':
            if not re.fullmatch(r'(' + clean_regex + r')+', check_data):
                return None
        else:
            if not re.fullmatch(clean_regex, check_data):
                return None
    except Exception:
        return None

    
    
    reasons.append('Charset match')

    # Check 4: Padding validation
    if pattern['padding_char']:
        padding_valid = _check_padding(
            check_data,             # input_data ki jagah check_data bhejo taaki space errors na aayein
            pattern['padding_char'],
            name                    # 🔥 Naya parameter: Name bhejo
        )
        if not padding_valid:
            return None
        reasons.append('Padding valid')
        boost += 0.05


    # Check 5: Length multiple validation
    if pattern['length_multiple']:
        if len(check_data) % pattern['length_multiple'] != 0:
            
            if 'Base64' in name or name == 'Base32':
                # Reject nahi karenge, par multiple wala boost bhi nahi denge
                reasons.append('Unpadded length (Valid in JWT/URLs)')
            else:
                return None  # Hex aur Binary ko reject kar do
        else:
            reasons.append(f'Length % {pattern["length_multiple"]} == 0')
            boost += 0.05

    final_confidence = round(
        min(pattern['confidence'] + boost, 0.99),
        4
    )

    return {
        'name'        : name,
        'confidence'  : final_confidence,
        'reasons'     : reasons,
        'description' : pattern['description'],
        'example'     : pattern['example'],
        'notes'       : pattern['notes'],
        'validated'   : False
    }



# ==============================
# STEP 3: PADDING CHECK
# ==============================
def _check_padding(input_data: str, padding_char: str, name: str) -> bool:
    """
    Padding structure sahi hai?
    Base64 (max 2) aur Base32 (max 6) ke liye padding check.
    """
    # Padding sirf end mein honi chahiye
    stripped = input_data.rstrip(padding_char)

    # Original se zyada padding nahi honi chahiye
    padding_count = len(input_data) - len(stripped)

    # Base64 mein max 2 padding allowed hai
    if name == 'Base64' and padding_count > 2:
        return False
    
    # Base32 mein max 6 padding allowed hai
    if name == 'Base32' and padding_count > 6:
        return False

    return True


# ==============================
# STEP 4: SILENT DECODE VALIDATION
# ==============================
def _validate_candidates(input_data: str,
                         candidates: list) -> list:
    """
    Har candidate ke liye silent decode test.
    """
    validated = []

    for candidate in candidates:
        name   = candidate['name']
        result = _silent_decode(input_data, name)

        
        if name == 'URL Encoding':
            if '%' not in input_data:
                continue

        
        if name == 'Base32':
            import re
            clean = re.sub(r'\s+', '', input_data).upper()
            if not re.match(r'^[A-Z2-7]+=*$', clean):
                continue
            
            common_words = {'this', 'that', 'with', 'from', 'normal', 'plain'}
            words = input_data.lower().split()
            if any(w in common_words for w in words):
                continue

        
        if name == 'Base64':
            import re
            # Agar string sirf Hex characters (0-9, a-f) se bani hai aur lambi hai
            # Toh high chance hai ki wo Hash hai, Base64 nahi.
            if re.match(r'^[0-9a-fA-F]+$', input_data) and len(input_data) > 10:
                candidate['confidence'] -= 0.15  # Penalty: 0.75 - 0.15 = 0.60
                candidate['reasons'].append('Penalty: Looks like pure Hex/Hash')


        if 'Base85' in name or name == 'Base91':
            import re
            # Agar string mein sirf Alphanumeric hain (koi special character nahi hai)
            if re.match(r'^[A-Za-z0-9]+$', input_data):
                candidate['confidence'] -= 0.15  # Bhayankar penalty
                candidate['reasons'].append('Penalty: Lacks special chars, likely Base62/58')

        
        if name == 'Base64 (URL Safe)':
            # Agar string mein URL-safe ke specific characters (- ya _) nahi hain
            if '-' not in input_data and '_' not in input_data:
                candidate['confidence'] -= 0.05  # Penalty taaki Standard Base64 jeet jaye
                candidate['reasons'].append('Penalty: Lacks specific chars (- or _)')

        if name == 'Base64 (Atom128)':
            # Standard aur Atom128 almost same dikhte hain. 
            # Atom128 ko hamesha thoda dabakar rakho jab tak explicitly prove na ho jaye.
            candidate['confidence'] -= 0.05
            candidate['reasons'].append('De-prioritized against Standard Base64')
        

        
        if result['success']:
            # Validation pass hone par boost
            candidate['confidence'] = round(
                min(candidate['confidence'] + 0.08, 0.99), 4
            )
            candidate['validated'] = True
            candidate['reasons'].append('Decode validation passed')
            validated.append(candidate)

        elif result['partial']:
            candidate['confidence'] = round(
                max(candidate['confidence'] - 0.20, 0.30), 4
            )
            candidate['validated'] = False
            candidate['reasons'].append('Partial decode')
            validated.append(candidate)

    return validated

def _silent_decode(input_data: str, encoding: str) -> dict:
    """
    Internally decode karta hai —
    output user ko nahi dikhata.
    Sirf success/fail return karta hai.
    """
    try:
        decoded = None

        if encoding == 'Base64':
            import base64
            # Padding fix karo agar missing ho
            padded = input_data + '=' * (
                -len(input_data) % 4
            )
            decoded = base64.b64decode(padded)

        
        elif encoding == 'Base64 (URL Safe)':
            import base64
            padded = input_data + '=' * (-len(input_data) % 4)
            # Python ka built-in urlsafe decoder use karo
            decoded = base64.urlsafe_b64decode(padded)

        elif encoding == 'Base64 (Atom128)':
            import base64
            # Standard Base64 Alphabet
            std_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            # Atom128 Alphabet
            atom_alpha = "/128GhIoPQROSTeUbADfgHijKLM+n0pFWXYZaBcdeC456789VmAqtSszKkNJrwtv"
            
            # Custom alphabet ko standard alphabet mein map karo
            trans = str.maketrans(atom_alpha, std_alpha)
            mapped_data = input_data.translate(trans)
            
            padded = mapped_data + '=' * (-len(mapped_data) % 4)
            decoded = base64.b64decode(padded)
        

        elif encoding == 'Base32':
            import base64
            # Uppercase enforce karo
            clean  = input_data.replace(' ', '').upper().strip()
            # Padding fix karo
            padded = clean + '=' * (-len(clean) % 8)
            decoded = base64.b32decode(padded, casefold=True)

        
        elif encoding == 'Base85 (Standard)':
            import base64
            
            clean_data = input_data.replace('<~', '').replace('~>', '')
            decoded = base64.a85decode(clean_data)

        elif encoding == 'Base85 (IPv6)':
            import base64
            
            clean_data = input_data.replace('<~', '').replace('~>', '')
            decoded = base64.b85decode(clean_data)

        elif encoding in ['Base45', 'Base62', 'Base91', 'Base85 (Z85)']:

            return {'success': False, 'partial': False}
        elif encoding == 'Hex':
            import re
            clean_hex = input_data.replace('0x', '').replace('0X', '')
            clean_hex = clean_hex.replace('\\x', '').replace('\\X', '')
            clean_hex = clean_hex.replace('%', '')
            clean_hex = re.sub(r'[\s,:;]+', '', clean_hex)
            
            try:
                decoded = bytes.fromhex(clean_hex)
            except ValueError:
                return {'success': False, 'partial': False}

        elif encoding == 'URL Encoding':
            from urllib.parse import unquote
            decoded = unquote(input_data).encode()

        elif encoding == 'HTML Entity':
            import html
            decoded = html.unescape(input_data).encode()

        elif encoding == 'Binary':
            import re
            # Saare delimiters hatao
            clean = re.sub(r'[\s,:;]+', '', input_data)
            if len(clean) % 8 == 0:
                chunks = [clean[i:i+8] for i in range(0, len(clean), 8)]
                decoded = bytes([int(c, 2) for c in chunks])

        elif encoding == 'Octal':
            import re
            # Split by space, comma, colon, or semicolon (Filter out empty strings)
            parts = re.split(r'[\s,:;]+', input_data.strip())
            decoded = bytes([int(p, 8) for p in parts if p])

        
        elif encoding in ['Base45', 'Base62', 'Base91']:
            # Python standard library mein inke built-in decoders nahi hain.
            # Kyunki input ne Strict Regex test pass kar liya hai, 
            # hum isko triage ke liye valid (True) maan lenge.
            return {'success': True, 'partial': False}
        

        else:
            # Unknown encoding — partial success
            return {'success': False, 'partial': True}

        if decoded is None:
            return {'success': False, 'partial': False}

        # Decoded output printable hai?
        printable = _is_printable(decoded)

        if printable:
            return {'success': True, 'partial': False}
        else:
            return {'success': False, 'partial': True}

    except Exception:
        return {'success': False, 'partial': False}


def _decode_base58(input_data: str) -> bytes:
    """
    Base58 decode — supports both Bitcoin and Ripple alphabets.
    """
    bitcoin_alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    ripple_alphabet  = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'

    def decode_with(alphabet):
        base_count = len(alphabet)
        num = 0
        for char in input_data:
            if char not in alphabet:
                raise ValueError(f'Invalid Base58 char: {char}')
            num = num * base_count + alphabet.index(char)

        result = []
        while num > 0:
            result.append(num % 256)
            num //= 256

        # Leading 1s (Bitcoin) ya rs (Ripple) -> leading zero bytes
        for char in input_data:
            if char == alphabet[0]:
                result.append(0)
            else:
                break
        return bytes(reversed(result))

    # 1. Pehle Bitcoin alphabet try karo
    try:
        btc_bytes = decode_with(bitcoin_alphabet)
        # Agar output readable hai, toh yehi best match hai!
        if _is_printable(btc_bytes):
            return btc_bytes
    except ValueError:
        pass

    # 2. Agar Bitcoin se gibberish aaya, toh Ripple alphabet try karo
    try:
        xrp_bytes = decode_with(ripple_alphabet)
        return xrp_bytes  # Silent decode ab iska printability check karega
    except ValueError:
        pass

    # 3. Fallback (Agar kuch bhi theek na ho, toh default Bitcoin return karo)
    return decode_with(bitcoin_alphabet)


def _is_printable(data: bytes) -> bool:
    """
    Decoded output human-readable hai?
    Printable ASCII ratio check karta hai.
    """
    if not data:
        return False

    printable_count = sum(
        1 for b in data
        if 32 <= b <= 126 or b in (0, 9, 10, 13) # 🔥 Added 0 (Null Byte)
    )

    ratio = printable_count / len(data)
    return ratio >= MIN_PRINTABLE_RATIO


# ==============================
# STEP 5: FALSE POSITIVE FILTER
# ==============================
def _filter_false_positives(candidates: list) -> list:
    """
    Common false positives filter karta hai.

    Example:
    Short random strings jo Base64
    jaisi lagti hain lekin nahi hain.
    """
    filtered = []

    for candidate in candidates:
        
        if not candidate['validated'] and \
           candidate['confidence'] < 0.70:
            continue

        
        if candidate['confidence'] < 0.40:
            continue

        filtered.append(candidate)

    return filtered


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
def format_encoding_result(result: dict,
                            input_data: str) -> str:
    """
    Encoding result ko CLI output
    format mein convert karta hai.
    """
    lines = []
    sep   = "─" * 54

    if not result['detected']:
        return ""

    lines.append(sep)
    lines.append("  PILLAR A — ENCODING DETECTION")
    lines.append(sep)

    top = result['top']

    if not result['ambiguous']:
        lines.append(f"  Type       : {top['name']}")
        lines.append(
            f"  Confidence : {int(top['confidence'] * 100)}%"
        )
        lines.append(
            f"  Validated  : "
            f"{'✓ Yes' if top['validated'] else '✗ No'}"
        )
        lines.append(
            f"  Reason     : {', '.join(top['reasons'])}"
        )
        if top['notes']:
            lines.append(f"  Notes      : {top['notes']}")

    else:
        lines.append("  [!] Multiple Candidates:")
        lines.append("")
        lines.append(
            f"  {'Type':<20} {'Confidence':<12} {'Validated'}"
        )
        lines.append(
            f"  {'─'*20} {'─'*12} {'─'*10}"
        )

        for c in result['candidates']:
            conf      = f"{int(c['confidence'] * 100)}%"
            validated = '✓' if c['validated'] else '✗'
            lines.append(
                f"  {c['name']:<20} {conf:<12} {validated}"
            )

        lines.append("")
        lines.append(
            f"  Reason : {', '.join(top['reasons'])}"
        )

    lines.append(sep)
    return "\n".join(lines)