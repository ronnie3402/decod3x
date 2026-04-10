import re
from utils.db_connector import fetch_all
from utils.entropy      import entropy_summary
from utils.chi_square   import full_randomness_analysis


# ==============================
# CONSTANTS
# ==============================
ENTROPY_THRESHOLD_ENCRYPTED   = 7.85
ENTROPY_THRESHOLD_COMPRESSED  = 7.20
MIN_BYTES_FOR_ENTROPY          = 64   # Entropy reliable
                                       # tab hoti hai


# ==============================
# CORE DETECTION
# ==============================
def detect_encryption(input_data) -> dict:
    """
    Input data ko analyze karke encrypted/compressed/container identify karta hai.
    Standard Version: Strings ko UTF-8 handle karta hai, Bytes ko as-is.
    """
    try:
        if isinstance(input_data, str):
            # Wapas normal behavior: String ko bytes mein badlo
            raw = input_data.encode('utf-8', errors='replace')
        else:
            raw = input_data
    except Exception:
        return _empty_result()

    if not raw: 
        return _empty_result()

    # Step 1: Magic Bytes (Forensic Check)
    # Ye standalone binary files ya Hex-decoded output par perfectly chalega
    magic_result = _check_magic_bytes(raw)
    if magic_result: 
        return _build_result([magic_result], method='magic_bytes')

    # Step 2: Text-based Headers (PGP/PEM)
    if isinstance(input_data, str):
        pgp_res = _check_pgp_header(input_data)
        if pgp_res: return _build_result([pgp_res], method='pgp_header')
        
        pem_res = _check_pem_header(input_data)
        if pem_res: return _build_result([pem_res], method='pem_header')

    # Step 3: Entropy (Bade strings ke liye)
    if len(raw) >= MIN_BYTES_FOR_ENTROPY:
        entropy_res = _check_entropy(raw)
        if entropy_res: return _build_result([entropy_res], method='entropy')

    return _empty_result()


# ==============================
# STEP 1: MAGIC BYTES CHECK
# ==============================
def _check_magic_bytes(raw: bytes):
    """
    File signature database se
    magic bytes match karta hai.
    High confidence — instant result.
    """
    query = '''
        SELECT name, hex_sig, byte_offset,
               file_type, category,
               confidence, priority,
               description, example, next_step
        FROM magic_bytes
        ORDER BY priority ASC, confidence DESC
    '''
    rows = fetch_all(query)

    for row in rows:
        sig_hex = row['hex_sig'].replace(' ', '')

        try:
            sig_bytes = bytes.fromhex(sig_hex)
        except ValueError:
            continue

        offset = row['byte_offset'] or 0

        # Offset pe signature match karo
        if raw[offset: offset + len(sig_bytes)] == sig_bytes:
            # ✅ Fix: PEM match mila lekin
            # pehle PGP check karo
            if row['file_type'] == 'pem' or row['name'] == 'PEM Header':
                pgp_check = _check_pgp_in_raw(raw)
                if pgp_check:
                    return pgp_check

            return {
                'name'        : row['name'],
                'confidence'  : row['confidence'],
                'category'    : row['category'],
                'file_type'   : row['file_type'],
                'description' : row['description'],
                'next_step'   : row['next_step'],
                'indicators'  : [
                    f'Magic bytes match: {row["hex_sig"]}',
                    f'Offset: {row["file_type"]}'
                ],
                'method'      : 'magic_bytes'
            }

    return None

def _check_pgp_in_raw(raw: bytes):
    """
    Raw bytes mein PGP keyword
    check karta hai.
    PEM match ke baad call hota hai.
    """
    try:
        # Pehle 100 bytes text mein convert karo
        header_text = raw[:100].decode(
            'utf-8', errors='ignore'
        ).upper()
    except Exception:
        return None

    if 'BEGIN PGP' not in header_text:
        return None

    # PGP type identify karo
    pgp_type  = 'PGP Armored Data'
    next_step = 'gpg --decrypt file.gpg'

    if 'MESSAGE' in header_text:
        pgp_type  = 'PGP Encrypted Message'
        next_step = 'gpg --decrypt file.gpg'
    elif 'PUBLIC KEY' in header_text:
        pgp_type  = 'PGP Public Key'
        next_step = 'gpg --import key.gpg'
    elif 'PRIVATE KEY' in header_text:
        pgp_type  = 'PGP Private Key'
        next_step = 'gpg --import privatekey.gpg'
    elif 'SIGNATURE' in header_text:
        pgp_type  = 'PGP Signature'
        next_step = 'gpg --verify signature.gpg'

    return {
        'name'        : pgp_type,
        'confidence'  : 0.99,
        'category'    : 'Encrypted',
        'file_type'   : 'pgp',
        'description' : 'PGP armored format detected '
                        'via BEGIN PGP header.',
        'next_step'   : next_step,
        'indicators'  : [
            '-----BEGIN PGP header detected',
            f'Type: {pgp_type}'
        ],
        'method'      : 'pgp_header'
    }

def _check_pgp_header(input_data: str):
    """
    PGP Armored format detect karta hai.
    -----BEGIN PGP ... -----
    """
    pgp_pattern = r'-----BEGIN PGP[\w\s]+-----'

    if re.search(pgp_pattern, input_data.upper()):

        pgp_type = 'PGP Armored Data'

        if 'MESSAGE' in input_data.upper():
            pgp_type = 'PGP Encrypted Message'
        elif 'PUBLIC KEY' in input_data.upper():
            pgp_type = 'PGP Public Key'
        elif 'PRIVATE KEY' in input_data.upper():
            pgp_type = 'PGP Private Key'
        elif 'SIGNATURE' in input_data.upper():
            pgp_type = 'PGP Signature'

        return {
            'name'        : pgp_type,
            'confidence'  : 0.99,
            'category'    : 'Encrypted',
            'file_type'   : 'pgp',
            'description' : 'PGP armored format detected.',
            'next_step'   : 'gpg --decrypt file.gpg',
            'indicators'  : [
                '-----BEGIN PGP header detected',
                f'Type: {pgp_type}'
            ],
            'method'      : 'pgp_header'
        }

    return None


# ==============================
# STEP 2: PEM HEADER CHECK
# ==============================
def _check_pem_header(input_data: str):
    """
    PEM format detect karta hai.
    -----BEGIN ... -----
    """
    pem_pattern = r'-----BEGIN\s+[\w\s]+-----'

    if re.search(pem_pattern, input_data):
        # Kaunsa type hai identify karo
        pem_type = 'PEM Data'

        if 'CERTIFICATE' in input_data.upper():
            pem_type = 'PEM Certificate'
        elif 'PRIVATE KEY' in input_data.upper():
            pem_type = 'PEM Private Key'
        elif 'PUBLIC KEY' in input_data.upper():
            pem_type = 'PEM Public Key'
        elif 'ENCRYPTED' in input_data.upper():
            pem_type = 'PEM Encrypted Data'
        elif 'PGP' in input_data.upper():
            pem_type = 'PGP Armored Data'

        return {
            'name'        : pem_type,
            'confidence'  : 0.99,
            'category'    : 'Cryptographic',
            'file_type'   : 'pem',
            'description' : 'PEM format with -----BEGIN header.',
            'next_step'   : 'openssl x509 -in file.pem -text',
            'indicators'  : [
                '-----BEGIN header detected',
                f'Type: {pem_type}'
            ],
            'method'      : 'pem_header'
        }

    return None


# ==============================
# STEP 3: ENTROPY BASED CHECK
# ==============================
def _check_entropy(raw: bytes):
    """
    Shannon entropy + Chi-Square
    combine karke classification karta hai.

    DB ke entropy_profiles se match karta hai.
    """
    # Full analysis karo
    analysis = full_randomness_analysis(raw)
    entropy  = analysis['entropy']
    verdict  = analysis['verdict']

    # DB se matching profile dhundo
    profile = _match_entropy_profile(entropy, verdict)

    if not profile:
        return None

    # Only encrypted ya compressed report karo
    if profile['category'] not in ('encrypted', 'compressed'):
        return None

    indicators = [
        f'Entropy     : {entropy}',
        f'Chi-Square  : {analysis["chi_square"]}',
        f'Distribution: {analysis["distribution"]}',
        f'Verdict     : {verdict}'
    ]

    return {
        'name'        : profile['label'],
        'confidence'  : _calculate_entropy_confidence(
                            entropy, profile
                        ),
        'category'    : profile['category'].capitalize(),
        'file_type'   : 'unknown',
        'description' : profile['description'],
        'next_step'   : _get_entropy_next_step(
                            profile['category']
                        ),
        'indicators'  : indicators,
        'method'      : 'entropy'
    }


def _match_entropy_profile(entropy: float,
                            verdict: str):
    """
    Entropy value ko DB profiles se match karta hai.
    """
    query = '''
        SELECT label, min_entropy, max_entropy,
               chi_sq_type, byte_dist, category,
               confidence, description
        FROM entropy_profiles
        WHERE min_entropy <= ?
        AND   max_entropy >= ?
        ORDER BY confidence DESC
    '''
    rows = fetch_all(query, (entropy, entropy))

    if not rows:
        return None

    # Verdict se best match dhundo
    for row in rows:
        if verdict == 'encrypted' and \
           row['category'] == 'encrypted':
            return row
        if verdict == 'compressed' and \
           row['category'] == 'compressed':
            return row

    # Direct match nahi mila — best available lo
    return rows[0]


def _calculate_entropy_confidence(entropy: float,
                                   profile) -> float:
    """
    Entropy value profile ke center se
    kitna door hai — confidence calculate karo.
    """
    base_conf = profile['confidence']

    # Profile ke center pe maximum confidence
    center    = (profile['min_entropy'] +
                 profile['max_entropy']) / 2
    distance  = abs(entropy - center)
    max_dist  = (profile['max_entropy'] -
                 profile['min_entropy']) / 2

    if max_dist == 0:
        return base_conf

    # Center pe 100%, edges pe base_conf
    ratio      = 1 - (distance / max_dist)
    confidence = base_conf * (0.7 + 0.3 * ratio)

    return round(min(confidence, 0.99), 4)


def _get_entropy_next_step(category: str) -> str:
    steps = {
        'encrypted'  : 'Identify encryption algorithm. '
                       'Check for magic bytes manually. '
                       'Use binwalk for deeper analysis.',
        'compressed' : 'Try 7zip/WinRAR to decompress. '
                       'Use binwalk to identify format.',
    }
    return steps.get(category, 'Manual analysis recommended.')


# ==============================
# HELPERS
# ==============================
def _build_result(candidates: list,
                  method: str = '') -> dict:
    if not candidates:
        return _empty_result()

    top       = candidates[0]
    ambiguous = len(candidates) > 1

    return {
        'detected'   : True,
        'candidates' : candidates,
        'top'        : top,
        'method'     : method,
        'ambiguous'  : ambiguous,
    }


def _empty_result() -> dict:
    return {
        'detected'   : False,
        'candidates' : [],
        'top'        : None,
        'method'     : '',
        'ambiguous'  : False,
    }


# ==============================
# OUTPUT FORMATTER
# ==============================
def format_encryption_result(result: dict) -> str:
    """
    Encryption result ko CLI output
    format mein convert karta hai.
    """
    lines = []
    sep   = "─" * 54

    if not result['detected']:
        return ""

    lines.append(sep)
    lines.append("  PILLAR C — ENCRYPTION DETECTION")
    lines.append(sep)

    top    = result['top']
    method = result['method']

    lines.append(f"  Type        : {top['name']}")
    lines.append(f"  Category    : {top['category']}")
    lines.append(
        f"  Confidence  : {int(top['confidence'] * 100)}%"
    )
    lines.append(
        f"  Method      : {method.replace('_', ' ').title()}"
    )

    # Indicators
    if top.get('indicators'):
        lines.append("")
        lines.append("  Indicators  :")
        for ind in top['indicators']:
            lines.append(f"    → {ind}")

    # Description
    if top.get('description'):
        lines.append("")
        lines.append(f"  Description : {top['description']}")

    # Next step
    if top.get('next_step'):
        lines.append("")
        lines.append(f"  Next Step   : {top['next_step']}")

    lines.append(sep)
    return "\n".join(lines)