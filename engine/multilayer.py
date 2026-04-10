import base64
import binascii
import re
from urllib.parse import unquote
from engine.confidence import run_all_pillars


# ==============================
# CONSTANTS
# ==============================
MAX_DEPTH      = 5     # Maximum recursion depth
MIN_LENGTH     = 4     # Minimum input length
                        # to analyze further


# ==============================
# CORE MULTILAYER DETECTION
# ==============================
def detect_layers(input_data: str,
                  max_depth: int = MAX_DEPTH) -> dict:
    """
    Nested/Multi-layer encoding detect karta hai.

    Example:
    Base64 → Hex → MD5 Hash

    Returns:
    {
        'layers'      : list,
        'total_layers': int,
        'chain'       : str,
        'next_step'   : str,
        'final_type'  : str,
    }
    """
    input_data = input_data.strip()

    if not input_data:
        return _empty_layers()

    layers = []

    _recursive_detect(
        data       = input_data,
        depth      = 1,
        max_depth  = max_depth,
        layers     = layers,
        seen       = set()
    )

    if not layers:
        return _empty_layers()

    chain     = _build_chain(layers)
    next_step = _build_next_step(layers)
    final     = layers[-1]['type'] \
                if layers else 'unknown'

    return {
        'layers'      : layers,
        'total_layers': len(layers),
        'chain'       : chain,
        'next_step'   : next_step,
        'final_type'  : final,
        'multilayer'  : len(layers) > 1
    }


# ==============================
# RECURSIVE DETECTION
# ==============================
def _recursive_detect(data      : str,
                       depth     : int,
                       max_depth : int,
                       layers    : list,
                       seen      : set):
    """
    Recursively detect karta hai har layer.
    Depth limit aur loop prevention included.
    """
    # Depth limit check
    if depth > max_depth:
        return

    # Too short → stop
    if len(data) < MIN_LENGTH:
        return

    # Loop detection — same data dobara nahi
    data_hash = hash(data[:100])
    if data_hash in seen:
        return
    seen.add(data_hash)

    # Current layer analyze karo
    result = run_all_pillars(data)

    if result['category'] == 'unknown':
        return

    category = result['category']
    top      = result['result']['top'] \
               if result['result'] else {}
    name     = top.get('name', 'Unknown') \
               if top else 'Unknown'
    conf     = result['confidence']

    # Layer record karo
    layers.append({
        'layer'      : depth,
        'type'       : name,
        'category'   : category,
        'confidence' : conf,
        'data_preview': _preview(data)
    })

    # Encoding hai toh decode karo aur
    # next layer check karo
    if category == 'encoding':
        decoded = _silent_decode(data, name)

        if decoded and decoded != data:
            _recursive_detect(
                data      = decoded,
                depth     = depth + 1,
                max_depth = max_depth,
                layers    = layers,
                seen      = seen
            )


# ==============================
# SILENT DECODER
# ==============================
def _silent_decode(data: str,
                   encoding: str) -> str:
    """
    Internally decode karta hai —
    output user ko nahi dikhata.
    Next layer detection ke liye use hota hai.
    """
    try:
        decoded_bytes = None

        if encoding == 'Base64':
            padded = data + '=' * (-len(data) % 4)
            decoded_bytes = base64.b64decode(padded)

        elif encoding == 'Base32':
            clean  = data.upper().strip()
            padded = clean + '=' * (-len(clean) % 8)
            decoded_bytes = base64.b32decode(
                padded, casefold=True
            )

        elif encoding == 'Base58':
            decoded_bytes = _decode_base58(data)

        elif encoding == 'Base85':
            decoded_bytes = base64.b85decode(data)

        elif encoding == 'Hex':
            decoded_bytes = bytes.fromhex(data)

        elif encoding == 'URL Encoding':
            return unquote(data)

        elif encoding == 'HTML Entity':
            import html
            return html.unescape(data)

        elif encoding == 'Binary':
            clean = data.replace(' ', '')
            if len(clean) % 8 == 0:
                chunks = [
                    clean[i:i+8]
                    for i in range(0, len(clean), 8)
                ]
                decoded_bytes = bytes(
                    [int(c, 2) for c in chunks]
                )

        elif encoding == 'Octal':
            parts         = data.split()
            decoded_bytes = bytes(
                [int(p, 8) for p in parts]
            )

        else:
            return None

        if decoded_bytes is None:
            return None

        # Bytes → String convert karo
        try:
            result = decoded_bytes.decode(
                'utf-8', errors='strict'
            )
            return result.strip()
        except UnicodeDecodeError:
            # UTF-8 fail → latin-1 try karo
            try:
                result = decoded_bytes.decode('latin-1')
                return result.strip()
            except Exception:
                return None

    except Exception:
        return None


def _decode_base58(data: str) -> bytes:
    """Base58 decode."""
    alphabet  = '123456789ABCDEFGH' \
                'JKLMNPQRSTUVWXYZabcdefghijk' \
                'mnopqrstuvwxyz'
    base      = len(alphabet)
    num       = 0

    for char in data:
        if char not in alphabet:
            raise ValueError(f'Invalid char: {char}')
        num = num * base + alphabet.index(char)

    result = []
    while num > 0:
        result.append(num % 256)
        num //= 256

    for char in data:
        if char == '1':
            result.append(0)
        else:
            break

    return bytes(reversed(result))


# ==============================
# OUTPUT HELPERS
# ==============================
def _build_chain(layers: list) -> str:
    """
    Layer chain string build karta hai.
    Example: "Base64 → Hex → MD5 Hash"
    """
    if not layers:
        return 'None'

    return ' → '.join(
        layer['type'] for layer in layers
    )


def _build_next_step(layers: list) -> str:
    """
    Chain ke basis pe next step suggest karta hai.
    """
    if not layers:
        return 'Manual analysis recommended.'

    total = len(layers)

    if total == 1:
        return 'Single layer detected. ' \
               'Use appropriate decoder.'

    # Multi-layer chain
    steps = []
    for i, layer in enumerate(layers[:-1]):
        name = layer['type']
        step = _get_decode_tool(name)
        if step:
            steps.append(f'Step {i+1}: {step}')

    final     = layers[-1]['type']
    final_cat = layers[-1]['category']

    if final_cat == 'hash':
        steps.append(
            f'Final layer is {final} hash — '
            'use hashcat/crackstation to analyze.'
        )
    elif final_cat == 'encryption':
        steps.append(
            f'Final layer is {final} — '
            'identify key to decrypt.'
        )

    return '\n'.join(steps) if steps \
           else 'Use CyberChef to decode chain.'


def _get_decode_tool(encoding: str) -> str:
    """Encoding ke liye decode tool suggest karo."""
    tools = {
        'Base64'      : 'From Base64 (CyberChef)',
        'Base32'      : 'From Base32 (CyberChef)',
        'Base58'      : 'From Base58 (CyberChef)',
        'Base85'      : 'From Base85 (CyberChef)',
        'Hex'         : 'From Hex (CyberChef)',
        'URL Encoding': 'URL Decode (CyberChef)',
        'HTML Entity' : 'Unescape HTML (CyberChef)',
        'Binary'      : 'From Binary (CyberChef)',
        'Octal'       : 'From Octal (CyberChef)',
    }
    return tools.get(encoding, f'Decode {encoding}')


def _preview(data: str, length: int = 30) -> str:
    """Data ka short preview."""
    if len(data) <= length:
        return data
    return data[:length] + '...'


# ==============================
# HELPERS
# ==============================
def _empty_layers() -> dict:
    return {
        'layers'      : [],
        'total_layers': 0,
        'chain'       : 'None',
        'next_step'   : 'Unknown format.',
        'final_type'  : 'unknown',
        'multilayer'  : False
    }


# ==============================
# OUTPUT FORMATTER
# ==============================
def format_multilayer_result(result: dict) -> str:
    """
    Multi-layer result ko CLI output
    format mein convert karta hai.
    """
    lines = []
    sep   = "─" * 54

    if not result['layers']:
        return ""

    lines.append(sep)
    lines.append("  MULTI-LAYER DETECTION")
    lines.append(sep)

    total = result['total_layers']

    if not result['multilayer']:
        lines.append(
            f"  Layers      : Single layer detected"
        )
        layer = result['layers'][0]
        lines.append(f"  Type        : {layer['type']}")
        lines.append(
            f"  Confidence  : "
            f"{int(layer['confidence'] * 100)}%"
        )
    else:
        lines.append(
            f"  Total Layers: {total}"
        )
        lines.append(
            f"  Chain       : {result['chain']}"
        )
        lines.append("")

        # Har layer dikhao
        for layer in result['layers']:
            conf    = int(layer['confidence'] * 100)
            preview = layer['data_preview']
            lines.append(
                f"  Layer {layer['layer']}"
                f"  → {layer['type']:<20} "
                f"[{conf}%]"
            )
            lines.append(
                f"         Preview: {preview}"
            )

        lines.append("")
        lines.append("  Next Steps  :")
        for step in result['next_step'].split('\n'):
            if step:
                lines.append(f"    → {step}")

    lines.append(sep)
    return "\n".join(lines)