# ==============================
# NEXT STEPS GENERATOR
# ==============================

# ── Encoding Next Steps ──
ENCODING_STEPS = {
    'Base64'      : {
        'tool'   : 'CyberChef → From Base64',
        'online' : 'base64decode.org',
        'cmd'    : 'python -c "import base64; '
                   'print(base64.b64decode(\'<input>\'))"'
    },
    'Base32'      : {
        'tool'   : 'CyberChef → From Base32',
        'online' : 'base32decode.org',
        'cmd'    : 'python -c "import base64; '
                   'print(base64.b32decode(\'<input>\'))"'
    },
    'Base58'      : {
        'tool'   : 'CyberChef → From Base58',
        'online' : 'appdevtools.com/base58-decoder',
        'cmd'    : 'Use base58 Python library'
    },
    'Base85'      : {
        'tool'   : 'CyberChef → From Base85',
        'online' : 'CyberChef online',
        'cmd'    : 'python -c "import base64; '
                   'print(base64.b85decode(\'<input>\'))"'
    },
    'Base62'      : {
        'tool'   : 'CyberChef → From Base62',
        'online' : 'appdevtools.com/base62-decoder',
        'cmd'    : 'Use pybase62 Python library'
    },
    'Hex'         : {
        'tool'   : 'CyberChef → From Hex',
        'online' : 'rapidtables.com/convert/number/hex-to-ascii',
        'cmd'    : 'python -c "print(bytes.fromhex(\'<input>\'))"'
    },
    'URL Encoding': {
        'tool'   : 'CyberChef → URL Decode',
        'online' : 'urldecoder.org',
        'cmd'    : 'python -c "from urllib.parse '
                   'import unquote; print(unquote(\'<input>\'))"'
    },
    'HTML Entity' : {
        'tool'   : 'CyberChef → Unescape HTML',
        'online' : 'htmldecoder.org',
        'cmd'    : 'python -c "import html; '
                   'print(html.unescape(\'<input>\'))"'
    },
    'Binary'      : {
        'tool'   : 'CyberChef → From Binary',
        'online' : 'rapidtables.com/convert/number/binary-to-ascii',
        'cmd'    : 'python -c "print(int(\'<input>\', 2))"'
    },
    'Octal'       : {
        'tool'   : 'CyberChef → From Octal',
        'online' : 'browserling.com/tools/octal-to-text',
        'cmd'    : 'python -c "print(int(\'<input>\', 8))"'
    },
    'Base45': {
        'tool'   : 'CyberChef → From Base45',
        'online' : 'base45.com',
        'cmd'    : 'pip install base45 → base45.b45decode()'
    },
    'Base91': {
        'tool'   : 'CyberChef → From Base91',
        'online' : 'base91.sourceforge.net',
        'cmd'    : 'pip install pybase91 → base91.decode()'
    },
}

# ── Hash Next Steps ──
HASH_STEPS = {
    'MD5'         : {
        'risk'   : '⚠ HIGH collision risk — avoid for security',
        'crack'  : 'crackstation.net / hashcat -m 0',
        'verify' : 'hashlib.md5 in Python'
    },
    'SHA-1'       : {
        'risk'   : '⚠ MEDIUM risk — deprecated for security',
        'crack'  : 'hashcat -m 100',
        'verify' : 'sha1sum / hashlib.sha1'
    },
    'SHA-256'     : {
        'risk'   : '✓ LOW risk — secure',
        'crack'  : 'hashcat -m 1400 (very hard)',
        'verify' : 'sha256sum / hashlib.sha256'
    },
    'SHA-512'     : {
        'risk'   : '✓ LOW risk — very secure',
        'crack'  : 'hashcat -m 1700 (extremely hard)',
        'verify' : 'sha512sum / hashlib.sha512'
    },
    'NTLM'        : {
        'risk'   : '⚠ HIGH risk — Windows auth hash',
        'crack'  : 'hashcat -m 1000 / john --format=nt',
        'verify' : 'Used in Windows NTLM authentication'
    },
    'bcrypt'      : {
        'risk'   : '✓ LOW risk — slow hash, secure',
        'crack'  : 'hashcat -m 3200 (very slow)',
        'verify' : 'bcrypt.checkpw() in Python'
    },
    'Argon2'      : {
        'risk'   : '✓ LOW risk — memory hard, very secure',
        'crack'  : 'Practically infeasible',
        'verify' : 'argon2-cffi library in Python'
    },
    'CRC32'       : {
        'risk'   : '✗ NOT for security — checksum only',
        'crack'  : 'N/A — not cryptographic',
        'verify' : 'binascii.crc32() in Python'
    },
    'MD4'         : {
        'risk'   : '✗ BROKEN — do not use',
        'crack'  : 'hashcat -m 900',
        'verify' : 'Avoid — use SHA-256 instead'
    },
    'SHA-1': {
        'risk'   : '⚠ MEDIUM risk — deprecated',
        'crack'  : 'hashcat -m 100',
        'verify' : 'sha1sum / hashlib.sha1'
    },
    'SHA-224': {
        'risk'   : '✓ LOW risk — secure',
        'crack'  : 'hashcat -m 1300',
        'verify' : 'hashlib.sha224 in Python'
    },
    'SHA-256': {
        'risk'   : '✓ LOW risk — secure',
        'crack'  : 'hashcat -m 1400 (very hard)',
        'verify' : 'sha256sum / hashlib.sha256'
    },
    'SHA-384': {
        'risk'   : '✓ LOW risk — very secure',
        'crack'  : 'hashcat -m 10800',
        'verify' : 'hashlib.sha384 in Python'
    },
    'SHA-512': {
        'risk'   : '✓ LOW risk — very secure',
        'crack'  : 'hashcat -m 1700 (extremely hard)',
        'verify' : 'sha512sum / hashlib.sha512'
    },
    'SHA3-256': {
        'risk'   : '✓ LOW risk — very secure',
        'crack'  : 'hashcat -m 17300',
        'verify' : 'hashlib.sha3_256 in Python'
    },
    'SHA3-512': {
        'risk'   : '✓ LOW risk — very secure',
        'crack'  : 'hashcat -m 17600',
        'verify' : 'hashlib.sha3_512 in Python'
    },
    'RIPEMD-160': {
        'risk'   : '✓ LOW risk — used in Bitcoin',
        'crack'  : 'hashcat -m 6000',
        'verify' : 'Used in Bitcoin address generation'
    },
    'BLAKE2b': {
        'risk'   : '✓ LOW risk — very secure, fast',
        'crack'  : 'hashcat -m 600',
        'verify' : 'hashlib.blake2b in Python'
    },
    'Whirlpool': {
        'risk'   : '✓ LOW risk — secure',
        'crack'  : 'hashcat -m 6100',
        'verify' : 'rhash tool / Whirlpool library'
    },
    'scrypt': {
        'risk'   : '✓ LOW risk — memory hard, secure',
        'crack'  : 'Practically infeasible',
        'verify' : 'hashlib.scrypt in Python'
    },
    'Adler-32': {
        'risk'   : '✗ NOT for security — checksum only',
        'crack'  : 'N/A — not cryptographic',
        'verify' : 'zlib.adler32() in Python'
    },
    # HASH_STEPS dict mein add karo:

    'SM3': {
        'risk'   : '✓ LOW risk — Chinese national standard',
        'crack'  : 'No known hashcat mode yet',
        'verify' : 'gmssl or pysmx Python library'
    },
    'Keccak-256': {
        'risk'   : '✓ LOW risk — Ethereum standard',
        'crack'  : 'No practical attack known',
        'verify' : 'web3.py: Web3.keccak() function'
    },
    'BLAKE2s': {
        'risk'   : '✓ LOW risk — fast and secure',
        'crack'  : 'No practical attack known',
        'verify' : 'hashlib.blake2s in Python'
    },
    'BLAKE3': {
        'risk'   : '✓ LOW risk — very fast, very secure',
        'crack'  : 'No practical attack known',
        'verify' : 'pip install blake3 → blake3.hash()'
    },
    'LM Hash': {
        'risk'   : '✗ BROKEN — extremely weak',
        'crack'  : 'hashcat -m 3000 (very fast)',
        'verify' : 'Windows only — avoid completely'
    },
    'RIPEMD-128': {
        'risk'   : '⚠ MEDIUM risk — weaknesses found',
        'crack'  : 'hashcat -m 6100',
        'verify' : 'rhash --ripemd-128 file'
    },
    'RIPEMD-256': {
        'risk'   : '✓ LOW risk — secure',
        'crack'  : 'hashcat -m 6100',
        'verify' : 'rhash --ripemd-256 file'
    },
    'CRC8': {
        'risk'   : '✗ NOT for security — checksum only',
        'crack'  : 'N/A — not cryptographic',
        'verify' : 'crcmod Python library'
    },
    'CRC16': {
        'risk'   : '✗ NOT for security — checksum only',
        'crack'  : 'N/A — not cryptographic',
        'verify' : 'crcmod Python library'
    },
    'Streebog-256': {
        'risk'   : '✓ LOW risk — Russian GOST standard',
        'crack'  : 'hashcat -m 11700',
        'verify' : 'gostcrypto Python library'
    },
    'Streebog-512': {
        'risk'   : '✓ LOW risk — Russian GOST standard',
        'crack'  : 'hashcat -m 11800',
        'verify' : 'gostcrypto Python library'
    },
    'SHA3-224': {
        'risk'   : '✓ LOW risk — secure',
        'crack'  : 'hashcat -m 17300',
        'verify' : 'hashlib.sha3_224 in Python'
    },
    'SHA3-384': {
        'risk'   : '✓ LOW risk — secure',
        'crack'  : 'hashcat -m 17400',
        'verify' : 'hashlib.sha3_384 in Python'
    },
}

# ── Encryption Next Steps ──
ENCRYPTION_STEPS = {
    'OpenSSL Encrypted' : {
        'tool'  : 'openssl enc -d -aes-256-cbc '
                  '-in file.enc -out file.dec',
        'note'  : 'Password/key required to decrypt'
    },
    'PGP Encrypted Message' : {
        'tool'  : 'gpg --decrypt file.gpg',
        'note'  : 'Private key required'
    },
    'PGP Public Key'    : {
        'tool'  : 'gpg --import key.gpg',
        'note'  : 'Import key to use for encryption'
    },
    'PGP Private Key'   : {
        'tool'  : 'gpg --import privatekey.gpg',
        'note'  : '⚠ Keep private key secure!'
    },
    'PEM Header'        : {
        'tool'  : 'openssl x509 -in cert.pem -text',
        'note'  : 'May be certificate, key, or CSR'
    },
    'PEM Certificate'   : {
        'tool'  : 'openssl x509 -in cert.pem -text',
        'note'  : 'SSL/TLS certificate'
    },
    'PEM Private Key'   : {
        'tool'  : 'openssl rsa -in key.pem -text',
        'note'  : '⚠ Keep private key secure!'
    },
    'ZIP Archive'       : {
        'tool'  : 'unzip file.zip',
        'note'  : 'Compressed — not encrypted '
                  '(unless password protected)'
    },
    'Zlib Compressed'   : {
        'tool'  : 'python -c "import zlib; '
                  'open(\'out\',\'wb\').write('
                  'zlib.decompress(open(\'in\',\'rb\')'
                  '.read()))"',
        'note'  : 'zlib compressed data'
    },
    'KeePass Database'  : {
        'tool'  : 'Open with KeePass application',
        'note'  : 'Master password required'
    },
    'ELF Binary'        : {
        'tool'  : 'file binary / strings binary',
        'note'  : 'Linux executable — analyze with Ghidra/IDA'
    },
    'Windows EXE'       : {
        'tool'  : 'pestudio / PE-bear / Ghidra',
        'note'  : 'Windows executable — analyze carefully'
    },
    'Zlib Compressed': {
        'tool'  : 'python -c "import zlib; '
                'open(\'out\',\'wb\').write('
                'zlib.decompress(open(\'in\',\'rb\').read()))"',
        'note'  : 'zlib compressed data'
    },
    'Zlib Best Compression': {
        'tool'  : 'python -c "import zlib; '
                'open(\'out\',\'wb\').write('
                'zlib.decompress(open(\'in\',\'rb\').read()))"',
        'note'  : 'zlib best compression (0x78 0xDA)'
    },
    'Zlib Low Compression': {
        'tool'  : 'python -c "import zlib; '
                'open(\'out\',\'wb\').write('
                'zlib.decompress(open(\'in\',\'rb\').read()))"',
        'note'  : 'zlib low compression (0x78 0x01)'
    },
    'RAR Archive': {
        'tool'  : 'unrar x file.rar / WinRAR',
        'note'  : 'RAR compressed archive'
    },
    '7-Zip Archive': {
        'tool'  : '7z x file.7z / 7-Zip application',
        'note'  : '7z compressed archive'
    },
    'PNG Image': {
        'tool'  : 'Any image viewer / exiftool',
        'note'  : 'PNG image — check for steganography'
    },
    'PDF Document': {
        'tool'  : 'Any PDF reader / pdfinfo',
        'note'  : 'PDF document — may contain embedded data'
    },
}

# ── Classical Cipher Next Steps ──
CIPHER_STEPS = {
    'Caesar Cipher'       : {
        'tool'  : 'dcode.fr/caesar-cipher',
        'note'  : 'Try all 25 shifts',
        'cmd'   : 'quipqiup.com for auto-solve'
    },
    'ROT13'               : {
        'tool'  : 'rot13.com',
        'note'  : 'Fixed shift of 13',
        'cmd'   : 'python -c "import codecs; '
                  'print(codecs.decode(\'<input>\', \'rot_13\'))"'
    },
    'Vigenere Cipher'     : {
        'tool'  : 'dcode.fr/vigenere-cipher',
        'note'  : 'Key needed — try cryptanalysis',
        'cmd'   : 'Use Index of Coincidence to find key length'
    },
    'Atbash Cipher'       : {
        'tool'  : 'dcode.fr/atbash-cipher',
        'note'  : 'A=Z, B=Y reverse substitution',
        'cmd'   : 'quipqiup.com for auto-solve'
    },
    'Substitution Cipher' : {
        'tool'  : 'quipqiup.com',
        'note'  : 'Frequency analysis needed',
        'cmd'   : 'dcode.fr/substitution-cipher'
    },
    'Playfair Cipher'     : {
        'tool'  : 'dcode.fr/playfair-cipher',
        'note'  : 'Digraph cipher — key needed',
        'cmd'   : 'dcode.fr for cryptanalysis'
    },
    'Transposition Cipher': {
        'tool'  : 'dcode.fr/transposition-cipher',
        'note'  : 'Column/rail fence transposition',
        'cmd'   : 'Try different column counts'
    },
}


# ==============================
# MAIN GENERATOR
# ==============================
def get_next_steps(category : str,
                   type_name: str) -> dict:
    """
    Category aur type ke basis pe
    actionable next steps return karta hai.

    Returns:
    {
        'primary'  : str,   Main action
        'tool'     : str,   Recommended tool
        'online'   : str,   Online resource
        'cmd'      : str,   Command/code
        'warning'  : str,   Risk warning
        'note'     : str,   Additional info
    }
    """
    category = category.lower()
    result   = {
        'primary' : '',
        'tool'    : '',
        'online'  : '',
        'cmd'     : '',
        'warning' : '',
        'note'    : ''
    }

    if category == 'encoding':
        steps = ENCODING_STEPS.get(type_name, {})
        result['primary'] = f'Decode using {type_name} decoder'
        result['tool']    = steps.get('tool', 'CyberChef')
        result['online']  = steps.get('online', 'gchq.github.io/CyberChef')
        result['cmd']     = steps.get('cmd', '')

    elif category == 'hash':
        steps = HASH_STEPS.get(type_name, {})
        result['primary'] = f'Identify source of {type_name} hash'
        result['tool']    = steps.get('verify', '')
        result['cmd']     = steps.get('crack', '')
        result['warning'] = steps.get('risk', '')

    elif category == 'encryption':
        steps = ENCRYPTION_STEPS.get(type_name, {})
        result['primary'] = f'Analyze {type_name}'
        result['tool']    = steps.get('tool', '')
        result['note']    = steps.get('note', '')
        result['warning'] = 'Decryption requires key/password'

    elif category == 'cipher':
        steps = CIPHER_STEPS.get(type_name, {})
        result['primary'] = f'Decode {type_name}'
        result['tool']    = steps.get('tool', 'dcode.fr')
        result['note']    = steps.get('note', '')
        result['cmd']     = steps.get('cmd', '')

    else:
        result['primary'] = 'Manual analysis recommended'
        result['tool']    = 'binwalk / hexdump / strings'

    return result


# ==============================
# FORMATTER
# ==============================
def format_next_steps(steps: dict) -> str:
    """Next steps ko CLI format mein convert karo."""
    lines = []
    sep   = "─" * 54

    lines.append(sep)
    lines.append("  NEXT STEPS")
    lines.append(sep)

    if steps.get('primary'):
        lines.append(f"  Action  : {steps['primary']}")

    if steps.get('tool'):
        lines.append(f"  Tool    : {steps['tool']}")

    if steps.get('online'):
        lines.append(f"  Online  : {steps['online']}")

    if steps.get('cmd'):
        lines.append(f"  Command : {steps['cmd']}")

    if steps.get('note'):
        lines.append(f"  Note    : {steps['note']}")

    if steps.get('warning'):
        lines.append(f"  ⚠ Risk  : {steps['warning']}")

    lines.append(sep)
    return "\n".join(lines)