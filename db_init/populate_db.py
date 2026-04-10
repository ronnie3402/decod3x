import sqlite3
import os
from pathlib import Path

# ==============================
# DB PATH SETUP
# ==============================
def get_db_path():
    if os.name == 'nt':  # Windows
        base = Path(os.environ['APPDATA']) / 'decod3x'
    else:  # Linux
        base = Path.home() / '.decod3x'
    
    base.mkdir(parents=True, exist_ok=True)
    return base / 'triage_engine.db'

# ==============================
# CREATE TABLES
# ==============================
def create_tables(cursor):

    # TABLE 1: encoding_signatures
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS encoding_signatures (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            regex           TEXT NOT NULL,
            min_length      INTEGER DEFAULT 1,
            max_length      INTEGER DEFAULT NULL,
            padding_char    TEXT DEFAULT NULL,
            length_multiple INTEGER DEFAULT NULL,
            base_confidence REAL NOT NULL,
            priority        INTEGER DEFAULT 1,
            description     TEXT DEFAULT NULL,
            example         TEXT DEFAULT NULL,
            notes           TEXT DEFAULT NULL
        )
    ''')

    # TABLE 2: magic_bytes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS magic_bytes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            hex_sig     TEXT NOT NULL,
            byte_offset INTEGER DEFAULT 0,
            file_type   TEXT NOT NULL,
            category    TEXT NOT NULL,
            confidence  REAL NOT NULL,
            priority    INTEGER DEFAULT 1,
            description TEXT DEFAULT NULL,
            example     TEXT DEFAULT NULL,
            next_step   TEXT DEFAULT NULL
        )
    ''')

    # TABLE 3: hash_formats
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hash_formats (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL,
            hex_length      INTEGER DEFAULT NULL,
            prefix          TEXT DEFAULT NULL,
            charset         TEXT NOT NULL,
            category        TEXT NOT NULL,
            base_confidence REAL NOT NULL,
            priority        INTEGER DEFAULT 1,
            output_format   TEXT DEFAULT NULL,
            collision_risk  TEXT DEFAULT NULL,
            ambiguous_with  TEXT DEFAULT NULL,
            description     TEXT DEFAULT NULL,
            example         TEXT DEFAULT NULL,
            next_step       TEXT DEFAULT NULL
        )
    ''')

    # TABLE 4: entropy_profiles
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS entropy_profiles (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            label        TEXT NOT NULL,
            min_entropy  REAL NOT NULL,
            max_entropy  REAL NOT NULL,
            chi_sq_type  TEXT NOT NULL,
            byte_dist    TEXT NOT NULL,
            category     TEXT NOT NULL,
            confidence   REAL NOT NULL,
            description  TEXT DEFAULT NULL,
            example      TEXT DEFAULT NULL
        )
    ''')

    # TABLE 5: cipher_profiles
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cipher_profiles (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            name         TEXT NOT NULL,
            ic_min       REAL NOT NULL,
            ic_max       REAL NOT NULL,
            charset      TEXT NOT NULL,
            freq_pattern TEXT NOT NULL,
            keyspace     TEXT DEFAULT NULL,
            confidence   REAL NOT NULL,
            priority     INTEGER DEFAULT 1,
            description  TEXT DEFAULT NULL,
            example      TEXT DEFAULT NULL
        )
    ''')

    print("[+] All tables created successfully.")

# ==============================
# INSERT DATA
# ==============================

def insert_encoding_signatures(cursor):
    data = [
        (
            'Base64',
            r'^[A-Za-z0-9+/=]+$',
            4, None, '=', 4, 0.75, 1,
            'Base64 encodes binary data using 64 printable ASCII characters.',
            'aGVsbG8gd29ybGQ=',
            'Length must be multiple of 4. Padding with = at end.'
        ),
        (
            'Base64 (URL Safe)',
            r'^[A-Za-z0-9\-_]+={0,2}$', # + aur / ki jagah - aur _
            4, None, '=', 4, 0.76, 1,
            'URL-safe Base64 encoding (RFC 4648). Uses - and _ instead of + and /.',
            'aGVsbG8td29ybGRf',
            'Commonly used in JWT tokens and web URLs.'
        ),
        (
            'Base64 (Atom128)',
            r'^[A-Za-z0-9+/]+={0,2}$', # Same regex as standard Base64
            4, None, '=', 4, 0.65, 3,
            'Custom Base64 variant using Atom128 alphabet.',
            'PGk9v1s=',
            'Used in obfuscation and CTFs. Requires custom alphabet mapping to decode.'
        ),
        (
            'Base32',
            r'^[A-Z2-7=]+$',
            8, None, '=', 8, 0.80, 2,
            'Base32 uses uppercase letters and digits 2-7.',
            'JBSWY3DPEBLW64TMMQ======',
            'Length must be multiple of 8.'
        ),
        (
            'Base58',
            r'^[1-9A-HJ-NP-Za-km-z]+$',
            4, 
            None, None, None, 0.72, 3,
            'Base58 removes confusing characters like 0, O, I, l.',
            '3yZe7d',
            'Commonly used in Bitcoin addresses.'
        ),
        (
            'Base62',
            r'^[A-Za-z0-9]+$',
            1, None, None, None, 0.65, 4,
            'Base62 uses alphanumeric characters only.',
            'aHR0cHM',
            'No padding, no special chars. Often confused with Base64.'
        ),
        (
            'Base85 (Standard)',
            r'^(?:<~)?[!-uz]+(?:~>)?$',
            4, None, None, None, 0.70, 4,
            'Ascii85 standard encoding. Commonly used in PDF files.',
            '<~E-#Q#F(Ss+~>',
            'Uses base64.a85decode() in Python.'
        ),
        (
            'Base85 (IPv6)',
            r'^(?:<~)?[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+(?:~>)?$', 
            4, None, None, None, 0.70, 4,
            'RFC 1924 Base85 encoding. Avoids quotes and commas.',
            '<~4)+k&C#VzJ4br>0~>',
            'Uses base64.b85decode() in Python.'
        ),
        (
            'Base85 (Z85)',
            r'^(?:<~)?[0-9a-zA-Z.\-:+=^!/*?&<>()\[\]{}@%$#]+(?:~>)?$',
            5, None, None, None, 0.70, 4, 
            'ZeroMQ Base85 encoding. Designed to be string-safe in C.',
            '<~v{[$}v{[$}~>',
            'Requires custom z85 library to decode.'
        ),
        (
            'Hex',
            r'^[0-9a-fA-F]+$',
            4, 
            None, None, 2, 0.85, 1,
            'Hexadecimal encoding using characters 0-9 and a-f.',
            '48656c6c6f',
            'Length must be even.'
        ),
        (
            'URL Encoding',
            r'^(?=.*%[0-9A-Fa-f]{2})(%[0-9A-Fa-f]{2}|[A-Za-z0-9\-_.~!*\'();:@&=+$,/?#\[\]])+$',
            3, None, None, None, 0.95, 1,
            'URL encoding replaces special characters with % followed by hex.',
            '%48%65%6C%6C%6F',
            'Must contain at least one % sequence.'
        ),
        (
            'HTML Entity',
            r'&[#xX0-9a-zA-Z]{2,};', 
            4, None, None, None, 0.90, 2,
            'HTML entity encoding (Named, Decimal, Hex).',
            '&#112;&#x70;',
            'Common in XSS and Web Obfuscation.'
        ),
        (
            'Base45',
            r'^[0-9A-Z $%*+\-./:]+$',
            1, None, None, None, 0.70, 4,
            'Base45 encoding used in QR codes (EU Digital Certificates).',
            'UJCLQE7W581',
            'Used in compact encoding scenarios.'
        ),
        (
            'Base91',
            r'^[\x21-\x7E]+$',
            1, None, None, None, 0.68, 5,
            'Base91 encoding with high efficiency.',
            'TPwJh>Io2Tv!',
            'More efficient than Base64 but less common.'
        ),
        (
            'Binary',
            r'^[01]+$',
            8, None, None, 8, 0.90, 1,
            'Binary encoding using 0 and 1.',
            '01001000',
            'Length should be multiple of 8.'
        ),
        (
            'Octal',
            r'^[0-7]+$',
            3, None, None, None, 0.65, 3,
            'Octal encoding using digits 0-7.',
            '110 145 154 154 157',
            'Less common but appears in legacy systems.'
        ),
    ]

    cursor.executemany('''
        INSERT INTO encoding_signatures
        (name, regex, min_length, max_length, padding_char,
         length_multiple, base_confidence, priority,
         description, example, notes)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    ''', data)

    print("[+] Encoding signatures inserted.")


def insert_magic_bytes(cursor):
    data = [
        (
            'OpenSSL Encrypted',
            '53 61 6C 74 65 64 5F 5F',
            0, 'encrypted_blob', 'Encrypted',
            0.99, 1,
            'OpenSSL symmetric encryption always starts with "Salted__".',
            'Salted__<binary>',
            'openssl enc -d -aes-256-cbc -in file.enc -out file.dec'
        ),
        (
            'PGP Message',
            '8C 0D',
            0, 'pgp_message', 'Encrypted',
            0.99, 1,
            'PGP encrypted message header.',
            'Binary PGP data',
            'gpg --decrypt file.gpg'
        ),
        (
            'PGP Public Key',
            '85 03',
            0, 'pgp_key', 'Encrypted',
            0.99, 2,
            'PGP public key block header.',
            'Binary PGP key data',
            'gpg --import key.gpg'
        ),
        (
            'KeePass Database',
            '21 44 42',
            0, 'kdbx', 'Encrypted Container',
            0.99, 1,
            'KeePass password database file header.',
            'KeePass .kdbx file',
            'Open with KeePass application.'
        ),
        (
            'ZIP Archive',
            '50 4B 03 04',
            0, 'zip', 'Compressed',
            0.99, 1,
            'ZIP file format magic bytes (PK header).',
            'Compressed ZIP file',
            'unzip file.zip or 7zip'
        ),
        (
            'PDF Document',
            '25 50 44 46',
            0, 'pdf', 'Document',
            0.99, 2,
            'PDF file format magic bytes (%PDF).',
            '%PDF-1.4...',
            'Open with any PDF reader.'
        ),
        (
            'PEM Header',
            '2D 2D 2D 2D 2D 42 45 47 49 4E',
            0, 'pem', 'Cryptographic',
            0.99, 1,
            'PEM format begins with -----BEGIN.',
            '-----BEGIN CERTIFICATE-----',
            'openssl x509 -in cert.pem -text'
        ),
        (
            'RAR Archive',
            '52 61 72 21 1A 07 00',
            0, 'rar', 'Compressed',
            0.99, 1,
            'RAR compressed archive file.',
            'RAR file',
            'unrar x file.rar'
        ),
        (
            '7-Zip Archive',
            '37 7A BC AF 27 1C',
            0, '7z', 'Compressed',
            0.99, 1,
            '7z compressed archive.',
            '7z file',
            '7z x file.7z'
        ),
        (
            'ELF Binary',
            '7F 45 4C 46',
            0, 'elf', 'Executable',
            0.99, 1,
            'Linux executable format.',
            'ELF binary',
            'file binary'
        ),
        (
            'Windows EXE',
            '4D 5A',
            0, 'exe', 'Executable',
            0.99, 1,
            'Windows executable (MZ header).',
            'EXE file',
            'run or analyze with PE tools'
        ),
        (
            'PNG Image',
            '89 50 4E 47 0D 0A 1A 0A',
            0, 'png', 'Image',
            0.99, 1,
            'PNG image file format.',
            'PNG file',
            'open in image viewer'
        ),
        (
            'Zlib Compressed',
            '78 9C',
            0, 'zlib', 'Compressed',
            0.99, 1,
            'Zlib default compression magic bytes.',
            'Zlib compressed data',
            'python -c "import zlib; data=open(\'f\',\'rb\').read(); open(\'out\',\'wb\').write(zlib.decompress(data))"'
        ),
        (
            'Zlib Best Compression',
            '78 DA',
            0, 'zlib', 'Compressed',
            0.99, 1,
            'Zlib best compression magic bytes.',
            'Zlib compressed data',
            'Use zlib.decompress() in Python.'
        ),
        (
            'Zlib Low Compression',
            '78 01',
            0, 'zlib', 'Compressed',
            0.99, 1,
            'Zlib low compression magic bytes.',
            'Zlib compressed data',
            'Use zlib.decompress() in Python.'
        ),
    ]

    cursor.executemany('''
        INSERT INTO magic_bytes
        (name, hex_sig, byte_offset, file_type, category,
         confidence, priority, description, example, next_step)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    ''', data)

    print("[+] Magic bytes inserted.")


def insert_hash_formats(cursor):
    data = [
        (
            'MD5',
            32, None, 'lowercase_hex',
            'cryptographic', 0.78, 1,
            'hex', 'high',
            'NTLM,MD4,MD2',
            'MD5 produces a 128-bit hash. Widely used but cryptographically broken.',
            'd41d8cd98f00b204e9800998ecf8427e',
            'Use hashcat or crackstation.net to crack. Avoid for security use.'
        ),
        # Agar MD2 nahi hai, toh ise add karke dobara populate_db.py chalao
        (
            'MD2',
            32, None, 'lowercase_hex',
            'cryptographic', 0.65, 2,
            'hex', 'critical',
            'MD5,NTLM,MD4',
            'MD2 is a legacy 128-bit hash function (RFC 1319). Highly insecure and slow.',
            '83878c91171338902e0fe0fb97a8c47a',
            'Use hashcat -m 700. Legacy hash, strictly for forensics or research purposes.'
        ),
        (
            'MD6',
            64, None, 'lowercase_hex',
            'cryptographic', 0.65, 2,
            'hex', 'medium',
            'SHA-256,SM3,Keccak-256,BLAKE2s',
            'MD6 is a variable-length cryptographic hash function submitted to the SHA-3 competition.',
            'fb99d37f3db9317cabbf6c982f32b40bd617ecd4ce6aa909d3fbe6cec92f6a63',
            'Check Hashcat modules or use custom scripts. Not commonly used in production.'
        ),
        (
            'SHA-0',
            40, None, 'lowercase_hex',
            'cryptographic', 0.65, 2,
            'hex', 'critical',
            'SHA-1,RIPEMD-160',
            'SHA-0 is the withdrawn original version of the 160-bit SHA hash function. Highly insecure.',
            '6aa9ca6960e00b7150e80f80a916d2644e9822dd',
            'Hashcat does not natively support SHA-0. Custom tooling required. Completely broken.'
        ),
        (
            'SHA-1',
            40, None, 'lowercase_hex',
            'cryptographic', 0.75, 1,
            'hex', 'medium',
            'RIPEMD-160',
            'SHA-1 produces a 160-bit hash. Deprecated for security use.',
            'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'Use sha1sum to verify. Avoid for security applications.'
        ),
        (
            'SHA-224',
            56, None, 'lowercase_hex',
            'cryptographic', 0.80, 2,
            'hex', 'low',
            'SHA3-224',
            'SHA-224 is a truncated version of SHA-256.',
            'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
            'Part of SHA-2 family. Verify with sha224sum.'
        ),
        (
            'SHA-256',
            64, None, 'lowercase_hex',
            'cryptographic', 0.82, 1,
            'hex', 'low',
            'SHA3-256,BLAKE2s',
            'SHA-256 is the most widely used SHA-2 variant.',
            'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'Verify with sha256sum. Widely used in TLS, Bitcoin.'
        ),
        (
            'SHA-384',
            96, None, 'lowercase_hex',
            'cryptographic', 0.80, 2,
            'hex', 'low',
            'SHA3-384',
            'SHA-384 is a truncated version of SHA-512.',
            '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
            'Part of SHA-2 family. Verify with sha384sum.'
        ),
        (
            'SHA-512',
            128, None, 'lowercase_hex',
            'cryptographic', 0.75, 1,
            'hex', 'low',
            'Whirlpool,BLAKE2b,SHA3-512',
            'SHA-512 produces a 512-bit hash.',
            'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
            'Verify with sha512sum.'
        ),
        
        (
            'bcrypt',
            60, '$2b$', 'base64_custom',
            'kdf', 0.99, 1,
            'modular_crypt', 'low',
            None,
            'bcrypt is a slow password hashing function with built-in salt.',
            '$2b$12$D4G1nEH0VqvFUhFnEzEd8.',
            'Use bcrypt library to verify. Cannot be cracked easily.'
        ),
        
        (
            'bcrypt',
            60, '$2y$', 'base64_custom',
            'kdf', 0.99, 1,
            'modular_crypt', 'low',
            None,
            'bcrypt password hash ($2y$ variant).',
            '$2y$10$abcdefghijklmnopqrstuuABC...',
            'Use bcrypt library to verify.'
        ),
        # db_init/populate_db.py mein add karo
        (
            'bcrypt',
            60, '$2a$', 'base64_custom',
            'kdf', 0.99, 1,
            'modular_crypt', 'low',
            None,
            'bcrypt password hash ($2a$ variant).',
            '$2a$12$...',
            'Use bcrypt library to verify.'
        ),  
        (
            'Argon2',
            None, '$argon2', 'base64_custom',
            'kdf', 0.99, 1,
            'modular_crypt', 'low',
            None,
            'Argon2 is the winner of the Password Hashing Competition.',
            '$argon2id$v=19$m=65536,t=3,p=4$...',
            'Use argon2-cffi library to verify.'
        ),
        (
            'CRC32',
            8, None, 'mixed_hex',
            'checksum', 0.70, 3,
            'hex', 'none',
            'Adler-32',
            'CRC32 is a non-cryptographic checksum used for error detection.',
            '4C2750BD',
            'Used in ZIP, Ethernet. Not for security purposes.'
        ),
        (
            'RIPEMD-160',
            40, None, 'lowercase_hex',
            'cryptographic', 0.65, 3,
            'hex', 'low',
            'SHA-1',
            'RIPEMD-160 produces a 160-bit hash, used in Bitcoin.',
            '9c1185a5c5e9fc54612808977ee8f548b2258d31',
            'Used in Bitcoin address generation.'
        ),
        (
            'BLAKE2b',
            128, None, 'lowercase_hex',
            'cryptographic', 0.70, 2,
            'hex', 'low',
            'SHA-512,Whirlpool',
            'BLAKE2b is faster than MD5 and SHA-3 while being highly secure.',
            '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce',
            'Use hashlib.blake2b in Python to verify.'
        ),
        (
            'Whirlpool',
            128, None, 'lowercase_hex',
            'cryptographic', 0.65, 3,
            'hex', 'low',
            'SHA-512,BLAKE2b',
            'Whirlpool is a 512-bit hash based on modified AES.',
            '19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3',
            'Less common. Verify with rhash tool.'
        ),
        (
            'NTLM',
            32, None, 'uppercase_hex',
            'cryptographic', 0.78, 1,
            'hex', 'high',
            'MD5,MD4',
            'NTLM hash used in Windows authentication.',
            '32ED87BDB5FDC5E9CBA88547376818D4',
            'Use hashcat mode 1000.'
        ),
        (
            'MD4',
            32, None, 'lowercase_hex',
            'cryptographic', 0.70, 2,
            'hex', 'high',
            'MD5,NTLM',
            'MD4 is an old and broken hash function.',
            '31d6cfe0d16ae931b73c59d7e0c089c0',
            'Rarely used today.'
        ),
        (
            'SHA3-256',
            64, None, 'lowercase_hex',
            'cryptographic', 0.80, 3,
            'hex', 'low',
            'SHA-256',
            'SHA-3 variant based on Keccak.',
            'a7ffc6f8bf1ed76651c14756a061e667f0',
            'Use hashlib.sha3_256.'
        ),
        (
            'SHA3-512',
            128, None, 'lowercase_hex',
            'cryptographic', 0.80, 2,
            'hex', 'low',
            'SHA-512',
            'SHA-3 512-bit variant.',
            '0eab42de4c3ceb9235fc91acffe746b29c29',
            'Use hashlib.sha3_512.'
        ),
        (
            'scrypt',
            None, '$scrypt$', 'base64_custom',
            'kdf', 0.99, 1,
            'modular_crypt', 'low',
            None,
            'Memory-hard password hashing algorithm.',
            '$scrypt$N=16384,r=8,p=1$...',
            'Use scrypt library.'
        ),
        (
            'Adler-32',
            8, None, 'uppercase_hex',
            'checksum', 0.65, 3,
            'hex', 'none',
            'CRC32',
            'Adler-32 checksum used in zlib.',
            '1A2B3C4D',
            'Used in compression libraries.'
        ),
        # ── NEW: RIPEMD Series ──
        (
            'RIPEMD-128',
            32, None, 'lowercase_hex',
            'cryptographic', 0.65, 3,
            'hex', 'low',
            'MD5,MD4,NTLM',
            'RIPEMD-128 produces a 128-bit hash.',
            'c14a12199c66e4ba84636b0f69144c77',
            'Use rhash tool to verify.'
        ),
        (
            'RIPEMD-256',
            64, None, 'lowercase_hex',
            'cryptographic', 0.65, 3,
            'hex', 'low',
            'SHA-256,SHA3-256,SM3',
            'RIPEMD-256 is an extended version of RIPEMD-128.',
            'afbd6e228b9d8cbbcef5ca2d03e6dba1'
            '0ac0bc7dcbe4680e1e42d2e975459b65',
            'Use rhash tool to verify.'
        ),
        (
            'RIPEMD-320',
            80, None, 'lowercase_hex',
            'cryptographic', 0.70, 3,
            'hex', 'medium',
            '', 
            'RIPEMD-320 is a 320-bit extension of RIPEMD-160. Produces an 80-character hex string.',
            'bc54cd4175a1679c65184b74389901d17c03841ef9e08488902e77e52c5088e98a7960b9370d83b2',
            'Very rare. Use custom Python scripts (pycryptodome) for hashing/cracking.'
        ),

        # ── NEW: SM3 (Chinese Standard) ──
        (
            'SM3',
            64, None, 'lowercase_hex',
            'cryptographic', 0.68, 2,
            'hex', 'low',
            'SHA-256,SHA3-256,RIPEMD-256',
            'SM3 is the Chinese national cryptographic '
            'hash standard (GB/T 32905-2016).',
            '66c7f0f462eeedd9d1f2d46bdc10e4e2'
            '4167c4875cf2f7a2297da02b8f4ba8e0',
            'Use gmssl or pysmx library to verify.'
        ),

        # ── NEW: Keccak-256 (Ethereum) ──
        (
            'Keccak-256',
            64, None, 'lowercase_hex',
            'cryptographic', 0.68, 2,
            'hex', 'low',
            'SHA-256,SHA3-256,SM3',
            'Keccak-256 is used in Ethereum blockchain. '
            'Different from SHA3-256 despite same length.',
            'c5d2460186f7233c927e7db2dcc703c0'
            'e500b653ca82273b7bfad8045d85a470',
            'Use web3.py or pysha3 library to verify.'
        ),
        (
            'Keccak-512',
            128, None, 'lowercase_hex',
            'cryptographic', 0.70, 2,
            'hex', 'medium',
            'SHA-512,SHA3-512,BLAKE2b',
            'Keccak-512 is the predecessor to SHA3-512. It uses different padding than the final NIST SHA-3 standard.',
            '0fb9658f91abe527942d100b13e5cee020d74f1eff8ee9e926e18135dfb2e541414bc267bd5cee0c8462ea543651d1838d2b5cc0991acfc4dfdb94c8b936c902',
            'Hashcat or custom Keccak scripts depending on padding.'
        ),
        (
            'Keccak-384',
            96, None, 'lowercase_hex',
            'cryptographic', 0.70, 2,
            'hex', 'medium',
            'SHA-384,SHA3-384',
            'Keccak-384 is the predecessor to SHA3-384. It uses different padding than the final NIST standard.',
            '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47f65022976a7edca5',
            'Custom Keccak scripts or specific Hashcat modules depending on padding.'
        ),
        (
            'Keccak-224',
            56, None, 'lowercase_hex',
            'cryptographic', 0.65, 2,
            'hex', 'medium',
            'SHA-224,SHA3-224',
            'Keccak-224 is the predecessor to SHA3-224. It uses different padding than the final NIST standard.',
            'f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd',
            'Custom Keccak scripts or specific Hashcat modules depending on padding.'
        ),

        # ── NEW: BLAKE2s ──
        (
            'BLAKE2s',
            64, None, 'lowercase_hex',
            'cryptographic', 0.70, 2,
            'hex', 'low',
            'SHA-256,SHA3-256,SM3,Keccak-256',
            'BLAKE2s is optimized for 8-32 bit platforms.',
            '508c5e8c327c14e2e1a72ba34eeb452f'
            '37458b209ed63a294d999b4c86675982',
            'Use hashlib.blake2s in Python to verify.'
        ),

        # ── NEW: BLAKE3 ──
        (
            'BLAKE3',
            64, None, 'lowercase_hex',
            'cryptographic', 0.70, 2,
            'hex', 'low',
            'SHA-256,SHA3-256,BLAKE2s',
            'BLAKE3 is the newest member of BLAKE family. '
            'Extremely fast.',
            'af1349b9f5f9a1a6a0404dea36dcc949'
            '9bcbe2eb0f78a76b4b5c2f95eb4a1b0d',
            'Use blake3 Python library to verify.'
        ),

        # ── NEW: LM Hash (Windows) ──
        (
            'LM Hash',
            32, None, 'uppercase_hex',
            'cryptographic', 0.72, 2,
            'hex', 'high',
            'NTLM,MD5',
            'LM Hash is an old Windows password hash. '
            'Extremely weak — DES based.',
            'AAD3B435B51404EEAAD3B435B51404EE',
            'hashcat -m 3000. Very easy to crack.'
        ),

        # ── NEW: CRC8 ──
        (
            'CRC8',
            2, None, 'mixed_hex',
            'checksum', 0.60, 4,
            'hex', 'none',
            None,
            'CRC8 is an 8-bit cyclic redundancy check.',
            'F4',
            'Used in embedded systems, 1-Wire protocol.'
        ),

        # ── NEW: CRC16 ──
        (
            'CRC16',
            4, None, 'mixed_hex',
            'checksum', 0.62, 3,
            'hex', 'none',
            'Adler-32',
            'CRC16 is a 16-bit cyclic redundancy check.',
            'B4C8',
            'Used in USB, ANSI protocols.'
        ),

        # ── NEW: Streebog-256 (Russian GOST) ──
        (
            'Streebog-256',
            64, None, 'lowercase_hex',
            'cryptographic', 0.65, 3,
            'hex', 'low',
            'SHA-256,SM3,Keccak-256',
            'Streebog-256 is Russian GOST R 34.11-2012 '
            'hash standard.',
            '3f539a213e97c802cc229d474c6aa32a'
            '825a360b2a933a949fd925208d9ce1bb',
            'Use pystreebog or gostcrypto library.'
        ),

        # ── NEW: Streebog-512 (Russian GOST) ──
        (
            'Streebog-512',
            128, None, 'lowercase_hex',
            'cryptographic', 0.65, 3,
            'hex', 'low',
            'SHA-512,Whirlpool,BLAKE2b',
            'Streebog-512 is Russian GOST R 34.11-2012 '
            '512-bit hash standard.',
            '486f64e3f6a7b6aab7aa6dbf82e2c584'
            'b6bed4f6b9ea0e9fa9f7b7f5e0b9b0c2'
            'a0f0e9d8c7b6a5948382716059483726'
            '1504f3e2d1c0b9a8978685746362514f',
            'Use pystreebog or gostcrypto library.'
        ),

        # ── NEW: SHA3-224 ──
        (
            'SHA3-224',
            56, None, 'lowercase_hex',
            'cryptographic', 0.80, 2,
            'hex', 'low',
            'SHA-224',
            'SHA3-224 is SHA-3 variant with 224-bit output.',
            '6b4e03423667dbb73b6e15454f0eb1ab'
            'd4597f9a1b078e3f5b5a6bc7',
            'Use hashlib.sha3_224 in Python.'
        ),

        # ── NEW: SHA3-384 ──
        (
            'SHA3-384',
            96, None, 'lowercase_hex',
            'cryptographic', 0.80, 2,
            'hex', 'low',
            'SHA-384',
            'SHA3-384 is SHA-3 variant with 384-bit output.',
            '0c63a75b845e4f7d01107d852e4c2485'
            'c51a50aaaa94fc61995e71bbee983a2a'
            'c3713831264adb47fb6bd1e058d5f004',
            'Use hashlib.sha3_384 in Python.'
        ),
        (
            'SHAKE256 (XOF)',
            128, None, 'lowercase_hex',
            'cryptographic', 0.65, 2,
            'hex', 'medium',
            'SHA-512,SHA3-512,BLAKE2b,Keccak-512',
            'SHAKE256 is an Extendable-Output Function (XOF) from the SHA-3 family. Output length is variable.',
            '32f260536c57fb4b3088f3173556e1e007208da3ab30d0d7b48a4305f5a0fadb13850457b135036a2f439ca8f168ac318569f07a6460b099b4caa725a57323e6',
            'Requires custom scripts depending on the generated length.'
        ),
        (
            'SHAKE128 (XOF)',
            128, None, 'lowercase_hex',
            'cryptographic', 0.65, 2,
            'hex', 'medium',
            'SHA-512,SHA3-512,BLAKE2b,Keccak-512',
            'SHAKE128 is an Extendable-Output Function (XOF) from the SHA-3 family. Output length is variable.',
            '0a1b2c3d4e5f6g7h8i9j...', # Sample placeholder
            'Requires custom scripts depending on the generated length.'
        ),
        (
            'HAS-160',
            40, None, 'lowercase_hex',
            'cryptographic', 0.65, 3,
            'hex', 'medium',
            'SHA-1,RIPEMD-160,SHA-0',
            'HAS-160 is a Korean cryptographic hash function designed for the KCDSA digital signature algorithm.',
            'd8a001c587a85f95efd47af2e2e86c6d84801fe4',
            'Rare outside of Korean standards. Custom Python/C scripts required for cracking.'
        ),
        (
            'Snefru-256',
            64, None, 'lowercase_hex',
            'cryptographic', 0.65, 3,
            'hex', 'medium',
            'SHA-256,SM3,Keccak-256,BLAKE2s,MD6,SHA3-256,RIPEMD-256,BLAKE3,Streebog-256',
            'Snefru-256 is an early cryptographic hash function designed by Ralph Merkle in 1990. Highly insecure.',
            'e29d6f6e... (Rare 64-char hex)', # Placeholder for structure
            'Completely broken. Custom scripts required for cracking.'
        ),
        (
            'Snefru-128',
            32, None, 'lowercase_hex',
            'cryptographic', 0.65, 3,
            'hex', 'medium',
            'MD5,NTLM,MD4,MD2,LM Hash,RIPEMD-128',
            'Snefru-128 is the 128-bit variant of the early Snefru hash. Highly insecure and vulnerable to collisions.',
            'c89b2f3a... (Rare 32-char hex)', # Placeholder for structure
            'Completely broken. Custom scripts required for cracking.'
        ),
        (
            'GOST R 34.11-94',
            64, None, 'lowercase_hex',
            'cryptographic', 0.65, 3,
            'hex', 'medium',
            'SHA-256,SM3,Keccak-256,BLAKE2s,MD6,SHA3-256,RIPEMD-256,Snefru-256,Streebog-256',
            'GOST R 34.11-94 is a legacy Russian national standard cryptographic hash function. Replaced by Streebog in 2012.',
            '0820063229ab17ea5cf896c21e646271c6dc0082f5b84c8d5045a4a50d27c62b', # Typical 64-char output
            'hashcat -m 6900'
        ),
        (
            'Streebog-256',
            64, None, 'lowercase_hex',
            'cryptographic', 0.65, 3,
            'hex', 'medium',
            'SHA-256,SM3,Keccak-256,BLAKE2s,MD6,SHA3-256,RIPEMD-256,GOST R 34.11-94,Snefru-256,BLAKE3',
            'Streebog-256 (GOST R 34.11-2012) is the modern Russian national standard cryptographic hash function.',
            '3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb',
            'hashcat -m 11700'
        ),
        (
            'Streebog-512',
            128, None, 'lowercase_hex',
            'cryptographic', 0.65, 3,
            'hex', 'medium',
            'SHA-512,BLAKE2b,Keccak-512,SHA3-512,SHAKE128 (XOF),SHAKE256 (XOF),Whirlpool',
            'Streebog-512 (GOST R 34.11-2012) is the 512-bit modern Russian national standard cryptographic hash function.',
            '486f64c1917879417f46325146b2b73259eec81b5fb28df41bc56306eebf2390a3c200ab56461c360db9f18a223e7a02dbd80bb1bb54e605d581561bf46879e9',
            'hashcat -m 11800'
        ),
        (
            'ssdeep (Fuzzy Hash)',
            None, r'^\d+:[a-zA-Z0-9\/\+]+:[a-zA-Z0-9\/\+]+$', 'custom',
            'fuzzy', 0.95, 1,
            'mixed', 'critical',
            '', # Iska format itna unique hai ki ye kisi ke sath clash nahi karega
            'Context-Triggered Piecewise Hash (CTPH). Used heavily in malware analysis to identify similar (but not identical) files.',
            '192:1F9zH8x40BvE1Vv58tD1J9/3Z:1F9zH8x40BvE1Vv58tD1J9/3Z', # Example format
            'Compare against malware databases like VirusTotal, MalwareBazaar, or use the ssdeep CLI.'
        ),
        (
            'scrypt',
            128, None, 'lowercase_hex',
            'kdf', 0.70, 2,
            'hex', 'low',
            'SHA-512,BLAKE2b,HMAC-SHA512,Yescrypt',
            'scrypt is a password-based key derivation function, designed to be memory-intensive to resist ASIC attacks.',
            '04d80c89dccde9f80b46c94473e5076073cc3700c64ef076d9977a4ae5ab08200253f8fb72d9a94106e1283e5a7e68e744cfe965badb49f3a6f7c240da3c5b46',
            'Requires N, r, p parameters for verification. Hashcat -m 8900'
        ),
        (
            'Yescrypt',
            128, None, 'lowercase_hex',
            'kdf', 0.70, 2,
            'hex', 'low',
            'SHA-512,scrypt,BLAKE2b',
            'Yescrypt is a modern KDF based on scrypt, used as the default password hashing scheme in modern Linux distributions.',
            '...', # Use the same or similar 128-char example
            'Modern Linux default. Hashcat -m 23100'
        ),
        (
            'yescrypt',
            None, '$y$', 'modular_crypt',
            'kdf', 0.95, 1,
            'mixed', 'low',
            'scrypt',
            'yescrypt is a modern password hashing scheme based on scrypt, used as the default in many Linux distros.',
            '$y$j9T$fMG8bY7RqXLZ6lErkSjCn.$VVxLk6hL2hEE0fGrpWUwE.7RaV.NE9sn7jKBzM9zvO2',
            'Default in Debian/Fedora. Use Hashcat -m 23100'
        ),
        (
            'CMAC-AES (64-bit)',
            16, None, 'lowercase_hex',
            'mac', 0.70, 2,
            'hex', 'medium',
            'CRC64,MySQL-Old-Password',
            'Cipher-based Message Authentication Code (truncated to 64 bits). Often used in embedded systems or protocols with limited bandwidth.',
            '9fb775f8136e0f7b',
            'Requires the original Block Cipher key (usually AES) to verify. Extremely hard to crack without the key.'
        ),

        (
            'Fletcher-8',
            2, None, 'uppercase_hex',
            'checksum', 0.60, 4,
            'hex', 'none',
            'CRC8,XOR-8',
            'Fletcher-8 checksum. Slightly more robust than simple XOR/Sum.',
            'D4',
            'Commonly used in lightweight serial communication.'
        ),
        (
            'XOR-8 / Checksum-8',
            2, None, 'uppercase_hex',
            'checksum', 0.60, 4,
            'hex', 'none',
            'CRC8,Fletcher-8',
            'Simple 8-bit XOR or modular sum checksum.',
            'D4',
            'Used heavily in NMEA GPS sentences and basic embedded systems.'
        ),
        (
            'Fletcher-16',
            4, None, 'lowercase_hex',
            'checksum', 0.65, 4,
            'hex', 'none',
            'CRC16',
            'Fletcher-16 checksum. Produces a 16-bit output (4 hex chars).',
            '1cc7',
            'Used in some low-level network protocols and simple data blocks.'
        ),
        (
            'Fletcher-32',
            8, None, 'lowercase_hex',
            'checksum', 0.65, 4,
            'hex', 'none',
            'CRC32,Adler-32',
            'Fletcher-32 checksum. Produces a 32-bit output (8 hex chars).',
            'e04d1cc7',
            'Often used as a faster alternative to CRC32. Used in ZFS.'
        ),
        (
            'Fletcher-64',
            16, None, 'lowercase_hex',
            'checksum', 0.65, 4,
            'hex', 'none',
            'CRC64,CMAC-AES (64-bit)',
            'Fletcher-64 checksum. Produces a 64-bit output (16 hex chars).',
            'cbf439261cc7a4e2',
            'Used in modern file systems and highly reliable data streams.'
        ),
        (
            'TCP/IP Checksum',
            4, None, 'mixed_hex',
            'checksum', 0.65, 4,
            'hex', 'none',
            'CRC16,Fletcher-16',
            'Internet Checksum (RFC 1071). 16-bit one\'s complement sum used heavily in IPv4, TCP, and UDP headers.',
            'b8b1',
            'Often seen in PCAP network forensics. Validate using Wireshark or Python Scapy.'
        ),
        
        ('HMAC-MD5', 32, None, 'lowercase_hex', 'mac', 0.70, 2, 'hex', 'medium', 'MD5,NTLM,MD4,RIPEMD-128', 'HMAC using MD5 hash.', '0fb9658f...', 'Hashcat -m 50'),
        ('HMAC-MD4', 32, None, 'lowercase_hex', 'mac', 0.60, 3, 'hex', 'high', 'MD4,MD5,NTLM', 'HMAC using legacy MD4 hash.', '...', 'Hashcat -m 10'),
        ('HMAC-RIPEMD128', 32, None, 'lowercase_hex', 'mac', 0.60, 3, 'hex', 'medium', 'RIPEMD-128,MD5', 'HMAC using RIPEMD-128.', '...', 'Custom scripts'),
        
        # 40 Chars (160-bit)
        ('HMAC-SHA1', 40, None, 'lowercase_hex', 'mac', 0.70, 2, 'hex', 'medium', 'SHA-1,RIPEMD-160,HAS-160', 'HMAC using SHA-1. Very common in older APIs.', '...', 'Hashcat -m 150'),
        ('HMAC-RIPEMD160', 40, None, 'lowercase_hex', 'mac', 0.65, 3, 'hex', 'medium', 'RIPEMD-160,SHA-1', 'HMAC using RIPEMD-160.', '...', 'Hashcat -m 6000'),
        ('HMAC-HAS160', 40, None, 'lowercase_hex', 'mac', 0.60, 3, 'hex', 'medium', 'HAS-160,SHA-1', 'HMAC using Korean HAS-160.', '...', 'Custom scripts'),

        # 56 Chars (224-bit)
        ('HMAC-SHA224', 56, None, 'lowercase_hex', 'mac', 0.65, 2, 'hex', 'low', 'SHA-224,Keccak-224', 'HMAC using SHA-224.', '...', 'Hashcat -m 110'),

        # 64 Chars (256-bit)
        ('HMAC-SHA256', 64, None, 'lowercase_hex', 'mac', 0.75, 2, 'hex', 'low', 'SHA-256,SM3,Keccak-256,MD6', 'HMAC using SHA-256. Industry standard for JWT/API.', '...', 'Hashcat -m 1450'),
        ('HMAC-RIPEMD256', 64, None, 'lowercase_hex', 'mac', 0.60, 3, 'hex', 'medium', 'RIPEMD-256,SHA-256', 'HMAC using RIPEMD-256.', '...', 'Custom scripts'),

        # 128 Chars (512-bit)
        ('HMAC-SHA512', 128, None, 'lowercase_hex', 'mac', 0.75, 2, 'hex', 'low', 'SHA-512,BLAKE2b,SHA3-512', 'HMAC using SHA-512.', '...', 'Hashcat -m 1750'),
        # --- CMAC SECTION (Cipher-based) ---
        ('CMAC-AES128', 32, None, 'lowercase_hex', 'mac', 0.70, 2, 'hex', 'low', 'MD5,AES-128-Key', 'CMAC using AES-128 block cipher. Common in embedded systems.', '...', 'Requires 16-byte key.'),
        ('CMAC-AES256', 32, None, 'lowercase_hex', 'mac', 0.70, 2, 'hex', 'low', 'MD5,AES-256-Key', 'CMAC using AES-256 block cipher.', '...', 'Requires 32-byte key.')

        


    ]

    cursor.executemany('''
        INSERT INTO hash_formats
        (name, hex_length, prefix, charset, category,
         base_confidence, priority, output_format,
         collision_risk, ambiguous_with, description,
         example, next_step)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', data)

    print("[+] Hash formats inserted.")


def insert_entropy_profiles(cursor):
    data = [
        (
            'Plain Text',
            3.50, 5.50,
            'skewed', 'skewed',
            'plaintext', 0.90,
            'Natural language text has low entropy due to character frequency patterns.',
            'Hello World, normal readable text'
        ),
        (
            'Source Code',
            4.50, 6.00,
            'skewed', 'skewed',
            'plaintext', 0.85,
            'Source code has moderate entropy due to keywords and symbols.',
            'Python, C, JavaScript files'
        ),
        (
            'Base64 Blob',
            5.90, 6.10,
            'pseudo_random', 'mixed',
            'encoded', 0.88,
            'Base64 encoded data has characteristic entropy in 5.9-6.1 range.',
            'aGVsbG8gd29ybGQ='
        ),
        (
            'ZIP Compressed',
            7.20, 7.80,
            'pseudo_random', 'mixed',
            'compressed', 0.85,
            'ZIP compression produces high but not maximum entropy.',
            '.zip, .gz, .zlib files'
        ),
        (
            'LZMA Compressed',
            7.30, 7.90,
            'pseudo_random', 'mixed',
            'compressed', 0.83,
            'LZMA compression similar to ZIP but slightly higher entropy.',
            '.xz, .7z files'
        ),
        (
            'AES Encrypted',
            7.85, 8.00,
            'truly_random', 'flat',
            'encrypted', 0.90,
            'AES encryption produces near-perfect entropy with flat byte distribution.',
            'OpenSSL AES-256-CBC output'
        ),
        (
            'Packed Malware',
            7.70, 8.00,
            'truly_random', 'flat',
            'encrypted', 0.75,
            'Packed/obfuscated malware exhibits high entropy similar to encryption.',
            'UPX packed executables'
        ),
        (
            'JSON Data',
            4.50, 6.50,
            'skewed', 'mixed',
            'plaintext', 0.85,
            'JSON structured data with moderate entropy.',
            '{"key":"value"}'
        ),
        (
            'XML Data',
            4.50, 6.20,
            'skewed', 'mixed',
            'plaintext', 0.83,
            'XML structured text.',
            '<tag>Hello</tag>'
        ),
        (
            'Encrypted TLS Payload',
            7.85, 8.00,
            'truly_random', 'flat',
            'encrypted', 0.92,
            'TLS encrypted traffic payload.',
            'Captured HTTPS packet'
        ),
    ]

    cursor.executemany('''
        INSERT INTO entropy_profiles
        (label, min_entropy, max_entropy, chi_sq_type,
         byte_dist, category, confidence,
         description, example)
        VALUES (?,?,?,?,?,?,?,?,?)
    ''', data)

    print("[+] Entropy profiles inserted.")


def insert_cipher_profiles(cursor):
    data = [
        (
            'Rotation Cipher (ROT/Caesar)',
            0.055, 0.095,
            'alpha_only', 'shifted_english',
            '26', 0.70, 2, 
            'Caesar cipher shifts each letter by a fixed number of positions.',
            'Khoor Zruog (Hello World shifted by 3)'
        ),
        (
            'ROT13',
            0.060, 0.070,
            'alpha_only', 'shifted_english',
            '13', 0.85, 1,
            'ROT13 is a special case of Caesar cipher with shift of 13.',
            'Uryyb Jbeyq (Hello World in ROT13)'
        ),
        (
            'Vigenere Cipher',
            0.030, 0.095,
            'alpha_only', 'polyalphabetic',
            'variable', 0.68, 2, 
            'Vigenere uses a keyword to apply multiple Caesar shifts.',
            'Rijvs Uyvjn (variable key)'
        ),
        (
            'Atbash Cipher',
            0.055, 0.095,
            'alpha_only', 'reversed_english',
            '26', 0.75, 1,
            'Atbash reverses the alphabet: A=Z, B=Y, etc.',
            'Svool Dliow (Hello World in Atbash)'
        ),
        (
            'Plain English',
            0.065, 0.070,
            'mixed', 'normal_english',
            'N/A', 0.99, 1,
            'Normal English text with standard character distribution.',
            'Hello World'
        ),
        (
            'Random Data',
            0.035, 0.042,
            'any', 'random',
            'N/A', 0.99, 1,
            'Truly random data with near-uniform character distribution.',
            'xK9#mP2$nL5@qR8'
        ),
        (
            'Substitution Cipher',
            0.055, 0.095,
            'alpha_only', 'substituted',
            '26!', 0.82, 1, 
            'General monoalphabetic substitution cipher.',
            'Gsv jfrxp yildm ulc'
        ),
        (
            'Transposition Cipher',
            0.055, 0.095,
            'alpha_only', 'scrambled',
            'variable', 0.70, 3,
            'Characters rearranged but frequency same.',
            'HWeolrllod'
        ),
        (
            'Playfair Cipher',
            0.030, 0.070,
            'alpha_only', 'digraph',
            '25x25', 0.80, 1, 
            'Digraph substitution cipher.',
            'BM OD ZB XD NA BE KU DM UI XM MO UV IF'
        ),

        
        
    ]

    cursor.executemany('''
        INSERT INTO cipher_profiles
        (name, ic_min, ic_max, charset, freq_pattern,
         keyspace, confidence, priority,
         description, example)
        VALUES (?,?,?,?,?,?,?,?,?,?)
    ''', data)

    print("[+] Cipher profiles inserted.")


# ==============================
# MAIN
# ==============================
def main():
    print("\n" + "="*50)
    print("   decod3x — Database Initialization")
    print("="*50 + "\n")

    db_path = get_db_path()
    print(f"[*] Database location: {db_path}")

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    print("[*] Creating tables...")
    create_tables(cursor)

    print("[*] Inserting data...")
    insert_encoding_signatures(cursor)
    insert_magic_bytes(cursor)
    insert_hash_formats(cursor)
    insert_entropy_profiles(cursor)
    insert_cipher_profiles(cursor)

    conn.commit()
    conn.close()

    print("\n" + "="*50)
    print("   [✓] Database ready!")
    print("="*50 + "\n")


if __name__ == '__main__':
    main()