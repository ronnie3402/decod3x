# decod3x — Smart Data Triage Engine
```
  ____                     _ _____      
 |  _ \  ___  ___ ___   __| |___ /_  __
 | | | |/ _ \/ __/ _ \ / _` | |_ \ \/ /
 | |_| |  __/ (_| (_) | (_| |___) >  < 
 |____/ \___|\___\___/ \__,_|____/_/\_\
```

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.7+-blue?style=flat-square&logo=python"/>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0.0-orange?style=flat-square"/>
</p>

> **A fast, offline CLI tool for Cybersecurity Professionals and CTF players to rapidly identify unknown data formats — with actionable next steps.**

decod3x analyzes any unknown string or binary file and identifies whether it is an encoding, hash, encrypted data, or classical cipher — all within milliseconds, entirely offline.

---

## Why decod3x?

Cybersecurity Professionals and CTF players often encounter unknown data during investigations. Identifying whether a string is Base64, an MD5 hash, AES-encrypted, or a Caesar cipher typically requires switching between multiple tools. decod3x consolidates this into a single command.
```
Unknown data → decod3x → Identified + Next Steps
```

**decod3x identifies data. It does not decode, decrypt, or crack it.**

---

## Features

- **4-Pillar Detection Engine** — Encoding, Hash, Encryption, Classical Cipher
- **Confidence Scoring** — Every result includes a confidence percentage
- **Multi-layer Detection** — Detects nested encodings (e.g. Base64 → Hex → MD5)
- **Actionable Output** — Suggests the right tool for every detection
- **Cross-Platform** — Fully supported on Windows and Linux
- **100% Offline** — No internet connection required
- **Fast** — Average analysis time under 50ms

---

## What It Detects

### Encodings
`Base64 (Standard, URL Safe, Atom128)` `Base32` `Base45` `Base58` `Base62` `Base91`
`Base85 (Standard/Ascii85)` `Base85 (IPv6)` `Base85 (Z85/ZeroMQ)`
`Hex (Hexadecimal)` `URL Encoding (Percent Encoding)` `HTML Entity (Named, Decimal, Hex)`   
`Binary (0/1)` `Octal (0-7)`

### Hash Algorithms
`MD2` `MD4` `MD5` `MD6` `SHA-0` `SHA-1` `SHA-224` `SHA-256` `SHA-384` `SHA-512`
`SHA3-224` `SHA3-256` `SHA3-384` `SHA3-512` `Keccak-224` `Keccak-256` `Keccak-384`
`Keccak-512` `SHAKE128 (XOF)` `SHAKE256 (XOF)` `bcrypt` `Argon2` `scrypt` `yescrypt` `NTLM` `LM Hash`
`BLAKE2b` `BLAKE2s` `BLAKE3` `RIPEMD-128` `RIPEMD-160` `RIPEMD-256` `RIPEMD-320` `Whirlpool` 
`SM3` `Streebog-256` `Streebog-512` `GOST R 34.11-94` `HAS-160` `Snefru-128` `Snefru-256`
`CRC8` `CRC16` `CRC32` `Adler-32` `Fletcher-8` `Fletcher-16` `Fletcher-32` `Fletcher-64` `TCP/IP` 
`Checksum` `XOR-8` `ssdeep` `HMAC-MD4` `HMAC-MD5` `HMAC-SHA1` `HMAC-SHA224` `HMAC-SHA256` `HMAC-SHA512` 
`HMAC-RIPEMD128` `HMAC-RIPEMD160` `HMAC-RIPEMD256` `HMAC-HAS160` `CMAC-AES128` `CMAC-AES256` `CMAC-AES (64-bit)`

### Encrypted / Compressed Formats
`OpenSSL Encrypted` `PGP Message` `PGP Public Key` `KeePass Database` `PEM Header`
`ZIP Archive` `RAR Archive` `7-Zip Archive` `Zlib Compressed`
`Windows EXE (MZ Header)` `ELF Binary (Linux Executable)`
`PDF Document` `PNG Image`

### Classical Ciphers
`Caesar` `ROT13` `Atbash Cipher` `Substitution Cipher`
`Vigenere Cipher` `Playfair Cipher` `Transposition Cipher`
`Plain English (Normal distribution)` `Random Data (High entropy/Uniform distribution)`

---

## Installation

### Requirements
- Python 3.7 or higher
- Git

### Linux
```bash
git clone https://github.com/yourname/decod3x
cd decod3x
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python db_init/populate_db.py
pip install -e .
decod3x --version
```

### Windows
```cmd
git clone https://github.com/yourname/decod3x
cd decod3x
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python db_init\populate_db.py
pip install -e .
decod3x --version
```

> **Note:** The `populate_db.py` command only needs to be run once after cloning.

---

## Usage
```
decod3x [-i STRING] [-f FILE] [-o OUTPUT] [-v] [-d N] [--no-color]

Options:
  -i, --input   STRING   Analyze a string directly
  -f, --file    PATH     Analyze a file (Identifies the file format or its content as a single blob)
  -o, --output  PATH     Save the analysis report to a file
  -v, --verbose          Show detailed per-pillar analysis
  -d, --depth   N        Max multi-layer detection depth (default: 5)
  --no-color             Disable colored output (for logging/piping)
  --version              Show version information
  -h, --help             Show this help message

> **Note:** The `-f` flag is designed to identify the format of a single file (e.g., Is this a PDF? Is this a PGP encrypted file?). It does **not** extract or batch-process multiple hashes from a single text file.
```

---

## Examples
```bash
# Identify a Base64 string
decod3x -i "aGVsbG8gd29ybGQ="

# Identify an MD5 hash with verbose output
decod3x -i "d41d8cd98f00b204e9800998ecf8427e" -v

# Identify a bcrypt hash (Linux/macOS)
decod3x -i '$2b$12$D4G1nEH0VqvFUhFnEzEd8.'

# Analyze a suspicious binary file
decod3x -f suspicious.bin

# Analyze a file and save the report
decod3x -f malware.bin -o report.txt

# Pipe-friendly output without colors
decod3x -i "aGVsbG8=" --no-color
```

---

## Sample Output
```
──────────────────────────────────────────────────────
  ANALYSIS RESULT
──────────────────────────────────────────────────────
  [✓] CATEGORY   : HASH
  [✓] TYPE       : MD5
  [✓] CONFIDENCE : 92%
  [i] INFO       : MD5 produces a 128-bit hash.
                   Widely used but cryptographically broken.

  NEXT STEPS
──────────────────────────────────────────────────────
  [→] Identify source of MD5 hash
  Tool    : hashlib.md5 in Python
  Command : crackstation.net / hashcat -m 0
  ⚠ Risk  : HIGH collision risk — avoid for security use
──────────────────────────────────────────────────────
[✓] Done        : Analysis complete | Time: 0.024s
```

---

## Use Cases

| Scenario | How decod3x Helps |
|---|---|
| SOC Alert Triage | Quickly identify unknown data in alerts |
| CTF Challenges | Instantly recognize encoding/cipher formats |
| Malware Analysis | Identify encoded payloads and encrypted blobs |
| Incident Response | Rapid classification of suspicious strings |
| Penetration Testing | Identify data formats in captured traffic |

---

## Dependencies
```
colorama>=0.4.6
```

All other components (`sqlite3`, `re`, `math`, `argparse`,
`pathlib`, `os`, `platform`) are part of the Python standard library.
No external services or internet access required.

---

## Important Notice

decod3x is a **data identification tool only**.

1. **Identification Only:** It will tell you *what* the data is. It will **not** decode, decrypt, or crack it.
2. **Single-Target Analysis:** It analyzes the input (string or file) as a **single unit**. 
   - It **cannot** "scan" a file to find and list 100 different hashes hidden inside it.
   - It **cannot** perform batch analysis on wordlists or log files.
3. **Forensic Focus:** The `-f` flag is for identifying unknown file types (via Magic Bytes) or analyzing the entropy of a single suspicious binary blob.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Author

Built for the cybersecurity community.

*"What is this data?" — answered in milliseconds.*