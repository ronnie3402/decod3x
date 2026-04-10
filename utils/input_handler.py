import os
import sys
from pathlib import Path
from utils.system import (
    is_valid_file,
    get_file_size,
    resolve_path
)


# ==============================
# CONSTANTS
# ==============================
MAX_STRING_LENGTH = 100_000   # 100KB string limit
MAX_FILE_SIZE     = 50 * 1024 * 1024  # 50MB file limit
CHUNK_SIZE        = 8192      # File read chunk size


# ==============================
# STRING INPUT HANDLER
# ==============================
def handle_string_input(input_str: str) -> dict:
    """
    String input ko validate aur
    process karta hai.

    Returns:
    {
        'success'  : bool,
        'data'     : str,
        'length'   : int,
        'error'    : str,
        'type'     : 'string'
    }
    """
    # Empty check
    if not input_str:
        return _error_result('empty_input')

    # Strip whitespace
    cleaned = input_str.strip()

    if not cleaned:
        return _error_result('empty_input')

    # Length check
    if len(cleaned) > MAX_STRING_LENGTH:
        return _error_result(
            'too_long',
            f'Input too large: {len(cleaned)} chars '
            f'(max: {MAX_STRING_LENGTH})'
        )

    return {
        'success' : True,
        'data'    : cleaned,
        'length'  : len(cleaned),
        'error'   : None,
        'type'    : 'string'
    }


# ==============================
# FILE INPUT HANDLER
# ==============================
def handle_file_input(filepath: str) -> dict:
    """
    File input ko validate aur
    read karta hai.

    Returns:
    {
        'success'   : bool,
        'data'      : bytes,
        'filepath'  : str,
        'filename'  : str,
        'size'      : str,
        'size_bytes': int,
        'error'     : str,
        'type'      : 'file'
    }
    """
    if not filepath:
        return _error_result('empty_input')

    # Path resolve karo (cross-platform)
    try:
        path = resolve_path(filepath)
    except Exception as e:
        return _error_result(
            'invalid_path',
            str(e)
        )

    # File exist karti hai?
    if not path.exists():
        return _error_result(
            'file_missing',
            str(path)
        )

    # File hai ya directory?
    if not path.is_file():
        return _error_result(
            'not_a_file',
            f'{path} is a directory'
        )

    # Size check
    size_bytes = path.stat().st_size

    if size_bytes == 0:
        return _error_result(
            'empty_file',
            str(path)
        )

    if size_bytes > MAX_FILE_SIZE:
        return _error_result(
            'file_too_large',
            f'{get_file_size(str(path))} '
            f'(max: 50MB)'
        )

    # File read karo
    data = _read_file(path)

    if data is None:
        return _error_result(
            'read_error',
            str(path)
        )

    return {
        'success'   : True,
        'data'      : data,
        'filepath'  : str(path),
        'filename'  : path.name,
        'size'      : get_file_size(str(path)),
        'size_bytes': size_bytes,
        'error'     : None,
        'type'      : 'file'
    }


# ==============================
# FILE READER
# ==============================
def _read_file(path: Path) -> bytes:
    """
    File ko binary mode mein read karta hai.
    Large files ke liye chunked reading.
    """
    try:
        with open(str(path), 'rb') as f:
            # Small file → direct read
            if path.stat().st_size <= 1024 * 1024:
                return f.read()

            # Large file → chunked read
            chunks = []
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                chunks.append(chunk)
            return b''.join(chunks)

    except PermissionError:
        return None
    except OSError:
        return None
    except Exception:
        return None


# ==============================
# INPUT DETECTOR
# ==============================
def detect_input_type(data) -> str:
    """
    Input data ka type detect karta hai.
    Engine ko pass karne se pehle.

    Returns: 'string' ya 'binary'
    """
    if isinstance(data, bytes):
        # Printable ratio check
        printable = sum(
            1 for b in data
            if 32 <= b <= 126 or b in (9, 10, 13)
        )
        ratio = printable / len(data) if data else 0

        # 85%+ printable → treat as string
        if ratio >= 0.85:
            try:
                decoded = data.decode('utf-8')
                return 'string'
            except UnicodeDecodeError:
                return 'binary'
        return 'binary'

    return 'string'


def normalize_input(data) -> tuple:
    """
    Input ko normalize karta hai
    engine ke liye.

    Returns: (str_data, bytes_data)
    Both always available.
    """
    if isinstance(data, bytes):
        input_type = detect_input_type(data)

        if input_type == 'string':
            try:
                str_data   = data.decode(
                    'utf-8', errors='replace'
                ).strip()
                bytes_data = data
            except Exception:
                str_data   = None
                bytes_data = data
        else:
            str_data   = None
            bytes_data = data

    else:
        str_data   = data.strip()
        bytes_data = data.encode(
            'utf-8', errors='replace'
        )

    return str_data, bytes_data

def get_clean_input(raw_input: str) -> str:
    # Analysis ke liye spaces aur newlines hata do
    return "".join(raw_input.split())
# ==============================
# STDIN HANDLER
# ==============================
def handle_stdin_input() -> dict:
    """
    Stdin se input read karta hai.
    Pipe input ke liye:
    echo "data" | decod3x
    """
    try:
        if not sys.stdin.isatty():
            data = sys.stdin.read().strip()
            if data:
                return handle_string_input(data)
    except Exception:
        pass

    return _error_result('no_input')


# ==============================
# DISPLAY HELPERS
# ==============================
def get_input_summary(input_result: dict) -> dict:
    """
    Input ka summary dict return karta hai.
    CLI display ke liye.
    """
    if input_result['type'] == 'string':
        data    = input_result['data']
        preview = data[:50] + '...' \
                  if len(data) > 50 else data

        return {
            'type'   : 'String',
            'length' : f"{input_result['length']} chars",
            'preview': preview
        }

    else:
        return {
            'type'    : 'File',
            'filename': input_result.get('filename', ''),
            'size'    : input_result.get('size', ''),
            'path'    : input_result.get('filepath', ''),
        }


# ==============================
# ERROR RESULTS
# ==============================
def _error_result(error_type: str,
                  detail    : str = '') -> dict:
    """Standard error result."""

    messages = {
        'empty_input'   : 'Empty input provided.',
        'too_long'      : detail or 'Input too large.',
        'file_missing'  : f'File not found: {detail}',
        'not_a_file'    : f'Not a file: {detail}',
        'empty_file'    : f'File is empty: {detail}',
        'file_too_large': f'File too large: {detail}',
        'read_error'    : f'Cannot read file: {detail}',
        'invalid_path'  : f'Invalid path: {detail}',
        'no_input'      : 'No input provided.',
    }

    return {
        'success'   : False,
        'data'      : None,
        'error'     : messages.get(error_type, detail),
        'error_type': error_type,
        'type'      : 'error'
    }