import os
import platform
from pathlib import Path


# ==============================
# PLATFORM DETECTION
# ==============================
def get_platform() -> str:
    """
    'windows' ya 'linux' return karta hai.
    """
    if os.name == 'nt':
        return 'windows'
    return 'linux'


def get_platform_info() -> dict:
    """
    Platform ki complete info return karta hai.
    """
    return {
        'os'         : platform.system(),
        'os_version' : platform.version(),
        'python'     : platform.python_version(),
        'machine'    : platform.machine(),
        'platform'   : get_platform()
    }


# ==============================
# SCREEN
# ==============================
def clear_screen():
    """
    Terminal screen clear karta hai.
    Windows + Linux dono pe kaam karta hai.
    """
    if get_platform() == 'windows':
        os.system('cls')
    else:
        os.system('clear')


# ==============================
# FILE HELPERS
# ==============================
def is_valid_file(filepath: str) -> bool:
    """
    File exist karti hai aur readable hai?
    """
    path = Path(filepath)
    return path.exists() and path.is_file()


def get_file_size(filepath: str) -> str:
    """
    File size human-readable format mein.
    Example: "2.4 MB", "512 KB"
    """
    size = Path(filepath).stat().st_size

    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024*1024):.1f} MB"
    else:
        return f"{size / (1024*1024*1024):.1f} GB"


def resolve_path(filepath: str) -> Path:
    """
    Relative ya absolute path ko
    safely resolve karta hai.
    Windows backslash + Linux slash
    dono handle karta hai.
    """
    return Path(filepath).resolve()