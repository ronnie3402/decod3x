import sqlite3
import os
from pathlib import Path


# ==============================
# DB PATH
# ==============================
def get_db_path() -> Path:
    """
    Platform-safe DB path return karta hai.
    Windows : C:/Users/user/AppData/Roaming/decod3x/
    Linux   : ~/.decod3x/
    """
    if os.name == 'nt':  # Windows
        base = Path(os.environ['APPDATA']) / 'decod3x'
    else:  # Linux/Mac
        base = Path.home() / '.decod3x'

    base.mkdir(parents=True, exist_ok=True)
    return base / 'triage_engine.db'


# ==============================
# CONNECTION
# ==============================
def get_connection() -> sqlite3.Connection:
    """
    SQLite connection return karta hai.
    DB nahi mili? Clear error deta hai.
    """
    db_path = get_db_path()

    if not db_path.exists():
        raise FileNotFoundError(
            f"\n[!] Database not found: {db_path}"
            f"\n[→] Run this first: python db_init/populate_db.py\n"
        )

    conn = sqlite3.connect(str(db_path))

    # Column names by name access karne ke liye
    conn.row_factory = sqlite3.Row

    return conn


# ==============================
# QUERY HELPERS
# ==============================
def fetch_all(query: str, params: tuple = ()) -> list:
    """
    Multiple rows fetch karta hai.
    Returns: list of sqlite3.Row objects
    """
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(query, params)
        results = cur.fetchall()
        conn.close()
        return results

    except FileNotFoundError as e:
        print(e)
        return []

    except sqlite3.Error as e:
        print(f"[!] Database error: {e}")
        return []


def fetch_one(query: str, params: tuple = ()):
    """
    Single row fetch karta hai.
    Returns: sqlite3.Row ya None
    """
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute(query, params)
        result = cur.fetchone()
        conn.close()
        return result

    except FileNotFoundError as e:
        print(e)
        return None

    except sqlite3.Error as e:
        print(f"[!] Database error: {e}")
        return None


# ==============================
# HEALTH CHECK
# ==============================
def check_db_health() -> bool:
    """
    DB exist karti hai aur
    saari tables hain? Check karta hai.
    Returns: True ya False
    """
    required_tables = [
        'encoding_signatures',
        'magic_bytes',
        'hash_formats',
        'entropy_profiles',
        'cipher_profiles'
    ]

    try:
        conn = get_connection()
        cur = conn.cursor()

        for table in required_tables:
            cur.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name=?",
                (table,)
            )
            if not cur.fetchone():
                print(f"[!] Missing table: {table}")
                conn.close()
                return False

        conn.close()
        return True

    except FileNotFoundError:
        return False

    except sqlite3.Error as e:
        print(f"[!] Health check failed: {e}")
        return False