import os
from colorama import init, Fore, Back, Style

# ==============================
# INITIALIZE COLORAMA
# ==============================
# Windows + Linux dono pe kaam karta hai
init(autoreset=True)


# ==============================
# COLOR SCHEME
# ==============================
class Color:
    """
    decod3x color scheme.

    Category Colors:
    ─────────────────
    ENCODING   → Green
    HASH       → Cyan
    ENCRYPTION → Red
    CIPHER     → Yellow
    UNKNOWN    → White

    Confidence Colors:
    ──────────────────
    HIGH       → Green
    MEDIUM     → Yellow
    LOW        → Red
    """

    # ── Category Colors ──
    ENCODING   = Fore.GREEN
    HASH       = Fore.CYAN
    ENCRYPTION = Fore.RED
    CIPHER     = Fore.YELLOW
    UNKNOWN    = Fore.WHITE

    # ── Confidence Colors ──
    HIGH       = Fore.GREEN
    MEDIUM     = Fore.YELLOW
    LOW        = Fore.RED

    # ── UI Colors ──
    HEADER     = Fore.MAGENTA
    SEPARATOR  = Fore.BLUE
    INFO       = Fore.CYAN
    SUCCESS    = Fore.GREEN
    WARNING    = Fore.YELLOW
    ERROR      = Fore.RED
    DIM        = Style.DIM
    BOLD       = Style.BRIGHT

    # ── Reset ──
    RESET      = Style.RESET_ALL


# ==============================
# COLOR ENABLED FLAG
# ==============================
_COLOR_ENABLED = True


def disable_colors():
    """--no-color flag ke liye."""
    global _COLOR_ENABLED
    _COLOR_ENABLED = False


def enable_colors():
    """Colors enable karo."""
    global _COLOR_ENABLED
    _COLOR_ENABLED = True


def is_color_enabled() -> bool:
    return _COLOR_ENABLED


# ==============================
# COLORIZE HELPERS
# ==============================
def colorize(text: str, color: str) -> str:
    """
    Text ko color mein wrap karo.
    Color disabled hone pe plain text return karo.
    """
    if not _COLOR_ENABLED:
        return text
    return f"{color}{text}{Style.RESET_ALL}"


def category_color(category: str) -> str:
    """
    Category ke basis pe color return karo.
    """
    color_map = {
        'encoding'  : Color.ENCODING,
        'hash'      : Color.HASH,
        'encryption': Color.ENCRYPTION,
        'cipher'    : Color.CIPHER,
        'unknown'   : Color.UNKNOWN,
    }
    return color_map.get(category.lower(), Color.UNKNOWN)


def confidence_color(confidence: float) -> str:
    """
    Confidence value ke basis pe color return karo.
    """
    if confidence >= 0.80:
        return Color.HIGH
    elif confidence >= 0.60:
        return Color.MEDIUM
    else:
        return Color.LOW


# ==============================
# PRINT HELPERS
# ==============================
def print_header(text: str):
    """
    Tool header print karo — Magenta + Bold.
    """
    if _COLOR_ENABLED:
        print(f"{Color.BOLD}{Color.HEADER}{text}{Color.RESET}")
    else:
        print(text)


def print_separator(char: str = "─",
                    length: int = 54):
    """
    Separator line print karo.
    """
    line = char * length
    if _COLOR_ENABLED:
        print(f"{Color.SEPARATOR}{line}{Color.RESET}")
    else:
        print(line)


def print_info(label: str, value: str):
    """
    Info line print karo.
    Format: [*] Label : Value
    """
    if _COLOR_ENABLED:
        print(
            f"{Color.INFO}[*]{Color.RESET} "
            f"{label:<12}: {value}"
        )
    else:
        print(f"[*] {label:<12}: {value}")


def print_success(label: str, value: str):
    """
    Success line print karo.
    Format: [✓] Label : Value
    """
    if _COLOR_ENABLED:
        print(
            f"{Color.SUCCESS}[✓]{Color.RESET} "
            f"{label:<12}: {value}"
        )
    else:
        print(f"[✓] {label:<12}: {value}")


def print_warning(label: str, value: str):
    """
    Warning line print karo.
    Format: [!] Label : Value
    """
    if _COLOR_ENABLED:
        print(
            f"{Color.WARNING}[!]{Color.RESET} "
            f"{label:<12}: {value}"
        )
    else:
        print(f"[!] {label:<12}: {value}")


def print_error(label: str, value: str):
    """
    Error line print karo.
    Format: [✗] Label : Value
    """
    if _COLOR_ENABLED:
        print(
            f"{Color.ERROR}[✗]{Color.RESET} "
            f"{label:<12}: {value}"
        )
    else:
        print(f"[✗] {label:<12}: {value}")


def print_result_line(label  : str,
                      value  : str,
                      color  : str = ""):
    """
    Result line print karo with custom color.
    """
    if _COLOR_ENABLED and color:
        print(
            f"  {label:<14}: "
            f"{color}{value}{Color.RESET}"
        )
    else:
        print(f"  {label:<14}: {value}")


def print_category_banner(category  : str,
                           type_name : str,
                           confidence: float):
    """
    Category result ka colored banner.
    """
    color  = category_color(category)
    c_conf = confidence_color(confidence)
    conf   = int(confidence * 100)

    if _COLOR_ENABLED:
        print(
            f"\n  {color}[✓] CATEGORY{Color.RESET}"
            f"   : {color}{category.upper()}{Color.RESET}"
        )
        print(
            f"  {color}[✓] TYPE{Color.RESET}"
            f"       : {color}{type_name}{Color.RESET}"
        )
        print(
            f"  {c_conf}[✓] CONFIDENCE{Color.RESET}"
            f" : {c_conf}{conf}%{Color.RESET}"
        )
    else:
        print(f"\n  [✓] CATEGORY   : {category.upper()}")
        print(f"  [✓] TYPE       : {type_name}")
        print(f"  [✓] CONFIDENCE : {conf}%")