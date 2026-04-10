from utils.colors import (
    Color, colorize,
    print_header, print_separator,
    print_info, print_success,
    print_warning, print_error,
    print_category_banner,
    print_result_line,
    category_color, confidence_color,
    is_color_enabled
)
from engine.next_steps import (
    get_next_steps,
    format_next_steps
)


# ==============================
# MAIN FORMATTER
# ==============================
def format_result(
        analysis_result : dict,
        input_data      : str,
        verbose         : bool = False,
        multilayer      : dict = None
) -> str:
    """
    Complete analysis result ko
    CLI output format mein convert karta hai.

    Modes:
    1. Normal   → Clean summary
    2. Verbose  → Detailed analysis
    3. Ambiguous→ Multiple candidates
    4. Multilayer → Chain display
    """
    lines = []

    category   = analysis_result.get('category', 'unknown')
    confidence = analysis_result.get('confidence', 0.0)
    result     = analysis_result.get('result')
    ambiguous  = analysis_result.get('ambiguous', False)
    all_res    = analysis_result.get('all_results', {})

    # Top result
    top = result['top'] if result else None

    # ── Section: Result Header ──
    lines.append(_format_result_header(
        category, top, confidence
    ))

    # ── Section: Verbose Details ──
    if verbose and all_res:
        lines.append(_format_verbose_section(all_res))

    # ── Section: Ambiguous Candidates ──
    if ambiguous:
        lines.append(_format_ambiguous_section(analysis_result))

    # ── Section: Indicators (Encryption) ──
    if category == 'encryption' and top:
        indicators = top.get('indicators', [])
        if indicators:
            lines.append(_format_indicators(indicators))

    # ── Section: Multi-layer Chain ──
    if multilayer and multilayer.get('multilayer'):
        lines.append(_format_multilayer_section(multilayer))

    # ── Section: Next Steps ──
    if top and category != 'unknown':
        type_name = top.get('name', '')
        steps     = get_next_steps(category, type_name)
        lines.append(_format_next_steps_section(steps))

    # ── Section: Unknown ──
    if category == 'unknown':
        lines.append(_format_unknown_section(input_data))

    return "\n".join(filter(None, lines))


# ==============================
# SECTION FORMATTERS
# ==============================
def _format_result_header(category  : str,
                           top       : dict,
                           confidence: float) -> str:
    """Main result section."""
    lines = []
    sep   = "─" * 54

    color  = category_color(category)
    c_conf = confidence_color(confidence)
    conf   = int(confidence * 100)

    type_name = top.get('name', 'Unknown') if top else 'Unknown'

    lines.append(sep)
    lines.append(
        colorize("  ANALYSIS RESULT", Color.HEADER)
    )
    lines.append(sep)

    if category == 'unknown':
        lines.append(
            colorize(
                "  [?] CATEGORY   : UNKNOWN",
                Color.UNKNOWN
            )
        )
        return "\n".join(lines)

    lines.append(
        colorize(
            f"  [✓] CATEGORY   : {category.upper()}",
            color
        )
    )
    lines.append(
        colorize(
            f"  [✓] TYPE       : {type_name}",
            color
        )
    )
    lines.append(
        colorize(
            f"  [✓] CONFIDENCE : {conf}%",
            c_conf
        )
    )

    # Description
    if top and top.get('description'):
        lines.append(
            f"  [i] INFO       : {top['description']}"
        )

    return "\n".join(lines)


def _format_verbose_section(all_results: dict) -> str:
    """Verbose mode — saare pillars ka detail."""
    lines = []
    sep   = "─" * 54

    lines.append("")
    lines.append(
        colorize("  DETAILED ANALYSIS", Color.HEADER)
    )
    lines.append(sep)

    pillar_names = {
        'encoding'  : 'PILLAR A — ENCODING',
        'hash'      : 'PILLAR B — HASH',
        'encryption': 'PILLAR C — ENCRYPTION',
        'cipher'    : 'PILLAR D — CIPHER',
    }

    for category, result in all_results.items():
        pillar = pillar_names.get(category, category.upper())
        color  = category_color(category)
        top    = result['top']
        conf   = int(top['confidence'] * 100)

        lines.append(
            colorize(f"\n  {pillar}", color)
        )
        lines.append(
            f"  {'─'*40}"
        )
        lines.append(
            f"  Type       : {top.get('name', 'N/A')}"
        )
        lines.append(
            f"  Confidence : {conf}%"
        )

        # Reasons
        if isinstance(top, dict):
            reasons = top.get('reasons', [])
            if reasons:
                lines.append(
                    f"  Reasons    : "
                    f"{', '.join(reasons)}"
                )

        # Hash specific
        if category == 'hash':
            risk = top.get('collision_risk', '')
            if risk:
                lines.append(
                    f"  Risk       : {risk}"
                )
            amb = top.get('ambiguous_with', '')
            if amb:
                lines.append(
                    f"  Similar    : {amb}"
                )

        # Encryption specific
        if category == 'encryption':
            method = result.get('method', '')
            if method:
                lines.append(
                    f"  Method     : "
                    f"{method.replace('_', ' ').title()}"
                )

    return "\n".join(lines)


def _format_ambiguous_section(analysis_result: dict) -> str:
    """
    Hybrid Ambiguity: Pillars aur Pillar-internal candidates dono dikhao.
    """
    lines = []
    sep   = "─" * 54
    all_res = analysis_result.get('all_results', {})
    win_cat = analysis_result.get('category', 'unknown')
    win_res = analysis_result.get('result', {})
    
    lines.append("")
    lines.append(colorize("  [!] MULTIPLE CANDIDATES / AMBIGUITY DETECTED", Color.WARNING))
    lines.append(sep)
    lines.append(f"  {'Source':<12} {'Type':<22} {'Conf'}")
    lines.append(f"  {'─'*12} {'─'*22} {'─'*5}")

    # 1. PEHLE: Winning Pillar ke top 3-4 candidates dikhao (Agar close hain)
    candidates = win_res.get('candidates', []) if win_res else []
    top_score = candidates[0]['confidence'] if candidates else 0
    
    for c in candidates[:10]: # Top 10 candidates
        # Agar candidate ka score top score ke 10% ke andar hai
        if abs(top_score - c['confidence']) < 0.10:
            conf_str = f"{int(c['confidence'] * 100)}%"
            color = category_color(win_cat)
            
            lines.append(
                f"  {win_cat.capitalize():<12} "
                f"{colorize(f'{c['name']:<22}', color)} "
                f"{colorize(conf_str, confidence_color(c['confidence']))}"
            )

    # 2. DOOSRA: Agar koi doosra PILLAR bhi competition mein hai (e.g. Hex)
    for cat, res in all_res.items():
        if cat == win_cat: continue # Winner toh pehle hi dikha diya
        
        top_cand = res['top']
        # Agar doosra pillar winner ke 15% range mein hai
        if abs(top_score - top_cand['confidence']) < 0.15:
            conf_str = f"{int(top_cand['confidence'] * 100)}%"
            lines.append(
                f"  {cat.capitalize():<12} "
                f"{colorize(f'{top_cand['name']:<22}', category_color(cat))} "
                f"{colorize(conf_str, confidence_color(top_cand['confidence']))}"
            )

    lines.append("")
    lines.append(colorize("  [→] Manual check recommended: Data matches multiple known patterns.", Color.INFO))
    return "\n".join(lines)


def _format_indicators(indicators: list) -> str:
    """Encryption indicators display."""
    lines = []

    lines.append("")
    lines.append(
        colorize("  INDICATORS", Color.HEADER)
    )

    for ind in indicators:
        lines.append(
            colorize(f"    → {ind}", Color.INFO)
        )

    return "\n".join(lines)


def _format_multilayer_section(multilayer: dict) -> str:
    """Multi-layer chain display."""
    lines = []
    sep   = "─" * 54

    layers = multilayer.get('layers', [])
    chain  = multilayer.get('chain', '')
    total  = multilayer.get('total_layers', 0)

    lines.append("")
    lines.append(
        colorize(
            f"  MULTI-LAYER DETECTED ({total} layers)",
            Color.HEADER
        )
    )
    lines.append(sep)
    lines.append(
        colorize(f"  Chain : {chain}", Color.INFO)
    )
    lines.append("")

    for layer in layers:
        color = category_color(layer['category'])
        conf  = int(layer['confidence'] * 100)

        lines.append(
            colorize(
                f"  Layer {layer['layer']}"
                f"  → {layer['type']:<20} [{conf}%]",
                color
            )
        )
        lines.append(
            f"         Preview: "
            f"{layer['data_preview']}"
        )

    # Next steps for chain
    next_s = multilayer.get('next_step', '')
    if next_s:
        lines.append("")
        lines.append(
            colorize("  Steps to decode:", Color.INFO)
        )
        for step in next_s.split('\n'):
            if step:
                lines.append(
                    colorize(f"    → {step}", Color.SUCCESS)
                )

    return "\n".join(lines)


def _format_next_steps_section(steps: dict) -> str:
    """Next steps section."""
    lines = []
    sep   = "─" * 54

    lines.append("")
    lines.append(
        colorize("  NEXT STEPS", Color.HEADER)
    )
    lines.append(sep)

    if steps.get('primary'):
        lines.append(
            colorize(
                f"  [→] {steps['primary']}",
                Color.SUCCESS
            )
        )

    if steps.get('tool'):
        lines.append(
            f"  Tool    : {steps['tool']}"
        )

    if steps.get('online'):
        lines.append(
            f"  Online  : {steps['online']}"
        )

    if steps.get('cmd'):
        lines.append(
            f"  Command : {steps['cmd']}"
        )

    if steps.get('note'):
        lines.append(
            colorize(
                f"  Note    : {steps['note']}",
                Color.INFO
            )
        )

    if steps.get('warning'):
        lines.append(
            colorize(
                f"  ⚠ Risk  : {steps['warning']}",
                Color.WARNING
            )
        )

    return "\n".join(lines)


def _format_unknown_section(input_data) -> str:
    """Unknown format section."""
    lines = []
    sep   = "─" * 54

    lines.append(sep)
    lines.append(
        colorize(
            "  [?] FORMAT UNKNOWN",
            Color.UNKNOWN
        )
    )
    lines.append(sep)
    lines.append(
        "  No known pattern matched."
    )
    lines.append(
        colorize(
            "  [→] Try: binwalk / hexdump / strings",
            Color.INFO
        )
    )
    lines.append(
        colorize(
            "  [→] Manual analysis recommended.",
            Color.INFO
        )
    )

    return "\n".join(lines)


# ==============================
# ERROR FORMATTER
# ==============================
def format_error(error_type: str,
                 message   : str = "") -> str:
    """Error messages format karo."""
    errors = {
        'no_input'    : 'No input provided.\n'
                        '  Use -i for string or '
                        '-f for file input.\n'
                        '  Run "decod3x --help" for usage.',
        'file_missing': f'File not found → {message}\n'
                        '  Check the file path and try again.',
        'empty_input' : 'Empty input provided.\n'
                        '  Please provide non-empty '
                        'string or file.',
        'read_error'  : f'Could not read file → {message}\n'
                        '  Check file permissions.',
        'db_missing'  : 'Database not found!\n'
                        '  Run: python db_init/populate_db.py',
    }

    msg = errors.get(error_type, message or 'Unknown error')

    lines = [
        "─" * 54,
        colorize(f"  [✗] ERROR", Color.ERROR),
        "─" * 54,
        colorize(f"  {msg}", Color.ERROR),
        "─" * 54,
    ]

    return "\n".join(lines)


# ==============================
# REPORT FORMATTER (No Colors)
# ==============================
def format_report(analysis_result : dict,
                  input_data      : str,
                  platform_info   : dict,
                  elapsed_time    : float) -> str:
    """
    Plain text report generate karta hai.
    -o flag ke liye — no colors.
    """
    from datetime import datetime

    lines = []
    sep   = "=" * 54

    category   = analysis_result.get('category', 'unknown')
    confidence = analysis_result.get('confidence', 0.0)
    result     = analysis_result.get('result')
    top        = result['top'] if result else None
    type_name  = top.get('name', 'Unknown') if top else 'Unknown'

    # Header
    lines.append(sep)
    lines.append("  decod3x Analysis Report")
    lines.append(
        f"  Generated : "
        f"{datetime.now().strftime('%Y-%m-%d | %H:%M:%S')}"
    )
    lines.append(
        f"  Platform  : "
        f"{platform_info.get('os', 'Unknown')} "
        f"{platform_info.get('os_version', '')}"
    )
    lines.append("  Version   : 1.0.0")
    lines.append(sep)

    # Input
    lines.append("")
    lines.append("INPUT SUMMARY")
    lines.append("─" * 30)

    if isinstance(input_data, str):
        lines.append("Type   : String")
        lines.append(f"Length : {len(input_data)} characters")
        preview = input_data[:50] + "..." \
                  if len(input_data) > 50 else input_data
        lines.append(f"Value  : {preview}")
    else:
        lines.append("Type   : Binary/File")
        lines.append(f"Size   : {len(input_data)} bytes")

    # Result
    lines.append("")
    lines.append("RESULT")
    lines.append("─" * 30)
    lines.append(f"Category   : {category.upper()}")
    lines.append(f"Type       : {type_name}")
    lines.append(
        f"Confidence : {int(confidence * 100)}%"
    )

    if top and top.get('description'):
        lines.append(f"Info       : {top['description']}")

    # Next Steps
    if category != 'unknown':
        steps = get_next_steps(category, type_name)
        lines.append("")
        lines.append("NEXT STEPS")
        lines.append("─" * 30)

        if steps.get('primary'):
            lines.append(f"Action  : {steps['primary']}")
        if steps.get('tool'):
            lines.append(f"Tool    : {steps['tool']}")
        if steps.get('online'):
            lines.append(f"Online  : {steps['online']}")
        if steps.get('warning'):
            lines.append(f"Risk    : {steps['warning']}")

    # Footer
    lines.append("")
    lines.append(sep)
    lines.append(
        f"  Analysis Time : {elapsed_time:.3f}s"
    )
    lines.append("  End of decod3x Report")
    lines.append(sep)

    return "\n".join(lines)