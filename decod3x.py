#!/usr/bin/env python3
"""
decod3x — Smart Data Triage Engine
====================================
SOC Analysts aur CTF Players ke liye
rapid data identification tool.

Usage:
    decod3x -i <string>
    decod3x -f <filepath>
    decod3x -i <string> -v
    decod3x -f <file> -o report.txt
"""

import sys
import time
import argparse
from pathlib import Path

from utils.colors import (
    Color, colorize,
    print_header, print_separator,
    print_info, print_error,
    print_success, print_warning,
    disable_colors
)
from utils.system        import (
    clear_screen,
    get_platform_info
)
from utils.input_handler import (
    handle_string_input,
    handle_file_input,
    normalize_input,
    get_input_summary
)
from utils.output_formatter import (
    format_result,
    format_error,
    format_report
)
from utils.db_connector  import check_db_health
from engine.confidence   import run_all_pillars
from engine.multilayer   import detect_layers


# ==============================
# VERSION
# ==============================
VERSION = "1.0.0"

BANNER = r"""
  ____                     _ _____      
 |  _ \  ___  ___ ___   __| |___ /_  __
 | | | |/ _ \/ __/ _ \ / _` | |_ \ \/ /
 | |_| |  __/ (_| (_) | (_| |___) >  < 
 |____/ \___|\___\___/ \__,_|____/_/\_\
"""


# ==============================
# ARGUMENT PARSER
# ==============================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='decod3x',
        description='decod3x — Smart Data Triage Engine',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  decod3x -i "aGVsbG8="
  decod3x -i "d41d8cd98f00b204e9800998ecf8427e" -v
  decod3x -f malware.bin -o report.txt
  decod3x -i "SGVsbG8=" -d 3 --no-color
        """
    )

    # Input group
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        '-i', '--input',
        metavar='STRING',
        help='Analyze a string directly'
    )
    input_group.add_argument(
        '-f', '--file',
        metavar='PATH',
        help='Analyze a file'
    )

    # Output options
    parser.add_argument(
        '-o', '--output',
        metavar='PATH',
        help='Save report to text file'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed analysis'
    )

    # Control options
    parser.add_argument(
        '-d', '--depth',
        type=int,
        default=5,
        metavar='N',
        help='Max multi-layer depth (default: 5)'
    )
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'decod3x v{VERSION}'
    )

    return parser


# ==============================
# DISPLAY HEADER
# ==============================
def display_banner(no_color: bool = False):
    """Tool banner print karo."""
    if no_color:
        print(BANNER)
        print(f"  decod3x v{VERSION} — Smart Data Triage Engine")
        print(
            "  Cybersecurity Professionals & CTF Player's Best Friend\n"
        )
    else:
        print(
            colorize(BANNER, Color.HEADER)
        )
        print(
            colorize(
                f"  decod3x v{VERSION}"
                " — Smart Data Triage Engine",
                Color.BOLD
            )
        )
        print(
            colorize(
                "  Cybersecurity Professionals & CTF Player's "
                "Best Friend\n",
                Color.DIM
            )
        )


def display_input_info(summary: dict):
    """Input summary print karo."""
    print_separator()

    if summary.get('type') == 'String':
        print_info("Input Type", summary['type'])
        print_info("Length",     summary['length'])
        print_info("Preview",    summary['preview'])
    else:
        print_info("Input Type", summary['type'])
        print_info("File",       summary.get('filename', ''))
        print_info("Size",       summary.get('size', ''))
        print_info("Path",       summary.get('path', ''))

    print_separator()


# ==============================
# CORE ANALYSIS
# ==============================
def run_analysis(data,
                 verbose  : bool = False,
                 depth    : int  = 5) -> tuple:
    """
    Core analysis run karta hai.
    Returns: (result, multilayer, elapsed)
    """
    start = time.time()

    # Normalize input
    str_data, bytes_data = normalize_input(data)

    # Main analysis
    result = run_all_pillars(
        str_data if str_data else bytes_data
    )

    # Multi-layer detection
    ml_result = None
    if str_data:
        ml_result = detect_layers(str_data, depth)

    elapsed = round(time.time() - start, 3)

    return result, ml_result, elapsed


# ==============================
# OUTPUT HANDLER
# ==============================
def display_results(result     : dict,
                    ml_result  : dict,
                    verbose    : bool,
                    input_data,
                    elapsed    : float):
    """Results display karo."""

    # Main formatted output
    output = format_result(
        analysis_result = result,
        input_data      = input_data,
        verbose         = verbose,
        multilayer      = ml_result
    )

    print(output)

    # Footer
    print_separator()
    print_success(
        "Done",
        f"Analysis complete | Time: {elapsed}s"
    )
    print_separator()


def save_report(result     : dict,
                input_data,
                output_path: str,
                elapsed    : float):
    """Report file mein save karo."""
    try:
        platform_info = get_platform_info()
        report        = format_report(
            result,
            input_data,
            platform_info,
            elapsed
        )

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(str(path), 'w',
                  encoding='utf-8') as f:
            f.write(report)

        print_success(
            "Report",
            f"Saved → {output_path}"
        )

    except Exception as e:
        print_error("Report", f"Save failed: {e}")


# ==============================
# DB HEALTH CHECK
# ==============================
def check_database() -> bool:
    """DB health check karo."""
    if not check_db_health():
        print(format_error('db_missing'))
        print(
            colorize(
                "\n  Run: python db_init/populate_db.py\n",
                Color.WARNING
            )
        )
        return False
    return True


# ==============================
# MAIN
# ==============================
def main():
    parser = build_parser()
    try:
        args   = parser.parse_args()
    except SystemExit:
        raise
    except Exception:
        parser.print_help()
        sys.exit(1)

    # No-color mode
    if args.no_color:
        disable_colors()

    # Banner
    display_banner(args.no_color)

    # DB Check
    try:
        if not check_database():
            sys.exit(1)
    except Exception:
        print(format_error('db_missing'))
        sys.exit(1)

    # Input validate karo
    if not args.input and not args.file:
        print(format_error('no_input'))
        parser.print_help()
        sys.exit(1)

    # ── String Input ──
    if args.input:
        try:
            input_result = handle_string_input(args.input)

        except Exception as e:
            print(format_error('empty_input', str(e)))
            sys.exit(1)

        if not input_result['success']:
            print(format_error(
                input_result.get('error_type', 'empty_input'),
                input_result.get('error', '')
            ))
            sys.exit(1)

        data    = input_result['data']
        summary = get_input_summary(input_result)

    # ── File Input ──
    else:

        try:
            input_result = handle_file_input(args.file)

        except Exception as e:
            print(format_error('read_error', str(e)))
            sys.exit(1)

        if not input_result['success']:
            print(format_error(
                input_result.get('error_type', 'read_error'),
                input_result.get('error', '')
            ))
            sys.exit(1)

        data    = input_result['data']
        summary = get_input_summary(input_result)

    # Display input info
    display_input_info(summary)

    # Analyzing message
    print_info("Status", "Analyzing...")
    print()

    # Run analysis
    try:
        result, ml_result, elapsed = run_analysis(
            data,
            verbose = args.verbose,
            depth   = args.depth
        )
    except KeyboardInterrupt:
        print("\n")
        print_warning("Stopped", "Analysis interrupted.")
        sys.exit(0)

    except Exception as e:
        print_error("Analysis", f"Failed: {e}")
        sys.exit(1)
    
    # Display results
    try:
        display_results(
            result,
            ml_result,
            args.verbose,
            data,
            elapsed
        )
    except Exception as e:
        print_error("Output", f"Display failed: {e}")

    # Save report
    if args.output:
        try:
            save_report(result, data, args.output, elapsed)
        except Exception as e:
            print_error("Report", f"Save failed: {e}")

    # Exit code
    if result['category'] == 'unknown':
        sys.exit(2)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()

