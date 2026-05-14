# scan.py
# -------
# File Type Checker — finds files that are secretly something dangerous.
#
# HOW TO RUN:
#   python scan.py
#
# WHAT IT DOES:
#   1. Asks you to enter a file path
#   2. Checks if the file is really what its extension says it is
#   3. Keeps asking for more files until you type "done"
#   4. Shows you a summary of everything it found
#   5. Asks if you want to save a report
#
# FILES NEEDED (keep them all in the same folder):
#   scan.py      <- this file (the main program)
#   checker.py   <- does the actual checking logic
#   magic_db.py  <- the database of file fingerprints


import os                        # used to check if a path exists
from pathlib import Path         # used to work with file paths
from datetime import datetime    # used to put a timestamp on the report
from checker import check_file   # our own function that checks one file


# --- Colour codes for the terminal ---
# These make the output easier to read.
# Each one is a special code the terminal understands.
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"   # this resets colour back to normal


def print_line(char="─", width=58):
    """Prints a divider line across the screen."""
    print(BOLD + char * width + RESET)


def print_result(result):
    """
    Prints the result of checking one file in a readable way.
    Uses colour to make the severity obvious at a glance.
    """

    status = result["status"]

    # Pick a colour and label based on how serious the finding is
    if status == "danger":
        colour = RED + BOLD
        label  = "[ DANGER ]"
    elif status == "warning":
        colour = YELLOW + BOLD
        label  = "[ WARNING ]"
    elif status == "notice":
        colour = CYAN
        label  = "[ NOTICE ]"
    elif status == "error":
        colour = DIM
        label  = "[ COULD NOT READ ]"
    else:
        colour = GREEN
        label  = "[ CLEAN ]"

    # Print the file info
    print(colour + label + RESET)
    print(f"  File      : {result['name']}")
    print(f"  Location  : {Path(result['path']).parent}")

    # Only show extension and real type if we know them
    if result["extension"]:
        print(f"  Extension : {result['extension']}   (what the name says it is)")
    if result["real_type"]:
        print(f"  Reality   : {result['real_type']}   (what's actually inside)")

    # Print the plain-English explanation
    print(f"\n  {DIM}{result['message']}{RESET}")
    print()


def save_report(all_results):
    """
    Saves all results to a plain text file.
    The filename includes the date and time so it's unique each run.
    """

    # Build a filename like: report_2025-05-14_13-45-22.txt
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename  = f"report_{timestamp}.txt"

    lines = []
    lines.append("FILE TYPE SCAN REPORT")
    lines.append(f"Date  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Files : {len(all_results)}")
    lines.append("=" * 58)
    lines.append("")

    for result in all_results:
        lines.append(f"[{result['status'].upper()}]  {result['name']}")
        lines.append(f"  Location  : {Path(result['path']).parent}")
        if result["extension"]:
            lines.append(f"  Extension : {result['extension']}")
        if result["real_type"]:
            lines.append(f"  Reality   : {result['real_type']}")
        lines.append(f"  Note      : {result['message']}")
        lines.append("")

    # Count how many of each status we found
    counts = {"danger": 0, "warning": 0, "notice": 0, "clean": 0, "error": 0}
    for r in all_results:
        counts[r["status"]] += 1

    lines.append("=" * 58)
    lines.append("SUMMARY")
    lines.append(f"Total checked : {len(all_results)}")
    lines.append(f"Dangerous     : {counts['danger']}")
    lines.append(f"Warnings      : {counts['warning']}")
    lines.append(f"Notices       : {counts['notice']}")
    lines.append(f"Clean         : {counts['clean']}")
    lines.append(f"Could not read: {counts['error']}")

    # Write everything to the file
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\n  {GREEN}Report saved: {filename}{RESET}")
    print(f"  {DIM}You can find it in the same folder as scan.py{RESET}\n")


def print_summary(all_results):
    """Prints a short summary after all files have been scanned."""

    total   = len(all_results)
    danger  = sum(1 for r in all_results if r["status"] == "danger")
    warning = sum(1 for r in all_results if r["status"] == "warning")
    notice  = sum(1 for r in all_results if r["status"] == "notice")
    clean   = sum(1 for r in all_results if r["status"] == "clean")

    print_line()
    print(BOLD + "  SUMMARY" + RESET)
    print_line()
    print(f"  Total files checked : {total}")

    # Only show lines that have at least 1 result
    if danger:
        print(f"  {RED + BOLD}DANGEROUS files found   : {danger}{RESET}")
    if warning:
        print(f"  {YELLOW + BOLD}Warnings                : {warning}{RESET}")
    if notice:
        print(f"  {CYAN}Notices (low risk)      : {notice}{RESET}")
    if clean:
        print(f"  {GREEN}Clean files             : {clean}{RESET}")

    print()

    if danger == 0 and warning == 0:
        print(f"  {GREEN + BOLD}All clear! No dangerous files found.{RESET}\n")
    elif danger > 0:
        print(f"  {RED + BOLD}Action needed! {danger} file(s) look dangerous.{RESET}")
        print(f"  {DIM}Do not open those files. Investigate or delete them.{RESET}\n")
    else:
        print(f"  {YELLOW}Found {warning} suspicious file(s). Worth a closer look.{RESET}\n")


# ─────────────────────────────────────────────
# MAIN PROGRAM — this is where everything runs
# ─────────────────────────────────────────────

def main():

    # Print the welcome banner
    print()
    print_line()
    print(BOLD + "        FILE TYPE CHECKER" + RESET)
    print(DIM  + "  Detects files hiding dangerous content" + RESET)
    print_line()
    print()
    print(f"  Enter file paths one at a time to scan them.")
    print(f"  When you are done, type {BOLD}done{RESET} and press Enter.")
    print()

    # This list will hold the results of every file we check
    all_results = []

    # --- MAIN LOOP ---
    # Keep asking for file paths until the user types "done"
    while True:

        # Ask the user for input
        user_input = input("  Enter file path (or 'done' to finish):\n  > ").strip()

        # Remove any quotes the user may have accidentally typed around the path
        user_input = user_input.strip("'\"")

        # --- Check if the user wants to stop ---
        if user_input.lower() == "done":
            # Make sure they've actually scanned something before stopping
            if len(all_results) == 0:
                print(f"\n  {YELLOW}You haven't scanned any files yet.{RESET}")
                print(f"  {DIM}Enter at least one file path first.{RESET}\n")
                continue   # go back to the top of the loop
            else:
                break      # exit the loop and move on to the summary

        # --- Check if the user typed nothing ---
        if user_input == "":
            print(f"  {DIM}Nothing entered. Try again or type 'done' to finish.{RESET}\n")
            continue

        # --- Expand shortcuts like ~ (home folder) ---
        file_path = Path(user_input).expanduser()

        # --- Check if the path actually exists ---
        if not file_path.exists():
            print(f"\n  {RED}Could not find: {file_path}{RESET}")
            print(f"  {DIM}Check the path and try again.{RESET}\n")
            continue

        # --- Check if they gave us a folder instead of a file ---
        if file_path.is_dir():
            print(f"\n  {YELLOW}That's a folder, not a file.{RESET}")
            print(f"  {DIM}Please enter the path to a specific file.{RESET}\n")
            continue

        # --- Run the check ---
        print(f"\n  Checking: {file_path.name} ...")
        result = check_file(file_path)

        # Store the result so we can include it in the final report
        all_results.append(result)

        # Show the result immediately
        print()
        print_line("·")
        print_result(result)
        print_line("·")

        # Tell the user how many files they've checked so far
        print(f"\n  {DIM}Files checked so far: {len(all_results)}{RESET}")
        print(f"  {DIM}Type another path to keep going, or type 'done' to finish.{RESET}\n")

    # --- We're out of the loop — the user typed "done" ---

    print()
    print_line()
    print()

    # Print the full list of results one more time
    print(BOLD + "  ALL RESULTS" + RESET)
    print()
    for result in all_results:
        print_result(result)

    # Print the summary counts
    print_summary(all_results)

    # Ask if they want to save a report
    while True:
        save = input("  Save a full report to a text file? (y/n): ").strip().lower()
        if save in ("y", "yes"):
            save_report(all_results)
            break
        elif save in ("n", "no"):
            print(f"\n  {DIM}No report saved. Goodbye!{RESET}\n")
            break
        else:
            print(f"  {DIM}Please type y or n.{RESET}")


# This line means: only run main() if we run this file directly.
# If another file imports scan.py, main() won't run automatically.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # This handles Ctrl+C — lets the user quit without an ugly error message
        print(f"\n\n  {DIM}Scan cancelled. Goodbye!{RESET}\n")
