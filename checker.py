# checker.py
# This file does the actual work of checking one file.
#
# It reads the first few bytes of a file, looks up what type those
# bytes belong to, then compares that to the file's extension.
# If they don't match, we flag it.
#
# Other files (scan.py) import and use the check_file() function below.

from pathlib import Path     # Path makes it easy to work with file paths
from magic_db import BYTES_TO_READ, get_file_type


# These file types are dangerous if they're hiding behind a different extension.
# A .jpg that's actually one of these? That's a red flag.
DANGEROUS_TYPES = [
    "Windows Program (.exe/.dll)",
    "Linux Program (ELF binary)",
    "Script file (bash/python/etc)",
    "Python Compiled Code",
]

# These are "normal-looking" extensions that attackers often use to disguise files.
# Nobody expects a .jpg or .pdf to secretly be a program.
DISGUISE_EXTENSIONS = [
    ".jpg", ".jpeg", ".png", ".gif", ".bmp",
    ".pdf", ".doc", ".docx", ".xlsx", ".txt",
    ".mp3", ".mp4", ".wav",
]


def check_file(path):
    """
    Checks a single file and returns a result dictionary.

    The dictionary contains:
      - 'path'       : the full path to the file
      - 'name'       : just the filename
      - 'extension'  : the file extension (e.g. '.jpg')
      - 'real_type'  : what the file ACTUALLY is (based on magic bytes)
      - 'status'     : 'danger', 'warning', 'notice', 'clean', or 'error'
      - 'message'    : a plain-English explanation of the result
      - 'error'      : error message if we couldn't read the file
    """

    file = Path(path)

    # Build the result dictionary with default values
    result = {
        "path":      str(file.resolve()),
        "name":      file.name,
        "extension": file.suffix.lower(),   # e.g. '.jpg'
        "real_type": None,
        "status":    "clean",
        "message":   "",
        "error":     None,
    }

    # --- Step 1: Try to read the first few bytes of the file ---
    try:
        with open(file, "rb") as f:          # "rb" = read as raw bytes
            header = f.read(BYTES_TO_READ)
    except FileNotFoundError:
        result["status"]  = "error"
        result["error"]   = "File not found."
        result["message"] = "Could not find this file. Check the path."
        return result
    except PermissionError:
        result["status"]  = "error"
        result["error"]   = "Permission denied."
        result["message"] = "You don't have permission to read this file."
        return result
    except Exception as e:
        result["status"]  = "error"
        result["error"]   = str(e)
        result["message"] = f"Something went wrong: {e}"
        return result

    # --- Step 2: Look up what type the file really is ---
    match = get_file_type(header)

    # If we don't recognise the file type, just mark it as unknown and move on
    if match is None:
        result["message"] = "File type not recognised — could not check it."
        return result

    real_type, allowed_extensions = match
    result["real_type"] = real_type

    # --- Step 3: Compare the real type to the file extension ---
    ext = result["extension"]
    extension_matches = ext in allowed_extensions

    if extension_matches:
        # Everything is fine
        result["status"]  = "clean"
        result["message"] = "The file looks normal. Extension matches its contents."
        return result

    # The extension does NOT match — now we decide how serious it is

    is_dangerous  = real_type in DANGEROUS_TYPES
    is_disguised  = ext in DISGUISE_EXTENSIONS

    if is_dangerous and is_disguised:
        # Worst case: a program hiding behind a harmless-looking extension
        result["status"]  = "danger"
        result["message"] = (
            f"This file is pretending to be a '{ext}' file, "
            f"but it actually contains a {real_type}. "
            f"This is a common trick to hide malware. Do NOT open it."
        )

    elif is_dangerous:
        # Still a program, just has a slightly wrong extension
        result["status"]  = "warning"
        result["message"] = (
            f"This file contains a {real_type}, "
            f"but has a '{ext}' extension. "
            f"It could be tampered with. Be careful."
        )

    else:
        # The types don't match, but it's not a dangerous program
        result["status"]  = "notice"
        result["message"] = (
            f"This file has a '{ext}' extension, "
            f"but it actually contains: {real_type}. "
            f"It may have been renamed. Probably not dangerous."
        )

    return result
