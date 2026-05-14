# magic_db.py
# This file is a dictionary of "file fingerprints"
#
# Every file type has a unique pattern hidden in its first few bytes.
# For example, every real JPEG image starts with the bytes: FF D8 FF
# We call these patterns "magic numbers" or "magic bytes"
#
# How this file works:
#   - Each entry has: the magic bytes to look for, the real file type name,
#     and a list of extensions that type is allowed to have
#   - scan.py uses this list to check if a file's extension matches its real content


# Each entry looks like this:
#   ( bytes_to_match,  "Real Type Name",  [".allowed", ".extensions"] )

SIGNATURES = [

    # --- Programs & Executables (HIGH RISK if hiding) ---

    (b"MZ",
        "Windows Program (.exe/.dll)",
        [".exe", ".dll", ".scr", ".sys", ".com"]),

    (b"\x7fELF",
        "Linux Program (ELF binary)",
        [".elf", ".so", ""]),

    (b"#!",
        "Script file (bash/python/etc)",
        [".sh", ".py", ".pl", ".rb", ""]),

    (b"\x42\x0d\x0d\x0a",
        "Python Compiled Code",
        [".pyc"]),

    # --- Archive / Compressed Files ---

    (b"PK\x03\x04",
        "ZIP file (also used by .docx/.xlsx/.apk)",
        [".zip", ".jar", ".docx", ".xlsx", ".pptx", ".apk"]),

    (b"\x1f\x8b",
        "GZIP Compressed file",
        [".gz", ".tgz"]),

    (b"Rar!\x1a\x07",
        "RAR Archive",
        [".rar"]),

    (b"7z\xbc\xaf\x27\x1c",
        "7-Zip Archive",
        [".7z"]),

    # --- Images ---

    (b"\xff\xd8\xff",
        "JPEG Image",
        [".jpg", ".jpeg"]),

    (b"\x89PNG\r\n\x1a\n",
        "PNG Image",
        [".png"]),

    (b"GIF87a",
        "GIF Image",
        [".gif"]),

    (b"GIF89a",
        "GIF Image",
        [".gif"]),

    (b"BM",
        "BMP Image",
        [".bmp"]),

    # --- Documents ---

    (b"%PDF",
        "PDF Document",
        [".pdf"]),

    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "Old Microsoft Office file (Word/Excel/PowerPoint)",
        [".doc", ".xls", ".ppt", ".msg"]),

    (b"{\\rtf",
        "Rich Text Document",
        [".rtf"]),

    # --- Audio & Video ---

    (b"ID3",
        "MP3 Audio",
        [".mp3"]),

    (b"\xff\xfb",
        "MP3 Audio",
        [".mp3"]),

    (b"fLaC",
        "FLAC Audio",
        [".flac"]),

    (b"OggS",
        "OGG Audio/Video",
        [".ogg", ".oga", ".ogv"]),

    (b"RIFF",
        "WAV Audio or AVI Video",
        [".wav", ".avi", ".webp"]),

    # --- Web & Code ---

    (b"<?xml",
        "XML file",
        [".xml", ".svg", ".xhtml"]),

    (b"<!DOCTYPE html",
        "HTML webpage",
        [".html", ".htm"]),

    (b"<html",
        "HTML webpage",
        [".html", ".htm"]),

    # --- Database ---

    (b"SQLite format 3\x00",
        "SQLite Database",
        [".db", ".sqlite", ".sqlite3"]),

    # --- Certificates & Keys ---

    (b"-----BEGIN",
        "Security Certificate or Key",
        [".pem", ".crt", ".cer", ".key"]),
]

# How many bytes to read from the start of the file
# 32 bytes is enough to match all the patterns above
BYTES_TO_READ = 32


def get_file_type(file_header):
    """
    Takes the first few bytes of a file and tries to identify it.
    Returns (type_name, allowed_extensions) if found, or None if unknown.
    """
    for magic_bytes, type_name, allowed_extensions in SIGNATURES:
        # Check if the file starts with this magic pattern
        if file_header.startswith(magic_bytes):
            return type_name, allowed_extensions

    # Nothing matched — file type is unknown
    return None
