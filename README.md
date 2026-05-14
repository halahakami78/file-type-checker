# file-type-checker
File Type Checker
A command-line tool that detects files pretending to be something they are not.
Every file has a hidden fingerprint in its first few bytes called "magic numbers."
This tool reads that fingerprint and compares it to the file extension.
If they do not match — especially if a file is secretly an executable — it flags it.
This is a common technique used in cybersecurity to detect malware disguised as
harmless files like images, PDFs, or documents.

What it detects
SituationExampleLabelExecutable hiding as an image or document.jpg file that is actually a .exeDANGERExecutable with the wrong extension.exe content with an unusual extensionWARNINGNon-dangerous type mismatch.doc file that is actually a .zipNOTICEExtension matches contentNormal .pdf, .png, etc.CLEAN

How to run it
Make sure all three files are in the same folder, then run:
python scan.py
The tool will ask you to enter file paths one at a time.
Type done when you are finished and it will show a full summary.
You can also choose to save a report as a .txt file.

Example output
[ DANGER ]
  File      : invoice.pdf
  Location  : C:\Downloads
  Extension : .pdf   (what the name says it is)
  Reality   : Windows Program (.exe/.dll)   (what is actually inside)

  This file is pretending to be a '.pdf' file, but it actually contains
  a Windows Program. This is a common trick to hide malware. Do NOT open it.

Files
FilePurposescan.pyMain program — run this to start the toolchecker.pyLogic for reading and checking a single filemagic_db.pyDatabase of magic byte signatures and file types

Requirements

Python 3.8 or higher
No external libraries needed — uses Python's built-in modules only


File types covered
The tool can identify over 30 file types including:

Executables: .exe, .dll, ELF binaries, shell scripts
Archives: .zip, .rar, .7z, .gz
Images: .jpg, .png, .gif, .bmp
Documents: .pdf, .doc, .xls, .rtf
Audio / Video: .mp3, .wav, .flac, .ogg
Web: .html, .xml
Databases: .sqlite
Security: .pem, .crt


Background
This project was built as part of a cybersecurity course to demonstrate
how magic number analysis works in practice.
Magic numbers are used by tools like the Unix file command and many
antivirus and forensic analysis tools to identify file types independently
of their names or extensions.
