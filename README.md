# bgrep

Binary grep with support for sophisticated regexes and grep(1)-like usage.

## Usage

`bgrep`'s command-line options mirror those of `grep(1)` very closely. The main difference is that `bgrep` operates on hex strings instead of text strings.

Examples:

- `bgrep -r 'ffd9' /home/user/pictures` - find all files with a JPEG header in them
- `bgrep '00??00' binary` - find one-byte strings in a binary
- `bgrep -C 16 -t hex '09f91102' dvdcss` - find instances of a certain encryption key in a program
- `bgrep -F 'PK' file.zip` - find zip entry headers in a zip file
- `bgrep -E '\0[\x20-\x7e]{1,8}\0' unknown.exe` - find printable strings between 1 and 8 chars long in a program (using Python regex syntax)

`bgrep` defaults to displaying binary content in a hexdump format, and even supports colour by default on supported terminals, just like `grep`.

## Installing

As a prerequisite, you will need Python 3, at least 3.2 (higher preferred). After installing that, a simple

    wget 'https://raw.githubusercontent.com/nneonneo/bgrep/master/bgrep.py' -O /usr/local/bin/bgrep

will do the trick.
