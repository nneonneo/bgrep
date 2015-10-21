#!/usr/bin/env python3
"""
Byte-oriented grep tool.

Robert Xiao <nneonneo@gmail.com>
Created June 2, 2012
Last Updated Oct 21, 2015
"""

__version__ = '0.3'

import argparse
import sys
import re
import os
import stat
import fnmatch
try:
    import mmap
except ImportError:
    mmap = None

# State variables (attributes of the global state object):
#   pattern: compiled match pattern
#   pat_maxlen: maximum possible length of a match, for optimization (None=infinity)
#   total_matches: total number of matches, over all files

HELP_DESCRIPTION = r'''
Search for PATTERN in each binary FILE or standard input.
Example: bgrep 'ffd9' pic.jpg
'''.strip()

HELP_EPILOG = r'''
With no FILE, or when FILE is -, read standard input.  If less than
two FILEs given, assume -h. Exit status is 0 if match, 1 if no match,
and 2 if trouble.

Report bugs to <nneonneo@gmail.com>.
'''.strip()

HELP_VERSION = r'''
bgrep (binary-oriented grep) %(version)s

This program was originally developed by Robert Xiao <nneonneo@gmail.com>.
'''.strip() % {'version': __version__}

class ExtendAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        items = getattr(namespace, self.dest, None)
        if items is None:
            items = []
        items.extend(values)
        setattr(namespace, self.dest, items)

def argparser():
    class ContextAction(argparse.Action):
        def __call__(self, parser, namespace, values, option_string=None):
            if values:
                context = values
            else:
                context = 0
            namespace.before_context = context
            namespace.after_context = context

    parser = argparse.ArgumentParser(
        description=HELP_DESCRIPTION,
        epilog=HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        prog='bgrep',
        usage='%(prog)s [OPTION]... PATTERN [FILE] ...',
        add_help=False
    )

    parser.add_argument('args', help=argparse.SUPPRESS, nargs='*', action=ExtendAction)
    parser.add_argument('args_tail', help=argparse.SUPPRESS, nargs=argparse.REMAINDER)

    group = parser.add_argument_group('Pattern selection and interpretation')
    exgroup = group.add_mutually_exclusive_group()
    exgroup.add_argument('-E', '--extended-regexp', help='PATTERN is a Python byte regexp',
        dest='pat_type', action='store_const', const='extended', default='basic')
    exgroup.add_argument('-F', '--fixed-regexp', help='PATTERN is a single binary string',
        dest='pat_type', action='store_const', const='fixed')
    exgroup.add_argument('-G', '--basic-regexp', help='PATTERN is a basic hexadecimal string, optionally with wildcards (default)',
        dest='pat_type', action='store_const', const='basic')
    group.add_argument('-e', '--regexp', metavar='PATTERN', help='use PATTERN as a regular expression')
    group.add_argument('-f', '--file', help='obtain PATTERN from FILE',
        type=argparse.FileType('rb'), dest='pat_file')
    # left out: -i (ignore case), -w (word regexp), -x (line regexp), -z (null data)

    group = parser.add_argument_group('Miscellaneous')
    group.add_argument('-s', '--no-messages', help='suppress error messages',
        action='store_true')
    group.add_argument('-V', '--version', help='print version information and exit',
        action='store_true')
    group.add_argument('--help', help='display this help and exit',
        action='store_true')
    group.add_argument('--mmap', help='use memory-mapped input if possible',
        action='store_true', default='auto')
    group.add_argument('--no-mmap', help="don't use mmap even if available",
        action='store_false', dest='mmap')
    # left out: -v (invert match)

    group = parser.add_argument_group('Output control')
    group.add_argument('-m', '--max-count', help='stop after NUM matches (per file)',
        type=int)
    group.add_argument('-b', '--byte-offset', help='print the byte offset with output lines',
        action='store_true')
    group.add_argument('-n', help='same as --byte-offset',
        action='store_true', dest='byte_offset')
    group.add_argument('--line-buffered', help='flush output on every line',
        action='store_true')
    group.add_argument('-H', '--with-filename', help='print the filename for each match',
        action='store_true', dest='show_filename', default=None)
    group.add_argument('-h', '--without-filename', help='suppress the prefixing filename on output',
        action='store_false', dest='show_filename')
    group.add_argument('--label', help='print LABEL as filename for standard input',
        default='(standard input)')
    group.add_argument('-o', '--only-matching', help='show only the byte sequence matching PATTERN',
        nargs=0, action=ContextAction)
    group.add_argument('-q', '--quiet', '--silent', help='suppress all normal output',
        action='store_true')
    group.add_argument('-d', '--directories', metavar='ACTION', help="how to handle directories. ACTION is 'recurse' or 'skip'",
        choices=('recurse', 'skip'), default='skip')
    group.add_argument('-D', '--devices', metavar='ACTION', help="how to handle devices, FIFOs and sockets. ACTION is 'read' or 'skip'",
        choices=('read', 'skip'), default='read')
    group.add_argument('-r', '-R', '--recursive', '--recurse', help='equivalent to --directories=recurse',
        action='store_const', dest='directories', const='recurse')
    group.add_argument('--include', metavar='PATTERN', help='files that match PATTERN will be examined',
        action='append')
    group.add_argument('--exclude', metavar='PATTERN', help='files that match PATTERN will be skipped',
        action='append')
    group.add_argument('--exclude-from', metavar='FILE', help='files that match PATTERN in FILE will be skipped',
        action='append', type=argparse.FileType('r'))
    group.add_argument('-L', '--files-without-match', help='only print FILE names containing no match',
        action='store_const', dest='file_summary', const='without_match')
    group.add_argument('-l', '--files-with-match', help='only print FILE names containing matches',
        action='store_const', dest='file_summary', const='with_match')
    group.add_argument('-c', '--count', help='only print a count of matches per FILE',
        action='store_true')
    group.add_argument('-Z', '--null', help='print 0 byte after FILE name',
        action='store_true')
    # left out: --binary-files, --text, -I (--binary-files=without-match), -d read

    group = parser.add_argument_group('Context control')
    group.add_argument('-B', '--before-context', metavar='NUM', help='print NUM bytes of leading context (default 8)',
        type=int, default=8)
    group.add_argument('-A', '--after-context', metavar='NUM', help='print NUM bytes of trailing context (default 8)',
        type=int, default=8)
    group.add_argument('-C', '--context', metavar='NUM', help='print NUM bytes of output context',
        action=ContextAction, type=int)
    group.add_argument('--color', '--colour', metavar='WHEN', help="use colour to distinguish the matching string. WHEN may be 'always', 'never' or 'auto' (default).",
        nargs='?', choices=('always', 'never', 'auto'), dest='colour', default='auto')
    # left out: -NUM, -U (binary), -u (unix-byte-offsets)

    group = parser.add_argument_group('bgrep-specific options')
    # hexdump basically combines -n, --hex-addr, -t hex and -t printable
    group.add_argument('-t', '--output-format', metavar='FORMAT', help="print file bytes in FORMAT. FORMAT may be 'hexdump' (default), 'hex', 'printable', 'escape' or 'raw'.",
        choices=('hexdump', 'hex', 'raw', 'printable', 'escapes'), default='hexdump')
    group.add_argument('--hex-addr', help='print addresses in hexadecimal',
        action='store_true', default='auto')
    group.add_argument('--dec-addr', help='print addresses in decimal',
        action='store_false', dest='hex_addr')
    group.add_argument('--hex-group', metavar='BYTES', help='group output hex bytes into groups of BYTES bytes each',
        type=int)

    group = parser.add_argument_group('bgrep word-size search',
'''Configure word-search mode, which works with basic (-G) patterns.
In word-search mode, the pattern is considered to consist of a series of complete words.
With word search in -G mode, the * operator still matches any sequence of bytes,
while the new ** operator matches any sequence of words.''')
    group.add_argument('-w', '--word-search', help='Enable word search with the specified word size in bytes',
        type=int, default=None)
    group.add_argument('-W', '--flip-words', help='Flip the bytes of each word (useful for searching for little-endian words)',
        action='store_true')

    return parser

def msg(*x):
    if not opts.no_messages:
        print('bgrep:', *x, file=sys.stderr)

def warn(*x):
    msg('warning:', *x)

def err(*x):
    msg('error:', *x)
    sys.exit(2)

def main():
    global opts
    global state
    state = argparse.Namespace()
    parser = argparser()

    # argparse can't inherently parse interleaved command lines like getopt does.
    # Work around this by consuming the input one [options, arguments] chunk at a time.
    opts = parser.parse_args()
    optargs = opts.args_tail
    while optargs:
        opts = parser.parse_args(optargs, opts)
        optargs = opts.args_tail

    if opts.version:
        print(HELP_VERSION)
        return 0
    elif opts.help:
        parser.print_help()
        return 0

    if opts.mmap == 'auto':
        # Try to use mmap if possible, because it will be faster for Python.
        opts.mmap = mmap is not None
    if opts.mmap and mmap is None:
        warn('mmap module not available')
        opts.mmap = False

    if opts.pat_file:
        opts.regexp = opts.pat_file.read()
        opts.pat_file.close()

    if not opts.exclude:
        opts.exclude = []

    if opts.exclude_from:
        for f in opts.exclude_from:
            opts.exclude.extend(s.rstrip('\r\n') for s in f)
            f.close()

    if opts.regexp is None:
        if not opts.args:
            parser.print_usage()
            return 0
        opts.regexp = opts.args.pop(0)

    if opts.show_filename is None:
        # Yes, 'bgrep PATTERN - -' will show the filename. GNU grep does likewise.
        if opts.args == [] or opts.args == ['-']:
            opts.show_filename = False
        else:
            opts.show_filename = True

    if opts.file_summary:
        opts.max_count = 1

    if opts.colour == 'always':
        opts.colour = True
    elif opts.colour == 'never':
        opts.colour = False
    elif opts.colour == 'auto':
        if hasattr(os, 'isatty') and os.isatty(sys.stdout.fileno()) and os.environ.get('TERM', '') not in ('dumb', ''):
            opts.colour = True
        else:
            opts.colour = False

    if opts.output_format == 'hexdump':
        opts.byte_offset = True
    if opts.hex_addr == 'auto':
        opts.hex_addr = opts.output_format == 'hexdump'

    if opts.flip_words and not opts.word_search:
        err("can't specify -W/--flip-words without -w/--word-search")
    if opts.word_search and opts.pat_type != 'basic':
        err("-w/--word-search requires basic (-G) regexps")

    try:
        bgrep()
    except KeyboardInterrupt as e:
        print()
        return 130
    except SystemExit as e:
        raise
    except BaseException as e:
        err(e)

    if state.total_matches == 0:
        # no matches
        return 1
    return 0

HEXDIGITS = '0123456789abcdef'
HEXPATTERN_TABLE = {}
for i in HEXDIGITS:
    HEXPATTERN_TABLE[ord(i)] = int(i, 16)
HEXPATTERN_TABLE[ord('?')] = -1

def load_pattern(regexp):
    if isinstance(regexp, str):
        # We use iso-8859-1 so that we get a 1-1 mapping of the high-ASCII bytes
        # (if they are somehow being provided "raw" on the command line)
        regexp = regexp.encode('iso-8859-1')
    if opts.pat_type == 'extended':
        state.pat_maxlen = None
        return regexp
    elif opts.pat_type == 'fixed':
        state.pat_maxlen = len(regexp)
        return re.escape(regexp)
    elif opts.pat_type == 'basic':
        i = 0
        pat = []
        used_star = False
        num_hex = [0]
        regexp = regexp.lower()
        try:
            # we use 'in' to test "equality" because elements of byte strings are integers
            while i < len(regexp):
                c = regexp[i]
                if c in b' \r\n\v\t.,-:/':
                    i += 1
                    continue
                elif c in b'|':
                    pat.append('|')
                    num_hex.append(0)
                elif c in b'*':
                    if regexp[i:i+2] == b'**':
                        if opts.word_search:
                            pat.append('(?:.{%d})*' % opts.word_search)
                        else:
                            err("can't use ** without word search mode")
                        used_star = True
                        i += 2
                    else:
                        pat.append('.*')
                        used_star = True
                        i += 1
                    continue

                nbytes = 1
                if opts.word_search:
                    nbytes = opts.word_search
                word = []
                for _ in range(nbytes):
                    a = HEXPATTERN_TABLE[regexp[i]]
                    b = HEXPATTERN_TABLE[regexp[i+1]]
                    i += 2
                    num_hex[-1] += 1
                    if a == -1 and b == -1:
                        p = '.'
                    elif a == -1:
                        p = '[' + ''.join(r'\x' + HEXDIGITS[a] + HEXDIGITS[b] for a in range(16)) + ']'
                    elif b == -1:
                        p = r'[\x%x0-\x%xf]' % (a, a)
                    else:
                        p = r'\x%x%x' % (a, b)
                    word.append(p)
                if opts.flip_words:
                    word = word[::-1]
                pat.extend(word)
        except IndexError:
            if opts.word_search:
                err("pattern length was not a multiple of the word size")
            else:
                err("odd-length hex pattern")
        except KeyError as e:
            err("bad hex character '%c'" % e.args[0])
        if used_star:
            state.pat_maxlen = None
        else:
            state.pat_maxlen = max(num_hex)
        if not pat:
            warn("empty pattern")
        return ''.join(pat).encode('ascii')
    else:
        err("bad pat_type " + opts.pat_type)

def write_filename(fn, ch=None):
    if opts.file_summary or opts.show_filename:
        sys.stdout.write(fn)
        if opts.null:
            sys.stdout.write('\0')
        elif ch:
            sys.stdout.write(ch)

def flush_if_needed():
    if opts.line_buffered:
        sys.stdout.flush()

def format_hex(s, ctx_start, ctx_end, start, end):
    for i in range(start, end):
        sys.stdout.write('%02x' % s[i])
        if (opts.hex_group is not None) and (i - ctx_start) % opts.hex_group == opts.hex_group-1 and i != end:
            sys.stdout.write(' ')

def format_raw(s, ctx_start, ctx_end, start, end):
    sys.stdout.write(s[start:end].decode('iso-8859-1'))

PRINTABLE_TABLE = b'''................................ !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................'''

def format_printable(s, ctx_start, ctx_end, start, end):
    sys.stdout.write(s[start:end].translate(PRINTABLE_TABLE).decode('iso-8859-1'))

def format_escapes(s, ctx_start, ctx_end, start, end):
    sys.stdout.write(s[start:end].decode('iso-8859-1').encode('unicode_escape'))

def write_match(formatter, s, ctx_start, ctx_end, match_start, match_end):
    formatter(s, ctx_start, ctx_end, ctx_start, match_start)
    if opts.colour:
        sys.stdout.write('\033[01;31m')
    formatter(s, ctx_start, ctx_end, match_start, match_end)
    if opts.colour:
        sys.stdout.write('\033[00m')
    formatter(s, ctx_start, ctx_end, match_end, ctx_end)

def report_match(fn, s, match, offset=0):
    if opts.quiet:
        return

    if opts.count or opts.file_summary:
        return

    write_filename(fn, ':')

    start, end = match.start(), match.end()

    ctx_start = start - opts.before_context
    if ctx_start < 0:
        ctx_start = 0

    ctx_end = end + opts.after_context
    if ctx_end > len(s):
        ctx_end = len(s)

    abs_ctx_start = offset + ctx_start

    if opts.output_format == 'hexdump':
        if opts.hex_addr:
            sys.stdout.write('%08x: ' % abs_ctx_start)
        else:
            sys.stdout.write('%8d  ' % abs_ctx_start)
    elif opts.byte_offset:
        if opts.hex_addr:
            sys.stdout.write('%x:' % abs_ctx_start)
        else:
            sys.stdout.write('%d:' % abs_ctx_start)

    if opts.output_format == 'hexdump':
        write_match(format_hex, s, ctx_start, ctx_end, start, end)
        sys.stdout.write('  ')
        write_match(format_printable, s, ctx_start, ctx_end, start, end)
    else:
        formatter = {
            'hex': format_hex,
            'raw': format_raw,
            'printable': format_printable,
            'escapes': format_escapes
        }[opts.output_format]
        write_match(formatter, s, ctx_start, ctx_end, start, end)

    sys.stdout.write('\n')
    flush_if_needed()

def report_file(fn, count):
    state.total_matches += count
    if opts.quiet:
        return

    if opts.file_summary == 'with_match' and count > 0:
        write_filename(fn, '\n')
        flush_if_needed()
    elif opts.file_summary == 'without_match' and count == 0:
        write_filename(fn, '\n')
        flush_if_needed()
    elif opts.count:
        write_filename(fn, ':')
        sys.stdout.write(str(count))
        sys.stdout.write('\n')
        flush_if_needed()

def match_mmap(fn, map_obj):
    count = 0
    if opts.max_count:
        for i, m in zip(range(opts.max_count), state.pattern.finditer(map_obj)):
            report_match(fn, map_obj, m)
            count += 1
    else:
        for m in state.pattern.finditer(map_obj):
            report_match(fn, map_obj, m)
            count += 1
    return count

def read_chunks(f, chunksize=4096):
    while 1:
        c = f.read(chunksize)
        if not c:
            break
        yield c

def readline_chunks(f):
    # files are iterators over their lines
    return f

def match_chunks(fn, chunks):
    # This may give wrong answers for unbounded quantifiers,
    # patterns with optional tails, or patterns with
    # lookahead/lookbehind assertions.
    # However, it will work for any kind of file, whereas
    # mmap only works for regular files.
    # The alternative is to simply read in the whole file
    # in one go, which will use a ton of memory but produce
    # correct answers for complex regexes.

    cur = bytearray()
    searchpos = 0
    start_offs = 0
    count = 0
    for chunk in chunks:
        cur.extend(chunk)
        while 1:
            if opts.max_count and count >= opts.max_count:
                return count
            m = state.pattern.search(cur, searchpos)
            if m is None:
                break
            count += 1
            report_match(fn, cur, m, offset=start_offs)

            # cut cur to save memory
            searchpos = m.end() # disallow overlapping matches
            cutpos = searchpos - opts.before_context
            if cutpos <= 4096:
                # we won't save much memory with this cut
                continue
            del cur[:cutpos]
            start_offs += cutpos
            searchpos -= cutpos

        # opportunistically cut if we can upper-bound the match length
        if state.pat_maxlen is not None:
            searchpos = len(cur) - (state.pat_maxlen - 1)
            cutpos = searchpos - opts.before_context
            if cutpos <= 4096:
                continue
            del cur[:cutpos]
            start_offs += cutpos
            searchpos -= cutpos
    return count

def is_excluded(fn):
    fn = os.path.basename(fn)
    for e in opts.exclude:
        if fnmatch.fnmatch(fn, e):
            return True
    return False

def is_included(fn):
    if opts.include:
        for i in opts.include:
            if fnmatch.fnmatch(fn, i):
                return True
        return False
    return True

def examine_file(fn):
    if is_excluded(fn):
        return

    if fn == '-' and is_included('-'):
        count = match_chunks(opts.label, readline_chunks(sys.stdin.buffer))
        report_file(opts.label, count)
        return

    try:
        st = os.stat(fn)
    except OSError as e:
        msg(fn+':', e)
        return

    if stat.S_ISDIR(st.st_mode):
        if opts.directories == 'recurse':
            for sfn in os.listdir(fn):
                examine_file(os.path.join(fn, sfn))
        else:
            # directories count as having no matches, for any search
            report_file(fn, 0)
        return

    # include checks apply only to files
    if not is_included(fn):
        return

    if stat.S_ISREG(st.st_mode):
        if st.st_size == 0:
            # mmap may fail on zero-length files
            report_file(fn, 0)
            return
        try:
            f = open(fn, 'rb')
        except Exception as e:
            msg(fn+':', e)
            return

        try:
            if opts.mmap:
                try:
                    mmap_obj = mmap.mmap(f.fileno(), st.st_size, access=mmap.ACCESS_READ)
                    use_mmap = True
                except Exception as e:
                    warn(fn+':', 'mmap:', e)
                    use_mmap = False
            else:
                use_mmap = False

            if use_mmap:
                with mmap_obj:
                    count = match_mmap(fn, mmap_obj)
            else:
                count = match_chunks(fn, read_chunks(f))
            report_file(fn, count)
        except Exception as e:
            msg(fn+':', e)
            return
        finally:
            f.close()

    elif opts.devices == 'read':
        try:
            with open(fn, 'rb') as f:
                count = match_chunks(fn, read_chunks(f))
            report_file(fn, count)
        except Exception as e:
            msg(fn+':', e)

def bgrep():
    pattern = load_pattern(opts.regexp)
    try:
        pattern = re.compile(pattern, re.DOTALL)
    except Exception as e:
        err("bad pattern:", e)
    state.pattern = pattern

    state.total_matches = 0

    if not opts.args:
        if opts.directories == 'recurse':
            warn('recursive search of stdin')
        match_chunks(opts.label, readline_chunks(sys.stdin.buffer))
    else:
        for fn in opts.args:
            examine_file(fn)

if __name__ == '__main__':
    sys.exit(main())
