import re


def check_contains(src_code, s):
    assert s in src_code, f'Could not find "{s}" in source code'


def check_count(src_code, s, c):
    assert src_code.count(s) == c, f'Expected "{s}" {c}x'


def safe_replace(src_code, old, new, count=1):
    check_contains(src_code, old)
    return src_code.replace(old, new, count)


def apply_repl(repl_or_str):
    def actual_repl(m: re.Match) -> str:
        if callable(repl_or_str):
            return repl_or_str(m)
        elif isinstance(repl_or_str, str):
            return repl_or_str
        raise TypeError(f'Repl {repl_or_str!r} neither str or callable')
    return actual_repl


def insert_after(src_code, pattern, repl):
    return re.sub(
        pattern,
        lambda m: m.group(0) + apply_repl(repl)(m),
        src_code
    )


def find(src_code, s):
    check_count(src_code, s, 1)
    pos = src_code.index(s)
    return pos, pos + len(s)


def remove(src_code, s):
    return safe_replace(src_code, s, '', 1)


def clean(s):
    return ' '.join(s.split()).strip()


def snippet_to_pattern(snippet):
    return clean(snippet).replace(' ', r'\s+').replace('\n', r'\s+')


def index_lines(src_code):
    pos_to_line = dict()
    line_to_pos = {1: 0}
    line = 1

    for i, char in enumerate(src_code):
        pos_to_line[i] = line
        if char == '\n':
            line += 1
            line_to_pos[line] = i + 1

    return pos_to_line, line_to_pos


def replace_section(src_code, start, end, s):
    return src_code[:start] + s + src_code[end:]


def hexs_to_ints(hexs):
    return map(lambda x: int(x, 16), hexs)


def count_lines(src_code):
    return len(src_code.splitlines())


def sign(x: float):
    if x == 0:
        return ''
    if x > 0:
        return '+'
    return '-'
