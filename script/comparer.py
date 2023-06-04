from utils import *
from math import ceil


CONTRACT_SIZE_LIMIT = 0x6000


def main():
    with open('src/VerifierApp.sol', 'r') as f:
        orig_src_code = f.read()
    with open('src/SimplifiedVerifier.sol', 'r') as f:
        src_code = f.read()

    diff = count_lines(src_code) - count_lines(orig_src_code)
    pct = count_lines(src_code) / count_lines(orig_src_code) - 1
    print(
        f'Total lines: {count_lines(src_code):,} ({sign(pct)}{abs(pct):.2%}   lines: {sign(diff)}{abs(diff):,})'
    )


if __name__ == '__main__':
    main()
