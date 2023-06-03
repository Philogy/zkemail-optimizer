import re
from utils import *
import json


def main():
    with open('src/SimplifiedVerifier.sol', 'r') as f:
        src_code = f.read()

    char_to_line, line_to_char = index_lines(src_code)

    instances = [
        *re.finditer(
            snippet_to_pattern(r'''
            (\{
                let x := calldataload\(add\(proof.offset, 0x([0-9a-f]{2,})\)\)
                mstore\(add\(transcript, 0x([0-9a-f]{2,})\), x\)
                let y := calldataload\(add\(proof.offset, 0x([0-9a-f]{2,})\)\)
                mstore\(add\(transcript, 0x([0-9a-f]{2,})\), y\)
                success := and\(validate_ec_point\(x, y\), success\)
            \}
             )+
            '''),
            src_code

        )
    ]

    for m in instances:
        start = char_to_line[m.start()]
        end = char_to_line[m.end()]
        print(f'{start}-{end}')


if __name__ == '__main__':
    main()
