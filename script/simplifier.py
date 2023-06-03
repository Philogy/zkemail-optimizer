import re
import json
import pyperclip
import subprocess
from utils import *


def simplify_pub_inputs(src_code: str):
    check_count(src_code, 'pubInputs', 2)
    check_contains(src_code, 'add(pubInputs, 0x20)')

    src_code = safe_replace(
        src_code,
        'uint256[] memory pubInputs',
        'uint256 pubInput'
    )
    src_code = safe_replace(
        src_code,
        'mload(add(pubInputs, 0x20))',
        'pubInput'
    )

    check_count(src_code, 'pubInputs', 0)

    return src_code


def optimize_validate_ec_point(src_code):
    return safe_replace(
        src_code,
        '\n'.join([
            '                {',
            '                    let x_lt_p := lt(x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)',
            '                    let y_lt_p := lt(y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)',
            '                    valid := and(x_lt_p, y_lt_p)',
            '                }',
            '                {',
            '                    let x_is_zero := eq(x, 0)',
            '                    let y_is_zero := eq(y, 0)',
            '                    let x_or_y_is_zero := or(x_is_zero, y_is_zero)',
            '                    let x_and_y_is_not_zero := not(x_or_y_is_zero)',
            '                    valid := and(x_and_y_is_not_zero, valid)',
            '                }'
        ]),
        '\n'.join([
            '                {',
            '                    let x_lt_p := lt(sub(x, 1), 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46)',
            '                    let y_lt_p := lt(sub(y, 1), 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46)',
            '                    valid := and(x_lt_p, y_lt_p)',
            '                }'
        ])

    )


ASM_START = f'assembly {OPEN_CURLY}\n'


def replace_sol_success(src_code):
    src_code = remove(src_code, 'bool success = true;')
    src_code = insert_after(src_code, ASM_START, 'let success := 1\n')
    src_code = safe_replace(
        src_code,
        f'{CLOSE_CURLY}\n        return success;\n',
        f'    mstore(0x00, success)\n            return(0x00, 0x20)\n        {CLOSE_CURLY}\n',
    )
    return src_code


def proof_mem_repl(m: re.Match) -> str:
    ptr = int(m.group(1), 16)
    return f'calldataload(add(proof.offset, 0x{ptr - 0x20:02x}))'


def proof_mem_to_calldata(src_code):
    src_code = safe_replace(
        src_code,
        'bytes memory proof',
        'bytes calldata proof'
    )
    src_code = re.sub(
        r'mload\(add\(proof, 0x([0-9a-f]{2,})\)\)',
        proof_mem_repl,
        src_code
    )

    return src_code


def summarize_validate_point_blocks(src_code):
    char_to_line, line_to_char = index_lines(src_code)

    def summarize_validate_point_block(m: re.Match) -> str:
        blocks = [*re.finditer(
            snippet_to_pattern(r'''
           \{
                let x := calldataload\(add\(proof.offset, 0x([0-9a-f]{2,})\)\)
                mstore\(add\(transcript, 0x([0-9a-f]{2,})\), x\)
                let y := calldataload\(add\(proof.offset, 0x([0-9a-f]{2,})\)\)
                mstore\(add\(transcript, 0x([0-9a-f]{2,})\), y\)
                success := and\(validate_ec_point\(x, y\), success\)
            \}'''),
            m.group(0)
        )]
        for m in blocks:

    return re.sub(
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
        summarize_validate_point_block,
        src_code
    )


NAME = 'SimplifiedVerifier'


def main():
    with open('src/VerifierApp.sol', 'r') as f:
        src_code = f.read()

    # Rename
    src_code = safe_replace(src_code, 'VerifierApp', NAME)
    # Optimize start/end
    src_code = safe_replace(src_code, 'public', 'external')
    src_code = simplify_pub_inputs(src_code)
    src_code = optimize_validate_ec_point(src_code)
    src_code = replace_sol_success(src_code)
    # Optimize body
    src_code = proof_mem_to_calldata(src_code)
    src_code = summarize_validate_point_blocks(src_code)

    target_fp = f'src/{NAME}.sol'
    with open(target_fp, 'w') as f:
        f.write(src_code)

    print(f'Wrote simplified to {target_fp}')
    subprocess.run(['forge', 'fmt'])
    print(f'Ran `forge fmt`')

    with open(target_fp, 'r') as f:
        src_code = f.read()

    print(f'Total lines: {len(src_code.splitlines()):,}')


if __name__ == '__main__':
    main()
