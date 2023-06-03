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

        # Validate offsets
        for a, b in zip(blocks[:-1], blocks[1:]):
            a1, a2, a3, a4 = hexs_to_ints(a.groups())
            b1, b2, b3, b4 = hexs_to_ints(b.groups())
            assert a1 + 0x40 == b1
            assert a2 + 0x40 == b2
            assert a3 + 0x40 == b3
            assert a4 + 0x40 == b4

        for block in blocks:
            a1, a2, a3, a4 = hexs_to_ints(block.groups())
            assert a1 + 0x20 == a3
            assert a2 + 0x20 == a4

        start_cd1, start_mem1, start_cd2, _ = hexs_to_ints(blocks[0].groups())
        last_cd, _, _, _ = hexs_to_ints(blocks[-1].groups())
        end_cd = last_cd + 0x40

        return f'''
            for {{ let ptr := 0x{start_cd1:x} }} lt(ptr, 0x{end_cd:x}) {{ ptr := add(ptr, 0x40) }} {{
                let x := calldataload(add(proof.offset, ptr))
                let y := calldataload(add(proof.offset, add(ptr, 0x20)))
                success := and(validate_ec_point(x, y), success)
            }}
            calldatacopy(add(transcript, 0x{start_mem1:x}), add(proof.offset, 0x{start_cd1:x}), 0x{len(blocks) * 0x40:x})
        '''

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


def remove_transcript_var(src_code):
    return re.sub(
        r'add\(transcript, (0x[0-9a-f]+)\)',
        lambda m: m.group(1),
        src_code
    )


NAME = 'SimplifiedVerifier'


def main():
    with open('src/VerifierApp.sol', 'r') as f:
        orig_src_code = f.read()

    src_code = orig_src_code
    # Rename
    src_code = safe_replace(src_code, 'VerifierApp', NAME)
    # Optimize start/end
    src_code = safe_replace(src_code, 'public', 'external')
    src_code = remove(src_code, 'bytes32[5707] memory transcript;')
    src_code = insert_after(
        src_code,
        ASM_START,
        '''
            mstore(0x00, 0)
            mstore(0x20, 0)
            mstore(0x40, 0)
            mstore(0x60, 0)
        '''
    )
    src_code = simplify_pub_inputs(src_code)
    src_code = optimize_validate_ec_point(src_code)
    src_code = replace_sol_success(src_code)
    # Optimize body
    src_code = proof_mem_to_calldata(src_code)
    src_code = summarize_validate_point_blocks(src_code)
    src_code = remove_transcript_var(src_code)

    target_fp = f'src/{NAME}.sol'
    with open(target_fp, 'w') as f:
        f.write(src_code)

    print(f'Wrote simplified to {target_fp}')
    subprocess.run(['forge', 'fmt'])
    print(f'Ran `forge fmt`')

    with open(target_fp, 'r') as f:
        src_code = f.read()

    diff = count_lines(src_code) - count_lines(orig_src_code)
    pct = count_lines(src_code) / count_lines(orig_src_code) - 1
    print(
        f'Total lines: {count_lines(src_code):,} ({sign(pct)}{abs(pct):.2%}   lines: {sign(diff)}{abs(diff):,})'
    )


if __name__ == '__main__':
    main()
