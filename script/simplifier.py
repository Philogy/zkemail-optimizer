import re
import json
import pyperclip
import subprocess
from utils import *
from enum import Enum


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
    src_code = safe_replace(
        src_code,
        f'{CLOSE_CURLY}\n        return success;\n',
        f'    mstore(0x00, success)\n            return(0x00, 0x20)\n        {CLOSE_CURLY}\n',
    )
    return src_code


PROOF_OFFSET = 0x64


def proof_mem_to_calldata(src_code):
    src_code = safe_replace(
        src_code,
        'bytes memory proof',
        'bytes calldata proof'
    )
    src_code = insert_after(
        src_code,
        ASM_START,
        f'let success := eq(proof.offset, 0x{PROOF_OFFSET:x})'
    )

    def proof_mem_repl(m: re.Match) -> str:
        ptr = int(m.group(1), 16)
        return f'calldataload(0x{PROOF_OFFSET + ptr - 0x20:x})'

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
                let x := calldataload\(0x([0-9a-f]{2,})\)
                mstore\(add\(transcript, 0x([0-9a-f]{2,})\), x\)
                let y := calldataload\(0x([0-9a-f]{2,})\)
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

        start_cd1, start_mem1, _, _ = hexs_to_ints(blocks[0].groups())
        last_cd, _, _, _ = hexs_to_ints(blocks[-1].groups())
        end_cd = last_cd + 0x40

        return f'''
            for {{ let ptr := 0x{start_cd1:x} }} lt(ptr, 0x{end_cd:x}) {{ ptr := add(ptr, 0x40) }} {{
                let x := calldataload(ptr)
                let y := calldataload(add(ptr, 0x20))
                success := and(validate_ec_point(x, y), success)
            }}
            calldatacopy(add(transcript, 0x{start_mem1:x}), 0x{PROOF_OFFSET + start_cd1:x}, 0x{len(blocks) * 0x40:x})
        '''

    return re.sub(
        snippet_to_pattern(r'''
                               (\{
                let x := calldataload\(0x([0-9a-f]{2,})\)
                mstore\(add\(transcript, 0x([0-9a-f]{2,})\), x\)
                let y := calldataload\(0x([0-9a-f]{2,})\)
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


def summarize_simple_range_checks(src_code):
    range_check_pattern = r'mstore\(0x([0-9a-f]+), mod\(calldataload\(0x([0-9a-f]+)\), f_q\)\)'
    blocks_pattern = snippet_to_pattern(r'(' + range_check_pattern + r'\s*)+')
    range_check_blocks = [*re.finditer(blocks_pattern, src_code)]
    assert len(range_check_blocks) == 1, 'Expected only 1 range check group'

    def replace_block(block: re.Match) -> str:
        range_checks = [
            *re.finditer(range_check_pattern, block.group(0))
        ]
        for a, b in zip(range_checks[:-1], range_checks[1:]):
            a1, a2 = hexs_to_ints(a.groups())
            b1, b2 = hexs_to_ints(b.groups())
            assert a1 + 0x20 == b1
            assert a2 + 0x20 == b2

        start_mem, start_cd = hexs_to_ints(range_checks[0].groups())

        return f'''
            for {{
                let ptr := 0x{start_cd:x}
                let endPtr := 0x{start_cd + 0x20 * len(range_checks):x}
            }} lt(ptr, endPtr) {{ ptr := add(ptr, 0x20)}} {{
                success := and(success, lt(calldataload(ptr), f_q))
            }}
            calldatacopy(0x{start_mem:x}, 0x{start_cd:x}, 0x{0x20 * len(range_checks):x})
        '''

    return re.sub(blocks_pattern, replace_block, src_code)


F_Q = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
F_Q_VARNAME = 'f_q'


def summarize_constants(src_code):
    check_contains(src_code, f'let {F_Q_VARNAME} := 0x{F_Q:x}')
    return re.sub(str(F_Q), F_Q_VARNAME, src_code)


def remove_redundant_success_check(src_code):
    call_pattern = r'eq\(staticcall\(gas\(\), (0x[0-9a-f]+), (0x[0-9a-f]+), (0x[0-9a-f]+), (0x[0-9a-f]+), (0x[0-9a-f]+)\), 1\)'
    src_code = re.sub(
        call_pattern,
        lambda m: f'staticcall(gas(), {m.group(1)}, {m.group(2)}, {m.group(3)}, {m.group(4)}, {m.group(5)})',
        src_code
    )
    return src_code


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
        '''mstore(0x00, 0)
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
    src_code = summarize_simple_range_checks(src_code)
    src_code = summarize_constants(src_code)
    src_code = remove_redundant_success_check(src_code)

    target_fp = f'src/{NAME}.sol'
    with open(target_fp, 'w') as f:
        f.write(src_code)

    print(f'Wrote simplified to {target_fp}')
    subprocess.run(['forge', 'fmt'])
    print(f'Ran `forge fmt`')


if __name__ == '__main__':
    main()
