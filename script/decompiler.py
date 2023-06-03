import json
import pyperclip


PUSH_OPS = [*range(0x60, 0x80)]


normal_ops = {
    0x51: 'MLOAD',
    0x52: 'MSTORE',
    0x56: 'JUMP',
    0x57: 'JUMPI',
    0x5B: 'JUMPDEST'
}


def decompile_simple(rt_bytecode):
    ptr = 0
    ops = []
    while ptr < len(rt_bytecode):
        op = rt_bytecode[ptr]
        if op in PUSH_OPS:
            size = op - 0x5f
            ops.append(
                (f'PUSH{size} 0x{rt_bytecode[ptr+1:ptr + size + 1].hex()}', f'0x{op:02x}')
            )
            ptr += 1 + size
        else:
            ops.append(
                (normal_ops.get(op, 'UNKNOWN'), f'0x{op:02x}')
            )
            ptr += 1
    return ops


def main():
    with open('out/VerifierApp.sol/VerifierApp.json', 'r') as f:
        compiled_obj = json.load(f)

    raw_bytecode = compiled_obj['deployedBytecode']['object']
    pyperclip.copy(raw_bytecode[:400])
    runtime_bytecode = bytes.fromhex(raw_bytecode[2:])

    all_ops = decompile_simple(runtime_bytecode)

    total_dests = 0

    for name, _ in all_ops:
        if name == 'JUMPI':
            total_dests += 1

    for name, val in all_ops[:1000]:
        print(name if name != 'UNKNOWN' else f'{name}({val})')

    print(f'total_dests: {total_dests}')


if __name__ == '__main__':
    main()
