import json
from collections import namedtuple

OPEN_CURLY = chr(123)
CLOSE_CURLY = chr(125)

counter_brackets = {
    chr(41): chr(40),
    CLOSE_CURLY: OPEN_CURLY,
    chr(93): chr(91)
}
open_brackets = set(counter_brackets.values())


def parse_brackets(src):
    bracket_stack = []
    bracket_open_close = dict()
    bracket_close_open = dict()

    for i, char in enumerate(src):
        if char in open_brackets:
            bracket_stack.append((char, i))
        elif char in counter_brackets:
            opposite_char, pos = bracket_stack.pop()
            assert counter_brackets[char] == opposite_char, f'Bracket mismatch'
            bracket_open_close[pos] = i
            bracket_close_open[i] = pos

    assert not bracket_stack, f'Not all brackets matched ({len(bracket_stack)})'

    return bracket_open_close, bracket_close_open


def pjson(obj):
    print(json.dumps(obj, indent=2))


def get_asm_statements(obj):
    ast = obj['ast']
    contract_def = ast['nodes'][1]
    fn_def = contract_def['nodes'][0]
    asm_node = fn_def['body']['statements'][0]

    assert asm_node['nodeType'] == 'InlineAssembly'

    return asm_node['AST']


MemWrite = namedtuple('MemWrite', ['offset'])
MemRead = namedtuple('MemRead', ['offset'])
MemBlockWrite = namedtuple('MemBlockWrite', ['word_offsets'])
MemBlockRead = namedtuple('MemBlockRead', ['word_offsets'])
MemCopy = namedtuple('MemCopy', ['from_offset', 'to_offset'])
MemNode = namedtuple('MemNode', ['start', 'end', 'node'])


def flatten_list_iterable(iterable):
    res = []
    for l in iterable:
        res.extend(l)
    return res


class MemParser:
    def __init__(self, obj) -> None:
        self._reset(obj)
        self.parse_to_mem()

    def _reset(self, obj):
        self.start_obj = obj
        self.printed = False
        self.unsorted_mem_nodes = []
        self.missed_types = set()
        self.identifiers = set()

    def parse_to_mem(self):
        self.unsorted_mem_nodes = []
        self.missed_types = set()
        self.mem_nodes = self.parse_statements(self.start_obj)

    def parse_statements(self, obj):
        statements = obj['statements']
        return flatten_list_iterable(map(self.parse_statement, statements))

    def parse_statement(self, obj):
        ntype = obj['nodeType']
        if ntype == 'YulFunctionDefinition':
            assert obj['name'] == 'validate_ec_point'
            assert not self.parse_statements(obj['body'])
            return []
        elif ntype == 'YulBlock':
            return self.parse_statements(obj)
        elif ntype == 'YulForLoop':
            assert not self.parse_statements(obj['pre'])
            assert not self.parse_statements(obj['post'])
            assert not self.parse_statements(obj['body'])
            assert not self.parse_statement(obj['condition'])
            return []
        elif ntype == 'YulAssignment':
            if 'value' not in obj:
                self.missed(obj, 'parse_statement')
                return []
            return self.parse_statement(obj['value'])
        elif ntype == 'YulVariableDeclaration':
            if 'value' not in obj:
                return []
            return self.parse_statement(obj['value'])
        elif ntype == 'YulFunctionCall':
            return self.parse_function_call(obj)
        elif ntype == 'YulIdentifier':
            self.identifiers.add(obj['name'])
            return []
        elif ntype == 'YulLiteral':
            return []
        elif ntype == 'YulExpressionStatement':
            return self.parse_statement(obj['expression'])
        else:
            self.missed(obj, 'parse_statement')

        return []

    def parse_function_call(self, obj):
        fn_name = obj['functionName']['name']
        args = obj['arguments']
        if fn_name in ('eq', 'lt', 'sub', 'and', 'mulmod', 'addmod', 'mod', 'add', 'calldataload',
                       'validate_ec_point'):
            return flatten_list_iterable(map(self.parse_statement, args))
        elif fn_name == 'mstore':
            offset, value = args
            assert offset['nodeType'] == 'YulLiteral'
            if value['nodeType'] == 'YulFunctionCall' and value['functionName']['name'] == 'mload':
                from_offset, = value['arguments']
                assert from_offset['nodeType'] == 'YulLiteral'
                return [MemNode(
                    *self.get_span(obj),
                    MemCopy(self.get_value(from_offset),
                            self.get_value(offset))
                )]
            else:
                return self.parse_statement(value) + [MemNode(
                    *self.get_span(obj),
                    MemWrite(self.get_value(offset))
                )]
        elif fn_name == 'mload':
            offset, = args
            assert offset['nodeType'] == 'YulLiteral'
            return [MemNode(*self.get_span(obj), MemRead(self.get_value(offset)))]
        elif fn_name == 'calldatacopy':
            offset, _, size = args
            return [MemNode(*self.get_span(obj), MemBlockWrite(self.get_word_offsets(offset, size)))]
        elif fn_name in ('keccak256', 'return', 'revert'):
            offset, size = args
            return [MemNode(*self.get_span(obj), MemBlockRead(self.get_word_offsets(offset, size)))]
        elif fn_name == 'mstore8':
            offset, value = args
            assert offset['nodeType'] == 'YulLiteral'
            assert value['nodeType'] == 'YulLiteral'
            return [MemNode(*self.get_span(obj), MemWrite(self.get_value(offset)))]
        elif fn_name == 'staticcall':
            _, _, arg_offset, arg_size, ret_offset, ret_size = args
            span = self.get_span(obj)
            return [
                MemNode(
                    *span,
                    MemBlockRead(self.get_word_offsets(arg_offset, arg_size))
                ),
                MemNode(
                    *span,
                    MemBlockWrite(self.get_word_offsets(ret_offset, ret_size))
                )
            ]
        elif fn_name == 'keccak256':
            offset, size = args
            assert offset['nodeType'] == 'YulLiteral'
            assert size['nodeType'] == 'YulLiteral'
            offset_value = self.get_value(offset)
            size_value = self.get_value(size)
            return [MemNode(*self.get_span(obj), MemBlockRead([*range(offset_value, offset_value + size_value, 0x20)]))]
        else:
            self.missed(obj, 'parse_function_call')
            return []

    @ staticmethod
    def get_span(obj):
        start, length, _ = obj['src'].split(':', 2)
        return int(start), int(start) + int(length)

    @ staticmethod
    def get_value(obj):
        if 'value' not in obj:
            pjson(obj)
        val = obj['value']
        if val.startswith('0x'):
            return int(val[2:], 16)
        else:
            return int(val)

    def get_word_offsets(self, offset_obj, size_obj):
        assert offset_obj['nodeType'] == 'YulLiteral'
        assert size_obj['nodeType'] == 'YulLiteral'
        offset_value = self.get_value(offset_obj)
        size_value = self.get_value(size_obj)
        return [*range(offset_value, offset_value + size_value, 0x20)]

    def missed(self, obj, fn):
        ntype = obj['nodeType']
        self.missed_types.add((ntype, fn))
        if not self.printed:
            self.printed = True
            pjson(obj)
            print(f'Node type ({fn}): {ntype}')


def main():
    with open('out/SimplifiedVerifier.sol/SimplifiedVerifier.json', 'r') as f:
        obj = json.load(f)

    with open('src/SimplifiedVerifier.sol', 'r') as f:
        src_code = f.read()

    statements = get_asm_statements(obj)

    mem_parser = MemParser(statements)

    for mem_node in mem_parser.mem_nodes:
        print(mem_node)
    print(f'len(mem_parser.mem_nodes): {len(mem_parser.mem_nodes)}')


if __name__ == '__main__':
    main()
