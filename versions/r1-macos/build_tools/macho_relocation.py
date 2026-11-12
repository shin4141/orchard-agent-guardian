"""Transform a copied Mach-O image in memory for a local developer Build.

Payload and slice offsets remain fixed. The Build script signs transformed
files afresh and never treats a source binary's old signature as valid.
"""
from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
import posixpath
import struct

def require(condition, code):
    if not condition:
        raise ValueError(code)

MAX_BYTES = 64 * 1024 * 1024
LOADS = {0xC, 0x18, 0x1F, 0x20, 0x23}
THIN = {b'\xcf\xfa\xed\xfe': ('<', 32), b'\xce\xfa\xed\xfe': ('<', 28),
        b'\xfe\xed\xfa\xcf': ('>', 32), b'\xfe\xed\xfa\xce': ('>', 28)}
FAT = {b'\xca\xfe\xba\xbe': ('>', 20), b'\xca\xfe\xba\xbf': ('>', 32),
       b'\xbe\xba\xfe\xca': ('<', 20), b'\xbf\xba\xfe\xca': ('<', 32)}
SYSTEM = ('/System/Library/', '/usr/lib/')


def _slices(raw):
    require(isinstance(raw, bytes) and 28 <= len(raw) <= MAX_BYTES, 'BLOCK_MACHO_SIZE')
    if raw[:4] in THIN:
        return [(0, len(raw), None)]
    require(raw[:4] in FAT, 'BLOCK_MACHO_FORMAT')
    endian, width = FAT[raw[:4]]
    count = struct.unpack_from(endian + 'I', raw, 4)[0]
    require(0 < count <= 16 and 8 + width * count <= len(raw), 'BLOCK_MACHO_FAT_TABLE')
    result, cpus = [], set()
    for i in range(count):
        fields = struct.unpack_from(endian + ('iiIII' if width == 20 else 'iiQQII'), raw, 8 + i * width)
        cpu, subtype, offset, size, align = fields[:5]
        require(0 <= align <= 31 and offset % (1 << align) == 0
                and offset >= 8 + width * count and size >= 28 and offset + size <= len(raw)
                and (cpu, subtype) not in cpus, 'BLOCK_MACHO_FAT_SLICE')
        require(all(offset + size <= old or old + length <= offset for old, length, _ in result),
                'BLOCK_MACHO_FAT_OVERLAP')
        cpus.add((cpu, subtype)); result.append((offset, size, (cpu, subtype)))
    return result


def _views(raw):
    result = []
    for start, length, expected_cpu in _slices(raw):
        require(raw[start:start + 4] in THIN, 'BLOCK_MACHO_SLICE_FORMAT')
        endian, header = THIN[raw[start:start + 4]]
        require(length >= header, 'BLOCK_MACHO_HEADER')
        cpu, subtype, kind, count, size = struct.unpack_from(endian + 'iiIII', raw, start + 4)
        require(kind in (2, 6, 8) and count <= 8192 and size <= 1024 * 1024
                and header + size <= length and (expected_cpu is None or expected_cpu == (cpu, subtype)),
                'BLOCK_MACHO_COMMAND_AREA')
        offset, end, commands = start + header, start + header + size, []
        for _ in range(count):
            require(offset + 8 <= end, 'BLOCK_MACHO_COMMAND_HEADER')
            command, width = struct.unpack_from(endian + 'II', raw, offset)
            require(width >= 8 and width % 4 == 0 and offset + width <= end, 'BLOCK_MACHO_COMMAND_SIZE')
            base = command & 0x7FFFFFFF
            item = {'offset': offset, 'size': width, 'command': command, 'kind': base}
            if base in LOADS | {0xD, 0x1C}:
                minimum = 12 if base == 0x1C else 24
                require(width >= minimum, 'BLOCK_MACHO_STRING_HEADER')
                name_offset = struct.unpack_from(endian + 'I', raw, offset + 8)[0]
                require(minimum <= name_offset < width, 'BLOCK_MACHO_STRING_OFFSET')
                terminator = raw.find(b'\0', offset + name_offset, offset + width)
                require(terminator > offset + name_offset, 'BLOCK_MACHO_STRING_TERMINATOR')
                try:
                    name = raw[offset + name_offset:terminator].decode('utf-8')
                except UnicodeDecodeError:
                    require(False, 'BLOCK_MACHO_STRING_ENCODING')
                require(all(ord(c) >= 32 and ord(c) != 127 for c in name), 'BLOCK_MACHO_STRING_CONTROL')
                item.update(name_offset=name_offset, name=name)
            commands.append(item); offset += width
        require(offset == end, 'BLOCK_MACHO_COMMAND_COUNT')
        result.append({'start': start, 'length': length, 'endian': endian, 'header': header,
                       'command_bytes': size, 'cpu_type': cpu, 'file_type': kind, 'commands': commands})
    return result


def analyze(raw):
    return [{'cpu_type': view['cpu_type'], 'file_type': view['file_type'],
             'dylibs': [c['name'] for c in view['commands'] if c['kind'] in LOADS],
             'rpaths': [c['name'] for c in view['commands'] if c['kind'] == 0x1C],
             'install_ids': [c['name'] for c in view['commands'] if c['kind'] == 0xD]}
            for view in _views(raw)]


def bundle_layout(name):
    require(isinstance(name, str) and name.startswith('Contents/')
            and str(PurePosixPath(name)) == name and '\\' not in name
            and all(p not in ('', '.', '..') for p in name.split('/'))
            and all(ord(c) >= 32 and ord(c) != 127 for c in name), 'BLOCK_APP_LAYOUT')
    return name


def resolve_load(layout, name):
    """Resolve a declared load against the bundle, without consulting the host."""
    bundle_layout(layout)
    if name.startswith(SYSTEM):
        require(posixpath.normpath(name) == name, 'BLOCK_MACHO_SYSTEM_ALIAS')
        return None
    if name.startswith('@loader_path/'):
        base, tail = posixpath.dirname(layout), name[len('@loader_path/'):]
    elif name.startswith('@executable_path/'):
        base, tail = 'Contents/MacOS', name[len('@executable_path/'):]
    else:
        require(False, 'BLOCK_MACHO_HOST_OR_RPATH_LOAD')
    target = posixpath.normpath(posixpath.join(base, tail))
    return bundle_layout(target)


def projected_architectures(layout, architectures, replacements):
    bundle_layout(layout)
    require(len(replacements) == len(set(replacements)), 'BLOCK_MACHO_REPAIR_MAP')
    result = []
    for arch in architectures:
        require(all(arch['dylibs'].count(old) == 1 for old in replacements), 'BLOCK_MACHO_REPAIR_EDGE')
        require(len(arch['install_ids']) == (1 if arch['file_type'] == 6 else 0), 'BLOCK_MACHO_INSTALL_ID')
        require(all(r in ('/opt/homebrew/lib', '@loader_path/../lib') for r in arch['rpaths']),
                'BLOCK_MACHO_UNEXPECTED_RPATH')
        loads = [replacements.get(old, old) for old in arch['dylibs']]
        for name in loads: resolve_load(layout, name)
        result.append({**arch, 'dylibs': loads, 'rpaths': [],
                       'install_ids': ['@rpath/' + PurePosixPath(layout).name] if arch['file_type'] == 6 else []})
    return result


def verify_graph(records):
    require(len({r['layout'] for r in records}) == len(records), 'BLOCK_MACHO_GRAPH_DUPLICATE')
    by_layout = {bundle_layout(r['layout']): r['architectures'] for r in records}
    edges = []
    for layout, architectures in by_layout.items():
        require(architectures, 'BLOCK_MACHO_GRAPH_ARCH')
        for arch in architectures:
            require(not arch['rpaths'], 'BLOCK_MACHO_GRAPH_RPATH')
            expected_id = ['@rpath/' + PurePosixPath(layout).name] if arch['file_type'] == 6 else []
            require(arch['install_ids'] == expected_id, 'BLOCK_MACHO_GRAPH_ID')
            for name in arch['dylibs']:
                target = resolve_load(layout, name)
                if target is not None:
                    require(target in by_layout and any(x['cpu_type'] == arch['cpu_type'] and x['file_type'] == 6
                            for x in by_layout[target]), 'BLOCK_MACHO_GRAPH_TARGET')
                    edges.append({'consumer': layout, 'load': name, 'target': target, 'cpu_type': arch['cpu_type']})
    return edges


def relocate(raw, *, layout, expected_sha256, expected_bytes, expected_architectures, replacements):
    """Transform a byte copy after checking its SHA, size and load commands."""
    require(type(expected_bytes) is int and len(raw) == expected_bytes
            and hashlib.sha256(raw).hexdigest() == expected_sha256, 'BLOCK_MACHO_INPUT_PIN')
    require(analyze(raw) == expected_architectures, 'BLOCK_MACHO_ANALYSIS_PIN')
    target = projected_architectures(layout, expected_architectures, replacements)
    output = bytearray(raw)
    for view in _views(raw):
        chunks = []
        for command in view['commands']:
            if command['kind'] == 0x1C:
                continue
            start, width = command['offset'], command['size']
            chunk = bytearray(raw[start:start + width])
            new_name = None
            if command['kind'] in LOADS:
                new_name = replacements.get(command['name'])
            elif command['kind'] == 0xD:
                new_name = '@rpath/' + PurePosixPath(layout).name
            if new_name is not None:
                encoded = new_name.encode('utf-8') + b'\0'
                offset = command['name_offset']
                require(len(encoded) <= width - offset, 'BLOCK_MACHO_COMMAND_CAPACITY')
                chunk[offset:] = encoded + bytes(width - offset - len(encoded))
            chunks.append(bytes(chunk))
        commands = b''.join(chunks)
        old_size = view['command_bytes']
        require(len(commands) <= old_size, 'BLOCK_MACHO_HEADER_GROWTH')
        start = view['start']
        struct.pack_into(view['endian'] + 'II', output, start + 16, len(chunks), len(commands))
        area = start + view['header']
        output[area:area + old_size] = commands + bytes(old_size - len(commands))
        require(output[area + old_size:start + view['length']] == raw[area + old_size:start + view['length']],
                'BLOCK_MACHO_PAYLOAD_CHANGED')
    transformed = bytes(output)
    require(len(transformed) == len(raw) and analyze(transformed) == target, 'BLOCK_MACHO_OUTPUT_READBACK')
    return transformed, {'layout': layout, 'input_sha256': expected_sha256,
                         'transformed_sha256': hashlib.sha256(transformed).hexdigest(), 'bytes': len(transformed),
                         'architectures': target, 'signature': 'INVALIDATED_REQUIRES_FRESH_SIGNATURE',
                         'signed': False, 'native_authorized': False}
