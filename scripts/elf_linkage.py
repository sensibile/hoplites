"""Read ELF64 little-endian dynamic dependencies and defined symbols without execution."""

import struct


def inspect(raw, symbols=()):
    if raw[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected ELF64 little-endian binary")
    offset = struct.unpack_from("<Q", raw, 32)[0]
    size, count = struct.unpack_from("<HH", raw, 54)
    headers = [struct.unpack_from("<IIQQQQQQ", raw, offset + i * size) for i in range(count)]
    dynamic = [p for p in headers if p[0] == 2]
    if len(dynamic) != 1:
        raise ValueError("Expected one dynamic segment")
    entries = []
    p = dynamic[0]
    for offset in range(p[2], p[2] + p[5], 16):
        tag, value = struct.unpack_from("<qQ", raw, offset)
        if not tag:
            break
        entries.append((tag, value))
    address = next(v for k, v in entries if k == 5)
    segment = next(p for p in headers if p[0] == 1 and p[3] <= address < p[3] + p[5])
    start = segment[2] + address - segment[3]

    def text(offset):
        return raw[offset : raw.index(b"\0", offset)].decode()

    needed = [text(start + v) for k, v in entries if k == 1]
    offset = struct.unpack_from("<Q", raw, 40)[0]
    size, count = struct.unpack_from("<HH", raw, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", raw, offset + i * size) for i in range(count)]
    defined = set()
    for section in sections:
        if section[1] not in (2, 11):
            continue
        base = sections[section[6]][4]
        if section[9] < 24:
            raise ValueError("Invalid symbol entry size")
        for offset in range(section[4], section[4] + section[5], section[9]):
            name, _, _, index, _, _ = struct.unpack_from("<IBBHQQ", raw, offset)
            symbol = text(base + name)
            if symbol in symbols and index:
                defined.add(symbol)
    return {
        "dt_needed": needed,
        "defined_symbols": sorted(defined),
        "machine": struct.unpack_from("<H", raw, 18)[0],
    }
