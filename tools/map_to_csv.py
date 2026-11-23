#!/usr/bin/env python3
"""Extract calibration records (name -> flash address) from a decrypted map.

Record layout as far as it is known (everything little endian):
  +0   ShortString[64]  name (cp1251), length byte + 64 chars
  +65  u8   kind        (1 flags, 2..5 scalar/table variants, see README)
  +66  u8   subkind
  +67  u32  record id
  +71  u32  flash address
  +75  u16  ?
  +77  ShortString      unit (only for scalars)
Records whose address is outside flash are tree nodes (sections, pins ...);
they are used as context for the records that follow them.

usage: map_to_csv.py ST10.map.dec calibrations.csv
"""
import csv
import struct
import sys

FLASH_LO, FLASH_HI = 0x60000, 0x90000


def is_text(b):
    return all(x >= 0x20 and x != 0x7F and not (0x80 <= x < 0xC0 and x not in (0xA8, 0xB8, 0xB9, 0xAB, 0xBB, 0x96, 0x97, 0x85, 0xB0)) for x in b)


def short_string(o, i, maxlen=64):
    n = o[i]
    if n > maxlen or not is_text(o[i + 1:i + 1 + n]):
        return None
    return o[i + 1:i + 1 + n].decode("cp1251")


def records(o):
    for i in range(len(o) - 80):
        n = o[i]
        if 1 <= n <= 64 and is_text(o[i + 1:i + 1 + n]) and not any(o[i + 1 + n:i + 65]):
            kind, sub = o[i + 65], o[i + 66]
            addr = struct.unpack_from("<I", o, i + 71)[0]
            yield i, o[i + 1:i + 1 + n].decode("cp1251"), kind, sub, addr


def main(src, dst):
    o = open(src, "rb").read()
    ctx = []
    rows = []
    for off, name, kind, sub, addr in records(o):
        if FLASH_LO <= addr < FLASH_HI and 1 <= kind <= 6:
            unit = short_string(o, off + 77, 32) if kind in (3, 5) and sub in (3, 4) else ""
            rows.append([f"0x{addr:05X}", f"{kind}.{sub}", name, unit or "", " / ".join(ctx[-2:]), f"0x{off:05X}"])
        else:
            ctx.append(name)
            del ctx[:-4]
    rows.sort(key=lambda r: int(r[0], 16))
    with open(dst, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["address", "type", "name", "unit", "context", "map_offset"])
        w.writerows(rows)
    print(f"{len(rows)} records")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    main(*sys.argv[1:])
