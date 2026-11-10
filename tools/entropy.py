#!/usr/bin/env python3
# Uso: python3 tools/entropy.py [ruta-al-pe]
# Desde la raíz del repo. Sin argumento usa fixtures/hello64.exe.

import struct
import math
import sys

def entropy(b):
    if not b:
        return 0.0
    n = len(b)
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    return -sum((c / n) * math.log2(c / n) for c in counts if c)

path = sys.argv[1] if len(sys.argv) > 1 else 'fixtures/hello64.exe'
d = open(path, 'rb').read()
e = struct.unpack_from('<I', d, 0x3c)[0]
coff = e + 4
n = struct.unpack_from('<H', d, coff + 2)[0]
so = struct.unpack_from('<H', d, coff + 16)[0]
table = coff + 20 + so

print(f'{path}: entropia global {entropy(d):.4f}')
print(f"{'seccion':10} {'rawsize':>10} {'entropia':>9}")
for i in range(n):
    o = table + i * 40
    name = d[o:o + 8].rstrip(b'\0').decode('ascii', 'replace')
    rs, rp = struct.unpack_from('<II', d, o + 0x10)
    print(f'{name:10} {rs:>10} {entropy(d[rp:rp + rs]):>9.4f}')
