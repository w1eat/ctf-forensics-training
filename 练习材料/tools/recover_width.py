"""Restore only width when a valid original IHDR CRC was retained. Python 3."""
from pathlib import Path
import argparse, struct, zlib
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('input'); p.add_argument('output'); a=p.parse_args()
src,dst=Path(a.input),Path(a.output)
if src.resolve()==dst.resolve(): p.error('Use a different output path')
d=bytearray(src.read_bytes())
if len(d)<33 or d[:8]!=b'\x89PNG\r\n\x1a\n' or d[8:16]!=b'\x00\x00\x00\rIHDR': p.error('Expected PNG with a 13-byte IHDR')
expected=struct.unpack('>I',d[29:33])[0]; matches=[]
for width in range(1,4097):
    candidate=bytearray(d[12:29]); candidate[4:8]=struct.pack('>I',width)
    if zlib.crc32(candidate)&0xffffffff==expected: matches.append(width)
print('Candidate widths:',matches)
if len(matches)!=1: p.error('No unique candidate; assumptions may not hold')
d[16:20]=struct.pack('>I',matches[0]); dst.parent.mkdir(parents=True,exist_ok=True); dst.write_bytes(d)
print('Saved',dst,'; verify parsing and image data separately')
