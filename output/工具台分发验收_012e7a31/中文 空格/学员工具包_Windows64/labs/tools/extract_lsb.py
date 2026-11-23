"""Training convention: red LSB, row-major pixels, MSB-first output bytes."""
from pathlib import Path
import argparse
from PIL import Image
p=argparse.ArgumentParser(description=__doc__); p.add_argument('input'); p.add_argument('output'); a=p.parse_args()
src,dst=Path(a.input),Path(a.output)
if src.resolve()==dst.resolve(): p.error('Use a different output path')
im=Image.open(src).convert('RGB'); bits=[r&1 for r,g,b in im.getdata()]; out=bytearray()
for i in range(0,len(bits)-7,8):
    value=0
    for bit in bits[i:i+8]: value=(value<<1)|bit
    out.append(value)
dst.parent.mkdir(parents=True,exist_ok=True); dst.write_bytes(out)
print(bytes(out).split(b'\0',1)[0].decode('utf-8'))
