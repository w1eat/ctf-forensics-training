"""Copy a known byte range to a new file. Offset/length accept decimal or 0x hex."""
from pathlib import Path
import argparse
p=argparse.ArgumentParser(description=__doc__); p.add_argument('input'); p.add_argument('output')
p.add_argument('--offset',required=True,type=lambda x:int(x,0)); p.add_argument('--length',type=lambda x:int(x,0)); a=p.parse_args()
src,dst=Path(a.input),Path(a.output)
if src.resolve()==dst.resolve(): p.error('Use a different output path')
d=src.read_bytes(); end=len(d) if a.length is None else a.offset+a.length
if a.offset<0 or end<a.offset or end>len(d): p.error('Invalid byte range')
dst.parent.mkdir(parents=True,exist_ok=True); dst.write_bytes(d[a.offset:end]); print('Saved bytes:',end-a.offset)
