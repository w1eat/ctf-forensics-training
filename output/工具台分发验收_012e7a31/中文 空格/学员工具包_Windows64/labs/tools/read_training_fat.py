"""Read this course's fixed single-cluster FAT16 fixture; not a general recovery tool."""
from pathlib import Path
import argparse, struct
p=argparse.ArgumentParser(description=__doc__); p.add_argument('input'); p.add_argument('output'); a=p.parse_args()
src,dst=Path(a.input),Path(a.output)
if src.resolve()==dst.resolve(): p.error('Use a different output path')
d=src.read_bytes()
if d[510:512]!=b'\x55\xaa' or d[450]!=6: p.error('Expected training MBR/FAT16')
start=struct.unpack_from('<I',d,454)[0]; boot=start*512
bps=struct.unpack_from('<H',d,boot+11)[0]; spc=d[boot+13]; reserved=struct.unpack_from('<H',d,boot+14)[0]
fats=d[boot+16]; entries=struct.unpack_from('<H',d,boot+17)[0]; fat_sectors=struct.unpack_from('<H',d,boot+22)[0]
root=boot+(reserved+fats*fat_sectors)*bps; data=root+((entries*32+bps-1)//bps)*bps
print('Partition sector:',start,'bytes/sector:',bps)
for idx in range(entries):
    entry=d[root+idx*32:root+(idx+1)*32]
    if not entry or entry[0]==0: break
    if entry[11] in (8,15): continue
    deleted=entry[0]==0xe5; cluster=struct.unpack_from('<H',entry,26)[0]; size=struct.unpack_from('<I',entry,28)[0]
    print('root entry',idx,'deleted=',deleted,'cluster=',cluster,'size=',size)
    if deleted:
        if size>bps*spc or cluster<2: p.error('This helper only handles a single-cluster fixture')
        offset=data+(cluster-2)*spc*bps; result=d[offset:offset+size]
        dst.parent.mkdir(parents=True,exist_ok=True); dst.write_bytes(result); print(result.decode()); break
else: p.error('No deleted training entry')
