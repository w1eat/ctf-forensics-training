"""Inspect/clear bit 0 in classic single-disk ZIP headers. This does not decrypt."""
from pathlib import Path
import argparse, struct, zipfile
p=argparse.ArgumentParser(description=__doc__); p.add_argument('action',choices=['inspect','clear']); p.add_argument('input'); p.add_argument('output',nargs='?'); a=p.parse_args()
src=Path(a.input); d=bytearray(src.read_bytes()); eocd=-1
for pos in range(len(d)-22,max(-1,len(d)-65558),-1):
    if d[pos:pos+4]==b'PK\x05\x06' and pos+22+struct.unpack_from('<H',d,pos+20)[0]==len(d): eocd=pos; break
if eocd<0: p.error('EOCD not found')
disk,cd_disk,on_disk,total,size,cd=struct.unpack_from('<HHHHII',d,eocd+4)
if disk or cd_disk or on_disk!=total or total==65535 or cd==0xffffffff or size==0xffffffff: p.error('Only classic single-disk ZIP is supported')
cursor=cd
for index in range(total):
    if d[cursor:cursor+4]!=b'PK\x01\x02': p.error('Central directory signature mismatch')
    flags=struct.unpack_from('<H',d,cursor+8)[0]; n,x,c=struct.unpack_from('<HHH',d,cursor+28); local=struct.unpack_from('<I',d,cursor+42)[0]
    if local+30>len(d) or d[local:local+4]!=b'PK\x03\x04': p.error('Local header mismatch')
    local_flags=struct.unpack_from('<H',d,local+6)[0]; name=bytes(d[cursor+46:cursor+46+n]).decode('utf-8','replace')
    print(name,'local_flags=',hex(local_flags),'central_flags=',hex(flags))
    if a.action=='clear':
        struct.pack_into('<H',d,local+6,local_flags&~1); struct.pack_into('<H',d,cursor+8,flags&~1)
    cursor+=46+n+x+c
if cursor!=cd+size: p.error('Directory size mismatch')
if a.action=='clear':
    if not a.output: p.error('Output path required')
    dst=Path(a.output)
    if src.resolve()==dst.resolve(): p.error('Use a different output path')
    dst.parent.mkdir(parents=True,exist_ok=True); dst.write_bytes(d)
    try:
        with zipfile.ZipFile(dst) as z: print('First bad CRC entry:',z.testzip())
    except Exception as exc: print('Validation failed:',exc); raise SystemExit(2)
