"""Small structured views for the offline classroom, all operations read-only."""
import argparse, base64, hashlib, json, struct, zlib
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('task',choices=['hash','base64','pngmap']);p.add_argument('input');a=p.parse_args()
    if a.task=='base64':
        raw=base64.b64decode(''.join(a.input.split()),validate=True)
        result=dict(kind='base64',text=raw.decode('utf-8',errors='replace'),hex=raw.hex(' '),bytes=len(raw))
    elif a.task=='hash':
        path=Path(a.input);digest=hashlib.sha256()
        with path.open('rb') as f:
            for data in iter(lambda:f.read(1024*1024),b''):digest.update(data)
        result=dict(kind='hash',name=path.name,bytes=path.stat().st_size,sha256=digest.hexdigest())
    else:
        data=Path(a.input).read_bytes()
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):raise ValueError('PNG 签名无效，请先判断文件头。')
        cursor=8;chunks=[];finished=False
        while cursor+12<=len(data):
            length=struct.unpack_from('>I',data,cursor)[0];end=cursor+12+length
            if end>len(data):raise ValueError('块超出文件边界：'+hex(cursor))
            kind=data[cursor+4:cursor+8];expected=struct.unpack_from('>I',data,cursor+8+length)[0]
            actual=zlib.crc32(data[cursor+4:cursor+8+length])&0xffffffff
            chunks.append(dict(type=kind.decode('ascii','replace'),offset=cursor,length=length,saved=f'{expected:08x}',computed=f'{actual:08x}',valid=expected==actual))
            cursor=end
            if kind==b'IEND':finished=True;break
        result=dict(kind='pngmap',bytes=len(data),chunks=chunks,iend=finished,trailing=len(data)-cursor,
                    columns=['块','字节偏移','数据长度','保存的 CRC','计算的 CRC','状态'],
                    rows=[[r['type'],hex(r['offset']),r['length'],r['saved'],r['computed'],'OK' if r['valid'] else 'BAD'] for r in chunks])
    print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':
    try:main()
    except (OSError,ValueError) as exc:raise SystemExit(str(exc))
