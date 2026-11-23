"""Small transparent training helpers; these are not GNU file or binwalk."""
import argparse, base64, hashlib, os, re, struct, subprocess, sys, zlib
from pathlib import Path

SIGNATURES = [(b'\x89PNG\r\n\x1a\n','PNG'), (b'\xff\xd8\xff','JPEG'), (b'GIF87a','GIF'), (b'GIF89a','GIF'),
              (b'PK\x03\x04','ZIP local header'), (b'PK\x01\x02','ZIP central directory'),
              (b'PK\x05\x06','ZIP end of central directory'), (b'%PDF-','PDF'),
              (b'SQLite format 3\0','SQLite3'), (b'7z\xbc\xaf\x27\x1c','7-Zip'), (b'Rar!\x1a\x07','RAR')]

def integer(value): return int(value, 0)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='action',required=True)
    q=sub.add_parser('type',help='Identify common signatures, not a general libmagic replacement');q.add_argument('input')
    q=sub.add_parser('scan',help='List signature candidates with byte offsets; matches can be false positives');q.add_argument('input')
    q=sub.add_parser('hex',help='Hex dump with byte offsets');q.add_argument('input');q.add_argument('--offset',type=integer,default=0);q.add_argument('--length',type=integer,default=128)
    q=sub.add_parser('strings',help='Read printable ASCII or UTF-16LE strings with offsets in this input');q.add_argument('input');q.add_argument('--encoding',choices=['ascii','utf16le'],default='ascii');q.add_argument('-n','--minimum',type=int,default=4)
    q=sub.add_parser('decode64',help='Strict Base64 decode to UTF-8');q.add_argument('text')
    q=sub.add_parser('png',help='List PNG chunks and independently check CRC');q.add_argument('input')
    q=sub.add_parser('patch-png-header',help='Restore only the eight PNG signature bytes to a new file');q.add_argument('input');q.add_argument('output')
    q=sub.add_parser('savebin',help='Save native stdout as bytes (safe for PowerShell 5.1)');q.add_argument('output');q.add_argument('command',nargs=argparse.REMAINDER)
    q=sub.add_parser('tryzip',help='Try only the supplied small wordlist against a course ZIP, checking file CRC');q.add_argument('input');q.add_argument('wordlist');q.add_argument('--limit',type=int,default=1000)
    a=p.parse_args()
    if a.action=='decode64':
        print(base64.b64decode(a.text,validate=True).decode('utf-8'));return
    if a.action=='savebin':
        command=a.command[1:] if a.command[:1]==['--'] else a.command
        if not command:p.error('Provide a native program and arguments after --')
        output=Path(a.output); output.parent.mkdir(parents=True,exist_ok=True)
        with output.open('wb') as stream:
            result=subprocess.run(command,stdout=stream)
        if result.returncode: raise SystemExit(result.returncode)
        print(f'Saved {output.stat().st_size} bytes to {output}');return
    if a.action=='tryzip':
        import zipfile
        words=Path(a.wordlist).read_text(encoding='utf-8-sig').splitlines()
        if len(words)>a.limit:p.error('Wordlist exceeds the explicit training limit')
        with zipfile.ZipFile(a.input) as archive:
            entries=[entry for entry in archive.infolist() if not entry.is_dir()]
            if not entries:p.error('No regular files')
            for n,word in enumerate(words,1):
                try:
                    contents=[archive.read(entry,pwd=word.encode('utf-8')) for entry in entries]
                except (RuntimeError,zipfile.BadZipFile,zlib.error):continue
                print(f'Password: {word} (candidate {n}/{len(words)}, all entries passed CRC)')
                for entry,content in zip(entries,contents):
                    print(entry.filename,repr(content[:256]))
                return
        raise SystemExit('No candidate succeeded; no data was decrypted successfully')
    src=Path(a.input);data=src.read_bytes()
    if a.action=='type':
        kinds=[kind for signature,kind in SIGNATURES if data.startswith(signature)]
        print(f'{src.name}: {", ".join(kinds) or "unrecognized signature"}; {len(data)} bytes')
        if data.startswith(b'\x89PNG') and len(data)>=24:
            print('IHDR dimensions:',*struct.unpack_from('>II',data,16))
        if len(data)>512 and data[510:512]==b'\x55\xaa':print('0x55AA at byte 510: inspect MBR/boot-sector structure; not proof by itself')
    elif a.action=='scan':
        found=[]
        for signature,kind in SIGNATURES:
            offset=0
            while (offset:=data.find(signature,offset))>=0:
                found.append((offset,kind));offset+=1
        for offset,kind in sorted(found):print(f'{offset:10d}  0x{offset:08x}  {kind}')
    elif a.action=='hex':
        if a.offset<0 or a.length<0:p.error('Offset and length must be nonnegative')
        for offset in range(a.offset,min(len(data),a.offset+a.length),16):
            line=data[offset: min(offset+16,a.offset+a.length)]
            print(f'{offset:08x}  '+line.hex(' ').ljust(47)+'  '+''.join(chr(c) if 32<=c<127 else '.' for c in line))
    elif a.action=='strings':
        if a.minimum<1:p.error('Minimum length must be positive')
        pattern=rb'[\x20-\x7e]{%d,}'%a.minimum if a.encoding=='ascii' else rb'(?:[\x20-\x7e]\x00){%d,}'%a.minimum
        for hit in re.finditer(pattern,data):
            print(f'0x{hit.start():08x}  '+hit.group().decode('ascii' if a.encoding=='ascii' else 'utf-16le'))
    elif a.action=='png':
        if not data.startswith(b'\x89PNG\r\n\x1a\n'):p.error('Invalid PNG signature')
        offset=8;bad=False
        while offset+12<=len(data):
            length=struct.unpack_from('>I',data,offset)[0];kind=data[offset+4:offset+8];end=offset+12+length
            if end>len(data):p.error(f'Truncated chunk at 0x{offset:x}')
            expected=struct.unpack_from('>I',data,offset+8+length)[0];actual=zlib.crc32(data[offset+4:offset+8+length])&0xffffffff
            good=expected==actual;bad|=not good
            print(f'0x{offset:08x} {kind.decode("ascii",errors="replace")} len={length} CRC={expected:08x} calculated={actual:08x} {"OK" if good else "BAD"}')
            if kind==b'tEXt': print('  '+repr(data[offset+8:offset+8+length]))
            offset=end
            if kind==b'IEND':
                if offset<len(data):print(f'Trailing bytes: {len(data)-offset}')
                break
        else:p.error('IEND not found')
        if bad:raise SystemExit(2)
    elif a.action=='patch-png-header':
        dst=Path(a.output)
        if src.resolve()==dst.resolve():p.error('Use a different output path')
        if len(data)<33 or data[8:16]!=b'\x00\x00\x00\rIHDR':p.error('Expected the course fixture with intact IHDR structure')
        dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(b'\x89PNG\r\n\x1a\n'+data[8:]);print('Only bytes 0..7 restored; verify every chunk and image data next')

if __name__=='__main__':
    try:main()
    except (OSError,ValueError) as exc:raise SystemExit(str(exc))
