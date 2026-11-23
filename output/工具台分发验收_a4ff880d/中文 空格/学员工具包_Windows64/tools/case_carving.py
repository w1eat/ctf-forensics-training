"""Bounded structural carving for ordinary CTF carriers, with provenance."""
from pathlib import Path
import bz2,csv,hashlib,io,json,lzma,mmap,struct,zipfile,zlib
MIB=1024**2
SIGNATURES=[('png',b'\x89PNG\r\n\x1a\n'),('jpg',b'\xff\xd8\xff'),('zip',b'PK\x03\x04'),
            ('gif',b'GIF87a'),('gif',b'GIF89a'),('pdf',b'%PDF-'),('gz',b'\x1f\x8b\x08'),
            ('bz2',b'BZh'),('xz',b'\xfd7zXZ\x00'),('7z',b'7z\xbc\xaf\x27\x1c'),
            ('riff',b'RIFF'),('sqlite',b'SQLite format 3\x00')]

def png_end(b,start,ceiling):
    pos=start+8;chunks=0;bad_crc=0;first=True
    while pos+12<=ceiling and chunks<100000:
        length=int.from_bytes(b[pos:pos+4],'big');kind=b[pos+4:pos+8];end=pos+12+length
        if end>ceiling or length>64*MIB:raise ValueError('PNG 块越界')
        if first and (kind!=b'IHDR' or length!=13):raise ValueError('缺少有效 IHDR')
        first=False;bad_crc+=zlib.crc32(b[pos+4:end-4])&0xffffffff!=int.from_bytes(b[end-4:end],'big')
        chunks+=1;pos=end
        if kind==b'IEND':
            if length:raise ValueError('IEND 长度不为零')
            return pos,'块边界到 IEND；CRC '+('全部一致' if not bad_crc else f'{bad_crc} 块不符，需修复复核')
    raise ValueError('未找到完整 IEND')

def jpeg_end(b,start,ceiling):
    pos=start+2;scan=False;segments=0
    while pos<ceiling and segments<200000:
        if scan:
            pos=b.find(b'\xff',pos,ceiling)
            if pos<0:break
        if b[pos]!=255:raise ValueError('JPEG 标记异常')
        while pos<ceiling and b[pos]==255:pos+=1
        if pos>=ceiling:break
        marker=b[pos];pos+=1;segments+=1
        if scan and marker==0:continue
        if marker==217:return pos,'JPEG 标记解析到 EOI'
        if marker in range(208,216) or marker==1:continue
        if marker in (0,216):raise ValueError('JPEG 标记冲突')
        if pos+2>ceiling:break
        length=int.from_bytes(b[pos:pos+2],'big')
        if length<2 or pos+length>ceiling:raise ValueError('JPEG 段越界')
        pos+=length
        if marker==218:scan=True
    raise ValueError('未找到有效 EOI')

def gif_end(b,start,ceiling):
    if start+13>ceiling:raise ValueError('GIF 头缺失')
    pos=start+13;packed=b[start+10]
    if packed&128:pos+=3*(2**((packed&7)+1))
    def subblocks(pos):
        while pos<ceiling:
            n=b[pos];pos+=1
            if n==0:return pos
            pos+=n
            if pos>ceiling:break
        raise ValueError('GIF 子块越界')
    while pos<ceiling:
        tag=b[pos];pos+=1
        if tag==59:return pos,'GIF 块解析到 trailer'
        if tag==33:pos=subblocks(pos+1)
        elif tag==44:
            if pos+9>ceiling:break
            packed=b[pos+8];pos+=9
            if packed&128:pos+=3*(2**((packed&7)+1))
            pos=subblocks(pos+1)
        else:raise ValueError('GIF 块类型异常')
    raise ValueError('未找到完整 GIF trailer')

def compressed_end(b,start,ceiling,kind,max_expanded=64*MIB):
    dec=zlib.decompressobj(31) if kind=='gz' else bz2.BZ2Decompressor() if kind=='bz2' else lzma.LZMADecompressor(memlimit=64*MIB)
    pos=start;expanded=0
    while pos<ceiling:
        chunk=b[pos:min(pos+65536,ceiling)];pos+=len(chunk)
        value=dec.decompress(chunk,max_expanded-expanded+1);expanded+=len(value)
        if expanded>max_expanded:raise ValueError('解压验证达到 64 MiB 上限')
        if dec.eof:return pos-len(dec.unused_data),f'{kind} 流结束；已验证展开 {expanded} 字节'
    raise ValueError('压缩流不完整')

def boundary(b,start,kind,cap):
    end=min(len(b),start+cap)
    if kind=='png':return png_end(b,start,end)
    if kind=='jpg':return jpeg_end(b,start,end)
    if kind=='gif':return gif_end(b,start,end)
    if kind in ('gz','bz2','xz'):return compressed_end(b,start,end,kind)
    if kind=='zip':
        pos=start
        for _ in range(10000):
            pos=b.find(b'PK\x05\x06',pos+1,end)
            if pos<0:break
            if pos+22>end:break
            disk,cd_disk,n_disk,n_total,cd_size,cd_offset,comment=struct.unpack_from('<HHHHIIH',b,pos+4)
            tail=pos+22+comment
            if disk or cd_disk or n_disk!=n_total or tail>end:continue
            if 0xffffffff in (cd_size,cd_offset):continue
            base=pos-cd_size-cd_offset
            if base!=start or b[pos-cd_size:pos-cd_size+4]!=b'PK\x01\x02':continue
            with zipfile.ZipFile(io.BytesIO(b[start:tail])) as z:
                infos=z.infolist()
                if len(infos)>4096:raise ValueError('ZIP 条目超过验证上限')
                if sum(v.file_size for v in infos)<=32*MIB and all(not v.flag_bits&1 for v in infos):
                    bad=z.testzip()
                    if bad:raise ValueError('ZIP CRC 校验失败')
                    note='EOCD / 中央目录 / 各条目 CRC 通过'
                else:note='EOCD / 中央目录通过；加密或较大条目未验证内容 CRC'
                return tail,note
        raise ValueError('未找到匹配的完整 ZIP 中央目录；ZIP64 交给 PhotoRec / 7-Zip')
    if kind=='7z':
        if start+32>end:raise ValueError('7z 起始头缺失')
        crc=int.from_bytes(b[start+8:start+12],'little')
        if zlib.crc32(b[start+12:start+32])&0xffffffff!=crc:raise ValueError('7z 起始头 CRC 不符')
        offset,size=struct.unpack_from('<QQ',b,start+12);tail=start+32+offset+size
        if tail>end:raise ValueError('7z next header 越界')
        if zlib.crc32(b[start+32+offset:tail])&0xffffffff!=int.from_bytes(b[start+28:start+32],'little'):raise ValueError('7z next header CRC 不符')
        return tail,'7z 起始头与 next header CRC 通过'
    if kind=='riff':
        tail=start+8+int.from_bytes(b[start+4:start+8],'little')
        if tail<=start+12 or tail>end or b[start+8:start+12] not in (b'WAVE',b'AVI ',b'WEBP'):raise ValueError('RIFF 类型或长度不符')
        return tail,'RIFF 长度字段与类型匹配'
    if kind=='sqlite':
        page=int.from_bytes(b[start+16:start+18],'big');page=65536 if page==1 else page
        count=int.from_bytes(b[start+28:start+32],'big');tail=start+page*count
        if page<512 or page>65536 or page&(page-1) or count<1 or tail>end:raise ValueError('SQLite 页大小 / 页数越界')
        return tail,'SQLite 头部页大小与数据库页数；未包含 WAL'
    if kind=='pdf':
        pos=b.find(b'%%EOF',start+5,end)
        if pos<0:raise ValueError('PDF 缺少 EOF')
        tail=pos+5
        while tail<end and b[tail:tail+1] in (b'\r',b'\n'):tail+=1
        from pypdf import PdfReader
        reader=PdfReader(io.BytesIO(b[start:tail]));len(reader.pages)
        return tail,'PDF 首个可解析 EOF；增量更新版本需另行核对'
    raise ValueError('无边界解析器')

def separate(path,out,scan_mib=0,max_files=64,budget_mib=128,depth=1):
    out.mkdir(parents=True,exist_ok=True);queue=[(Path(path),0,None)];rows=[];seen=set();used=0;warnings=[];candidates=0
    while queue and len(rows)<max_files:
        source,level,parent=queue.pop(0)
        if not source.stat().st_size:continue
        with source.open('rb') as stream,mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as blob:
            scanned=min(len(blob),scan_mib*MIB) if scan_mib else len(blob);matches=[]
            for kind,sig in SIGNATURES:
                pos=-1
                for _ in range(2048):
                    pos=blob.find(sig,pos+1,scanned)
                    if pos<0:break
                    matches.append((pos,kind))
            for start,kind in sorted(set(matches)):
                candidates+=1
                if len(rows)>=max_files:break
                try:
                    end,note=boundary(blob,start,kind,64*MIB)
                    if end>scanned:raise ValueError('完整对象超出本次扫描范围')
                    if end-start>budget_mib*MIB-used:raise ValueError('达到总导出预算')
                    value=blob[start:end];sha=hashlib.sha256(value).hexdigest()
                    if sha in seen or (level and start==0 and end==len(blob)):continue
                    seen.add(sha);used+=len(value)
                    ext='wav' if kind=='riff' and value[8:12]==b'WAVE' else 'webp' if kind=='riff' and value[8:12]==b'WEBP' else 'avi' if kind=='riff' else kind
                    name=f'{len(rows)+1:04}_{start:012x}.{ext}';dest=out/name;dest.write_bytes(value)
                    rows.append(dict(file=name,source=str(source),parent=parent,offset=start,offset_hex=hex(start),length=end-start,format=ext,sha256=sha,validation=note,depth=level))
                    if level<depth:queue.append((dest,level+1,name))
                except Exception as exc:
                    if len(warnings)<100:warnings.append(dict(offset=hex(start),format=kind,reason=str(exc)[:240]))
    with (out/'分离清单.csv').open('w',encoding='utf-8-sig',newline='') as f:
        keys=['file','source','parent','offset','offset_hex','length','format','sha256','validation','depth'];writer=csv.DictWriter(f,fieldnames=keys);writer.writeheader();writer.writerows(rows)
    return dict(kind='casework',operation='separate',title='自动文件分离',columns=['导出文件','源字节偏移','字节数','格式','边界验证'],rows=[[r['file'],r['offset_hex'],r['length'],r['format'],r['validation']] for r in rows],exports=rows,candidates=candidates,exported_bytes=used,warnings=warnings,scan_mib=scan_mib,total_input_bytes=Path(path).stat().st_size,note='偏移属于该行 source 文件；签名命中不等于完整文件。已记录边界与验证方式，不能恢复所有碎片文件。')
