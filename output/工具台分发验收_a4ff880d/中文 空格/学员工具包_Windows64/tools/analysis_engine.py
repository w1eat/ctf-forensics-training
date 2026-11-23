"""Offline, file-oriented forensics helpers. Inputs are never executed or modified.

Uses bundled Pillow, pypdf, pefile and yara-python where applicable. The auto
pipeline records coverage and individual failures rather than guessing a flag.
"""
from __future__ import annotations
import argparse, base64, collections, csv, datetime as dt, hashlib, html, io, json
import math, os, re, shutil, sqlite3, stat, struct, subprocess, sys, tempfile, time, zlib, zipfile
from pathlib import Path, PurePosixPath
sys.path.insert(0,str(Path(__file__).resolve().parent))
from forensic_workflows import Workflows,WORKFLOW_CATALOG,DEFAULT_KEYWORDS,detect_disk,targeted_scan,keywords

MIB=1024**2
SIGNATURES=[('PNG',b'\x89PNG\r\n\x1a\n'),('JPEG',b'\xff\xd8\xff'),('GIF87a',b'GIF87a'),('GIF89a',b'GIF89a'),
 ('ZIP local',b'PK\x03\x04'),('ZIP central',b'PK\x01\x02'),('ZIP end',b'PK\x05\x06'),('7z',b'7z\xbc\xaf\x27\x1c'),
 ('RAR4',b'Rar!\x1a\x07\x00'),('RAR5',b'Rar!\x1a\x07\x01\x00'),('GZIP',b'\x1f\x8b\x08'),
 ('PDF',b'%PDF-'),('SQLite',b'SQLite format 3\x00'),('ELF',b'\x7fELF'),('BMP',b'BM')]
BUILTIN_RULES=r'''rule Training_Flag_Candidate {
 meta: description = "CTF-style token candidate; manually validate context"
 strings: $a = /[fF][lL][aA][gG]\{[ -~]{1,180}\}/ ascii wide
 condition: $a
}
rule Training_Embedded_ZIP {
 strings: $zip = { 50 4B 03 04 }
 condition: $zip and uint32(0) != 0x04034b50
}
rule Training_PowerShell_Text {
 strings: $a = "powershell" ascii wide nocase
          $b = "-EncodedCommand" ascii wide nocase
 condition: all of them
}
'''

def emit(value):print(json.dumps(value,ensure_ascii=False,default=str),flush=True)
def save_json(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
def safe_text(value,limit=4096):return str(value)[:limit]
def bounded_file(path,limit=64*MIB):
    if path.stat().st_size>limit:raise ValueError(f'此格式解析限 {limit//MIB} MiB；可先运行基础流式分析。')
def table(columns,rows,**extra):return dict(columns=columns,rows=rows,**extra)

def identify(path):
    with path.open('rb') as f:head=f.read(8192)
    kind='unknown';label='未知二进制';evidence='未匹配内置文件头；请结合签名、字符串和题意判断。'
    for name,sig in SIGNATURES:
        if head.startswith(sig):kind={'PNG':'png','JPEG':'jpeg','GIF87a':'gif','GIF89a':'gif','SQLite':'sqlite','PDF':'pdf','BMP':'bmp','ELF':'elf','7z':'archive','RAR4':'archive','RAR5':'archive','GZIP':'archive'}.get(name,'zip' if name.startswith('ZIP') else 'unknown');label=name;evidence='文件头 '+sig.hex(' ');break
    if head.startswith((b'II\x2a\0',b'MM\0\x2a')):kind='tiff';label='TIFF';evidence='TIFF 字节序与版本标记'
    if head.startswith(b'RIFF') and head[8:12]==b'WEBP':kind='webp';label='WebP';evidence='RIFF + WEBP'
    if head.startswith(b'MZ'):
        kind='dos';label='DOS / PE 候选';evidence='MZ；尚需检查 PE 结构'
        if len(head)>=64:
            offset=struct.unpack_from('<I',head,60)[0]
            if offset<path.stat().st_size-4:
                with path.open('rb') as f:f.seek(offset);sig=f.read(4)
                if sig==b'PE\0\0':kind='pe';label='Windows PE';evidence=f'MZ + PE 签名 @ 0x{offset:x}'
    if len(head)>262 and head[257:262]==b'ustar':kind='archive';label='TAR';evidence='ustar @ 257'
    disk=detect_disk(head,path.stat().st_size) if kind=='unknown' else None
    if disk:kind='disk';label=disk;evidence='结构标记候选；继续由 TSK fsstat 验证，不使用练习固定扇区。'
    if kind=='zip' and path.stat().st_size<=16*MIB:
        try:
            with zipfile.ZipFile(path) as z:names=z.namelist()[:2048]
            if '[Content_Types].xml' in names and any(n.startswith(('word/','xl/','ppt/')) for n in names):kind='office';label='Office Open XML';evidence='ZIP + [Content_Types].xml + Office 内容目录'
        except (OSError,ValueError,zipfile.BadZipFile):pass
    if kind=='unknown' and head:
        for encoding in ('utf-8-sig','utf-16' if head.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8'):
            try:
                text=head.decode(encoding);printable=sum(c.isprintable() or c in '\r\n\t' for c in text)/max(1,len(text))
                if printable>.94:
                    kind='text';label='文本';evidence=encoding+' 抽样可读率 '+str(round(printable*100,1))+'%'
                    if text.lstrip().startswith(('{','[')):label='JSON / JSONL 候选'
                    break
            except UnicodeError:pass
    if path.stat().st_size==0:kind='empty';label='空文件';evidence='0 bytes'
    if kind=='unknown' and path.suffix.lower() in ('.raw','.mem','.vmem','.dmp'):
        evidence+=' 扩展名提示可能是内存或镜像，需用 Vol3 / TSK 验证，不能只凭后缀认定。'
    return dict(kind=kind,label=label,evidence=evidence,extension=path.suffix.lower(),bytes=path.stat().st_size,
                header=head[:64].hex(' '))

def fingerprint(path):
    hashes={n:hashlib.new(n) for n in ('md5','sha1','sha256')};counts=[0]*256;windows=[];total=0
    with path.open('rb') as f:
        while block:=f.read(MIB):
            for value in hashes.values():value.update(block)
            count=collections.Counter(block)
            for byte,n in count.items():counts[byte]+=n
            entropy=-sum((n/len(block))*math.log2(n/len(block)) for n in count.values())
            if len(windows)<4096:windows.append(dict(offset=total,bytes=len(block),entropy=round(entropy,5)))
            total+=len(block)
    entropy=-sum((n/total)*math.log2(n/total) for n in counts if n) if total else 0
    return dict(kind='hash',name=path.name,bytes=total,**{k:v.hexdigest() for k,v in hashes.items()},
                entropy=round(entropy,5),entropy_windows=windows,
                note='MD5 / SHA1 仅用于已知摘要对照；证据一致性优先记录 SHA256。熵高不等于一定加密。')

def scan(path,limit=64*MIB,minimum=4,encoding='both',keyword='',max_rows=2000):
    """Streaming scans, with overlap for signatures and bounded string previews."""
    limit=min(path.stat().st_size,limit or path.stat().st_size)
    patterns=[]
    if encoding in ('both','ascii'):patterns.append(('ASCII',re.compile(rb'[\x20-\x7e]{'+str(minimum).encode()+rb',}')))
    if encoding in ('both','utf16le'):patterns.append(('UTF-16LE',re.compile(rb'(?:[\x20-\x7e]\x00){'+str(minimum).encode()+rb',}')))
    strings=[];signatures=[];seen_strings=set();seen_signatures=set();pos=0;tail=b'';string_more=False;signature_more=False
    with path.open('rb') as f:
        while pos<limit:
            block=f.read(min(MIB,limit-pos))
            if not block:break
            data=tail+block;base=pos-len(tail)
            for label,sig in SIGNATURES:
                at=data.find(sig)
                while at>=0:
                    offset=base+at;key=(label,offset)
                    if key not in seen_signatures:
                        seen_signatures.add(key)
                        if len(signatures)<2000:signatures.append([hex(offset),label,'候选；需验证结构和边界'])
                        else:signature_more=True
                    at=data.find(sig,at+1)
                    if len(seen_signatures)>10000:break
            if len(strings)<max_rows:
                for label,pattern in patterns:
                    for m in pattern.finditer(data):
                        offset=base+m.start();key=(label,offset)
                        # Defer a run touching the chunk end to the next overlap.
                        if m.end()==len(data) and pos+len(block)<limit and len(m[0])<512:continue
                        if key in seen_strings:continue
                        seen_strings.add(key);text=m[0][:1024].decode('ascii' if label=='ASCII' else 'utf-16le','replace')
                        if keyword and keyword.casefold() not in text.casefold():continue
                        strings.append([hex(offset),label,text, len(m[0])])
                        if len(strings)>=max_rows:string_more=True;break
                    if len(strings)>=max_rows:break
            pos+=len(block);tail=data[-512:]
    return dict(kind='scan',strings=table(['字节偏移','编码','可读内容（最多 1024 字节）','匹配字节数'],strings),
                signatures=table(['字节偏移','签名','含义'],sorted(signatures,key=lambda r:int(r[0],16))),
                scanned_bytes=pos,total_bytes=path.stat().st_size,partial=pos<path.stat().st_size,
                string_rows_limited=string_more,signature_rows_limited=signature_more,
                note='仅提取 ASCII 可打印字符及其 UTF-16LE 表示；不覆盖所有语言。跨块长串可能分段显示。')

def pngmap(path):
    rows=[];chunks=[];iend=False;trailing=0;error='';size=path.stat().st_size
    with path.open('rb') as f:
        if f.read(8)!=b'\x89PNG\r\n\x1a\n':raise ValueError('不是 PNG 文件头。')
        while f.tell()<size and len(chunks)<4096:
            offset=f.tell();head=f.read(8)
            if len(head)!=8:error='块头截断';break
            length=struct.unpack('>I',head[:4])[0];name=head[4:].decode('ascii','replace')
            if length>size-f.tell()-4:error=f'{name} 声明长度越过 EOF';break
            crc=zlib.crc32(head[4:]);remaining=length
            while remaining:
                part=f.read(min(MIB,remaining));crc=zlib.crc32(part,crc);remaining-=len(part)
            saved=struct.unpack('>I',f.read(4))[0];valid=saved==(crc&0xffffffff)
            chunks.append(dict(offset=offset,type=name,length=length,valid=valid))
            rows.append([hex(offset),name,length,f'{saved:08x}',f'{crc&0xffffffff:08x}','OK' if valid else 'BAD'])
            if name=='IEND':iend=True;trailing=size-f.tell();break
    return table(['偏移','块','数据长度','保存 CRC','计算 CRC','校验'],rows,kind='pngmap',chunks=chunks,iend=iend,trailing=trailing,error=error,
                 limited=len(chunks)>=4096)

def image_info(path,out):
    from PIL import Image
    with Image.open(path) as image:
        result=dict(format=image.format,mode=image.mode,width=image.width,height=image.height,frames=getattr(image,'n_frames',1))
        if image.width*image.height>20_000_000:result['preview']='超过 2000 万像素，跳过解码预览';return result
        image.seek(0);image.thumbnail((900,600));image.convert('RGB').save(out/'preview.jpg')
        result['preview']='preview.jpg';return result

def image_bits(path,out,channels='r',bit=0,order='xy',byte_order='msb',max_bytes=1048576,planes=False):
    from PIL import Image
    bounded_file(path)
    with Image.open(path) as image:
        if image.width*image.height>20_000_000:raise ValueError('位平面分析限 2000 万像素。')
        if channels not in ('r','g','b','a','rgb','bgr','rgba'):raise ValueError('通道选项无效。')
        if not 0<=bit<=7 or order not in ('xy','yx') or byte_order not in ('msb','lsb'):raise ValueError('位序参数无效。')
        image=image.convert('RGBA');pixels=image.load();out.mkdir(parents=True,exist_ok=True)
        if planes:
            # Limit rendering work, not just file byte size.
            if image.width*image.height>4_000_000:raise ValueError('导出位平面限 400 万像素。')
            for channel in channels:
                index='rgba'.index(channel)
                plane=image.getchannel(channel.upper()).point(lambda v:255 if (v>>bit)&1 else 0)
                plane.save(out/(channel+f'_bit{bit}.png'))
            return dict(channels=channels,bit=bit,width=image.width,height=image.height)
        indices=['rgba'.index(c) for c in channels];data=bytearray();value=0;count=0
        positions=((x,y) for y in range(image.height) for x in range(image.width)) if order=='xy' else ((x,y) for x in range(image.width) for y in range(image.height))
        stop=False
        for x,y in positions:
            for index in indices:
                b=(pixels[x,y][index]>>bit)&1
                value=(value<<1)|b if byte_order=='msb' else value|(b<<count)
                count+=1
                if count==8:
                    data.append(value);value=0;count=0
                    if len(data)>=max_bytes:stop=True;break
            if stop:break
        (out/'lsb.bin').write_bytes(data)
        return dict(channels=channels,bit=bit,order=order,byte_order=byte_order,bytes=len(data),limited=stop,
                    trailing_bits=count,preview=bytes(data[:2048]).decode('utf-8','replace'),note='未遇 NUL 自动停止；提取长度和编码由题目条件决定。')

def sqlite_read(path,query=None,table_name=None,limit=200,scratch=None):
    # SQLite may create/update SHM even for a read-only WAL connection. Work on
    # private copies when companions exist, preserving the uploaded evidence.
    if Path(str(path)+'-wal').is_file():
        with tempfile.TemporaryDirectory(prefix='_sqlite_',dir=scratch) as temporary:
            copy=Path(temporary)/'evidence.db';companions=[]
            for suffix in ('','-wal','-shm'):
                source=Path(str(path)+suffix)
                if source.is_file():
                    shutil.copyfile(source,Path(str(copy)+suffix))
                    if suffix:
                        with source.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
                        companions.append(dict(name=source.name,bytes=source.stat().st_size,sha256=digest))
            result=_sqlite_read(copy,query,table_name,limit);result['companions']=companions
            result['wal_note']='已在临时副本上合并读取同名 WAL / SHM，未改动原始附件。'
            return result
    return _sqlite_read(path,query,table_name,limit)

def _sqlite_read(path,query=None,table_name=None,limit=200):
    db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=2)
    try:
        db.execute('PRAGMA query_only=ON');db.execute('PRAGMA trusted_schema=OFF')
        if hasattr(db,'setlimit'):db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,2*MIB)
        deadline=time.monotonic()+8
        db.set_progress_handler(lambda:int(time.monotonic()>deadline),10000)
        denied={getattr(sqlite3,n) for n in ('SQLITE_INSERT','SQLITE_UPDATE','SQLITE_DELETE','SQLITE_CREATE_INDEX','SQLITE_CREATE_TABLE','SQLITE_CREATE_TEMP_INDEX','SQLITE_CREATE_TEMP_TABLE','SQLITE_CREATE_TEMP_TRIGGER','SQLITE_CREATE_TEMP_VIEW','SQLITE_CREATE_TRIGGER','SQLITE_CREATE_VIEW','SQLITE_DROP_INDEX','SQLITE_DROP_TABLE','SQLITE_DROP_TEMP_INDEX','SQLITE_DROP_TEMP_TABLE','SQLITE_DROP_TEMP_TRIGGER','SQLITE_DROP_TEMP_VIEW','SQLITE_DROP_TRIGGER','SQLITE_DROP_VIEW','SQLITE_ALTER_TABLE','SQLITE_ATTACH','SQLITE_DETACH','SQLITE_PRAGMA','SQLITE_TRANSACTION','SQLITE_SAVEPOINT','SQLITE_REINDEX','SQLITE_ANALYZE')}
        def authorize(code,a,b,c,d):
            if code in denied:return sqlite3.SQLITE_DENY
            if code==sqlite3.SQLITE_FUNCTION and (b or a or '').lower() in ('load_extension','readfile','writefile','edit','fts3_tokenizer'):return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        db.set_authorizer(authorize)
        schema=[list(row) for row in db.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name LIMIT 500")]
        if query is None and table_name is None:return table(['类型','名称','所属表','SQL'],schema,kind='sqlite_schema')
        if table_name is not None:
            names=[r[1] for r in schema if r[0]=='table']
            if table_name not in names:raise ValueError('表名不在当前数据库结构中；先查看表结构。')
            query='SELECT * FROM "'+table_name.replace('"','""')+'"'
        if len(query or '')>16384 or not re.match(r'^\s*(SELECT\b|WITH\b|EXPLAIN\s+QUERY\s+PLAN\s+SELECT\b)',query or '',re.I):raise ValueError('只接受单条 SELECT / WITH 查询。')
        cursor=db.execute(query);columns=[r[0] for r in cursor.description or []];raw=cursor.fetchmany(limit+1)
        def cell(value):
            if isinstance(value,bytes):return f'[BLOB {len(value)} bytes] '+value[:128].hex()
            return value if not isinstance(value,str) else value[:16384]
        return table(columns,[[cell(v) for v in row] for row in raw[:limit]],kind='sqlite_query',limited=len(raw)>limit,query=query,limit=limit,
                     note='只读连接；需完整提取时在副本上使用 SQLite CLI。若存在 WAL，需将匹配的 -wal / -shm 与数据库一起放在同一目录。')
    finally:db.close()

def text_preview(path,encoding='utf-8-sig',limit=200):
    with path.open('rb') as f:raw=f.read(4*MIB+1)
    text=raw[:4*MIB].decode(encoding,'replace');lines=text.splitlines();suffix=path.suffix.lower();rows=[];errors=[]
    if suffix=='.json':
        try:
            obj=json.loads(text);values=obj if isinstance(obj,list) else [obj]
            return table(['序号','JSON 值'],[[i+1,json.dumps(v,ensure_ascii=False)[:8192]] for i,v in enumerate(values[:limit])],kind='text',limited=len(values)>limit or len(raw)>4*MIB,encoding=encoding)
        except ValueError as exc:errors.append(str(exc))
    if suffix=='.jsonl' or (lines and all(line.lstrip().startswith('{') for line in lines[:3] if line.strip())):
        for number,line in enumerate(lines[:limit],1):
            try:rows.append([number,json.dumps(json.loads(line),ensure_ascii=False)[:8192]])
            except ValueError as exc:rows.append([number,line[:8192]]);errors.append(f'第 {number} 行：{exc}')
        return table(['行号','JSON / 原始内容'],rows,kind='text',errors=errors,limited=len(lines)>limit or len(raw)>4*MIB,encoding=encoding)
    if suffix in ('.csv','.tsv'):
        reader=csv.reader(io.StringIO(text),delimiter='\t' if suffix=='.tsv' else ',')
        headers=next(reader,[]);headers=[s[:256] for s in headers[:100]]
        for i,row in enumerate(reader):
            if i>=limit:break
            rows.append([s[:8192] for s in row[:100]])
        return table(headers,rows,kind='text',limited=len(lines)>limit+1 or len(raw)>4*MIB,encoding=encoding)
    return table(['行号','文本'],[[i+1,line[:8192]] for i,line in enumerate(lines[:limit])],kind='text',limited=len(lines)>limit or len(raw)>4*MIB,errors=errors,encoding=encoding)

def pdf_read(path,out,password=''):
    from pypdf import PdfReader
    bounded_file(path);reader=PdfReader(str(path),strict=False);encrypted=reader.is_encrypted
    if encrypted and not reader.decrypt(password):return dict(encrypted=True,error='PDF 已加密；需要正确口令后提取。')
    metadata={str(k):safe_text(v) for k,v in (reader.metadata or {}).items()};pages=min(100,len(reader.pages));texts=[];total=0
    for i in range(pages):
        page=reader.pages[i]
        # Avoid expanding very large declared streams during automatic extraction.
        content=page.get('/Contents');refs=content if isinstance(content,list) else [content] if content else []
        if sum(int(ref.get_object().get('/Length',0)) for ref in refs)>8*MIB:
            texts.append(f'\n--- PAGE {i+1}: 内容流较大，跳过 ---\n');continue
        text=(page.extract_text() or '')[:200000];texts.append(f'\n--- PAGE {i+1} ---\n'+text);total+=len(text)
        if total>2*MIB:break
    (out/'pdf_text.txt').write_text('\n'.join(texts),encoding='utf-8')
    # List attachment names only; explicit extraction is a separate operation.
    attachments=list(reader.attachments)[:200]
    return dict(kind='pdf',encrypted=encrypted,pages=len(reader.pages),extracted_pages=len(texts),metadata=metadata,
                attachments=attachments,preview='\n'.join(texts)[:16000],note='最多 100 页 / 约 2 MiB 文本；扫描图片型 PDF 需要 OCR，本工具不把无文本解释为无内容。')

def pe_read(path):
    import pefile
    bounded_file(path);pe=pefile.PE(str(path),fast_load=True)
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        imports=[]
        for entry in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])[:200]:
            imports.append([entry.dll.decode('ascii','replace'),', '.join((s.name or ('#'+str(s.ordinal)).encode()).decode('ascii','replace') for s in entry.imports[:100])])
        sections=[[s.Name.rstrip(b'\0').decode('ascii','replace'),hex(s.PointerToRawData),s.SizeOfRawData,hex(s.VirtualAddress),round(s.get_entropy(),4)] for s in pe.sections]
        overlay=pe.get_overlay_data_start_offset()
        return dict(kind='pe',machine=hex(pe.FILE_HEADER.Machine),timestamp=pe.FILE_HEADER.TimeDateStamp,entry_point=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),image_base=hex(pe.OPTIONAL_HEADER.ImageBase),
                    sections=table(['节','原始偏移','原始大小','RVA','熵'],sections),imports=table(['DLL','导入函数（截取）'],imports),overlay_offset=hex(overlay) if overlay is not None else None,
                    note='静态解析，未运行样本；时间戳、节名和导入信息均可能被修改。')
    finally:pe.close()

def yara_read(path,source=''):
    import yara
    bounded_file(path,256*MIB)
    if len(source)>65536:raise ValueError('YARA 规则限 64 KiB。')
    yara.set_config(max_match_data=128)
    rules=yara.compile(source=source or BUILTIN_RULES,includes=False)
    # Python opens Unicode filenames; YARA's Windows C filepath API is ANSI.
    matches=rules.match(data=path.read_bytes(),timeout=20);rows=[]
    for match in matches[:200]:
        for string in match.strings:
            for instance in string.instances[:50]:
                rows.append([match.rule,string.identifier,hex(instance.offset),bytes(instance.matched_data).hex(),bytes(instance.matched_data).decode('utf-8','replace')])
                if len(rows)>=1000:break
            if len(rows)>=1000:break
        if len(rows)>=1000:break
    return table(['规则','字符串','字节偏移','匹配字节（截取）','文本预览'],rows,kind='yara',matched_rules=[m.rule for m in matches[:200]],
                 note='规则命中是线索，不能据此直接判定恶意或确认答案。自定义规则禁用 include。')

def native(tool,kit):
    if os.name=='nt':
        paths={'exiftool':'exiftool/exiftool.exe','7z':'7zip/7z.exe','pngcheck':'pngcheck/pngcheck.exe','mmls':'sleuthkit/bin/mmls.exe','fsstat':'sleuthkit/bin/fsstat.exe','fls':'sleuthkit/bin/fls.exe','istat':'sleuthkit/bin/istat.exe','icat':'sleuthkit/bin/icat.exe'}
        return str(kit/'tools'/paths[tool])
    found=shutil.which(tool) or (shutil.which('7zz') if tool=='7z' else None)
    if not found:raise ValueError('缺少原生工具 '+tool+'，请按 Kali 安装章节准备。')
    return found

def command_text(argv):
    if os.name=='nt':return '& '+' '.join("'"+a.replace("'","''")+"'" for a in argv)
    import shlex
    return shlex.join(argv)

def external(argv,out,name,timeout=40,argument=None,output_guard=None):
    log=out/(name+'.txt');err=out/(name+'_diagnostics.txt')
    with log.open('wb') as f,err.open('wb') as e:
        proc=subprocess.Popen(argv,stdout=f,stderr=e,stdin=subprocess.DEVNULL,shell=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        start=time.monotonic()
        try:
            while proc.poll() is None:
                if time.monotonic()-start>timeout or log.stat().st_size>8*MIB or err.stat().st_size>2*MIB:
                    proc.kill();proc.wait();raise ValueError('原生工具达到时间 / 输出限制，日志保留。')
                if output_guard is not None:
                    files=[p for p in output_guard.rglob('*') if p.is_file()]
                    if len(files)>2048 or sum(p.stat().st_size for p in files)>512*MIB:
                        proc.kill();proc.wait();raise ValueError('实际解压内容超过 2048 项 / 512 MiB，已停止并保留部分输出。')
                time.sleep(.08)
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
    raw=log.read_bytes()[:2*MIB]
    try:text=raw.decode('utf-8')
    except UnicodeError:text=raw.decode('mbcs' if os.name=='nt' else 'utf-8','replace')
    raw_err=err.read_bytes()[:65536]
    try:diagnostics=raw_err.decode('utf-8')
    except UnicodeError:diagnostics=raw_err.decode('mbcs' if os.name=='nt' else 'utf-8','replace')
    return dict(command=command_text(argv),exit_code=proc.returncode,preview=text[:20000],diagnostics=diagnostics,log=log.name,argument_file=argument)

def archive_read(path,out,kit,mode='list',password=''):
    argv=[native('7z',kit),'l','-slt','-ba','-sccUTF-8','-p'+(password or '__no_password_supplied__'),'--',str(path)]
    listing=external(argv,out,'archive_listing',30)
    # Parse complete bounded listing, not the UI preview, before extracting.
    text=(out/'archive_listing.txt').read_text(encoding='utf-8',errors='replace')
    records=[]
    for block in re.split(r'\r?\n\s*\r?\n',text):
        record=dict(line.split(' = ',1) for line in block.splitlines() if ' = ' in line)
        if 'Path' in record:records.append(record)
    rows=[[r.get('Path',''),r.get('Size',''),r.get('Packed Size',''),r.get('Encrypted',''),r.get('CRC','')] for r in records[:2000]]
    result=table(['路径','展开字节','压缩字节','加密','CRC'],rows,kind='archive',listing=listing,entries=len(records),mode=mode,exit_code=listing['exit_code'])
    if mode=='list':return result
    if listing['exit_code']!=0:raise ValueError('压缩包目录读取失败；请检查格式、口令和原始日志。')
    if mode=='test':
        result['test']=external([native('7z',kit),'t','-sccUTF-8','-p'+(password or '__no_password_supplied__'),'--',str(path)],out,'archive_test',60)
        result['exit_code']=result['test']['exit_code'];return result
    if not records or len(records)>2048:raise ValueError('无法确定条目或超过 2048 项，未解压。')
    total=0
    for r in records:
        name=r['Path'].replace('\\','/');parts=PurePosixPath(name).parts
        if name.startswith('/') or ':' in name or '..' in parts or any(ord(c)<32 for c in name):raise ValueError('压缩包含目录外路径，未解压。')
        if any(r.get(k) for k in ('Symbolic Link','Hard Link','Reparse Point')) or r.get('Mode','').startswith('l'):raise ValueError('压缩包含链接，未解压。')
        if not r.get('Size','').isdigit() and r.get('Folder')!='+':raise ValueError('展开大小未知，未解压。')
        total+=int(r.get('Size') or 0)
        if total>512*MIB:raise ValueError('展开总量超过 512 MiB，未解压。')
    dest=out/'extracted';dest.mkdir(exist_ok=True)
    result['extract']=external([native('7z',kit),'x','-y','-sccUTF-8','-p'+(password or '__no_password_supplied__'),'-o'+str(dest),'--',str(path)],out,'archive_extract',60,output_guard=dest)
    result['exit_code']=result['extract']['exit_code']
    return result

def carve(path,out,offset,length=None):
    size=path.stat().st_size
    if not 0<=offset<size:raise ValueError('起点必须在输入文件范围内。')
    length=size-offset if length is None else length
    if not 0<length<=size-offset:raise ValueError('长度必须为正且不越过 EOF。')
    with path.open('rb') as src,(out/'carved.bin').open('wb') as dst:
        src.seek(offset);remaining=length
        while remaining:
            block=src.read(min(MIB,remaining));dst.write(block);remaining-=len(block)
    return dict(offset=hex(offset),bytes=length,output='carved.bin',note='只复制选定字节，边界须由格式结构验证。')

def report_html(report):
    esc=lambda x:html.escape(str(x));sections=''
    def grid(data):
        columns=''.join('<th>'+esc(v)+'</th>' for v in data.get('columns',[]))
        rows=''.join('<tr>'+''.join('<td>'+esc(v if v is not None else '')+'</td>' for v in row)+'</tr>' for row in data.get('rows',[])[:500])
        return '<div class="table"><table><thead><tr>'+columns+'</tr></thead><tbody>'+rows+'</tbody></table></div>'
    def payload(data):
        if not isinstance(data,dict):return '<pre>'+esc(data)+'</pre>'
        body=''
        if data.get('error'):body+='<p class="error">'+esc(data['error'])+'</p>'
        if 'sha256' in data:body+='<pre>SHA256 '+esc(data['sha256'])+'\n字节数 '+esc(data.get('bytes',''))+' · 熵 '+esc(data.get('entropy',''))+'</pre>'
        if data.get('tables'):
            for item in data['tables']:body+='<h3>'+esc(item.get('title','结果'))+'</h3>'+grid(item)
        elif 'columns' in data:body+=grid(data)
        if data.get('command'):body+='<p class="label">实际命令 · '+esc(report['host'])+'</p><pre>'+esc(data['command'])+'</pre>'
        for key in ('note','explanation','skipped','diagnostics'):
            if data.get(key):body+='<p>'+esc(data[key])+'</p>'
        if data.get('scanned_bytes') is not None:body+='<p>扫描范围：'+esc(data['scanned_bytes'])+' / '+esc(data.get('total_bytes',''))+' 字节</p>'
        body+='<details><summary>原始结构与完整范围记录</summary><pre>'+esc(json.dumps(data,ensure_ascii=False,indent=2,default=str))+'</pre></details>'
        return body
    for section in report['sections']:
        status={'completed':'已执行','failed':'需复核','skipped':'已跳过'}.get(section['status'],section['status'])
        sections+='<section><h2>'+esc(section['title'])+' <small>'+esc(status)+'</small></h2>'+payload(section.get('data',{}))+'</section>'
    findings=report.get('findings',[])
    if findings:summary='<section><h2>flag 形态候选 · 请结合题干验证</h2>'+grid(dict(columns=['来源 / 对象','位置','编码','候选内容'],rows=[[r['source'],r['offset'],r['encoding'],r['value']] for r in findings]))+'</section>'
    else:summary='<p>本次未检出已支持的 flag 形态；这不等于没有隐藏内容。请继续查看格式结果与覆盖范围。</p>'
    limits=report.get('limits',{});overview='<p>流程：'+esc(report.get('selected_workflow',report['workflow']))+' · 模式：'+esc(report['profile'])+' · 子文件深度：'+esc(limits.get('child_depth',''))+' · 导出 / 分析文件：'+esc(limits.get('exported_files',''))+' / '+esc(limits.get('max_exported_files',''))+'</p>'
    style='body{font:14px/1.85 system-ui,sans-serif;max-width:1140px;margin:36px auto;padding:0 24px;color:#254a36;background:#f5f7ed}section{border:1px solid #ccdabb;background:#fffef8;margin:22px 0;padding:22px;border-radius:8px}h1{font-size:29px}h2{font-size:20px}h3{font-size:14px;margin-top:22px}small,.label{font-size:11px;font-weight:normal;color:#7a895f}.table{overflow:auto;max-height:540px}table{border-collapse:collapse;width:100%;font-size:11px}th,td{text-align:left;vertical-align:top;padding:8px 10px;border-bottom:1px solid #dce4d0;max-width:450px;overflow-wrap:anywhere}th{background:#e5edd9;position:sticky;top:0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:11px/1.85 Consolas,monospace;background:#edf2e5;padding:14px;border-radius:4px;max-height:480px;overflow:auto}details{margin-top:16px}summary{cursor:pointer;color:#66844f;font-size:12px}.error{background:#f6e4d7;padding:12px;border-radius:4px}@media(max-width:650px){body{padding:0 13px;margin:20px auto}section{padding:15px}h1{font-size:24px}}'
    return '<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>文件分析报告</title><style>'+style+'</style><h1>文件自动分析报告</h1><h2>'+esc(report.get('identification',{}).get('label',report['source']))+'</h2><p>'+esc(report['source'])+'</p><p>'+esc(report['created'])+' · '+esc(report['host'])+'</p>'+overview+summary+sections+'<section><h2>下一步与原始证据</h2><ul>'+''.join('<li>'+esc(s)+'</li>' for s in report['recommendations'])+'</ul><p>派生文件、CSV 与原始工具日志可在平台结果区另行下载。原件保持只读；命令使用上方标注的宿主系统。</p></section></html>'

def auto(path,out,kit,profile='standard',workflow='auto',options=None):
    out.mkdir(parents=True,exist_ok=True)
    report=dict(kind='analysis',source=path.name,created=dt.datetime.now().astimezone().isoformat(),host='Windows PowerShell' if os.name=='nt' else 'Kali / Linux Bash',profile=profile,workflow=workflow,sections=[],recommendations=[])
    def progress(title,state):
        brief=[{k:s[k] for k in ('id','title','status','seconds') if k in s} for s in report['sections']]
        save_json(out/'_progress.json',dict(stage=title,state=state,completed=len(brief),stages=brief))
    def step(key,title,fn):
        progress(title,'running');start=time.monotonic()
        try:
            data=fn();status='failed' if isinstance(data,dict) and (data.get('exit_code',0)!=0 or data.get('error')) else 'completed'
        except Exception as exc:data=dict(error=str(exc));status='failed'
        record=dict(id=key,title=title,status=status,seconds=round(time.monotonic()-start,3),data=data)
        report['sections'].append(record);save_json(out/(key+'.json'),data);progress(title,status);return data
    info=step('identify','识别文件结构与类型',lambda:identify(path));report['identification']=info
    step('fingerprint','全文件摘要与字节熵',lambda:fingerprint(path))
    limit={'quick':4*MIB,'standard':64*MIB,'full':0}[profile]
    clues=step('clues','通用字符串与嵌入签名',lambda:scan(path,limit=limit,max_rows=1000))
    kind=info.get('kind','unknown')
    def exif():
        args=out/'_exif.args'
        try:source='./'+path.relative_to(Path.cwd()).as_posix()
        except ValueError:source=path.as_posix()
        content='-a\n-u\n-G1\n-j\n'+source+'\n';args.write_text(content,encoding='utf-8')
        argument_path=args.relative_to(Path.cwd()).as_posix() if args.is_relative_to(Path.cwd()) else str(args)
        result=external([native('exiftool',kit),'-charset','filename=UTF8','-@',argument_path],out,'metadata',40,content)
        try:result['fields']=json.loads((out/'metadata.txt').read_text(encoding='utf-8'))
        except (ValueError,UnicodeError):pass
        return result
    runner=Workflows(sys.modules[__name__],path,out,kit,profile,step,options or {})
    if kind in ('png','jpeg','gif','bmp','tiff','webp','pdf','pe','zip','office') and profile!='quick':
        metadata=step('metadata','ExifTool 元数据',exif)
        if metadata.get('fields'):
            fields_path=out/'metadata_fields.txt';fields_path.write_text(json.dumps(metadata['fields'],ensure_ascii=False,indent=2),encoding='utf-8')
            step('metadata_decodings','元数据中的编码候选',lambda:runner.decode_text(fields_path,out))
    extension=runner.run(workflow,kind)
    report.update({k:v for k,v in extension.items() if k not in ('workflow_result','recommendations')})
    volumes=extension.get('workflow_result',{}).get('volumes',[])
    if extension['selected_workflow']=='disk' and volumes:
        label=volumes[0]['filesystem']+' 分区镜像 · 起点 '+str(volumes[0]['sector']) if len(volumes)==1 else '磁盘镜像 · '+str(len(volumes))+' 个已验证文件系统'
        report['identification']=dict(info,kind='disk',label=label,verified_by='TSK fsstat',volumes=[dict(sector=v['sector'],sector_size=v['sector_size'],filesystem=v['filesystem']) for v in volumes])
    report['recommendations'].extend(extension['recommendations'])
    if profile!='quick' and path.stat().st_size<=256*MIB:step('yara','内置 YARA 线索规则',lambda:yara_read(path))
    elif profile!='quick':report['sections'].append(dict(id='yara',title='内置 YARA 线索规则',status='skipped',data={'reason':'自动 YARA 输入限 256 MiB；完整文件关键词扫描不受此限制。'}))
    if clues.get('partial'):report['recommendations'].append('普通字符串表覆盖前 '+str(clues['scanned_bytes'])+' 字节；专门的关键词 / flag 形态扫描覆盖范围见独立阶段，不受字符串表条数限制。')
    report['recommendations'].append('命中仅是候选；请结合路径、对象结构和原始输出确认。未导出、跳过与预算限制均保留在报告中。')
    save_json(out/'analysis.json',report);(out/'analysis.html').write_text(report_html(report),encoding='utf-8')
    (out/'analysis.txt').write_text(json.dumps(report,ensure_ascii=False,indent=2,default=str),encoding='utf-8')
    progress('报告已生成','completed');return report


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('task',choices=['auto','probe','search','strings','scan','png','sqlite','text','pdf','pe','yara','lsb','planes','archive','carve'])
    p.add_argument('file',type=Path);p.add_argument('--out',type=Path);p.add_argument('--kit',type=Path,default=Path(__file__).resolve().parent.parent)
    p.add_argument('--profile',choices=['quick','standard','full'],default='standard');p.add_argument('--workflow',choices=[r[0] for r in WORKFLOW_CATALOG],default='auto');p.add_argument('--limit',type=int,default=64*MIB);p.add_argument('--minimum',type=int,default=4)
    p.add_argument('--keywords',default=DEFAULT_KEYWORDS);p.add_argument('--max-files',type=int,default=32);p.add_argument('--depth',type=int,default=2)
    p.add_argument('--encoding',default='both');p.add_argument('--keyword',default='');p.add_argument('--query');p.add_argument('--table');p.add_argument('--rows',type=int,default=200)
    p.add_argument('--password',default='');p.add_argument('--rules',type=Path);p.add_argument('--channels',default='r');p.add_argument('--bit',type=int,default=0);p.add_argument('--order',choices=['xy','yx'],default='xy')
    p.add_argument('--byte-order',choices=['msb','lsb'],default='msb');p.add_argument('--bytes',type=int,default=MIB);p.add_argument('--mode',choices=['list','test','extract'],default='list')
    p.add_argument('--offset',type=lambda x:int(x,0),default=0);p.add_argument('--length',type=lambda x:int(x,0))
    a=p.parse_args();out=a.out or Path.cwd();out.mkdir(parents=True,exist_ok=True)
    try:
        if not a.file.is_file():raise ValueError('输入文件不存在。')
        if a.task=='auto':result=auto(a.file.resolve(),out.resolve(),a.kit.resolve(),a.profile,a.workflow,dict(keywords=a.keywords,max_files=a.max_files,depth=a.depth,password=a.password))
        elif a.task=='probe':result=identify(a.file)
        elif a.task=='search':result=targeted_scan(a.file,keywords(a.keywords))
        elif a.task in ('strings','scan'):
            value=scan(a.file,a.limit,a.minimum,a.encoding,a.keyword)
            result=value['strings' if a.task=='strings' else 'signatures'];result.update(scanned_bytes=value['scanned_bytes'],total_bytes=value['total_bytes'],partial=value['partial'],limited=value['string_rows_limited' if a.task=='strings' else 'signature_rows_limited'],note=value['note'])
        elif a.task=='png':result=pngmap(a.file)
        elif a.task=='sqlite':result=sqlite_read(a.file,a.query,a.table,max(1,min(a.rows,1000)),scratch=out)
        elif a.task=='text':result=text_preview(a.file,a.encoding,max(1,min(a.rows,1000)))
        elif a.task=='pdf':result=pdf_read(a.file,out,a.password)
        elif a.task=='pe':result=pe_read(a.file)
        elif a.task=='yara':result=yara_read(a.file,a.rules.read_text(encoding='utf-8-sig') if a.rules else '')
        elif a.task in ('lsb','planes'):result=image_bits(a.file,out,a.channels,a.bit,a.order,a.byte_order,a.bytes,a.task=='planes')
        elif a.task=='archive':result=archive_read(a.file,out,a.kit,a.mode,a.password)
        elif a.task=='carve':result=carve(a.file,out,a.offset,a.length)
        save_json(out/'result.json',result)
        if a.task=='auto':emit(dict(kind='analysis',source=result['source'],selected_workflow=result.get('selected_workflow'),stages=[dict(title=s['title'],status=s['status']) for s in result['sections']],flag_candidates=len(result.get('findings',[])),report=str(out/'analysis.html')))
        else:emit(result)
        if isinstance(result,dict) and result.get('exit_code',0)!=0:sys.exit(2)
    except Exception as exc:print(str(exc),file=sys.stderr);sys.exit(2)

if __name__=='__main__':main()
