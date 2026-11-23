"""Deterministic training fixtures, command companions, and instructor guide."""
from pathlib import Path
import base64, datetime as dt, hashlib, html, io, json, random, re, sqlite3, struct, tempfile, zipfile, zlib

FLAGS = ['flag{file_type_before_extension}','flag{crc_checks_the_hypothesis}','flag{one_bit_one_clue}',
         'flag{offsets_make_carving_repeatable}','flag{deleted_entry_is_a_clue}','flag{query_the_schema_first}',
         'flag{192.0.2.44_091831}']

SCRIPTS = {}
SCRIPTS['recover_width.py'] = r'''"""Restore only width when a valid original IHDR CRC was retained. Python 3."""
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
'''
SCRIPTS['extract_lsb.py'] = r'''"""Training convention: red LSB, row-major pixels, MSB-first output bytes."""
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
'''
SCRIPTS['carve.py'] = r'''"""Copy a known byte range to a new file. Offset/length accept decimal or 0x hex."""
from pathlib import Path
import argparse
p=argparse.ArgumentParser(description=__doc__); p.add_argument('input'); p.add_argument('output')
p.add_argument('--offset',required=True,type=lambda x:int(x,0)); p.add_argument('--length',type=lambda x:int(x,0)); a=p.parse_args()
src,dst=Path(a.input),Path(a.output)
if src.resolve()==dst.resolve(): p.error('Use a different output path')
d=src.read_bytes(); end=len(d) if a.length is None else a.offset+a.length
if a.offset<0 or end<a.offset or end>len(d): p.error('Invalid byte range')
dst.parent.mkdir(parents=True,exist_ok=True); dst.write_bytes(d[a.offset:end]); print('Saved bytes:',end-a.offset)
'''
SCRIPTS['zip_flags.py'] = r'''"""Inspect/clear bit 0 in classic single-disk ZIP headers. This does not decrypt."""
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
'''
SCRIPTS['read_training_fat.py'] = r'''"""Read this course's fixed single-cluster FAT16 fixture; not a general recovery tool."""
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
'''
SCRIPTS['query_case.py'] = r'''"""Read-only query of the course's synthetic SQLite database."""
import argparse, sqlite3
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__); p.add_argument('input'); a=p.parse_args()
uri=Path(a.input).resolve().as_uri()+'?mode=ro'; con=sqlite3.connect(uri,uri=True)
print('Tables:',list(con.execute("SELECT name FROM sqlite_master WHERE type='table'")))
print('Columns:',list(con.execute('PRAGMA table_info(artifacts)')))
for row in con.execute('SELECT id,name,note FROM artifacts WHERE deleted=1'): print(row)
con.close()
'''
SCRIPTS['timeline.py'] = r'''"""Print synthetic audit events with explicit UTC+8 offset."""
import argparse, datetime as dt, json
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__); p.add_argument('input'); a=p.parse_args()
for number,line in enumerate(Path(a.input).read_text(encoding='utf-8').splitlines(),1):
    row=json.loads(line); original=dt.datetime.fromisoformat(row['timestamp'].replace('Z','+00:00'))
    local=original.astimezone(dt.timezone(dt.timedelta(hours=8)))
    print(number,local.isoformat(),row['event'],row['request_id'],row['user'],row['client_ip'])
'''


def chunk(kind,data):
    return struct.pack('>I',len(data))+kind+data+struct.pack('>I',zlib.crc32(kind+data)&0xffffffff)


def png(width,height,raw,comment=None):
    head=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',width,height,8,2,0,0,0))
    if comment: head+=chunk(b'tEXt',b'Comment\0'+comment.encode())
    return head+chunk(b'IDAT',zlib.compress(raw,9))+chunk(b'IEND',b'')


def zip_bytes(entries):
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,data in sorted(entries.items()):
            info=zipfile.ZipInfo(name,(2026,10,18,9,0,0)); info.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(info,data)
    return buf.getvalue()


def password_zip():
    # Classic ZipCrypto fixture, stored method, one file, known training password.
    plain=b'Teaching fixture\nflag{dictionary_from_the_hint}\n'; name=b'note.txt'; password=b'training2026'
    crc=zlib.crc32(plain)&0xffffffff; keys=[0x12345678,0x23456789,0x34567890]
    def crcbyte(value,old):
        result=(old^value)&0xff
        for _ in range(8): result=(result>>1)^(0xedb88320 if result&1 else 0)
        return (old>>8)^result
    def update(value):
        keys[0]=crcbyte(value,keys[0]); keys[1]=((keys[1]+(keys[0]&0xff))*134775813+1)&0xffffffff; keys[2]=crcbyte(keys[1]>>24,keys[2])
    for value in password: update(value)
    encoded=bytearray()
    for value in bytes(range(11))+bytes([crc>>24])+plain:
        temp=keys[2]|2; encoded.append(value^(((temp*(temp^1))>>8)&0xff)); update(value)
    dos_date=((2026-1980)<<9)|(10<<5)|18
    local=struct.pack('<4s5H3I2H',b'PK\x03\x04',20,1,0,0,dos_date,crc,len(encoded),len(plain),len(name),0)+name+encoded
    central=struct.pack('<4s6H3I5H2I',b'PK\x01\x02',20,20,1,0,0,dos_date,crc,len(encoded),len(plain),len(name),0,0,0,0,0,0)+name
    result=local+central+struct.pack('<4s4H2IH',b'PK\x05\x06',0,0,1,1,len(central),len(local),0)
    with zipfile.ZipFile(io.BytesIO(result)) as z: assert z.read('note.txt',pwd=password)==plain
    return result


def disk_image():
    start,sectors,bps=2048,16384,512; reserved,fats,fatsize,entries=1,2,64,512
    d=bytearray((start+sectors)*bps)
    d[446:462]=struct.pack('<B3sB3sII',0,b'\xfe\xff\xff',6,b'\xfe\xff\xff',start,sectors); d[510:512]=b'\x55\xaa'
    boot=start*bps; d[boot:boot+3]=b'\xeb\x3c\x90';d[boot+3:boot+11]=b'CTFDEMO '
    struct.pack_into('<HBHBHHBHHHII',d,boot+11,bps,1,reserved,fats,entries,sectors,0xf8,fatsize,32,64,start,0)
    d[boot+36:boot+39]=b'\x80\x00\x29'; struct.pack_into('<I',d,boot+39,0xc7f02610)
    d[boot+43:boot+54]=b'CTFTRAINING';d[boot+54:boot+62]=b'FAT16   ';d[boot+510:boot+512]=b'\x55\xaa'
    for n in range(fats):
        fat=boot+(reserved+n*fatsize)*bps; struct.pack_into('<HHHH',d,fat,0xfff8,0xffff,0xffff,0)
    root=boot+(reserved+fats*fatsize)*bps; data=root+entries*32
    payloads=[(b'README  TXT',2,b'Training FAT16 image. Look for a deleted root directory entry.\r\n'),
              (b'\xe5ECRET  TXT',3,(FLAGS[4]+'\r\n').encode())]
    date=((2026-1980)<<9)|(10<<5)|18
    for i,(name,cluster,payload) in enumerate(payloads):
        off=root+i*32;d[off:off+11]=name;d[off+11]=0x20;struct.pack_into('<HHHI',d,off+22,9<<11,date,cluster,len(payload))
        where=data+(cluster-2)*bps;d[where:where+len(payload)]=payload
    return bytes(d)


def sqlite_fixture():
    with tempfile.TemporaryDirectory(prefix='ctf-course-') as directory:
        path=Path(directory)/'case.db'; con=sqlite3.connect(path)
        con.execute('CREATE TABLE artifacts(id INTEGER PRIMARY KEY,name TEXT NOT NULL,deleted INTEGER NOT NULL,note TEXT NOT NULL)')
        con.executemany('INSERT INTO artifacts VALUES(?,?,?,?)',[(1,'readme',0,'Synthetic training database'),(2,'old-note',1,FLAGS[5]),(3,'active-note',0,'Use the schema before guessing column names')]);con.commit();con.close()
        return path.read_bytes()


def jpeg_demo(with_xmp=False):
    from PIL import Image,ImageDraw
    im=Image.new('RGB',(320,180),(231,240,222));draw=ImageDraw.Draw(im)
    for y in range(0,180,20):draw.rectangle((0,y,320,y+9),fill=(178,207,168))
    draw.rectangle((28,48,290,132),fill=(25,62,49));draw.text((45,75),'CTF CLASSROOM / REPRODUCTION',fill=(211,237,198))
    buf=io.BytesIO();im.save(buf,format='JPEG',quality=85);data=buf.getvalue()
    if with_xmp:
        value=base64.b64encode(b'flag{metadata_then_base64}').decode()
        xml=f'''<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:cc="http://creativecommons.org/ns#"><cc:license>{value}</cc:license></rdf:Description></rdf:RDF></x:xmpmeta>'''.encode()
        xmp=b'http://ns.adobe.com/xap/1.0/\0'+xml; data=data[:2]+b'\xff\xe1'+struct.pack('>H',len(xmp)+2)+xmp+data[2:]
    else:data+=b'\nTeaching reproduction only. flag{strings_see_more_than_pixels}\n'
    return data


def exercises(base_png):
    files={'01_file/unknown.dat':base_png}
    # Reuse the simple image data, replacing the text chunk.
    cur=8;raw=bytearray()
    while cur<len(base_png):
        n=struct.unpack_from('>I',base_png,cur)[0];kind=base_png[cur+4:cur+8]
        if kind==b'IDAT':raw.extend(base_png[cur+8:cur+8+n])
        cur+=n+12
    scan=zlib.decompress(raw); good=png(256,160,scan,FLAGS[1]); bad=bytearray(good);bad[16:20]=struct.pack('>I',1)
    files['02_png/broken_width.png']=bytes(bad);files['02_png/good.png']=good
    files['02_png/broken_header.png']=b'BROKEN!!'+good[8:]
    message=(FLAGS[2]+'\0').encode();bits=[(b>>(7-i))&1 for b in message for i in range(8)];rng=random.Random(20261019);rows=bytearray();index=0
    for y in range(64):
        rows.append(0)
        for x in range(96):
            r=(rng.randrange(60,200)&0xfe)|(bits[index] if index<len(bits) else 0);index+=1
            rows.extend((r,rng.randrange(90,180),rng.randrange(50,150)))
    files['03_lsb/quiet.png']=png(96,64,rows)
    payload=zip_bytes({'answer.txt':(FLAGS[3]+'\n').encode(),'README.txt':b'This ZIP was embedded at byte offset 512.\n'})
    prefix=b'CTF CLASSROOM CARRIER\nEmbedded ZIP begins at offset 0x200.\n';files['04_archive/carrier.bin']=prefix.ljust(512,b'\0')+payload
    flagged=bytearray(zip_bytes({'note.txt':b'This content was never encrypted. Verify CRC after clearing both flags.\n'}))
    local=flagged.index(b'PK\x03\x04');central=flagged.index(b'PK\x01\x02')
    struct.pack_into('<H',flagged,local+6,struct.unpack_from('<H',flagged,local+6)[0]|1);struct.pack_into('<H',flagged,central+8,struct.unpack_from('<H',flagged,central+8)[0]|1)
    files['04_archive/flagged.zip']=bytes(flagged);files['04_archive/locked.zip']=password_zip();files['04_archive/words.txt']=b'classroom\ntraining\ntraining2026\nforensics\n'
    files['05_disk/tiny_fat16.dd']=disk_image();files['06_sqlite/case.db']=sqlite_fixture()
    files['07_logs/access.log']='''192.0.2.44 - - [18/Oct/2026:09:15:50 +0800] "GET / HTTP/1.1" 200 532 "-" "TrainingBrowser/1.0" rid=r-099
203.0.113.9 - - [18/Oct/2026:09:16:00 +0800] "GET /admin HTTP/1.1" 404 42 "-" "TestClient/1.0" rid=r-100
192.0.2.44 - - [18/Oct/2026:09:16:10 +0800] "POST /api/login HTTP/1.1" 200 64 "-" "TrainingBrowser/1.0" rid=r-101
192.0.2.44 - - [18/Oct/2026:09:17:05 +0800] "GET /dashboard HTTP/1.1" 200 980 "-" "TrainingBrowser/1.0" rid=r-104
203.0.113.9 - - [18/Oct/2026:09:18:00 +0800] "GET /backup.zip HTTP/1.1" 404 42 "-" "TestClient/1.0" rid=r-105
192.0.2.44 - - [18/Oct/2026:09:18:30 +0800] "POST /api/export HTTP/1.1" 202 81 "-" "TrainingBrowser/1.0" rid=r-102
192.0.2.44 - - [18/Oct/2026:09:18:31 +0800] "GET /exports/42.zip HTTP/1.1" 200 2048 "-" "TrainingBrowser/1.0" rid=r-103
192.0.2.44 - - [18/Oct/2026:09:19:00 +0800] "GET /help HTTP/1.1" 200 420 "-" "TrainingBrowser/1.0" rid=r-106
'''.encode()
    events=[]
    for time,event,rid,extra in [('01:16:10','login_success','r-101',{}),('01:17:05','dashboard_view','r-104',{}),('01:18:30','export_started','r-102',{'object_id':42,'file_name':'case_notes.zip'}),('01:18:31','download_completed','r-103',{'object_id':42,'file_name':'case_notes.zip','bytes_sent':2048})]:
        events.append(dict(timestamp='2026-10-18T'+time+'Z',event=event,user='trainee',client_ip='192.0.2.44',session_id='TRAIN-7',request_id=rid,**extra))
    files['07_logs/audit.jsonl']=('\n'.join(json.dumps(e) for e in events)+'\n').encode()
    for name,text in SCRIPTS.items():files['tools/'+name]=text.encode()
    files['public_examples/garden_demo.jpg']=jpeg_demo();files['public_examples/cat_demo.jpg']=jpeg_demo(True)
    files['public_examples/SOURCES.md']='''# 公开例题来源与复现说明

这两张 *_demo.jpg 是自制教学复现，**不是 picoCTF 官方原始附件**，图像、哈希与 flag 均不同。
用于原始附件服务器不可访问时演示相同的入门方法。

## Glory of the Garden · picoCTF 2019

平台入口：https://play.picoctf.org/practice/challenge/44
历史官方附件：https://jupiter.challenges.picoctf.org/static/d0e1ffb10fc0017c6a82c57900f3ffe3/garden.jpg
方法：识别 JPEG → strings 检索 → 十六进制核对位置。不同附件版本 flag 后缀可能不同。
复现文件 garden_demo.jpg：flag{strings_see_more_than_pixels}

## information · picoCTF 2021

平台入口：https://play.picoctf.org/practice/challenge/186
历史官方附件：https://mercury.picoctf.net/static/d1375e383810d8d957c04eef9e345732/cat.jpg
方法：ExifTool 找 XMP License → 提取字段值 → Base64 解码。
复现文件 cat_demo.jpg：flag{metadata_then_base64}

核对日期：2026-10-19。当前执行环境无法解析旧附件域名及新附件域名，因此未宣称已下载或校验官方原件。
公开题的题意为课件作者转述；解题命令独立编写并在复现附件上验证。平台登录与原件获取由平台当前状态决定。
'''.encode()
    names=['文件识别与元数据','PNG 宽度恢复','红通道 LSB','偏移分离 ZIP','FAT16 删除项','SQLite 软删除','日志时间线']
    readme='# CTF 取证基础 · 学员练习\n\n从本目录运行课件中的相对路径命令。先保留原件并建立副本。\n\n'
    readme+='七组自制题与两份公开题同考点自制复现附件。所有自制数据可离线分析，不连接外部目标。\n\n'
    for i,name in enumerate(names,1):readme+=f'## {i:02} · {name}\n\n按课件对应练习页完成，提交 flag 与 3～5 行解题记录。\n\n'
    readme+='''## 环境与依赖

推荐使用配套“学员工具与练习_Windows64.zip”，完整解压后双击“01_启动课堂终端.cmd”，从 labs 运行命令。
该包内置 Python/Pillow、Volatility 3、7-Zip、ExifTool、SQLite、TSK、pngcheck、zsteg 与 BusyBox 常用命令。
若仅下载本练习 ZIP，则需要自己的工具环境。GNU 命令使用 Linux/WSL，Windows 参数对照见工具包使用指南。
John Jumbo、Autopsy 为可选拓展；小字典 ZIP 和磁盘题分别提供已验证的 Python/7-Zip 与 TSK 路线。
tools 里的 Python 脚本附源码，除 extract_lsb.py 依赖 Pillow 外只使用标准库。

## 补充练习材料

02_png/broken_header.png：已知 PNG 签名损坏；good.png 为对照件。
04_archive/flagged.zip：标志被设为加密，内容实际未加密。
04_archive/locked.zip：真正的教学口令 ZIP，配套 words.txt 为候选字典。
public_examples/*_demo.jpg：来源与原题的区别见 SOURCES.md，不是官方原件。

## 日志格式

access.log 为教学扩展访问日志，rid 对应 audit.jsonl 的 request_id；timestamp 的 Z 表示 UTC。
练习 07 按 flag{IP_HHMMSS} 提交，HHMMSS 取 UTC+8 下载完成时间，不含冒号。

## 输出与验证

脚本输出放在 out/，不要覆盖原件。哈希见 SHA256SUMS.txt，清单不包含自身。
题目校验答案在 HTML 本地完成，适合教学复核，不是竞赛防作弊系统。
'''
    from memory_module import memory_files
    files.update(memory_files())
    readme += '\n## Volatility 3 内存专题\n\n08_memory 提供三道合成输出读题例题、模拟导出片段与命令手册，不是完整 RAM。真实镜像另行提供。\n'
    files['README.md']=readme.encode()
    files['tools/finspect.py']=(Path(__file__).parent/'finspect.py').read_bytes()
    files['题目任务单.md']=(Path(__file__).parent/'problem_set.md').read_bytes()
    files['SHA256SUMS.txt']=''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n' for name,data in sorted(files.items())).encode()
    return files


def manual(slides,groups):
    from command_platforms import annotate_slides
    slides,_=annotate_slides(slides)
    text=f'''# CTF 取证基础专项培训 · 讲师手册

{len(slides)} 页，建议约 {sum(g[2] for g in groups)} 分钟，可拆为两次课。面向初学者，深入解释工具、命令与常见基础题解法。
课件入口 index.html，完全离线；七组自制题与两道公开基础题的方法讲解。
公开题的 *_demo.jpg 是自制复现，非官方原件。原始题目入口与不可达附件说明见练习包 public_examples/SOURCES.md。

## 课前环境

- 先完整解压配套学员工具包，运行环境自检，再用课堂终端从 labs 执行命令。
- Python/Pillow、Ruby/zsteg、Vol3、7-Zip、ExifTool、SQLite、TSK、pngcheck 已配套，不必逐项安装。
- xxd、strings、grep、dd 使用包内 BusyBox；GNU file、strings -e l 等 Windows 对照见工具包使用指南。
- Autopsy、John Jumbo、steghide、Linux binwalk 作为拓展；本课实操已配有包内可运行路线。
- Volatility 3 内存专题为 18 页，附三道合成输出读题例题、模拟导出片段与独立命令手册；真实 RAM 另行提供。磁盘部分附约 9 MiB 合成镜像。
- 右上角“备注”或 N 键会显示答案与讲授提示，投影时按需收起；不是独立双屏讲师窗口。

## 配套工具包

完整解压“学员工具与练习_Windows64.zip”，双击“01_启动课堂终端.cmd”，从 labs 运行题解命令。
Python/Pillow、Vol3、7-Zip、ExifTool、SQLite、TSK、pngcheck、zsteg、BusyBox 与 CyberChef 已配套；实际入口、版本与参数差异见工具包使用指南。
逐题的题意、提示、命令、输出判读、验证与答案见“讲师题解_逐题讲解.html”；讲师题解含 15 个案例。

## 模块时间（含演示和练习）

| 模块 | 分钟 |
|---|---:|
'''
    text+=''.join(f'| {name} | {minutes} |\n' for name,_,minutes in groups)
    text+='\n## 自制题答案\n\n'+''.join(f'{i:02}. `{flag}`\n\n' for i,flag in enumerate(FLAGS,1))
    text+='''练习 02：宽 256，高 160；恢复宽度后读取 Comment。练习 03：R 通道低位、逐行、按 MSB-first 组成字节。
练习 04：ZIP 从 0x200 / 十进制 512 开始，直到文件结尾。
练习 05：FAT16 从扇区 2048 开始，每扇区 512 字节；根目录第二个条目为删除项，簇 3 的内容仍在。
练习 06：业务软删除 deleted=1；不是物理页恢复。练习 07：access.log 第 7 行、audit.jsonl 第 4 行，r-103，账号 trainee、文件 case_notes.zip。
额外口令 ZIP 的口令 training2026，字典中含该值；仅用于讲解小字典恢复流程。
自制复现 A：flag{strings_see_more_than_pixels}；自制复现 B：flag{metadata_then_base64}。

## 逐页讲解与可复制命令

'''
    for number,s in enumerate(slides,1):
        text+=f'### {number:02} · {s["title"]}\n\n{s["subtitle"]}\n\n{s["notes"]}\n\n'
        for kind,snippet in re.findall(r'<div class="codebox" data-platform="([^"]+)".*?<pre><code>(.*?)</code></pre>',s['body'],flags=re.S):
            language={'windows':'powershell','kali':'bash','both':'console','python':'python','sql':'sql','output':'text','cmd':'cmd'}[kind]
            text+='~~~'+language+'\n'+html.unescape(snippet)+'\n~~~\n\n'
    from memory_module import CASE_FLAGS
    text += '\n## Volatility 3 教学例题答案\n\n' + '\n'.join(f'- {name.upper()}：{value}' for name,value in CASE_FLAGS.items()) + '\n\n完整顺序、命令与题解另见 Volatility3_内存镜像分析_命令与题解.md。\n'
    return text
