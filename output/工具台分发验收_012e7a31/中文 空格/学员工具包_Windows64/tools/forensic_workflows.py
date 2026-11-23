"""Bounded, reusable forensic workflows. No exercise names, PIDs or answers.

Only calls bundled parsers and trusted argv lists. Child evidence is kept in
new directories; filenames from an image are never used as output paths.
"""
from __future__ import annotations
import base64, collections, csv, hashlib, io, json, os, re, shutil, struct, subprocess, sys, time
from pathlib import Path

MIB=1024**2
WORKFLOW_CATALOG=[
 ('auto','自动选择流程','按结构识别文件，再运行适用的分析链。'),
 ('disk','磁盘 / 分区镜像','分区或裸文件系统 → 目录 / 删除项 → 候选导出 → 内容检索。'),
 ('archive','压缩包与嵌套附件','目录 / 加密 → 受限提取 → 子文件识别 → 递归分析。'),
 ('image','图片与隐写','元数据 / CRC → 尾随对象 → 位平面 / LSB → 文本线索。'),
 ('database','SQLite 数据库','表结构 / WAL → 表预览 → 逐表文本检索 → 证据位置。'),
 ('text','文本、日志与编码','编码识别 → 字段 / 时间 / 关联键 → 关键词 → 编码候选解码。'),
 ('document','PDF / Office 文档','正文 / 元数据 / 附件 → 附件提取 → 子文件分析。'),
 ('pe','PE 静态分析','节 / 导入 / 熵 → overlay → YARA / 字符串。'),
 ('embedded','嵌入对象与雕刻','签名偏移 → 格式边界验证 → 导出 → 继续分析。'),
 ('windows_memory','Windows 内存（Vol3）','info → 进程 / 参数 / 文件 → 线索关联 → 定向操作。'),
]
DEFAULT_KEYWORDS='flag,picoCTF,ctf,secret,password,credential,密码'
FLAG=re.compile(rb'\b(?:flag|picoctf|ctf)\{[\x20-\x7e]{1,200}?\}',re.I)
WIDE_FLAG=re.compile(rb'(?:(?:[fF]\0[lL]\0[aA]\0[gG]\0)|(?:p\0i\0c\0o\0C\0T\0F\0)|(?:[cC]\0[tT]\0[fF]\0))\{\0(?:[\x20-\x7e]\0){1,200}?\}\0')

def keywords(value):
    return list(dict.fromkeys(w.strip()[:64] for w in re.split(r'[,，;；\n]',value or DEFAULT_KEYWORDS) if w.strip()))[:16]

def detect_disk(head,size):
    if head.startswith((b'KDMV',b'# Disk DescriptorFile')):return 'VMDK 虚拟磁盘候选'
    if head.startswith(b'vhdxfile'):return 'VHDX 虚拟磁盘候选'
    if head.startswith(b'EVF\x09\x0d\x0a\xff\x00'):return 'EWF 镜像候选'
    if len(head)>=1082 and head[1080:1082]==b'\x53\xef':return 'EXT 文件系统候选（超级块魔数）'
    if head[3:11] in (b'NTFS    ',b'EXFAT   '):return head[3:11].decode().strip()+' 文件系统候选'
    if head[54:62].startswith((b'FAT12',b'FAT16')) or head[82:90].startswith(b'FAT32'):return 'FAT 文件系统候选'
    if head[512:520]==b'EFI PART' or head[4096:4104]==b'EFI PART':return 'GPT 磁盘候选'
    if len(head)>=512 and head[510:512]==b'\x55\xaa':
        for i in range(4):
            entry=head[446+i*16:462+i*16]
            if len(entry)==16:
                start,length=struct.unpack_from('<II',entry,8)
                if entry[0] in (0,128) and entry[4] and start and length and start*512<size and (start+length)*512<=size:return 'MBR 磁盘候选'
    return None

def targeted_scan(path,words,max_rows=300,limit=0):
    """Search the full selected byte range, even after printable-row limits."""
    maximum=min(path.stat().st_size,limit or path.stat().st_size);rows=[];flags=[];seen=set();position=0;tail=b'';limited=False
    needles=[]
    for word in words:
        for encoding in ('utf-8','utf-16le'):
            needle=word.encode(encoding).lower()
            if needle:needles.append((word,encoding,needle))
    with path.open('rb') as stream:
        while position<maximum:
            block=stream.read(min(MIB,maximum-position))
            if not block:break
            data=tail+block;origin=position-len(tail);lower=data.lower()
            for pattern,encoding in ((FLAG,'ascii'),(WIDE_FLAG,'utf-16le')):
                for match in pattern.finditer(data):
                    offset=origin+match.start();token=match[0].decode(encoding,'replace');key=('flag',offset,token)
                    if key not in seen:
                        seen.add(key)
                        if len(flags)<100:flags.append(dict(offset=hex(offset),encoding=encoding,value=token))
                        else:limited=True
            if len(rows)<max_rows:
                for word,encoding,needle in needles:
                    at=lower.find(needle)
                    while at>=0 and len(rows)<max_rows:
                        offset=origin+at;key=(word,encoding,offset)
                        if key not in seen:
                            seen.add(key);start=max(0,at-48);end=min(len(data),at+len(needle)+100)
                            if encoding=='utf-16le':start+=(at-start)%2;end-=((end-start)%2)
                            context=data[start:end].decode(encoding,'replace').replace('\x00','·')
                            rows.append([hex(offset),encoding,word,context])
                        at=lower.find(needle,at+len(needle))
            position+=len(block);tail=data[-1024:]
    return dict(columns=['字节偏移','编码','关键词','上下文'],rows=rows,flag_candidates=flags,scanned_bytes=position,total_bytes=path.stat().st_size,
                partial=position<path.stat().st_size,limited=limited or len(rows)>=max_rows,
                note='flag 形态是候选，必须回到文件 / 业务语义验证。命中条数有上限，扫描不会因普通字符串表满而提前结束。')

def parse_fls(text):
    result=[]
    for line in text.splitlines():
        m=re.match(r'^([\w-]/[\w-])\s+(\*\s*)?([\d-]+)(?:\([^)]*\))?:\s*(.*)$',line)
        if not m:continue
        result.append(dict(type=m[1],deleted=bool(m[2]),inode=m[3],path=m[4]))
    return result

def parse_mmls(text,size):
    units=re.search(r'Units are in (\d+)-byte sectors',text);sector_size=int(units[1]) if units else 512;parts=[]
    for line in text.splitlines():
        m=re.match(r'^\s*\d+:\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$',line)
        if not m or m[1] in ('Meta','-------') or re.search(r'Unallocated|Table|Extended',m[5],re.I):continue
        start,end,length=map(int,m.group(2,3,4))
        if length>0 and start*sector_size<size:parts.append(dict(sector=start,sector_size=sector_size,length=length,description=m[5]))
    return list({p['sector']:p for p in parts}.values())

def flatten_json(value):
    rows=[]
    if isinstance(value,list):
        for item in value:rows.extend(flatten_json(item))
    elif isinstance(value,dict):
        rows.append({k:v for k,v in value.items() if k!='__children'})
        rows.extend(flatten_json(value.get('__children',[])))
    return rows

class Workflows:
    def __init__(self,core,path,out,kit,profile,step,options):
        self.c=core;self.path=path;self.out=out;self.kit=kit;self.profile=profile;self.step=step
        self.words=keywords(options.get('keywords',DEFAULT_KEYWORDS));self.max_files=int(options.get('max_files',32));self.depth=int(options.get('depth',2));self.password=options.get('password','')
        self.files_seen=0;self.exported_bytes=0;self.max_bytes=128*MIB;self.findings=[];self.finding_keys=set();self.children=[];self.actions=[];self.recommendations=[];self.visited=set();self.serial=0
        self.max_files=max(1,min(self.max_files,100));self.depth=max(0,min(self.depth,3))

    def title_key(self,prefix):self.serial+=1;return prefix+'_'+str(self.serial)
    def small_json(self,path):
        try:return json.loads(path.read_text(encoding='utf-8'))
        except (ValueError,OSError):return None
    def log_text(self,folder,name):
        p=folder/name
        with p.open('rb') as f:raw=f.read(8*MIB)
        try:return raw.decode('utf-8')
        except UnicodeError:return raw.decode('mbcs' if os.name=='nt' else 'utf-8','replace')
    def add_findings(self,data,source):
        for row in data.get('flag_candidates',[]):
            key=(source,row['offset'],row['value'])
            if len(self.findings)<200 and key not in self.finding_keys:self.findings.append(dict(source=source,**row));self.finding_keys.add(key)
    def search(self,path,source=None):
        result=targeted_scan(path,self.words);self.add_findings(result,source or self.relative(path));return result
    def relative(self,path):
        try:return path.relative_to(self.out).as_posix()
        except ValueError:return path.name
    def reserve(self,size):
        if self.files_seen>=self.max_files or self.exported_bytes+size>self.max_bytes:return False
        self.files_seen+=1;self.exported_bytes+=size;return True
    def next_action(self,title,action,params):
        try:relative=self.path.relative_to(Path.cwd()).as_posix()
        except ValueError:return
        if len(self.actions)<20:self.actions.append(dict(title=title,action=action,params=dict(file=relative,**params)))

    def binary(self,argv,dest,limit=16*MIB):
        dest.parent.mkdir(parents=True,exist_ok=True);err=dest.with_suffix(dest.suffix+'.diagnostics.txt');count=0;limited=False;start=time.monotonic()
        with dest.open('wb') as output,err.open('wb') as errors:
            proc=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=errors,stdin=subprocess.DEVNULL,shell=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            try:
                while block:=proc.stdout.read(65536):
                    if count+len(block)>limit:
                        output.write(block[:max(0,limit-count)]);count=limit;limited=True;proc.kill();break
                    output.write(block);count+=len(block)
                    if time.monotonic()-start>45:limited=True;proc.kill();break
                proc.wait(timeout=10)
            finally:
                proc.stdout.close()
                if proc.poll() is None:proc.kill();proc.wait()
        return dict(command=self.c.command_text(argv),exit_code=proc.returncode,bytes=count,limited=limited,output=self.relative(dest))

    def candidate_score(self,entry):
        path=entry['path'].lower();name=path.rsplit('/',1)[-1]
        if entry['type'].split('/')[-1] not in ('r','-') or entry['type'].startswith(('d/','l/','v/','V/')):return -1
        score=0
        if any(word.casefold() in path for word in self.words):score+=35
        if entry['deleted']:score+=25
        if path.startswith(('home/','root/','users/','documents and settings/')):score+=24
        if name.startswith('.') or 'history' in name:score+=18
        if re.search(r'\.(txt|md|log|csv|jsonl?|ini|conf|xml|ya?ml|db|sqlite|zip|7z|pdf|png|jpe?g)$',name):score+=10
        if re.search(r'(^|/)(bin|sbin|lib|usr/lib|usr/share)/',path):score-=35
        if name in ('passwd','shadow','fstab','hosts','crontab'):score+=12
        return score

    def disk(self,path,folder):
        folder.mkdir(parents=True,exist_ok=True)
        from case_disk import image_source,native as disk_native
        path=image_source(path);logical_size=path.stat().st_size
        if path.suffix.lower() in ('.vmdk','.vhd','.vhdx','.e01'):
            image_info=self.c.external([disk_native(self.kit,'img_stat'),str(path)],folder,'image_structure',45)
            if image_info['exit_code']==0:
                size_match=re.search(r'Size (?:of data )?in bytes:\s*(\d+)',self.log_text(folder,'image_structure.txt'))
                if size_match:logical_size=int(size_match[1])
        probe=self.c.external([self.c.native('mmls',self.kit),str(path)],folder,'mmls',45)
        parts=parse_mmls(self.log_text(folder,'mmls.txt'),logical_size) if probe['exit_code']==0 else []
        if not parts:parts=[dict(sector=0,sector_size=512,length=path.stat().st_size//512,description='直接验证偏移 0 的裸文件系统')]
        valid=[];attempts=[]
        for part in parts[:8]:
            sf=folder/('fs_'+str(part['sector']));sf.mkdir(exist_ok=True)
            command=[self.c.native('fsstat',self.kit),'-b',str(part['sector_size']),'-o',str(part['sector']),str(path)]
            info=self.c.external(command,sf,'fsstat',45);attempts.append(dict(sector=part['sector'],exit_code=info['exit_code'],command=info['command'],diagnostics=info['diagnostics']))
            text=self.log_text(sf,'fsstat.txt');kind=re.search(r'File System Type:\s*(.+)',text)
            if info['exit_code']!=0 or not kind:continue
            volume=dict(**part,filesystem=kind[1].strip(),summary=text.split('BLOCK GROUP INFORMATION')[0][:8000],command=info['command'])
            valid.append(volume)
        if not valid:return dict(error='mmls 与候选起点的 fsstat 均未识别文件系统；请检查镜像格式、分片、扇区大小或加密条件。',probe=probe,attempts=attempts)
        mode='partition_table' if probe['exit_code']==0 and parse_mmls(self.log_text(folder,'mmls.txt'),logical_size) else 'filesystem_at_zero'
        result=dict(kind='disk',mode=mode,volumes=valid,probe=probe,attempts=attempts,partition_limit=8,partitions_limited=len(parts)>8,tables=[])
        if mode=='filesystem_at_zero':result['explanation']='mmls 无分区表结果后，fsstat 已在偏移 0 验证文件系统；这不是镜像损坏。'
        result['tables'].append(dict(title='已验证的文件系统',columns=['起始扇区','扇区字节','文件系统','说明'],rows=[[v['sector'],v['sector_size'],v['filesystem'],v['description']] for v in valid]))
        for volume in valid:
            sector=volume['sector'];sf=folder/('fs_'+str(sector));base=['-b',str(volume['sector_size']),'-o',str(sector),str(path)]
            listing=self.step(self.title_key('disk_files'),f'文件系统 {sector}：递归目录与删除项',lambda sf=sf,base=base:self.c.external([self.c.native('fls',self.kit),'-r','-p']+base,sf,'fls',60))
            if listing.get('exit_code')!=0:continue
            entries=parse_fls(self.log_text(sf,'fls.txt'))
            with (sf/'file_inventory.csv').open('w',encoding='utf-8-sig',newline='') as f:
                writer=csv.writer(f);writer.writerow(['inode','type','deleted','path']);writer.writerows([e['inode'],e['type'],e['deleted'],e['path']] for e in entries)
            candidates=sorted((dict(e,score=self.candidate_score(e)) for e in entries if self.candidate_score(e)>=0),key=lambda e:(-e['score'],e['path']))
            result['tables'].append(dict(title=f'起点 {sector}：文件 / 删除项（前 500，完整目录见 CSV）',columns=['元数据编号','类型','删除标记','路径','优先分'],rows=[[e['inode'],e['type'],e['deleted'],e['path'],self.candidate_score(e)] for e in entries[:500]]))
            recovered=[]
            for entry in candidates:
                if self.files_seen>=self.max_files:break
                # Inspect declared size first, then enforce an independent byte cap.
                index=len(recovered)+1;istat=self.c.external([self.c.native('istat',self.kit)]+base+[entry['inode']],sf,'istat_'+str(index),20)
                meta=self.log_text(sf,'istat_'+str(index)+'.txt');size_match=re.search(r'(?:^|\n)(?:File )?Size:\s*(\d+)',meta,re.I)
                size=int(size_match[1]) if size_match else None
                if istat['exit_code'] or size is None or size>16*MIB or not self.reserve(size):
                    recovered.append(dict(inode=entry['inode'],path=entry['path'],status='skipped',reason='大小未知 / 超过单文件 16 MiB / 达到总预算',bytes=size));continue
                name=re.sub(r'[^\w.\-]','_',entry['path'].rsplit('/',1)[-1])[:90] or 'file.bin'
                dest=sf/'recovered'/(f'{index:03}_'+name)
                exported=self.binary([self.c.native('icat',self.kit),'-r']+base+[entry['inode']],dest,limit=16*MIB)
                row=dict(inode=entry['inode'],path=entry['path'],deleted=entry['deleted'],status='exported' if exported['exit_code']==0 and not exported['limited'] else 'partial',**exported)
                if row['status']=='exported':
                    with dest.open('rb') as stream:row['sha256']=hashlib.file_digest(stream,'sha256').hexdigest()
                    search=self.search(dest,entry['path']);row['keyword_hits']=len(search['rows']);row['flag_candidates']=search['flag_candidates']
                    self.inspect_child(dest,1,origin=entry['path'])
                recovered.append(row)
            self.c.save_json(sf/'recovered_index.json',recovered)
            result['tables'].append(dict(title=f'起点 {sector}：候选文件导出',columns=['编号','原路径','状态','字节','关键词命中','输出'],rows=[[e['inode'],e['path'],e['status'],e.get('bytes'),e.get('keyword_hits',0),e.get('output',e.get('reason',''))] for e in recovered]))
            volume.update(entries=len(entries),deleted_entries=sum(e['deleted'] for e in entries),candidate_count=len(candidates),exported=sum(e['status']=='exported' for e in recovered),inventory=self.relative(sf/'file_inventory.csv'),budget_limited=len(candidates)>self.max_files)
            self.next_action(f'浏览起点 {sector} 的全部文件','disk_files',dict(sector=str(sector),deleted='no'))
            self.next_action(f'查看起点 {sector} 的文件系统','disk_fsstat',dict(sector=str(sector)))
            for entry in candidates[:3]:self.next_action('按实际编号导出 '+entry['path'],'disk_recover',dict(sector=str(sector),inode=entry['inode']))
        self.recommendations.append('磁盘已按实际起点分析；文件清单保留 inode、删除标记和完整路径。自动只导出有预算的优先候选，未导出内容需继续用 icat 定向提取。')
        return result

    def inspect_child(self,path,depth,origin=None):
        if depth>self.depth:return
        with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
        if digest in self.visited:return
        self.visited.add(digest);info=self.c.identify(path);source=origin or self.relative(path)
        record=dict(source=source,path=self.relative(path),depth=depth,identification=info,sha256=digest)
        if path.stat().st_size<=16*MIB:
            search=self.search(path,source);record['hits']=search['rows'][:30];record['flag_candidates']=search['flag_candidates']
        self.children.append(record)
        kind=info['kind'];folder=path.parent/(path.name+'.analysis');folder.mkdir(exist_ok=True)
        try:
            if kind in ('zip','archive','office') and depth<self.depth:record['analysis']=self.archive(path,folder,depth)
            elif kind=='pdf':record['analysis']=self.c.pdf_read(path,folder,self.password)
            elif kind=='sqlite':record['analysis']=self.c.sqlite_read(path,scratch=folder)
            elif kind=='png':record['analysis']=self.c.pngmap(path)
            elif kind=='text':record['decodings']=self.decode_text(path,folder)
        except Exception as exc:record['error']=str(exc)

    def archive(self,path,folder,depth=0):
        folder.mkdir(parents=True,exist_ok=True);result=self.c.archive_read(path,folder,self.kit,'list',self.password)
        if result.get('exit_code'):return result
        encrypted=any(str(r[3]).strip()=='+' for r in result.get('rows',[]))
        if encrypted and not self.password:
            result['skipped']='加密压缩包：已列目录，未尝试口令或提取。'
            self.next_action('输入已知口令后继续','archive_general',dict(mode='extract',password=''));return result
        if self.profile=='quick' and depth==0:
            result['skipped']='快速模式仅查看目录；标准 / 完整模式执行受限提取。';return result
        try:expanded=sum(int(row[1]) for row in result.get('rows',[]))
        except (ValueError,TypeError):result['skipped']='无法确认展开大小，未自动提取。';return result
        if result['entries']>len(result['rows']) or self.exported_bytes+expanded>self.max_bytes:
            result['skipped']='目录未完整覆盖或超过本次剩余 128 MiB 展开 / 导出预算，未自动提取。';return result
        try:extracted=self.c.archive_read(path,folder,self.kit,'extract',self.password)
        except Exception as exc:result['error']=str(exc);return result
        result['extract']=extracted.get('extract');result['exit_code']=extracted.get('exit_code',0)
        if result['exit_code']:return result
        self.exported_bytes+=expanded
        if depth>=self.depth:
            result['skipped_child_analysis']='已提取；达到所选子文件深度，未继续分析这些子文件。';result['analysed_children']=[];return result
        selected=[]
        for child in sorted((folder/'extracted').rglob('*')):
            if not child.is_file():continue
            size=child.stat().st_size
            if size>16*MIB or not self.reserve(0):continue
            selected.append(self.relative(child));self.inspect_child(child,depth+1)
        result['analysed_children']=selected;result['depth']=depth;result['depth_limit']=self.depth
        result['children_limited']=len(selected)<result.get('entries',0)
        return result

    def decode_text(self,path,folder):
        with path.open('rb') as stream:raw=stream.read(2*MIB)
        encoding='utf-16' if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig'
        try:text=raw.decode(encoding)
        except UnicodeError:
            try:text=raw.decode('gb18030');encoding='gb18030'
            except UnicodeError:text=raw.decode('utf-8','replace');encoding='utf-8（含替换）'
        candidates=[];seen=set()
        patterns=[('Base64',re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,4096}={0,2}(?![A-Za-z0-9+/=])')),
                  ('Hex',re.compile(r'(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,2048}(?![0-9a-fA-F])'))]
        for label,pattern in patterns:
            for match in pattern.finditer(text):
                if len(candidates)>=24:break
                try:decoded=base64.b64decode(match[0],validate=True) if label=='Base64' else bytes.fromhex(match[0])
                except (ValueError,base64.binascii.Error):continue
                if not decoded or decoded in seen:continue
                readable=sum(32<=b<127 or b in (9,10,13) for b in decoded)/len(decoded)
                if readable<.85 and not FLAG.search(decoded):continue
                seen.add(decoded);name='decoded_'+str(len(candidates)+1)+'.bin';dest=folder/name;dest.write_bytes(decoded)
                item=dict(method=label,text_character_offset=match.start(),preview=decoded[:1024].decode('utf-8','replace'),output=self.relative(dest))
                candidates.append(item);self.search(dest,self.relative(path)+' → '+label)
        return dict(encoding=encoding,read_bytes=len(raw),total_bytes=path.stat().st_size,limited=len(raw)<path.stat().st_size or len(candidates)>=24,
                    columns=['编码候选','文本字符位置','解码预览','输出'],rows=[[v['method'],v['text_character_offset'],v['preview'],v['output']] for v in candidates],
                    note='只做一层严格 Base64 / Hex 候选解码，字符位置不是原始文件字节偏移。编码形态不等于加密。')

    def text(self,path,folder):
        decoded=self.decode_text(path,folder);encoding=decoded['encoding'] if '替换' not in decoded['encoding'] else 'utf-8-sig'
        preview=self.c.text_preview(path,encoding=encoding);tables=[dict(title='结构预览',columns=preview.get('columns',[]),rows=preview.get('rows',[])),dict(title='编码候选',columns=decoded['columns'],rows=decoded['rows'])]
        with path.open('rb') as stream:raw=stream.read(4*MIB)
        text=raw.decode(encoding,'replace');events=[];keys=collections.Counter();times=[]
        for number,line in enumerate(text.splitlines()[:20000],1):
            try:value=json.loads(line)
            except ValueError:continue
            if not isinstance(value,dict):continue
            for key in ('request_id','trace_id','session_id','user','username','event','action'):
                if key in value:keys[(key,str(value[key])[:256])]+=1
            for key in ('timestamp','time','@timestamp','created_at'):
                if key in value:
                    try:
                        from datetime import datetime,timezone
                        parsed=datetime.fromisoformat(str(value[key]).replace('Z','+00:00'))
                        if parsed.tzinfo is not None:times.append([parsed.astimezone(timezone.utc).isoformat(),number,key,str(value[key])]);break
                    except ValueError:pass
        if keys:tables.append(dict(title='实际字段与关联值（统计前 20000 行）',columns=['字段','值','出现次数'],rows=[[k,v,n] for (k,v),n in keys.most_common(100)]))
        if times:tables.append(dict(title='带时区时间归一为 UTC（未标时区的值不猜测）',columns=['UTC','原始行号','字段','原值'],rows=sorted(times)[:200]))
        return dict(kind='workflow_text',tables=tables,encoding=encoding,read_bytes=len(raw),limited=len(raw)<path.stat().st_size,decodings=decoded)

    def database(self,path,folder):
        import sqlite3,tempfile
        schema=self.c.sqlite_read(path,scratch=folder);tables=[dict(title='SQLite 表结构',columns=schema['columns'],rows=schema['rows'])];hits=[];scanned=[]
        # All reads, including WAL/SHM activity, operate on a private snapshot.
        with tempfile.TemporaryDirectory(prefix='_db_search_',dir=folder) as temporary:
            copy=Path(temporary)/'case.db'
            for suffix in ('','-wal','-shm'):
                src=Path(str(path)+suffix)
                if src.is_file():shutil.copyfile(src,Path(str(copy)+suffix))
            names=[row[1] for row in schema['rows'] if row[0]=='table'][:20]
            for name in names:
                query='SELECT * FROM "'+name.replace('"','""')+'"'
                try:rows=self.c.sqlite_read(copy,query=query,limit=1000,scratch=folder)
                except Exception as exc:scanned.append(dict(table=name,error=str(exc)));continue
                scanned.append(dict(table=name,rows=len(rows['rows']),limited=rows['limited']))
                if len(tables)<=5:tables.append(dict(title='预览表：'+name,columns=rows['columns'],rows=rows['rows'][:50]))
                for index,row in enumerate(rows['rows'],1):
                    for column,value in zip(rows['columns'],row):
                        text=str(value or '')
                        if any(word.casefold() in text.casefold() for word in self.words):
                            if len(hits)<300:hits.append([name,index,column,text[:2048]])
                        for match in FLAG.finditer(text.encode('utf-8')):
                            if len(self.findings)<200:self.findings.append(dict(source=f'{path.name} / {name} / 结果行 {index} / {column}',offset='查询结果',encoding='UTF-8',value=match[0].decode('utf-8')))
        tables.append(dict(title='逐表检索命中',columns=['表','查询结果行号','字段','值'],rows=hits))
        return dict(kind='workflow_database',tables=tables,scanned_tables=scanned,table_limit=20,row_limit_per_table=1000,companions=schema.get('companions',[]),
                    note='结果行号是本次 SELECT 的位置，不保证是 rowid；最多 20 表、每表 1000 行。业务软删除与物理删除恢复不同。')

    def embedded(self,path,folder):
        signatures=self.c.scan(path,limit=0 if self.profile=='full' else 64*MIB,max_rows=1)['signatures']['rows'];outputs=[];size=path.stat().st_size
        for offset_hex,label,_ in signatures[:2000]:
            offset=int(offset_hex,16)
            if offset==0 or label not in ('PNG','ZIP local','PDF'):continue
            if self.files_seen>=self.max_files:break
            end=None;method=''
            if label=='PNG':
                with path.open('rb') as stream:
                    stream.seek(offset+8)
                    for _ in range(4096):
                        header=stream.read(8)
                        if len(header)!=8:break
                        length=struct.unpack('>I',header[:4])[0]
                        if length>16*MIB or stream.tell()+length+4>size:break
                        stream.seek(length+4,1)
                        if header[4:]==b'IEND':end=stream.tell();method='PNG 块边界到 IEND';break
            elif label=='PDF':
                with path.open('rb') as stream:stream.seek(offset);data=stream.read(16*MIB)
                marker=data.rfind(b'%%EOF')
                if marker>=0:end=offset+marker+5;method='PDF 最后一个 %%EOF 候选，再由 pypdf 验证'
            elif label=='ZIP local':
                with path.open('rb') as stream:stream.seek(offset);data=stream.read(16*MIB)
                start=0
                while True:
                    at=data.find(b'PK\x05\x06',start)
                    if at<0:break
                    if at+22<=len(data):
                        length=int.from_bytes(data[at+20:at+22],'little');boundary=at+22+length
                        if boundary<=len(data):
                            try:
                                import zipfile
                                with zipfile.ZipFile(io.BytesIO(data[:boundary])) as archive:
                                    infos=archive.infolist()
                                    valid=bool(infos) and all(0<=info.header_offset<boundary-4 and data[info.header_offset:info.header_offset+4]==b'PK\x03\x04' for info in infos)
                                if valid:end=offset+boundary;method='ZIP EOCD / 注释长度与中央目录验证';break
                            except (ValueError,zipfile.BadZipFile):pass
                    start=at+4
            if end is None or end-offset>16*MIB or not self.reserve(end-offset):continue
            suffix={'PNG':'.png','PDF':'.pdf','ZIP local':'.zip'}[label];dest=folder/('embedded_'+hex(offset)+suffix)
            with path.open('rb') as src,dest.open('wb') as dst:src.seek(offset);dst.write(src.read(end-offset))
            valid=True;error=''
            try:
                if label=='PNG':
                    png=self.c.pngmap(dest);valid=png['iend'] and not png['error'] and all(c['valid'] for c in png['chunks'])
                elif label=='PDF':self.c.pdf_read(dest,folder,self.password)
            except Exception as exc:valid=False;error=str(exc)
            outputs.append([hex(offset),end-offset,label,'结构通过' if valid else '需复核',method,self.relative(dest),error])
            if valid:self.inspect_child(dest,1)
        return dict(columns=['起始字节','字节数','格式','验证','边界依据','输出','诊断'],rows=outputs,scanned_bytes=size if self.profile=='full' else min(size,64*MIB),total_bytes=size,
                    note='自动雕刻仅支持可验证边界的 PNG / 经典 ZIP / PDF，单对象最多 16 MiB；其他签名继续用字节范围雕刻。')

    def image(self,path,folder):
        info=self.step(self.title_key('image_info'),'图片尺寸、模式与缩略图',lambda:self.c.image_info(path,folder))
        kind=self.c.identify(path)['kind'];result=dict(kind='workflow_image',image=info,tables=[])
        if kind=='png':
            png=self.step(self.title_key('png_crc'),'PNG 块、CRC 与尾随数据',lambda:self.c.pngmap(path));result['png']=png
        if self.profile!='quick' and path.stat().st_size<=64*MIB and info.get('width',0)*info.get('height',0)<=4_000_000:
            try:
                self.c.image_bits(path,folder/'planes','rgb',0,planes=True)
                for channels in ('r','g','b','rgb','bgr'):
                    dest=folder/('bits_'+channels);dest.mkdir(exist_ok=True)
                    extraction=self.c.image_bits(path,dest,channels,0,'xy','msb',65536)
                    search=self.search(dest/'lsb.bin',path.name+' / b0 '+channels+' xy msb')
                    result['tables'].append(dict(title='LSB 候选 '+channels,columns=['位序','导出字节','flag 形态','命中条数'],rows=[['bit0 / xy / msb',extraction['bytes'],', '.join(f['value'] for f in search['flag_candidates']),len(search['rows'])]]))
            except Exception as exc:result['bit_diagnostic']=str(exc)
        if kind in ('png','bmp') and self.profile!='quick' and info.get('width',0)*info.get('height',0)<=1_000_000 and not info.get('error'):
            if os.name=='nt':argv=[str(self.kit/'runtime/ruby/bin/ruby.exe'),str(self.kit/'runtime/ruby/bin/zsteg'),'--no-file',str(path)]
            else:argv=[shutil.which('zsteg') or 'zsteg',str(path)]
            result['zsteg']=self.step(self.title_key('zsteg'),'zsteg 枚举常见图片位流',lambda:self.c.external(argv,folder,'zsteg',60))
        result['embedded']=self.embedded(path,folder)
        self.next_action('调整位、通道、扫描与组字节顺序','lsb_custom',{})
        return result

    def document(self,path,folder):
        if self.c.identify(path)['kind']=='office':return self.archive(path,folder)
        pdf=self.c.pdf_read(path,folder,self.password)
        if pdf.get('error'):return pdf
        text=folder/'pdf_text.txt';self.search(text,path.name+' / PDF 正文');pdf['text_decodings']=self.decode_text(text,folder)
        from pypdf import PdfReader
        reader=PdfReader(str(path),strict=False)
        if reader.is_encrypted:reader.decrypt(self.password)
        attachments=[]
        for name in list(reader.attachments)[:16]:
            for data in reader.attachments[name][:4]:
                if len(data)>16*MIB or not self.reserve(len(data)):continue
                filename=re.sub(r'[^\w.\-]','_',name)[:90] or 'attachment.bin';dest=folder/(str(len(attachments)+1)+'_'+filename);dest.write_bytes(data);attachments.append(self.relative(dest));self.inspect_child(dest,1)
        pdf['extracted_attachments']=attachments;return pdf

    def pe(self,path,folder):
        result=self.c.pe_read(path)
        if result.get('overlay_offset'):
            start=int(result['overlay_offset'],16);size=path.stat().st_size-start
            if 0<size<=16*MIB and self.reserve(size):
                dest=folder/'overlay.bin'
                with path.open('rb') as src:src.seek(start);dest.write_bytes(src.read(size))
                result['overlay_export']=self.relative(dest);self.search(dest,path.name+' / overlay');result['embedded']=self.embedded(dest,folder)
        return result

    def memory(self,path,folder):
        self.next_action('旧系统控制台不兼容时：用 Vol2 识别 profile','vol2_identify',{})
        if os.name=='nt':vol=[str(self.kit/'runtime/python/python.exe'),str(self.kit/'tools/volatility3/vol.py')]
        else:vol=[shutil.which('vol')] if shutil.which('vol') else [sys.executable,'-c','from volatility3.cli import main; main()']
        first=self.step('vol_info','Vol3：验证系统、层与符号（离线）',lambda:self.c.external(vol+['--offline','-r','json','-f',str(path),'windows.info'],folder,'vol_info',120))
        if first.get('exit_code')!=0:return dict(error='windows.info 未成功，未运行后续插件；先检查真实 RAM 与匹配符号。',info=first)
        outputs={}
        for plugin in ('pslist','pstree','cmdline','filescan'):
            value=self.step('vol_'+plugin,'Vol3：'+plugin,lambda plugin=plugin:self.c.external(vol+['--offline','-r','json','-f',str(path),'windows.'+plugin],folder,'vol_'+plugin,120))
            outputs[plugin]=flatten_json(self.small_json(folder/('vol_'+plugin+'.txt')) or []) if value.get('exit_code')==0 else []
        related=[]
        for row in outputs['cmdline']:
            text=json.dumps(row,ensure_ascii=False)
            if any(w.casefold() in text.casefold() for w in self.words) or re.search(r'encodedcommand|--note|notepad',text,re.I):
                related.append(row)
                pid=row.get('PID')
                if isinstance(pid,int):self.next_action('查看关联 PID '+str(pid)+' 的句柄','vol_handles',dict(pid=str(pid)))
        file_rows=[row for row in outputs['filescan'] if any(w.casefold() in json.dumps(row,ensure_ascii=False).casefold() for w in self.words)]
        return dict(kind='workflow_memory',tables=[dict(title='按实际输出关联的进程参数',columns=['PID','进程','参数'],rows=[[r.get('PID'),r.get('Process'),r.get('Args')] for r in related[:100]]),dict(title='关键词相关文件对象',columns=['插件输出'],rows=[[json.dumps(r,ensure_ascii=False)] for r in file_rows[:100]])],
                    counts={k:len(v) for k,v in outputs.items()},note='未自动导出整个进程或所有缓存。根据当前 PID / FILE_OBJECT 与虚拟 / 物理类型使用定向操作，避免把示例地址带入真实镜像。')

    def run(self,workflow,kind):
        chosen=workflow
        if workflow=='auto':chosen={'disk':'disk','png':'image','jpeg':'image','gif':'image','bmp':'image','tiff':'image','webp':'image','zip':'archive','archive':'archive','office':'document','sqlite':'database','text':'text','pdf':'document','pe':'pe'}.get(kind,'embedded')
        if workflow=='auto' and kind=='unknown' and self.path.suffix.lower() in ('.img','.dd','.iso','.e01','.vmdk','.vhd','.vhdx'):chosen='disk'
        folder=self.out/'workflow';folder.mkdir(exist_ok=True)
        handlers={'disk':self.disk,'archive':self.archive,'image':self.image,'database':self.database,'text':self.text,'document':self.document,'pe':self.pe,'embedded':self.embedded,'windows_memory':self.memory}
        title=next(label for key,label,_ in WORKFLOW_CATALOG if key==chosen)
        data=self.step('workflow_'+chosen,title,lambda:handlers[chosen](self.path,folder))
        if self.profile!='quick' or chosen in ('disk','text','database'):
            self.step('targeted_search','全文件关键词与 flag 形态检索',lambda:self.search(self.path))
        else:self.step('targeted_search','关键词与 flag 形态检索（前 4 MiB）',lambda:self._limited_search())
        return dict(selected_workflow=chosen,findings=self.findings,children=self.children,next_actions=self.actions,recommendations=self.recommendations,
                    limits=dict(max_exported_files=self.max_files,exported_files=self.files_seen,max_exported_bytes=self.max_bytes,accounted_bytes=self.exported_bytes,child_depth=self.depth),workflow_result=data)

    def _limited_search(self):
        result=targeted_scan(self.path,self.words,limit=4*MIB);self.add_findings(result,self.path.name);return result
