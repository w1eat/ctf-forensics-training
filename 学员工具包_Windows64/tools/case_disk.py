"""Read-only filesystem inventory, batch export and PhotoRec wrappers."""
from pathlib import Path
import csv,hashlib,json,os,re,shutil,subprocess,time
from datetime import datetime,timezone,timedelta
from forensic_workflows import parse_fls,parse_mmls
MIB=1024**2

def image_source(path):
    """Resolve a single FLAT VMDK extent; validate sibling references first."""
    path=Path(path).resolve()
    if path.suffix.lower()!='.vmdk':return path
    with path.open('rb') as f:head=f.read(MIB)
    if not (head.startswith(b'# Disk DescriptorFile') or head.startswith(b'KDMV')):return path
    text=head.decode('latin-1');extents=re.findall(r'(?m)^\s*(?:RW|RDONLY|NOACCESS)\s+(\d+)\s+([A-Z]+)\s+"([^"\r\n]+)"(?:\s+(\d+))?',text)
    def sibling(name):
        dest=(path.parent/name).resolve()
        if re.match(r'^[A-Za-z]:|^[\\/]',name) or not dest.is_relative_to(path.parent):raise ValueError('VMDK 引用必须留在同批附件目录中。')
        if not dest.is_file():raise ValueError('缺少 VMDK 关联文件：'+name)
        return dest
    for _,_,name,_ in extents:sibling(name)
    for name in re.findall(r'(?m)^\s*parentFileNameHint\s*=\s*"([^"\r\n]+)"',text):sibling(name)
    if head.startswith(b'# Disk DescriptorFile') and len(extents)==1:
        sectors,kind,name,offset=extents[0]
        if kind=='FLAT' and int(offset or '0')==0:
            dest=sibling(name)
            if dest.stat().st_size!=int(sectors)*512:raise ValueError('FLAT extent 大小与描述符不一致。')
            return dest
    return path

def native(kit,name):
    if os.name=='nt':
        if name=='photorec':return str(kit/'tools/testdisk/photorec_win.exe')
        return str(kit/'tools/sleuthkit/bin'/(name+'.exe'))
    tool=shutil.which(name)
    if not tool:raise ValueError('Kali 未安装 '+name+'；请使用指南中的安装命令。')
    return tool

def execute(argv,folder,name,timeout=90,limit=16*MIB):
    stdout=folder/(name+'.txt');stderr=folder/(name+'.diagnostics.txt');start=time.monotonic()
    with stdout.open('wb') as out,stderr.open('wb') as err:
        proc=subprocess.Popen(argv,stdout=out,stderr=err,stdin=subprocess.DEVNULL,shell=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        while proc.poll() is None:
            if time.monotonic()-start>timeout or stdout.stat().st_size>limit:proc.kill();proc.wait();raise ValueError(name+' 达到时间或日志上限')
            time.sleep(.1)
    raw=stdout.read_bytes()
    try:text=raw.decode('utf-8')
    except UnicodeError:text=raw.decode('mbcs' if os.name=='nt' else 'utf-8','replace')
    return proc.returncode,text,dict(argv=argv,exit_code=proc.returncode,report=stdout.name,diagnostics=stderr.name)

def volumes(path,out,kit,sector='',sector_size=512):
    path=image_source(path);attempts=[];logical_size=path.stat().st_size
    if str(sector).strip():parts=[dict(sector=int(str(sector),0),sector_size=sector_size,description='指定起点')]
    else:
        code,text,log=execute([native(kit,'mmls'),str(path)],out,'partitions');attempts.append(log)
        if path.suffix.lower() in ('.vmdk','.vhd','.vhdx','.e01'):
            _,info,log=execute([native(kit,'img_stat'),str(path)],out,'image_structure');attempts.append(log)
            found=re.search(r'Size (?:of data )?in bytes:\s*(\d+)',info)
            if found:logical_size=int(found[1])
        parts=parse_mmls(text,logical_size) if code==0 else []
        if not parts:parts=[dict(sector=0,sector_size=sector_size,description='裸文件系统候选')]
    valid=[]
    for p in parts[:16]:
        if p['sector']<0:raise ValueError('分区起点不能为负数')
        argv=[native(kit,'fsstat'),'-b',str(p['sector_size']),'-o',str(p['sector']),str(path)]
        code,text,log=execute(argv,out,'fs_'+str(p['sector']));attempts.append(log)
        match=re.search(r'File System Type:\s*(.+)',text)
        if code==0 and match:valid.append(dict(**p,filesystem=match[1].strip()))
    if not valid:raise ValueError('未验证出文件系统。可能需要指定扇区大小、补齐分片、转换格式或先解密；原始诊断保存在任务目录。')
    return valid,attempts

def inventory(path,out,kit,sector='',sector_size=512,mode='all',name_filter='',limit=2000):
    path=image_source(path);valid,commands=volumes(path,out,kit,sector,sector_size);all_rows=[]
    for volume in valid:
        argv=[native(kit,'fls'),'-r','-p','-b',str(volume['sector_size']),'-o',str(volume['sector']),str(path)]
        code,text,log=execute(argv,out,'files_'+str(volume['sector']),timeout=150);commands.append(log)
        if code:continue
        for row in parse_fls(text):
            if mode=='deleted' and not row['deleted']:continue
            if name_filter and name_filter.casefold() not in row['path'].casefold():continue
            all_rows.append(dict(**row,sector=volume['sector'],sector_size=volume['sector_size']))
    with (out/'文件清单.csv').open('w',encoding='utf-8-sig',newline='') as f:
        keys=['sector','sector_size','type','inode','deleted','path'];w=csv.DictWriter(f,fieldnames=keys,extrasaction='ignore');w.writeheader();w.writerows(all_rows)
    rows=all_rows[:limit]
    return dict(kind='casework',operation='disk_inventory',title='镜像目录与删除项',columns=['分区扇区','元数据编号','已删除','类型','原路径'],rows=[[r['sector'],r['inode'],'是' if r['deleted'] else '否',r['type'],r['path']] for r in rows],entries=rows,total_entries=len(all_rows),limited=len(all_rows)>limit,volumes=valid,commands=commands,note='目录与删除标记不保证数据仍完整。可按本次元数据编号导出；CSV 保存全部匹配条目。支持当前 TSK 识别的 RAW / E01 / VMDK / VHD。')

def timeline(path,out,kit,p):
    """Build a UTC MACB timeline from TSK body files; never mount the source."""
    path=image_source(path)
    valid,commands=volumes(path,out,kit,p.get('sector',''),int(p.get('sector_size',512)))
    def bound(value,end=False):
        if not value.strip():return None
        try:
            stamp=datetime.fromisoformat(value.strip().replace('Z','+00:00'))
            if stamp.tzinfo is None:stamp=stamp.replace(tzinfo=timezone.utc)
            if end and re.fullmatch(r'\d{4}-\d{2}-\d{2}',value.strip()):stamp+=timedelta(days=1)
            return stamp.timestamp()
        except ValueError:raise ValueError('时间请填写 YYYY-MM-DD 或带时区的 ISO 8601；未指定时区按 UTC。')
    start,end=bound(p.get('start','')),bound(p.get('end',''),True)
    if start is not None and end is not None and start>=end:raise ValueError('开始时间必须早于结束时间。')
    fields=[('atime','A 访问'),('mtime','M 内容修改'),('ctime','C 元数据变更'),('crtime','B 创建')]
    events=[];errors=[];file_count=0
    for volume in valid:
        argv=[native(kit,'fls'),'-r','-m','/','-b',str(volume['sector_size']),'-o',str(volume['sector']),str(path)]
        code,text,log=execute(argv,out,'body_'+str(volume['sector']),timeout=150);commands.append(log)
        if code:raise ValueError('TSK 时间线读取失败，请查看 body 诊断文件。')
        for line in text.splitlines():
            parts=line.split('|')
            if len(parts)<11:
                if line.strip():errors.append(line[:160])
                continue
            name='|'.join(parts[1:-9]);tail=parts[-9:];file_count+=1
            if p.get('filter','').casefold() not in name.casefold():continue
            for key,label in fields:
                if p.get('time_field','all') not in ('all',key):continue
                try:epoch=int(tail[5+['atime','mtime','ctime','crtime'].index(key)])
                except ValueError:continue
                if epoch==0 or (start is not None and epoch<start) or (end is not None and epoch>=end):continue
                try:utc=datetime.fromtimestamp(epoch,timezone.utc).isoformat().replace('+00:00','Z')
                except (OverflowError,OSError,ValueError):continue
                events.append(dict(epoch=epoch,utc=utc,event=label,field=key,sector=volume['sector'],sector_size=volume['sector_size'],inode=tail[0],path=name,mode=tail[1],bytes=tail[4]))
    events.sort(key=lambda r:(r['epoch'],r['path'],r['event']),reverse=p.get('sort','newest')=='newest')
    keys=['epoch','utc','event','field','sector','sector_size','inode','path','mode','bytes']
    with (out/'文件时间线.csv').open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=keys);writer.writeheader();writer.writerows(events)
    limit=int(p.get('rows',1000));shown=events[:limit]
    return dict(kind='casework',operation='disk_timeline',title='文件时间线 / MACB',columns=['UTC 时间','事件','分区扇区','元数据编号','路径','字节数'],rows=[[r['utc'],r['event'],r['sector'],r['inode'],r['path'],r['bytes']] for r in shown],entries=shown,total_events=len(events),file_records=file_count,limited=len(events)>limit,parse_errors=errors[:10],volumes=valid,commands=commands,note='UTC 时间；CSV 保存所有匹配事件，网页有展示上限。M=内容修改、A=访问、C=元数据变更、B=创建（文件系统支持时）。C 不是创建时间；时间戳可被修改，需结合内容与其他痕迹验证。结束日期包含当日，带时间的结束值为不包含边界。')


def export_one(path,dest,kit,sector,sector_size,inode,limit=64*MIB):
    path=image_source(path)
    if not re.fullmatch(r'\d{1,20}(?:-\d{1,20}){0,2}',str(inode)):raise ValueError('元数据编号无效')
    argv=[native(kit,'icat'),'-r','-b',str(sector_size),'-o',str(sector),str(path),str(inode)]
    err=dest.with_suffix(dest.suffix+'.diagnostics.txt');count=0;limited=False;start=time.monotonic()
    with dest.open('wb') as output,err.open('wb') as errors:
        proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=errors,shell=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        try:
            while chunk:=proc.stdout.read(65536):
                if count+len(chunk)>limit or time.monotonic()-start>90:limited=True;proc.kill();break
                output.write(chunk);count+=len(chunk)
            proc.wait(timeout=10)
        finally:
            proc.stdout.close()
            if proc.poll() is None:proc.kill();proc.wait()
    return dict(argv=argv,exit_code=proc.returncode,bytes=count,limited=limited)

def recover(path,out,kit,p):
    listing=inventory(path,out,kit,p.get('sector',''),int(p.get('sector_size',512)),p.get('mode','deleted'),p.get('filter',''),limit=20000)
    max_files=int(p.get('max_files',64));budget=int(p.get('budget_mib',256))*MIB;used=0;exports=[];failures=[]
    destdir=out/'recovered';destdir.mkdir(exist_ok=True)
    candidates=[r for r in listing['entries'] if r['type'].split('/')[-1]=='r' and not r['type'].startswith(('d/','l/','v/','V/'))]
    for row in candidates:
        if len(exports)>=max_files or used>=budget:break
        ext=Path(row['path']).suffix
        if not re.fullmatch(r'\.[a-zA-Z0-9]{1,10}',ext):ext='.bin'
        dest=destdir/(str(len(exports)+len(failures)+1).zfill(4)+'_'+str(row['sector'])+'_'+str(row['inode'])+ext)
        result=export_one(path,dest,kit,row['sector'],row['sector_size'],row['inode'],min(64*MIB,budget-used));used+=result['bytes']
        if result['exit_code'] or result['limited']:
            partial=dest.with_suffix(dest.suffix+'.partial');dest.replace(partial)
            failures.append(dict(**row,**result,output=partial.relative_to(out).as_posix()));continue
        sha=hashlib.file_digest(dest.open('rb'),'sha256').hexdigest()
        exports.append(dict(**row,**result,output=dest.relative_to(out).as_posix(),sha256=sha))
    (out/'恢复来源.json').write_text(json.dumps(dict(exports=exports,failures=failures),ensure_ascii=False,indent=2),encoding='utf-8')
    return dict(kind='casework',operation='disk_recovery',title='批量恢复与导出',columns=['输出文件','原路径','元数据编号','字节数','SHA256'],rows=[[r['output'],r['path'],r['inode'],r['bytes'],r['sha256']] for r in exports],exports=exports,failures=failures,volumes=listing['volumes'],candidate_count=len(candidates),exported_bytes=used,limits=dict(max_files=max_files,budget_bytes=budget),note='仅完整且返回成功的 icat 输出计入恢复列表；失败或达到上限的内容以 .partial 保存。删除后重用、碎片和缺页可能导致无法恢复。')

def photorec(path,out,kit,p):
    tool=native(kit,'photorec');types=p.get('types','jpg,png,zip,pdf,txt').split(',')
    allowed={'jpg','png','gif','zip','pdf','txt','7z','rar','gz','bmp','doc','xls','sqlite','elf','exe','mp4','wav'}
    if any(t not in allowed for t in types):raise ValueError('PhotoRec 文件类型选项无效')
    commands=['partition_none'] if p.get('partition','auto')=='none' else []
    commands+=['fileopt','everything','disable']
    for typ in types:commands += [typ,'enable']
    commands+=['wholespace','search']
    prefix=out/'recup';log=out/'photorec.log';argv=[tool,'/log','/logname',str(log),'/d',str(prefix),'/cmd',str(path),','.join(commands)]
    timeout=int(p.get('seconds',300));budget=int(p.get('budget_mib',256))*MIB;start=time.monotonic();limited=False
    env=os.environ.copy();env.pop('PYTHONIOENCODING',None);env.pop('PYTHONUTF8',None)
    if os.name=='nt':env['__COMPAT_LAYER']='RunAsInvoker'
    with (out/'photorec.stdout.txt').open('wb') as stdout,(out/'photorec.diagnostics.txt').open('wb') as stderr:
        proc=subprocess.Popen(argv,cwd=out,env=env,stdout=stdout,stderr=stderr,stdin=subprocess.DEVNULL,shell=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        while proc.poll() is None:
            if time.monotonic()-start>timeout or sum(f.stat().st_size for f in out.glob('recup*/*') if f.is_file())>budget:
                limited=True;proc.kill();break
            time.sleep(.3)
        proc.wait(timeout=15)
    files=[f for f in out.glob('recup*/*') if f.is_file()];rows=[]
    for f in files[:1000]:rows.append([f.relative_to(out).as_posix(),f.stat().st_size,hashlib.file_digest(f.open('rb'),'sha256').hexdigest()])
    if proc.returncode and not limited and not files:raise ValueError('PhotoRec 未成功运行，查看 photorec.diagnostics.txt 与日志；确认镜像格式和程序依赖。')
    return dict(kind='casework',operation='photorec',title='PhotoRec 签名恢复',columns=['恢复文件','字节数','SHA256'],rows=rows,argv=argv,exit_code=proc.returncode,limited=limited,recovered_files=len(files),note='基于签名雕刻，通常不能还原原文件名和目录。已输出不代表完整；任务达到时间或空间上限时应逐个验证，输出目录保留 PhotoRec XML / 日志。')

def browser_history(path,out,limit=500):
    import sqlite3
    work=out/'browser_snapshot';work.mkdir(exist_ok=True);copy=work/'history.db';shutil.copy2(path,copy)
    for suffix in ('-wal','-shm'):
        side=Path(str(path)+suffix)
        if side.is_file():shutil.copy2(side,Path(str(copy)+suffix))
    con=sqlite3.connect(copy.as_uri()+'?mode=ro',uri=True)
    try:
        tables={r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        queries=[]
        if {'moz_places','moz_historyvisits'}<=tables:
            queries.append(('Firefox 访问历史',"SELECT p.url,p.title,v.visit_date AS raw_time,datetime(v.visit_date/1000000,'unixepoch') AS utc FROM moz_places p JOIN moz_historyvisits v ON p.id=v.place_id ORDER BY v.visit_date DESC"))
        elif 'moz_places' in tables:queries.append(('Firefox 页面记录','SELECT * FROM moz_places'))
        if {'urls','visits'}<=tables:queries.append(('Chromium 访问历史',"SELECT u.url,u.title,v.visit_time AS raw_time,datetime(v.visit_time/1000000-11644473600,'unixepoch') AS utc FROM urls u JOIN visits v ON u.id=v.url ORDER BY v.visit_time DESC"))
        if not queries:raise ValueError('没有发现支持的浏览器历史表。请先运行 SQLite 表结构工具，使用实际字段查询。')
        results=[]
        for title,sql in queries:
            cursor=con.execute(sql+' LIMIT ?', (limit,));columns=[d[0] for d in cursor.description];rows=[list(r) for r in cursor.fetchall()]
            results.append(dict(title=title,columns=columns,rows=rows,sql=sql+' LIMIT '+str(limit)))
        return dict(kind='casework',operation='browser_history',title='浏览器历史与时间',tables=results,snapshot=True,note='在工作副本中查询，保留同目录 WAL / SHM。UTC 为按已知 Firefox / Chromium 时间单位换算；访问记录不单独证明现实人物操作，字段随应用版本变化。')
    finally:con.close()
