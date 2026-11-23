"""Portable case-oriented operations used by the visual workbench."""
from pathlib import Path
import argparse,base64,csv,hashlib,html,json,os,re,shutil,subprocess,sys,time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from case_crypto import material,readable,transform,cipher,digest,hash_candidates
import case_carving,case_disk,case_mount,case_memory
MIB=1024**2

def integer(p,key,default=0,lo=0,hi=2**48):
    raw=str(p.get(key,default)).strip() or str(default)
    value=int(raw,0) if raw.lower().startswith(('0x','-0x')) else int(raw)
    if not lo<=value<=hi:raise ValueError(key+' 超出范围')
    return value

def input_data(p,path,limit=16*MIB):
    if p.get('source','text')=='file':
        if path is None:raise ValueError('选择附件作为输入后，需要指定文件。')
        if path.stat().st_size>limit:raise ValueError('此转换限 '+str(limit//MIB)+' MiB，先导出所需范围。')
        return path.read_bytes()
    raw=p.get('text','')
    if len(raw.encode('utf-8'))>limit:raise ValueError('文本超出范围')
    return material(raw,p.get('input_format','utf8'))

def output_data(data,out,extra=None):
    dest=out/'转换结果.bin';dest.write_bytes(data)
    value=dict(kind='casework',operation='transform',title='字节转换结果',bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),text=readable(data[:65536]),hex=data[:32768].hex(),base64=base64.b64encode(data[:32768]).decode(),preview_limited=len(data)>32768,output=dest.name,note='下载 .bin 保留完整字节。UTF-8、HEX 与 Base64 为预览，原始二进制不会经过文本重编码。')
    value['text_roundtrip']=value['text'].encode('utf-8')==data
    if extra:value.update(extra)
    return value

def hex_view(path,p):
    size=path.stat().st_size;offset=integer(p,'offset',0,0,size);length=integer(p,'length',256,16,4096)
    with path.open('rb') as f:f.seek(offset);data=f.read(length)
    return dict(kind='hex',operation='hex_view',title='交互式十六进制',offset=offset,length=length,total_bytes=size,hex=data.hex(),columns=['字节偏移','00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F','ASCII'],rows=[[hex(offset+i),data[i:i+16].hex(' '),''.join(chr(c) if 32<=c<127 else '.' for c in data[i:i+16])] for i in range(0,len(data),16)],previous=max(0,offset-length),next=min(size,offset+len(data)),note='偏移从 0 开始，以字节计数。使用前后页、定位或搜索，不需要把大镜像读入浏览器。')

def byte_search(path,p):
    pattern=material(p.get('pattern',''),p.get('pattern_format','hex'))
    if not pattern or len(pattern)>65536:raise ValueError('检索模式须为 1～65536 字节。')
    start=integer(p,'offset',0,0,path.stat().st_size);limit=integer(p,'scan_mib',0,0,1048576)*MIB;max_hits=1000;rows=[];carry=b'';processed=0
    with path.open('rb') as f:
        f.seek(start)
        while block:=f.read(min(MIB,max(0,limit-processed)) if limit else MIB):
            blob=carry+block;base=start+processed-len(carry);pos=0
            while (pos:=blob.find(pattern,pos))>=0:
                absolute=base+pos
                if absolute>=start and absolute+len(pattern)>start+processed:rows.append([hex(absolute),absolute])
                pos+=1
                if len(rows)>=max_hits:break
            processed+=len(block);carry=blob[-(len(pattern)-1):] if len(pattern)>1 else b''
            if len(rows)>=max_hits or (limit and processed>=limit):break
    limited=len(rows)>=max_hits or start+processed<path.stat().st_size
    return dict(kind='casework',operation='byte_search',title='原始字节检索',columns=['字节偏移 HEX','字节偏移十进制'],rows=rows,offsets=[r[1] for r in rows],read_bytes=processed,start_offset=start,total_bytes=path.stat().st_size,limited=limited,note='匹配的是原始字节；文本搜索先转换为所选编码。最多返回 1000 条；达到条数或扫描范围上限时，请缩小范围或从后续偏移继续检索。读取字节数可能包含最后一块中未继续枚举的部分。')

def patch(path,out,p):
    if path.stat().st_size>512*MIB:raise ValueError('副本补丁限 512 MiB；较大镜像先导出目标文件。')
    offset=integer(p,'offset',0,0,path.stat().st_size);replacement=material(p.get('replacement',''),'hex');expected=material(p.get('expected',''),'hex')
    if not replacement or len(replacement)>65536:raise ValueError('补丁须为 1～65536 字节。')
    if offset+len(replacement)>path.stat().st_size:raise ValueError('补丁超出文件长度，当前操作不追加字节。')
    with path.open('rb') as f:f.seek(offset);old=f.read(len(replacement))
    if expected and old!=expected:raise ValueError('原字节与预期不一致，已停止；请重新定位。')
    dest=out/('patched'+(path.suffix if re.fullmatch(r'\.[A-Za-z0-9]{1,10}',path.suffix) else '.bin'));shutil.copyfile(path,dest)
    with dest.open('r+b') as f:f.seek(offset);f.write(replacement)
    return dict(kind='casework',title='副本字节补丁',columns=['字节偏移','原值 HEX','新值 HEX','输出'],rows=[[hex(offset),old.hex(),replacement.hex(),dest.name]],sha256=hashlib.file_digest(dest.open('rb'),'sha256').hexdigest(),note='只修改新副本中指定的等长字节；原件保持不变。修复后继续使用相应格式解析器验证。')

def convert_image(path,out,kit,p):
    path=case_disk.image_source(path)
    maximum=integer(p,'budget_mib',2048,1,16384)*MIB
    if shutil.disk_usage(out).free<maximum+64*MIB:raise ValueError('可用空间不足以满足所选输出预算。')
    dest=out/'converted.raw';argv=[case_disk.native(kit,'img_cat'),str(path)]
    count=0;limited=False;start=time.monotonic()
    with dest.open('wb') as dst,(out/'img_cat.diagnostics.txt').open('wb') as err:
        proc=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=err,shell=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        try:
            while block:=proc.stdout.read(MIB):
                if count+len(block)>maximum or time.monotonic()-start>600:limited=True;proc.kill();break
                dst.write(block);count+=len(block)
            proc.wait(timeout=15)
        finally:
            proc.stdout.close()
            if proc.poll() is None:proc.kill();proc.wait()
    if limited or proc.returncode:
        dest.replace(out/'converted.raw.partial');raise ValueError('转换未完成，部分输出以 .partial 保留；请检查分片、格式支持与预算。')
    return dict(kind='casework',title='转换为 RAW 工作副本',columns=['输出','字节数','SHA256'],rows=[[dest.name,count,hashlib.file_digest(dest.open('rb'),'sha256').hexdigest()]],note='img_cat 通过当前 TSK 镜像后端读取逻辑字节，不修改容器原件。RAW 可继续浏览、恢复或按分区只读挂载。')

def run(task,path,out,kit,labs,p):
    if task=='hex':return hex_view(path,p)
    if task=='search':return byte_search(path,p)
    if task=='patch':return patch(path,out,p)
    if task=='separate':return case_carving.separate(path,out,integer(p,'scan_mib',0,0,1048576),integer(p,'max_files',64,1,256),integer(p,'budget_mib',128,1,1024),integer(p,'depth',1,0,3))
    if task=='inventory':return case_disk.inventory(path,out,kit,p.get('sector',''),integer(p,'sector_size',512,512,4096),p.get('mode','all'),p.get('filter',''),integer(p,'rows',1000,1,5000))
    if task=='timeline':return case_disk.timeline(path,out,kit,p)
    if task=='recovery':return case_disk.recover(path,out,kit,p)
    if task=='photorec':return case_disk.photorec(path,out,kit,p)
    if task=='browser':return case_disk.browser_history(path,out,integer(p,'rows',500,1,5000))
    if task=='convert':return convert_image(path,out,kit,p)
    if task=='mount':return case_mount.mount(path,out,kit,labs,p)
    if task=='mounted':return case_mount.browse(labs,out,p)
    if task=='memory':return case_memory.triage(path,out,kit,p)
    if task=='codec':
        data=input_data(p,path,limit=MIB if p.get('operation')=='xor_single_byte' else 16*MIB);value,table=transform(data,p.get('operation','base64_decode'),p)
        return output_data(value,out,table)
    if task=='cipher':
        value,details=cipher(input_data(p,path),p);return output_data(value,out,dict(cryptography=details,note='请以正确格式或已知明文复核。CBC/ECB/CTR 等模式本身不提供完整性认证；GCM 必须验证 tag。密钥和口令不写入运行报告。'))
    if task=='hash':
        if p.get('mode','calculate')=='calculate':
            data=input_data(p,path);return dict(kind='casework',title='摘要计算',columns=['算法','摘要'],rows=[[name,digest(data,name)] for name in ('md5','sha1','sha256','sha512')],note='摘要用于比对内容，不是可直接解密的密文。')
        words=p.get('words','').splitlines();wordfile=p.get('wordlist','')
        if wordfile:
            word=Path(wordfile)
            if not word.is_file() or not word.is_relative_to(labs):raise ValueError('字典不在附件目录中。')
            if word.stat().st_size>16*MIB:raise ValueError('候选字典限 16 MiB。')
            words=word.read_text(encoding='utf-8-sig',errors='strict').splitlines()
        return dict(kind='casework',title='摘要候选验证',**hash_candidates(p.get('target',''),p.get('algorithm','md5'),words))
    if task=='extundelete':
        if os.name=='nt':
            return dict(kind='casework',title='Ext 日志恢复的运行条件',columns=['平台','可执行路线'],rows=[['Windows','先用批量删除恢复与 PhotoRec；extundelete 原生工具在 Kali 使用。'],['Kali','在未挂载的 Ext3/Ext4 工作副本上，先查看 inode，再运行恢复。']],note='Ext4 特性、日志覆盖、卸载状态都会影响 extundelete；不能把 TSK 或签名雕刻结果冒充日志恢复。',next_actions=[dict(title='批量恢复删除文件',action='disk_batch_recover',params=dict(file=p.get('file',''),mode='deleted')),dict(title='PhotoRec 签名恢复',action='disk_photorec',params=dict(file=p.get('file','')))])
        tool=shutil.which('extundelete')
        if not tool:raise ValueError('请先在 Kali 安装 extundelete。')
        selector=p.get('selector','all');argv=[tool,str(path)]
        if selector=='all':argv+=['--restore-all']
        elif selector=='inode':argv+=['--restore-inode',str(integer(p,'inode',2,1))]
        elif selector=='file':
            name=p.get('path','').strip()
            if not name or name.startswith(('/', '-')) or '..' in Path(name).parts:raise ValueError('请输入分区内的相对文件路径。')
            argv+=['--restore-file',name]
        else:raise ValueError('恢复选择无效')
        proc=subprocess.run(argv,cwd=out,capture_output=True,timeout=300)
        (out/'extundelete.txt').write_bytes(proc.stdout+proc.stderr)
        if proc.returncode:raise ValueError('extundelete 未完成，查看诊断；确认输入是未挂载的 Ext 分区副本。')
        return dict(kind='casework',title='Ext 日志恢复',columns=['输出目录','退出码'],rows=[['RECOVERED_FILES',proc.returncode]],note='请逐个校验恢复内容。')
    raise ValueError('未知工作台操作')

def main():
    ap=argparse.ArgumentParser();ap.add_argument('task');ap.add_argument('--args',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--kit',type=Path,required=True);ap.add_argument('--labs',type=Path,required=True);a=ap.parse_args()
    try:
        if a.args.stat().st_size>MIB:raise ValueError('参数文件过大')
        p=json.loads(a.args.read_text(encoding='utf-8'));out=a.out.resolve();out.mkdir(parents=True,exist_ok=True);labs=a.labs.resolve();path=Path(p['_file']).resolve() if p.get('_file') else None
        if path and (not path.is_relative_to(labs) or not path.is_file()):raise ValueError('输入文件不在附件目录中。')
        value=run(a.task,path,out,a.kit.resolve(),labs,p)
        (out/'result.json').write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')
        (out/'结果报告.html').write_text('<!doctype html><meta charset="utf-8"><title>取证分析结果</title><style>body{font:15px/1.8 Microsoft YaHei;background:#f7f8f2;color:#193c33;padding:32px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>'+html.escape(value.get('title','分析结果'))+'</h1><pre>'+html.escape(json.dumps(value,ensure_ascii=False,indent=2))+'</pre>',encoding='utf-8')
        print(json.dumps(dict(title=value.get('title'),result='result.json',note=value.get('note','')),ensure_ascii=False),flush=True)
    except Exception as exc:print(str(exc),file=sys.stderr);sys.exit(2)

if __name__=='__main__':main()
