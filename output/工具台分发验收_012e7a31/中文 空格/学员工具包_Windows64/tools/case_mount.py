"""Prepare and execute workspace-owned read-only mounts; no physical disks."""
from pathlib import Path
import ctypes,json,os,re,shlex,shutil,subprocess

def kali_command(path,out,method,offset):
    if method in ('veracrypt','truecrypt'):
        argv=['veracrypt','--text','--mount',str(path),str(out/'mounted'),'--mount-options=ro']
        if method=='truecrypt':argv.insert(2,'--truecrypt')
        return argv
    if path.suffix.lower() in ('.vmdk','.e01','.vhd','.vhdx'):
        raise ValueError('Kali 的 loop 挂载需要 RAW 副本；请先用镜像转换，不能把虚拟磁盘容器直接当 RAW。')
    with path.open('rb') as stream:stream.seek(offset+1080);is_ext=stream.read(2)==b'\x53\xef'
    options='ro,'+('noload,' if is_ext else '')+'loop,offset='+str(offset)
    return ['mount','-o',options,str(path),str(out/'mounted')]

def mount(path,out,kit,labs,p):
    method=p.get('method','imdisk');mode=p.get('mode','plan');drive=p.get('drive','R').upper().rstrip(':')
    if method not in ('imdisk','windows','veracrypt','truecrypt') or mode not in ('plan','status','mount','unmount','install_imdisk'):raise ValueError('挂载方式无效')
    if not re.fullmatch('[R-Z]',drive):raise ValueError('盘符限 R～Z，不能选择系统盘符。')
    sector=int(p.get('sector','0') or '0',0);sector_size=int(p.get('sector_size','512'))
    if sector<0 or sector_size not in (512,4096):raise ValueError('分区扇区参数无效')
    registry=labs/'out/_mount_registry.json';registry.parent.mkdir(parents=True,exist_ok=True)
    def records():
        if not registry.is_file():return []
        value=json.loads(registry.read_text(encoding='utf-8-sig'));return value if isinstance(value,list) else [value]
    if mode=='status':
        rows=records();installed=False
        if os.name=='nt':
            service=subprocess.run([str(Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/sc.exe'),'query','imdisk'],capture_output=True,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0));installed=service.returncode==0
        note='仅列本工作区创建的记录，不列举或卸载其他磁盘。ImDisk 驱动状态：'+('已安装' if installed else '未检测到')
        if os.name!='nt':note='Kali 挂载脚本由终端手动运行，此处不跟踪终端挂载；请使用 findmnt 核对原挂载目录。'
        return dict(kind='casework',title='本工作区挂载状态',columns=['盘符','方式','输入镜像','只读','创建时间'],rows=[[r.get('drive'),r.get('method'),r.get('image'),r.get('readonly'),r.get('created')] for r in rows],driver_installed=installed,note=note)
    offset=sector*sector_size
    if method=='imdisk' and mode=='mount':
        from case_disk import image_source
        resolved=image_source(path)
        if resolved==path and path.suffix.lower() in ('.vmdk','.e01','.vhd','.vhdx'):raise ValueError('虚拟磁盘 / EWF 先转换为 RAW，或为 VHD/VHDX 选择 Windows 挂载。')
        path=resolved
    if mode=='plan':
        note='先确认文件系统与分区起点。挂载只允许只读；卸载只处理本工作区记录的盘符。Windows 的原生文件系统驱动不能浏览 Ext4。'
        command=[str(kit/'tools/imdisk/cli/amd64/imdisk.exe'),'-a','-t','file','-f',str(path),'-b',str(offset),'-o','ro','-m',drive+':']
        if method=='windows':command=['Mount-DiskImage','-ImagePath',str(path),'-Access','ReadOnly']
        if method in ('veracrypt','truecrypt'):command=[str(kit/'tools/veracrypt/VeraCrypt.exe'),'/volume',str(path),'/letter',drive,'/mountoption','readonly','/password','<在界面输入的已知口令>']
        if method=='truecrypt':
            command[0]=str(kit/'tools/veracrypt_legacy/VeraCrypt.exe');command+=['/truecrypt'];note+=' 旧 TrueCrypt 容器使用随包 1.25.9 兼容运行文件；1.26.29 已移除 TrueCrypt 模式。'
        if os.name!='nt':command=kali_command(path,out,method,offset)
        quote=lambda value:"'"+str(value).replace("'","''")+"'"
        shown=('Mount-DiskImage -ImagePath '+quote(path)+' -Access ReadOnly' if method=='windows' else '& '+' '.join(map(quote,command))) if os.name=='nt' else shlex.join(command)
        platform=['Windows 权限','系统挂载 / 驱动需要管理员，执行时可能出现 UAC'] if os.name=='nt' else ['Kali Bash','工作台只生成脚本；在终端使用 sudo bash 运行，Ext 自动增加 noload']
        public={k:v for k,v in p.items() if k not in ('password','_file','keyfile')}
        return dict(kind='casework',title='只读挂载准备',columns=['参数','值'],rows=[['方式',method],['字节偏移',offset],['计划命令',shown],platform,['普通查看 / 恢复','使用镜像目录与恢复工具，无需系统挂载']],note=note,next_actions=[dict(title='执行只读挂载' if os.name=='nt' else '生成 Kali 挂载脚本',action='disk_mount',params=dict(public,mode='mount')),dict(title='检查当前挂载和驱动状态',action='disk_mount',params=dict(public,mode='status'))])
    if os.name!='nt':
        if mode=='install_imdisk':raise ValueError('ImDisk 驱动仅用于 Windows；Kali 使用原生 loop 挂载。')
        if mode=='unmount':return dict(kind='casework',title='Kali 卸载方法',columns=['Kali Bash','说明'],rows=[["sudo umount -- '原挂载目录'",'填写之前脚本中使用的真实目录，先关闭打开的文件。']],note='此处未执行系统卸载。终端挂载不受 Windows 盘符记录管理；用 findmnt 核对实际挂载点后操作。')
        mountpoint=out/'mounted';mountpoint.mkdir(exist_ok=True)
        command=kali_command(path,out,method,offset)
        script=out/'只读挂载_Kali.sh';script.write_text('#!/bin/bash\nset -euo pipefail\n'+' '.join(shlex.quote(v) for v in command)+'\n',encoding='utf-8')
        return dict(kind='casework',title='Kali 只读挂载脚本',columns=['文件','运行环境'],rows=[[script.name,'Kali Bash：使用 sudo bash 运行，密码由终端交互输入']],note='脚本已生成，尚未在系统挂载。Ext3/Ext4 使用 noload 避免日志重放，其他文件系统应使用对应只读选项。')
    request=dict(mode=mode,method=method,drive=drive,image=str(path),offset=offset,kit=str(kit),labs=str(labs),registry=str(registry),result=str(out/'_mount_result.json'),password=p.get('password',''),pim=p.get('pim',''),keyfile=p.get('keyfile',''))
    args=out/'_mount_request.json';args.write_text(json.dumps(request,ensure_ascii=False),encoding='utf-8')
    ps=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/WindowsPowerShell/v1.0/powershell.exe'
    script=Path(__file__).with_name('mount_ops.ps1')
    try:
        subprocess.run([str(ps),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(script),'-RequestPath',str(args)],capture_output=True,timeout=240,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        rp=out/'_mount_result.json'
        if not rp.is_file():raise ValueError('系统操作没有返回结果；可能取消了 UAC。')
        response=json.loads(rp.read_text(encoding='utf-8-sig'))
        if response.get('status')=='failed':raise ValueError(response.get('error','系统挂载失败'))
        return dict(kind='casework',title='只读挂载结果',columns=['字段','值'],rows=list(response.items()),note='系统操作已返回结果。只读挂载保持到主动卸载；不要修改源文件，记得用同一工作区的卸载入口释放盘符。',next_actions=[dict(title='浏览挂载盘并导入文件',action='mounted_files',params=dict(drive=response.get('drive',drive),mode='list'))] if response.get('status')=='mounted_readonly' else [])
    finally:
        if args.is_file():args.unlink()

def browse(labs,out,p):
    import hashlib,stat
    drive=p.get('drive','R').upper().rstrip(':')
    if os.name!='nt':raise ValueError('此入口用于本工作区创建的 Windows 挂载盘；Kali 可从挂载目录导入附件。')
    registry=labs/'out/_mount_registry.json'
    if not registry.is_file():raise ValueError('本工作区没有挂载记录。')
    records=json.loads(registry.read_text(encoding='utf-8-sig'));records=records if isinstance(records,list) else [records]
    if not re.fullmatch('[R-Z]',drive) or not any(r.get('drive')==drive and r.get('readonly') for r in records):raise ValueError('只能访问本工作区创建的只读挂载盘。')
    record=next(r for r in records if r.get('drive')==drive)
    serial=ctypes.c_ulong()
    ok=ctypes.windll.kernel32.GetVolumeInformationW(drive+':\\',None,0,ctypes.byref(serial),None,None,None,0)
    if not ok:raise ValueError('挂载卷尚未就绪或文件系统不受 Windows 支持。')
    if record.get('serial') and str(record['serial']).replace('-','').upper()!=f'{serial.value:08X}':raise ValueError('该盘符的卷身份已改变，拒绝读取其他卷。')
    root=Path(drive+':/');relative=p.get('relative','').replace('\\','/')
    target=(root/relative).resolve()
    if not target.is_relative_to(root.resolve()) or not target.exists():raise ValueError('路径越界或不存在。')
    if p.get('mode','list')=='import':
        if not target.is_file() or target.is_symlink() or target.stat().st_size>64*1024**2:raise ValueError('只能导入最多 64 MiB 的普通文件。')
        dest=out/('imported'+target.suffix);shutil.copyfile(target,dest)
        return dict(kind='casework',title='已导入挂载盘文件',columns=['原路径','输出','SHA256'],rows=[[str(target),dest.name,hashlib.file_digest(dest.open('rb'),'sha256').hexdigest()]],note='副本已进入本次任务目录，可直接作为下一步输入。')
    if not target.is_dir():raise ValueError('目录不存在；导入文件时请选择 import。')
    entries=[]
    for child in sorted(target.iterdir(),key=lambda c:(not c.is_dir(),c.name.casefold())):
        if len(entries)>=1000:break
        attributes=getattr(child.lstat(),'st_file_attributes',0)
        if child.is_symlink() or attributes&getattr(stat,'FILE_ATTRIBUTE_REPARSE_POINT',1024):continue
        entries.append(dict(path=child.relative_to(root).as_posix(),name=child.name,directory=child.is_dir(),bytes=child.stat().st_size if child.is_file() else None))
    return dict(kind='casework',operation='mounted_files',title='挂载盘目录',drive=drive,relative=relative,entries=entries,columns=['名称','类型','字节数'],rows=[[e['name'],'目录' if e['directory'] else '文件',e['bytes']] for e in entries],note='只浏览本工作区挂载的卷，跳过符号链接和重解析点。选择文件即可复制进工作台继续分析。')
