"""Structured, offline runtime checks. Uses only the bundled Python executable."""
from pathlib import Path
import argparse,hashlib,importlib,json,os,platform,struct,subprocess,sys,time

def probe(kit,labs,basic=False):
    if os.name=='nt':
        import ctypes
        ctypes.windll.kernel32.SetErrorMode(0x8003)
    checks=[]
    env=os.environ.copy()
    for name in ('PYTHONHOME','PYTHONPATH'):env.pop(name,None)
    env.update(PYTHONUTF8='1',PYTHONIOENCODING='utf-8',PYTHONNOUSERSITE='1',PYTHONDONTWRITEBYTECODE='1',LANG='C')
    system=Path(os.environ.get('SystemRoot',r'C:\Windows'))
    env['PATH']=os.pathsep.join(map(str,[kit/'runtime/python',kit/'runtime/ruby/bin',kit/'tools/sleuthkit/bin',system/'System32',system]))
    env['GEM_HOME']=str(kit/'runtime/ruby/lib/ruby/gems/3.3.0')
    env['GEM_PATH']=env['GEM_HOME'];env['RUBYOPT']='-EUTF-8'
    def add(key,title,group,callback):
        start=time.monotonic()
        try:
            detail=callback()
            checks.append(dict(id=key,title=title,group=group,status='pass',detail=str(detail or '可以运行'),seconds=round(time.monotonic()-start,2)))
        except Exception as exc:
            checks.append(dict(id=key,title=title,group=group,status='failed',detail=(type(exc).__name__+': '+str(exc))[:1500],seconds=round(time.monotonic()-start,2)))
    def run(argv,contains=None,vol2=False):
        child_env=env.copy()
        if vol2:
            child_env.pop('PYTHONUTF8',None);child_env.pop('PYTHONIOENCODING',None)
        p=subprocess.run(list(map(str,argv)),cwd=labs,env=child_env,stdin=subprocess.DEVNULL,capture_output=True,timeout=50,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        raw=p.stdout+p.stderr
        if p.returncode or (contains and contains.lower().encode() not in raw.lower()):
            try:text=raw.decode('utf-8')
            except UnicodeError:text=raw.decode('mbcs' if os.name=='nt' else 'utf-8','replace')
            raise RuntimeError('退出码 '+str(p.returncode)+'；'+text[-1100:])
        if b'Failed to import volatility.plugins.mimikatz' in raw:raise RuntimeError('Vol2 社区依赖未能加载。')
        return '启动与关键输出正常'
    def imports():
        for n in ('ssl','sqlite3','ctypes','bz2','lzma','hashlib','http.server'):importlib.import_module(n)
        return platform.python_version()+' / '+str(struct.calcsize('P')*8)+' 位；来自包内 '+sys.executable
    add('python','Python 3 与标准库','core',imports)
    add('server','学习平台与文件分析入口','core',lambda:run([sys.executable,kit/'tools/learning_server.py','-h'],'--root'))
    add('python_modules','图片、PDF、PE、YARA、AES 依赖','tools',lambda:[importlib.import_module(n) and n for n in ('PIL','pypdf','pefile','yara','capstone','Crypto')])
    for key,title,path,args,token in [
        ('7zip','7-Zip 解压','tools/7zip/7z.exe',['i'],'7-Zip'),
        ('exiftool','ExifTool / 自带 Perl','tools/exiftool/exiftool.exe',['-ver'],None),
        ('sqlite','SQLite 命令工具','tools/sqlite/sqlite3.exe',['--version'],None),
        ('tsk','磁盘目录与恢复工具','tools/sleuthkit/bin/fls.exe',['-V'],'Sleuth'),
        ('busybox','strings / xxd / dd','tools/busybox/busybox.exe',['--list'],'xxd'),
        ('photorec','PhotoRec 文件恢复','tools/testdisk/photorec_win.exe',['/version'],'PhotoRec'),
        ('ruby','Ruby 运行时','runtime/ruby/bin/ruby.exe',['-v'],'ruby'),
    ]:
        def native(path=path,args=args,token=token,key=key):
            if key!='photorec':return run([kit/path,*args],token)
            previous=env.get('__COMPAT_LAYER');env['__COMPAT_LAYER']='RunAsInvoker'
            try:return run([kit/path,*args],token)
            finally:
                if previous is None:env.pop('__COMPAT_LAYER',None)
                else:env['__COMPAT_LAYER']=previous
        add(key,title,'tools',native)
    add('zsteg','zsteg 图片隐写','tools',lambda:run([kit/'runtime/ruby/bin/ruby.exe',kit/'runtime/ruby/bin/zsteg','--help'],'Usage'))
    add('pngcheck','PNG 结构校验','tools',lambda:run([kit/'tools/pngcheck/pngcheck.exe','-v',labs/'02_png/good.png'],'No errors detected'))
    add('vol3','Volatility 3 / 自带 Python 3','tools',lambda:run([sys.executable,kit/'tools/volatility3/vol.py','windows.info','-h'],'windows.info'))
    vol2=kit/'tools/volatility2/windows/volatility_2.6_win64_standalone.exe'
    add('vol2','Volatility 2 / 自带 Python 2，无需另装','tools',lambda:run([vol2,'--cache-directory=out/vol2_cache','--info'],'Win7SP1x86',True))
    def readonly_files():
        names=['tools/imdisk/cli/amd64/imdisk.exe','tools/imdisk/sys/amd64/imdisk.sys','tools/veracrypt/VeraCrypt.exe','tools/veracrypt_legacy/VeraCrypt.exe']
        missing=[n for n in names if not (kit/n).is_file()]
        if missing:raise FileNotFoundError('、'.join(missing))
        return '程序已备齐；此检查未安装驱动或挂载磁盘'
    add('mount_files','可选挂载程序','optional',readonly_files)
    if not basic:
        add('pypykatz','pypykatz 依赖与 Vol3 插件','community',lambda:run([sys.executable,kit/'tools/volatility3/vol.py','-p',kit/'tools/volatility3_extra','vol_pypykatz.pypykatz','-h'],'vol_pypykatz.pypykatz'))
        add('mimikatz','Vol2 mimikatz 隔离依赖','community',lambda:run([vol2,'--plugins='+str(kit/'tools/volatility2/extra_plugins'),'--cache-directory=out/vol2_cache','mimikatz','-h'],'mimikatz offline',True))
        add('bitlocker3','Vol3 BitLocker 插件','community',lambda:run([sys.executable,kit/'tools/volatility3/vol.py','-p',kit/'tools/volatility3_extra','bitlocker.BitlockerFVEKScan','-h'],'--tags'))
    failures=[r for r in checks if r['status']=='failed']
    needs_cpp=any(any(t in r['detail'].lower() for t in ('3221225781','-1073741515','3221225595','-1073741701','vcruntime','msvcp140','winerror 126')) for r in failures)
    ready=not any(r['group']=='core' for r in failures)
    return dict(schema=1,platform='Windows 10/11 x64',python=sys.executable,base_ready=ready,full_ready=ready and not failures,basic_requested=basic,needs_cpp_runtime=needs_cpp,checks=checks,failed_components=[r['id'] for r in failures],host_lsass_accessed=False,system_settings_changed=False)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--kit',type=Path,required=True);ap.add_argument('--labs',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--basic',action='store_true');a=ap.parse_args()
    result=probe(a.kit.resolve(),a.labs.resolve(),a.basic)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    for r in result['checks']:print(('通过' if r['status']=='pass' else '待处理')+' · '+r['title'],flush=True)
    raise SystemExit(0 if result['full_ready'] else 10 if result['base_ready'] else 20)

if __name__=='__main__':main()
