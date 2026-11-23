"""Version-aware Windows memory triage; preserves failures and actual parameters."""
from pathlib import Path
import json,os,re,shutil,subprocess,sys,time

ROUTES={
 'general':{'3':['pslist','pstree','cmdline','filescan'],'2':['pslist','pstree','cmdline','filescan']},
 'history':{'3':['pslist','cmdline','cmdscan','consoles'],'2':['pslist','cmdline','cmdscan','consoles']},
 'files':{'3':['pslist','cmdline','filescan','mftscan.MFTScan','mftscan.ResidentData'],'2':['pslist','cmdline','filescan','mftparser']},
 'registry':{'3':['registry.hivelist','registry.printkey'],'2':['hivelist']},
 'credentials':{'3':['registry.hivelist','registry.hashdump','@vol_pypykatz.pypykatz'],'2':['hivelist','hashdump','mimikatz']},
 'container':{'3':['pslist','cmdline','truecrypt.Passphrase'],'2':['pslist','cmdline','truecryptsummary','truecryptpassphrase']},
 'clipboard':{'3':['pslist','cmdline'],'2':['pslist','clipboard']},
}

def triage(path,out,kit,p):
    version=p.get('version','3');route=p.get('route','general');profile=p.get('profile','').strip()
    if version not in ('2','3') or route not in ROUTES:raise ValueError('内存路线无效')
    if profile and not re.fullmatch('[A-Za-z][A-Za-z0-9_]{1,79}',profile):raise ValueError('Vol2 profile 名称无效')
    env=os.environ.copy();file=p.get('file','');records=[];tables=[];next_actions=[]
    if version=='3':
        vol=[str(kit/'runtime/python/python.exe'),str(kit/'tools/volatility3/vol.py')] if os.name=='nt' else [shutil.which('vol')] if shutil.which('vol') else [sys.executable,'-c','from volatility3.cli import main; main()']
        if os.environ.get('CTF_FORENSICS_MODE','full')!='basic' and (kit/'tools/volatility3_extra').is_dir():vol+=['-p',str(kit/'tools/volatility3_extra')]
        base=vol+['--offline','-r','json','-f',str(path)];plugins=['info']+ROUTES[route]['3']
    else:
        env.pop('PYTHONIOENCODING',None);env.pop('PYTHONUTF8',None)
        exe=kit/('tools/volatility2/windows/volatility_2.6_win64_standalone.exe' if os.name=='nt' else 'tools/volatility2/linux/volatility_2.6_lin64_standalone')
        cache=out/'_cache';cache.mkdir(exist_ok=True);base=[str(exe)]
        if os.environ.get('CTF_FORENSICS_MODE','full')!='basic':base+=['--plugins='+str(kit/'tools/volatility2/extra_plugins')]
        base+=['--cache-directory='+os.path.relpath(cache,Path.cwd()),'-f',str(path)]
        if profile:base+=['--profile='+profile]
        plugins=['kdbgscan']+ROUTES[route]['2'] if profile else ['imageinfo']
    if os.environ.get('CTF_FORENSICS_MODE','full')=='basic':plugins=[n for n in plugins if n not in ('mimikatz','@vol_pypykatz.pypykatz')]
    for plugin in plugins:
        name=re.sub('[^A-Za-z0-9_]','_',plugin);stdout=out/(name+'.txt');stderr=out/(name+'.diagnostics.txt');argv=base+[(plugin[1:] if plugin.startswith('@') else 'windows.'+plugin) if version=='3' else plugin];start=time.monotonic();limited=False
        with stdout.open('wb') as stream,stderr.open('wb') as errors:
            proc=subprocess.Popen(argv,stdout=stream,stderr=errors,stdin=subprocess.DEVNULL,env=env,shell=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            while proc.poll() is None:
                if time.monotonic()-start>150 or stdout.stat().st_size>16*1024**2:limited=True;proc.kill();break
                time.sleep(.2)
            proc.wait(timeout=10)
        raw=stdout.read_bytes()[:1024**2]
        try:text=raw.decode('utf-8')
        except UnicodeError:text=raw.decode('mbcs' if os.name=='nt' else 'utf-8','replace')
        diagnostics=stderr.read_bytes()[:8192].decode('utf-8','replace');status='通过' if proc.returncode==0 and not limited else '未完成 / 不适用'
        records.append(dict(plugin=plugin,exit_code=proc.returncode,limited=limited,seconds=round(time.monotonic()-start,2),output=stdout.name,diagnostics=diagnostics))
        if version=='3' and proc.returncode==0:
            try:
                from forensic_workflows import flatten_json
                rows=flatten_json(json.loads(text))
                columns=list(dict.fromkeys(k for row in rows[:100] for k in row if not k.startswith('__')))
                tables.append(dict(title=plugin,columns=columns,rows=[[row.get(k,'') for k in columns] for row in rows[:200]]))
            except ValueError:tables.append(dict(title=plugin,columns=['输出预览'],rows=[[line] for line in text.splitlines()[:120]]))
        else:tables.append(dict(title=plugin+' · '+status,columns=['输出预览'],rows=[[line] for line in text.splitlines()[:120]]))
        if len(records)==1 and (proc.returncode!=0 or limited):break
    common=dict(file=file)
    if version=='2':
        common['profile']=profile
        next_actions += [dict(title='核对 profile 与 KDBG',action='vol2_identify',params=dict(common,plugin='kdbgscan')),dict(title='查看 MFT / 剪贴板 / 口令线索',action='vol2_artifacts',params=common),dict(title='按当前对象地址导出缓存',action='vol2_dumpfiles',params=common)]
    else:next_actions += [dict(title='按 PID 检查文件句柄',action='vol_handles',params=common),dict(title='查看注册表',action='vol_registry',params=common),dict(title='定向导出进程映射页',action='vol_memmap',params=common),dict(title='旧系统兼容：识别 Vol2 profile',action='vol2_identify',params=common)]
    note='先验证系统解析，再依据进程、参数与对象选择导出；报告保留单项失败，不把空输出等同于不存在。Vol3 离线运行，需要匹配符号。'
    if version=='2' and not profile:note='当前只运行 imageinfo。候选不等于最终 profile；用 kdbgscan / pslist 核对后填入 profile，再运行所选路线。'
    if route=='clipboard' and version=='3':note+=' 当前包的 Vol3 没有 stock clipboard 插件；使用 Vol2 兼容插件或定向进程页检索，未伪装运行不存在的插件。'
    return dict(kind='casework',operation='memory_triage',title='Vol'+version+' · '+route,tables=tables,columns=['步骤 / 插件','退出码','秒数','完整输出'],rows=[[r['plugin'],r['exit_code'],r['seconds'],r['output']] for r in records],steps=records,partial=any(r['exit_code'] or r['limited'] for r in records),next_actions=next_actions,note=note)
