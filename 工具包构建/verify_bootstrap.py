"""Test first run without Python on PATH, missing files, basic mode and hashes."""
from pathlib import Path
import hashlib,json,os,re,shutil,subprocess,sys,time,urllib.request,urllib.error,uuid
ROOT=Path(__file__).resolve().parent.parent
SOURCE=ROOT/'学员工具包_Windows64'

def main():
    qa=ROOT/'output'/('安装验收_'+uuid.uuid4().hex[:8]);kit=qa/'无Python (新手!)'/'学员工具包_Windows64';kit.mkdir(parents=True)
    manifest=(SOURCE/'SHA256SUMS.txt').read_text(encoding='utf-8').splitlines()
    for line in manifest:
        _,name=line.split('  ',1);dst=kit/name;dst.parent.mkdir(parents=True,exist_ok=True);os.link(SOURCE/name,dst)
    shutil.copy2(SOURCE/'SHA256SUMS.txt',kit/'SHA256SUMS.txt')
    env=os.environ.copy();system=Path(env.get('SystemRoot',r'C:\Windows'))
    env['PATH']=str(system/'System32');env['PYTHONHOME']=str(qa/'does-not-exist');env['PYTHONPATH']=str(qa/'does-not-exist')
    env.pop('CTF_FORENSICS_MODE',None)
    ps=system/'System32/WindowsPowerShell/v1.0/powershell.exe';cmd=system/'System32/cmd.exe'
    checks=[];saved={};processes=[]
    def check(name,ok,detail=''):
        checks.append(dict(name=name,pass_=bool(ok),detail=str(detail)[:600]));print(('PASS ' if ok else 'FAIL ')+name,flush=True)
        if not ok:raise AssertionError(name+': '+str(detail))
    def latest():
        records=sorted((kit/'labs/out/setup_runs').glob('*/环境检查.json'),key=lambda p:p.stat().st_mtime_ns)
        return json.loads(records[-1].read_text(encoding='utf-8-sig'))
    def run(name,mode='Setup',expected=0):
        argv=[str(ps),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(kit/'tools/bootstrap.ps1'),'-WorkspaceRoot',str(kit),'-Mode',mode,'-NoLaunch','-NoBrowser','-NonInteractive','-NoSystemChanges']
        r=subprocess.run(argv,cwd=qa,env=env,capture_output=True,timeout=180)
        (qa/(name+'.log')).write_bytes(r.stdout+r.stderr)
        check(name,r.returncode==expected,r.stdout.decode('utf-8','replace')[-500:])
        record=latest();check(name+' produces a structured report',record['exit_code']==expected)
        return record
    def withhold(name):
        src=kit/name;dst=qa/'withheld'/name;dst.parent.mkdir(parents=True,exist_ok=True)
        assert src.resolve().is_relative_to(kit.resolve()) and dst.resolve().is_relative_to(qa.resolve())
        src.rename(dst);saved[name]=dst
    def restore(name):
        dst=kit/name;src=saved.pop(name);src.rename(dst)
    def request(base,token,path,data=None):
        headers={'Authorization':'Bearer '+token}
        if data is not None:headers['Content-Type']='application/json'
        req=urllib.request.Request(base+path,headers=headers,data=json.dumps(data).encode() if data is not None else None)
        with urllib.request.urlopen(req,timeout=10) as response:return json.load(response)
    def service(name,launcher,args):
        out=qa/(name+'.stdout.txt');err=qa/(name+'.stderr.txt')
        quoted='"'+str(kit/launcher)+'" '+args
        streams=(out.open('wb'),err.open('wb'))
        command=str(cmd)+' /d /s /c "'+quoted+'"'
        p=subprocess.Popen(command,cwd=qa,env=env,stdout=streams[0],stderr=streams[1],stdin=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        processes.append((p,streams));deadline=time.monotonic()+120;match=None
        while time.monotonic()<deadline:
            if out.exists():match=re.search(r'http://127\.0\.0\.1:(\d+)/index\.html#token=([A-Za-z0-9_-]+)',out.read_text(encoding='utf-8',errors='replace'))
            if match:break
            if p.poll() is not None:break
            time.sleep(.2)
        check(name+' starts without a system Python',bool(match),(out.read_text(encoding='utf-8',errors='replace')+err.read_text(encoding='utf-8',errors='replace'))[-600:])
        return p,'http://127.0.0.1:'+match[1],match[2]
    try:
        r=subprocess.run([str(cmd),'/d','/c','where python'],env=env,capture_output=True)
        check('System Python is absent from the test PATH',r.returncode!=0)
        ready=run('First run with clean PATH')
        check('All bundled runtime checks pass',all(r['status']=='pass' for r in ready['checks']) and len(ready['checks'])>=18)
        check('Bootstrap does not install software or alter protection on a ready system',ready['vc_runtime_installed'] is False and ready['system_security_settings_changed'] is False)
        cached=run('Subsequent launch reuses valid checks','Launch');check('Cache is used after critical file verification',cached['cached'] is True)
        for n in ('tools/volatility2/extra_plugins/mimikatz.py','tools/volatility3_extra/vol_pypykatz.py'):withhold(n)
        partial=run('Missing community files allow basic operation',expected=10)
        check('Missing extensions are named and not automatically restored',partial['basic_mode'] and len(partial['missing_files'])>=2 and all(not (kit/n).exists() for n in saved))
        basic=run('Explicit basic mode needs no community plugins','Basic')
        check('Basic probe skips community imports',not any(r['group']=='community' for r in basic['checks']))
        p,base,token=service('Basic launcher','06_仅基础工具启动.cmd','-NoBrowser -NonInteractive -NoSystemChanges')
        state=request(base,token,'/api/state');check('Basic mode is exposed by the local API',state['community_enabled'] is False)
        j=request(base,token,'/api/run',dict(action='file_type',params=dict(file='01_file/unknown.dat')))
        while j['state'] in ('queued','running'):time.sleep(.1);j=request(base,token,'/api/jobs/'+j['id'])
        check('Actual file analysis works while community files are absent',j['state']=='completed' and 'PNG' in j['text'])
        try:request(base,token,'/api/preview',dict(action='vol_extra',params={}));check('Community execution is blocked in basic mode',False)
        except urllib.error.HTTPError as exc:check('Community execution is blocked in basic mode',exc.code==400)
        subprocess.run(['taskkill','/PID',str(p.pid),'/T','/F'],capture_output=True);p.wait(timeout=10)
        withhold('runtime/python/python.exe');missing_python=run('Missing portable Python is diagnosed',expected=20)
        check('Missing Python report explains the portable runtime requirement',any('基础运行文件缺失' in x['text'] for x in missing_python['issues']))
        restore('runtime/python/python.exe')
        for n in list(saved):restore(n)
        target=kit/'tools/setup_probe.py';target.unlink();target.write_bytes((SOURCE/'tools/setup_probe.py').read_bytes()+b'\nraise RuntimeError("tamper sentinel")\n')
        changed=run('Hash mismatch stops before running the modified helper',expected=20)
        check('Modified helper is recorded',changed['modified_files']==['tools/setup_probe.py'])
        target.unlink();os.link(SOURCE/'tools/setup_probe.py',target)
        run('Restored official files pass again')
        p,base,token=service('Legacy launcher','00_启动学习平台.cmd','--no-browser')
        check('Original launcher still starts full mode',request(base,token,'/api/state')['community_enabled'] is True)
        subprocess.run(['taskkill','/PID',str(p.pid),'/T','/F'],capture_output=True);p.wait(timeout=10)
        signature=subprocess.run([str(ps),'-NoProfile','-Command',"$env:PSModulePath=(Join-Path $PSHOME 'Modules')+[IO.Path]::PathSeparator+$env:PSModulePath;$s=Get-AuthenticodeSignature -LiteralPath '"+str(kit/'setup/vendor/VC_redist.x64.exe').replace("'","''")+"';@{valid=($s.Status -eq 'Valid');microsoft=($s.SignerCertificate.Subject -match 'O=Microsoft Corporation')}|ConvertTo-Json"],env=env,capture_output=True,timeout=40)
        signature_data=json.loads(signature.stdout.decode('utf-8-sig'));check('Bundled C++ installer has a valid Microsoft signature',all(signature_data.values()))
        forbidden=re.compile(r'\b(?:Add-MpPreference|Set-MpPreference|Set-ExecutionPolicy|Disable-WindowsOptionalFeature|Remove-MpThreat|Unblock-File)\b',re.I)
        check('Installer contains no protection-disable or quarantine-restore command',not forbidden.search((kit/'tools/bootstrap.ps1').read_text(encoding='utf-8-sig')))
        check('Original helper bytes remain unchanged',hashlib.sha256((SOURCE/'tools/setup_probe.py').read_bytes()).hexdigest()==next(l.split('  ',1)[0] for l in manifest if l.endswith('  tools/setup_probe.py')))
    except Exception as exc:
        if not checks or checks[-1]['pass_']:checks.append(dict(name='Installer verification completed',pass_=False,detail=type(exc).__name__))
        raise
    finally:
        for process,streams in processes:
            if process.poll() is None:subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],capture_output=True)
            for stream in streams:stream.close()
        result=dict(date='2026-10-21',passed=sum(c['pass_'] for c in checks),total=len(checks),checks=checks,validation_folder=str(qa),system_python_on_path=False,clean_vm_tested=False,vc_system_install_executed=False,defender_settings_changed=False,kali_executed=False)
        (ROOT/'output/新手环境安装验收.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('checks','validation_folder')},ensure_ascii=False))

if __name__=='__main__':main()
