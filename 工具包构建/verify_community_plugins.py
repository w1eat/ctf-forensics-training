"""Offline plugin installation checks; never access the host LSASS process."""
from pathlib import Path
import hashlib,json,os,re,subprocess,sys,time,uuid
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(Path(__file__).resolve().parent))
from learning_server import Runtime,Jobs,InputError

def main():
    folder=ROOT/'output'/('community_plugins_'+uuid.uuid4().hex[:8]);(folder/'labs').mkdir(parents=True)
    rt=Runtime(folder,ROOT/'学员工具包_Windows64');jobs=Jobs(rt);checks=[]
    original=ROOT/'练习材料/inputs/_vol2_ui_e4e0d5e71c/Challenge.raw';image=folder/'labs/中文 测试镜像.raw';os.link(original,image)
    def check(name,ok,detail=''):
        checks.append(dict(name=name,pass_=bool(ok),detail=detail));print(('PASS ' if ok else 'FAIL ')+name,flush=True)
        if not ok:raise AssertionError(name+': '+detail)
    def run(action,params):
        start=time.monotonic();job=jobs.submit(action,params)
        while not (job:=jobs.get(job['id'])).get('finished'):
            if time.monotonic()-start>240:jobs.stop(job);raise AssertionError('Timeout '+action)
            time.sleep(.1)
        return jobs.public(job)
    def native(name,argv,cwd,contains=None,env=None):
        with (folder/(name+'.txt')).open('wb') as out,(folder/(name+'.stderr.txt')).open('wb') as err:
            result=subprocess.run(argv,cwd=cwd,stdout=out,stderr=err,env=env,timeout=180)
        raw=(folder/(name+'.txt')).read_bytes()
        check(name,result.returncode==0 and (contains is None or contains.encode() in raw))
        return raw
    try:
        before=hashlib.file_digest(original.open('rb'),'sha256').hexdigest()
        for plugin,token in [('mimikatz','mimikatz offline'),('bitlocker','FVEK'),('editbox','Edit controls')]:
            j=run('vol2_help',dict(plugin=plugin));check('Course Vol2 help '+plugin,j['state']=='completed' and token in j['text'] and 'Failed to import' not in j['text'])
        for plugin in ('vol_pypykatz.pypykatz','bitlocker.BitlockerFVEKScan'):
            j=run('vol_help',dict(plugin=plugin));check('Course Vol3 help '+plugin,j['state']=='completed' and plugin in j['text'])
        p=dict(file=image.name,profile='Win7SP1x86',plugin='mimikatz')
        j=run('vol2_extra',p);check('Workbench Vol2 mimikatz processes real RAM',j['state']=='completed' and 'Traceback' not in j['text'])
        j=run('vol_extra',dict(file=image.name,plugin='vol_pypykatz.pypykatz'))
        check('Workbench Vol3 pypykatz returns a real credential schema',j['state']=='completed' and 'credtype' in j['data']['columns'] and len(j['data']['rows'])>0)
        check('Full JSON result is downloadable',any(f['name']=='社区插件完整结果.json' for f in j['files']))
        j=run('vol_extra',dict(file=image.name,plugin='bitlocker.BitlockerFVEKScan',tags='FVEc'))
        check('BitLocker scanner handles a negative teaching sample',j['state']=='completed' and j['data']['rows']==[],'No encrypted-volume positive sample supplied; not an unlock validation.')
        for action,params in [('vol_extra',dict(file=image.name,plugin='volshell')),('vol_extra',dict(file=image.name,plugin='bitlocker.BitlockerFVEKScan',tags='FVEc,--dump')),('vol2_extra',dict(file=image.name,profile='Win7SP1x86;whoami')),('vol2_extra',dict(file=image.name,profile='Win7SP1x86',plugin='editbox',pid='1;whoami'))]:
            try:rt.plan(action,params,folder/'bad');check('Invalid extra-plugin parameters rejected '+action,False)
            except (ValueError,OSError):check('Invalid extra-plugin parameters rejected '+action,True)
        local2=Path(r'E:\CTF\ctf工具箱\数字取证\volatility-master\volatility-master')
        local3=Path(r'E:\CTF\ctf工具箱\数字取证\volatility3')
        env=os.environ.copy();env.pop('PYTHONUTF8',None);env.pop('PYTHONIOENCODING',None)
        exe2=str(local2/'vol.exe');extra='--plugins='+str(local2/'extra_plugins');cache='--cache-directory=output/cache'
        for plugin,token in [('mimikatz','mimikatz offline'),('bitlocker','FVEK'),('editbox','Edit controls')]:
            native('Local Vol2 help '+plugin,[exe2,extra,cache,plugin,'-h'],folder,token,env)
        native('Local Vol2 mimikatz actual RAM',[exe2,extra,cache,'-f',str(image),'--profile=Win7SP1x86','mimikatz'],folder,env=env)
        for plugin in ('vol_pypykatz.pypykatz','bitlocker.BitlockerFVEKScan'):
            native('Local Vol3 help '+plugin,[str(local3/'venv/Scripts/python.exe'),str(local3/'vol.py'),plugin,'-h'],local3,plugin)
        raw=native('Local Vol3 pypykatz actual RAM',[str(local3/'venv/Scripts/python.exe'),str(local3/'vol.py'),'--cache-path',str(local3),'--offline','-q','-r','json','-f',str(image),'vol_pypykatz.pypykatz'],local3)
        parsed=json.loads(raw[raw.index(b'['):]);check('Local Vol3 returns structured offline records',bool(parsed) and 'credtype' in parsed[0])
        check('Original pre-existing Vol2 plugin remains present',(local2/'plugins/mimikatz.py').is_file())
        check('Original RAM fingerprint unchanged',before==hashlib.file_digest(original.open('rb'),'sha256').hexdigest())
    except Exception as exc:
        if not checks or checks[-1]['pass_']:checks.append(dict(name='Verification execution completed',pass_=False,detail=type(exc).__name__))
        raise
    finally:
        jobs.close()
        record=dict(date='2026-10-21',total=len(checks),passed=sum(c['pass_'] for c in checks),checks=checks,validation_folder=str(folder),real_ram_parsed=True,local_installations_verified=True,host_lsass_accessed=False,bitlocker_positive_volume_tested=False,kali_executed=False)
        (ROOT/'output/Volatility社区插件验收.json').write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in record.items() if k not in ('checks','validation_folder')},ensure_ascii=False))

if __name__=='__main__':main()
