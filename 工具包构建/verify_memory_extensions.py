"""Validate new standard plugin routes and registry offsets on a real old RAM."""
from pathlib import Path
import hashlib,json,os,re,sys,time,uuid
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(Path(__file__).resolve().parent))
from learning_server import Runtime,Jobs

def main():
    folder=ROOT/'output'/('memory_extension_'+uuid.uuid4().hex[:8]);(folder/'labs').mkdir(parents=True)
    rt=Runtime(folder,ROOT/'学员工具包_Windows64');jobs=Jobs(rt);checks=[]
    source=ROOT/'练习材料/inputs/_vol2_ui_e4e0d5e71c/Challenge.raw'
    target=folder/'labs/中文 镜像.raw';os.link(source,target)
    def check(name,ok,detail=''):
        checks.append(dict(name=name,pass_=bool(ok),detail=str(detail)[:400]))
        print(('PASS ' if ok else 'FAIL ')+name,flush=True)
        if not ok:raise AssertionError(name+': '+str(detail))
    def run(action,p):
        start=time.monotonic();job=jobs.submit(action,p)
        while not (job:=jobs.get(job['id'])).get('finished'):
            if time.monotonic()-start>500:jobs.stop(job);raise AssertionError('Timeout '+action)
            time.sleep(.1)
        return jobs.public(job)
    try:
        before=hashlib.file_digest(source.open('rb'),'sha256').hexdigest()
        for version,plugin,expected in [
            ('3','mftscan.ResidentData','ResidentData'),
            ('3','registry.printkey','--offset'),
            ('3','truecrypt.Passphrase','Passphrase'),
            ('3','malware.malfind','Malfind'),
            ('2','clipboard','Clipboard'),
            ('2','mftparser','-D'),
            ('2','truecryptmaster','-D'),
            ('2','printkey','-o'),
        ]:
            result=run('vol_help' if version=='3' else 'vol2_help',dict(plugin=plugin))
            check('Stock help Vol'+version+' '+plugin,result['state']=='completed' and expected.lower() in result['text'].lower(),result.get('error'))
        params=dict(file=target.name,profile='Win7SP1x86')
        hive=run('vol2_registry',dict(params,plugin='hivelist'))
        matches=re.findall(r'^(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+.*\\SYSTEM\s*$',hive['text'],re.M|re.I)
        check('SYSTEM virtual Hive address comes from actual hivelist',hive['state']=='completed' and bool(matches))
        selection=run('vol2_registry',dict(params,plugin='printkey',address=matches[0],key='Select'))
        current=re.search(r'REG_DWORD\s+Current\s*:\s*(?:\(S\)\s*)?(0x[0-9a-fA-F]+|\d+)',selection['text'])
        check('Select Current is parsed from the same Hive',selection['state']=='completed' and bool(current))
        number=int(current[1],0);key=f'ControlSet{number:03d}\\Control\\ComputerName\\ComputerName'
        host=run('vol2_registry',dict(params,plugin='printkey',address=matches[0],key=key))
        check('Active ControlSet hostname query succeeds',host['state']=='completed' and 'REG_SZ' in host['text'] and 'ComputerName' in host['text'])
        clipboard=run('vol2_artifacts',dict(params,plugin='clipboard'))
        check('Actual clipboard standard plugin executes',clipboard['state']=='completed','A successful empty result is not evidence of a recovered clipboard flag.')
        triage=run('memory_triage',dict(params,version='2',route='registry'))
        check('Route runs KDBG before registry and retains both outputs',triage['state']=='completed' and [s['plugin'] for s in triage['data']['steps']]==['kdbgscan','hivelist'] and not triage['data']['partial'])
        check('RAM source hash unchanged',before==hashlib.file_digest(source.open('rb'),'sha256').hexdigest())
    finally:
        jobs.close()
        result=dict(date='2026-10-21',passed=sum(c['pass_'] for c in checks),total=len(checks),checks=checks,validation_folder=str(folder),real_ram_parsed=True,kali_executed=False)
        (ROOT/'output/工作台内存扩展验收.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(passed=result['passed'],total=result['total'])))

if __name__=='__main__':main()
