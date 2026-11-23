"""Validate the Vol2 runner, version-error handoff and a separately supplied RAM.

The optional real image is read through a hard link under an isolated QA root.
Neither the image nor its raw analysis output enters the student releases.
"""
from pathlib import Path
import argparse, hashlib, json, os, re, sys, threading, time, urllib.error, urllib.request, uuid

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(Path(__file__).resolve().parent))
from learning_server import App,Handler,ThreadingHTTPServer,volatility_compatibility


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image',type=Path,help='Optional known MemLabs Lab 0 Challenge.raw for real-image regression checks')
    args=parser.parse_args();checks=[]
    folder=ROOT/'output'/('vol2_platform_'+uuid.uuid4().hex[:10]);labs=folder/'labs';labs.mkdir(parents=True)
    app=App(folder,ROOT/'学员工具包_Windows64')
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True;server.app=app
    threading.Thread(target=server.serve_forever,daemon=True).start()
    base='http://127.0.0.1:'+str(server.server_port)
    def check(name,ok,detail=''):
        checks.append(dict(name=name,pass_=bool(ok),detail=detail))
        print(('PASS ' if ok else 'FAIL ')+name,flush=True)
        if not ok:raise AssertionError(name+' '+str(detail))
    def request(path,body=None):
        headers={'Authorization':'Bearer '+app.token}
        if body is not None:headers['Content-Type']='application/json'
        req=urllib.request.Request(base+path,headers=headers,data=json.dumps(body).encode('utf-8') if body is not None else None)
        try:
            with urllib.request.urlopen(req,timeout=10) as response:return response.status,json.loads(response.read())
        except urllib.error.HTTPError as exc:return exc.code,json.loads(exc.read())
    def run(action,params=None):
        code,job=request('/api/run',dict(action=action,params=params or {}));assert code==202,job
        deadline=time.monotonic()+200
        while job['state'] in ('running','queued'):
            assert time.monotonic()<deadline,(action,'timeout')
            time.sleep(.1);_,job=request('/api/jobs/'+job['id'])
        check('Artifacts ready: '+action,bool(job['files']) and any(f['name']=='运行报告.txt' for f in job['files']))
        return job
    fixture='Traceback: windows.cmdscan -> windows.consoles\nNotImplementedError: This version of Windows is not supported: 6.1 15.7601!'
    try:
        _,catalog=request('/api/state')
        check('Ten distinct Vol2 actions',len([a for a in catalog['actions'] if a['id'].startswith('vol2_')])==10)
        check('Vol3 actions remain available',any(a['id']=='vol_history' for a in catalog['actions']))
        job=run('vol2_help');check('Native profiles listed',job['state']=='completed' and 'Win7SP1x86' in job['text'])
        job=run('vol2_help',dict(plugin='cmdscan'));check('Native command-history help',job['state']=='completed' and 'CommandCountMax' in job['text'])
        dummy=labs/'dummy.raw';dummy.write_bytes(b'\0'*512)
        csv=labs/'synthetic.csv';csv.write_text('PID,Process\n1,example\n')
        def rejected(action,params):return request('/api/preview',dict(action=action,params=dict(file='dummy.raw',**params)))[0]==400
        check('Missing profile is rejected',rejected('vol2_history',{}))
        check('Profile argument injection is rejected',rejected('vol2_history',dict(profile='Win7SP1x86 --write')))
        check('Plugin must be allowlisted',rejected('vol2_history',dict(profile='Win7SP1x86',plugin='volshell')))
        check('PID must be numeric',rejected('vol2_memdump',dict(profile='Win7SP1x86',pid='1;whoami')))
        check('psscan PID filter is not invented',rejected('vol2_processes',dict(profile='Win7SP1x86',plugin='psscan',pid='1')))
        check('Physical offset must be numeric',rejected('vol2_dumpfiles',dict(profile='Win7SP1x86',address='--write')))
        check('Synthetic table is not RAM',request('/api/preview',dict(action='vol2_identify',params=dict(file='synthetic.csv')))[0]==400)
        diagnostic=volatility_compatibility(fixture,'inputs/actual.raw')
        check('Unsupported structure offers same input in Vol2',diagnostic['next_actions'][0]['params']['file']=='inputs/actual.raw')
        check('Missing symbols is a separate diagnosis',volatility_compatibility('Unsatisfied requirement: kernel.symbol_table_name','x.raw') is None)
        if args.image:
            source=args.image.resolve()
            with source.open('rb') as stream:before=hashlib.file_digest(stream,'sha256').hexdigest()
            link=labs/'中文 空格.raw';os.link(source,link)
            params=dict(file=link.name,profile='Win7SP1x86')
            job=run('vol2_identify',dict(file=link.name));check('Real image identified without a supplied profile',job['state']=='completed' and 'IA32PagedMemoryPae' in job['text'] and 'Win7SP1x86' in job['text'])
            job=run('vol2_identify',dict(**params,plugin='kdbgscan'));check('KDBG validates architecture and process list',job['state']=='completed' and '32bit' in job['text'] and '34 processes' in job['text'])
            job=run('vol2_processes',params);check('Real process inventory',job['state']=='completed' and 'conhost.exe' in job['text'])
            job=run('vol2_history',dict(**params,plugin='cmdscan'));check('History contains the actual script command',job['state']=='completed' and 'demon.py.txt' in job['text'])
            pid=re.search(r'CommandProcess: conhost\.exe Pid:\s*(\d+)',job['text'])[1]
            job=run('vol2_history',dict(**params,plugin='consoles'));check('Console screen recovered',job['state']=='completed' and '335d366f5d6031767631707f' in job['text'])
            job=run('vol2_files',params);check('Physical file-object inventory',job['state']=='completed' and 'Offset(P)' in job['text'])
            candidates=re.findall(r'^(0x[0-9a-fA-F]+)\s+.*\\(?:cmd|conhost)\.exe\s*$',job['text'],re.M|re.I)
            check('Use a physical offset from this filescan',bool(candidates))
            job=run('vol2_dumpfiles',dict(**params,address=candidates[0]));check('Cache export uses a real physical object',job['state']=='completed' and any(f['name'].startswith('files/') and f['bytes']>0 for f in job['files']))
            job=run('vol2_memdump',dict(**params,pid=pid));check('Process dump uses actual history PID',job['state']=='completed' and any(f['name'].startswith('process/') and f['bytes']>0 for f in job['files']))
            job=run('vol_history',dict(file=link.name,plugin='cmdscan'))
            check('Actual Vol3 failure offers compatibility actions',job['state']=='failed' and isinstance(job['data'],dict) and job['data'].get('kind')=='volatility_compatibility',job['text'][-1000:])
            check('Failure handoff retains the same source',job['data']['next_actions'][0]['params']['file']==link.name)
            with source.open('rb') as stream:after=hashlib.file_digest(stream,'sha256').hexdigest()
            check('Source bytes unchanged',before==after)
    finally:
        app.jobs.close();server.shutdown();server.server_close()
        result=dict(total=len(checks),passed=sum(v['pass_'] for v in checks),checks=checks,real_ram_parsed=bool(args.image),kali_executed=False,validation_folder=str(folder))
        (ROOT/'output/Volatility2_兼容功能验收.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(total=len(checks),passed=sum(v['pass_'] for v in checks))))


if __name__=='__main__':main()
