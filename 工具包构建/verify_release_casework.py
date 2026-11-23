"""Verify every distributed byte and smoke-test the relocated Windows runtime."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,uuid,zipfile
ROOT=Path(__file__).resolve().parent.parent

def main():
    archive=ROOT/'学员工具与练习_Windows64.zip';base=ROOT/'output'/('工具台分发验收_'+uuid.uuid4().hex[:8])/'中文 空格';base.mkdir(parents=True)
    kit=base/'学员工具包_Windows64';prefix='学员工具包_Windows64/';checks=[]
    def check(name,ok,detail=''):
        checks.append(dict(name=name,pass_=bool(ok),detail=detail));print(('PASS ' if ok else 'FAIL ')+name,flush=True)
        if not ok:raise AssertionError(name)
    with zipfile.ZipFile(archive) as z:
        names=z.namelist()
        check('User inputs and analysis results are absent',not any(n.startswith((prefix+'labs/inputs/',prefix+'labs/out/')) for n in names))
        expected=z.read(prefix+'SHA256SUMS.txt').decode('utf-8').splitlines();verified=0
        for line in expected:
            sha,name=line.split('  ',1);raw=z.read(prefix+name)
            if hashlib.sha256(raw).hexdigest()!=sha:raise AssertionError('Manifest mismatch '+name)
            target=(kit/name).resolve()
            if not target.is_relative_to(kit.resolve()):raise AssertionError('Invalid archive path')
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);verified+=1
        (kit/'SHA256SUMS.txt').write_bytes(z.read(prefix+'SHA256SUMS.txt'))
        check('All files match embedded SHA256 manifest',verified==len(names)-1,str(verified))
    manifest=json.loads((kit/'TOOL_MANIFEST.json').read_text(encoding='utf-8'))
    for t in manifest['tools']:
        if t['license_location']:assert (kit/t['license_location']).exists()
        else:assert t['license']=='Public domain',t['name']
        assert hashlib.sha256((kit/t['entry']).read_bytes()).hexdigest()==t['entry_sha256']
    check('All tool entries have matching binaries and licenses',len(manifest['tools'])==26)
    page=(kit/'index.html').read_text(encoding='utf-8');data=json.loads(page.split('<script type="application/json" id="portal-data">',1)[1].split('</script>',1)[0])
    check('Unified index has 77 operations, 21 routes and 15 examples',len(data['actions'])==77 and len(data['recipes'])==21 and len(data['cases'])==15)
    check('Every indexed document exists in relocated package',all((kit/r['href']).is_file() for r in data['resources']))
    check('New helper modules and guide are packaged',all((kit/'tools'/n).is_file() for n in ('casework.py','case_crypto.py','case_carving.py','case_disk.py','case_mount.py','case_memory.py','mount_ops.ps1')) and (kit/'PPT解题思路与工作台指南.html').is_file())
    env=os.environ.copy();env['PYTHONUTF8']='1';env['PYTHONIOENCODING']='utf-8'
    result=subprocess.run([str(kit/'runtime/python/python.exe'),str(kit/'tools/check_environment.py')],cwd=kit,env=env,capture_output=True,timeout=120)
    (base/'relocated_environment.txt').write_bytes(result.stdout+result.stderr)
    check('Relocated runtime and native tools pass environment check',result.returncode==0)
    params=base/'params.json';params.write_text(json.dumps({'_file':str(kit/'labs/04_archive/carrier.bin'),'offset':'512','length':'128'}),encoding='utf-8')
    output=base/'hex_result'
    result=subprocess.run([str(kit/'runtime/python/python.exe'),str(kit/'tools/casework.py'),'hex','--args',str(params),'--out',str(output),'--kit',str(kit),'--labs',str(kit/'labs')],cwd=kit,env=env,capture_output=True,timeout=30)
    check('Relocated casework processes real bytes under a Chinese path',result.returncode==0 and json.loads((output/'result.json').read_text(encoding='utf-8'))['hex'].startswith('504b0304'))
    record=dict(date='2026-10-21',archive=archive.name,archive_sha256=hashlib.file_digest(archive.open('rb'),'sha256').hexdigest(),files_verified=verified,tools_manifest_entries=len(manifest['tools']),operations=len(data['actions']),resources=len(data['resources']),guided_routes=len(data['recipes']),tool_cards=22,worked_cases=15,total=len(checks),passed=sum(c['pass_'] for c in checks),checks=checks,runtime_extracted=str(kit),system_mount_executed=False,driver_install_executed=False,kali_executed=False)
    (ROOT/'output/工作台分发完整性验收.json').write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in record.items() if k!='checks'},ensure_ascii=False))

if __name__=='__main__':main()
