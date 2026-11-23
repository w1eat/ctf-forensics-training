"""Exercise real workbench jobs, provenance and negative input boundaries."""
from pathlib import Path
from datetime import date
import ast,base64,bz2,gzip,hashlib,json,os,sqlite3,struct,sys,time,uuid,zipfile
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'工具包构建'))
from learning_server import Runtime,Jobs,InputError

def main():
    test_root=ROOT/'output'/('工作台验收_'+uuid.uuid4().hex[:8]);(test_root/'labs').mkdir(parents=True)
    sys.path.insert(0,str(ROOT/'课件源码'))
    from build import exercises
    for name,data in exercises().items():
        p=test_root/'labs'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    runtime=Runtime(test_root,ROOT/'学员工具包_Windows64');jobs=Jobs(runtime);records=[];fixture=runtime.labs/'inputs'/'casework_samples';fixture.mkdir(parents=True)
    def rel(path):return path.relative_to(runtime.labs).as_posix()
    def check(name,condition,detail=''):
        records.append(dict(name=name,pass_=bool(condition),detail=str(detail)[:800]))
        print(('PASS ' if condition else 'FAIL ')+name,flush=True)
        if not condition:raise AssertionError(name+': '+str(detail))
    def run(name,action,params,validate=lambda job:True,expected='completed',timeout=180):
        result=jobs.submit(action,params);start=time.monotonic()
        while not (job:=jobs.get(result['id'])).get('finished'):
            if time.monotonic()-start>timeout:jobs.stop(job);raise AssertionError('Timeout '+name)
            time.sleep(.1)
        public=jobs.public(job);good=public['state'] in ([expected] if isinstance(expected,str) else expected)
        check(name,good and validate(public),json.dumps({k:public[k] for k in ('id','state','error','text')},ensure_ascii=False))
        return public
    try:
        initial=hashlib.sha256((runtime.labs/'05_disk/tiny_fat16.dd').read_bytes()).hexdigest()
        inv=run('FAT inventory identifies sector 2048','disk_inventory',{'file':'05_disk/tiny_fat16.dd'},lambda j:j['data']['volumes'][0]['sector']==2048 and any(r['deleted'] for r in j['data']['entries']))
        timeline=run('MACB timeline identifies partition and exports complete CSV','disk_timeline',{'file':'05_disk/tiny_fat16.dd','rows':'1','sort':'oldest'},lambda j:j['data']['volumes'][0]['sector']==2048 and len(j['data']['rows'])==1 and j['data']['limited'])
        body=timeline['data'];csv_path=runtime.labs/next(f['path'] for f in timeline['files'] if f['name']=='evidence/文件时间线.csv')
        with csv_path.open(encoding='utf-8-sig') as stream:timeline_rows=list(__import__('csv').DictReader(stream))
        check('Timeline CSV retains hidden rows and chronological UTC epochs',len(timeline_rows)==body['total_events'] and all(r['utc'].endswith('Z') and int(r['epoch'])!=0 for r in timeline_rows) and [int(r['epoch']) for r in timeline_rows]==sorted(int(r['epoch']) for r in timeline_rows))
        day=timeline_rows[0]['utc'][:10]
        run('Timeline inclusive end-date and timestamp type filter','disk_timeline',{'file':'05_disk/tiny_fat16.dd','start':day,'end':day,'time_field':'mtime'},lambda j:j['data']['total_events']>0 and all(r['field']=='mtime' and r['utc'].startswith(day) for r in j['data']['entries']))
        run('Timeline rejects malformed dates','disk_timeline',{'file':'05_disk/tiny_fat16.dd','start':'not-a-date'},expected='failed')
        run('Timeline rejects reversed date bounds','disk_timeline',{'file':'05_disk/tiny_fat16.dd','start':'2030-01-01','end':'2020-01-01'},expected='failed')
        restored=run('Deleted file batch recovery','disk_batch_recover',{'file':'05_disk/tiny_fat16.dd','mode':'deleted'},lambda j:len(j['data']['exports'])==1)
        output_name='evidence/'+restored['data']['exports'][0]['output']
        dest=runtime.labs/next(f['path'] for f in restored['files'] if f['name']==output_name)
        check('Recovered FAT bytes contain exact expected content',b'flag{deleted_entry_is_a_clue}' in dest.read_bytes())
        item=next(r for r in inv['data']['entries'] if r['deleted'])
        run('Single export uses sector size','disk_recover',{'file':'05_disk/tiny_fat16.dd','sector':'2048','sector_size':'512','inode':item['inode']},lambda j:any(f['bytes']>0 and f['name']=='recovered.bin' for f in j['files']))
        png=(runtime.labs/'01_file/unknown.dat').read_bytes();zipbytes=(runtime.labs/'04_archive/carrier.bin').read_bytes()[512:]
        carrier=fixture/'含 空格_载体.bin';carrier.write_bytes(b'not a format\0'+png+b'gap'+zipbytes+b'gap'+gzip.compress(b'flag{gzip_boundary}')+bz2.compress(b'flag{bzip_boundary}'))
        run('Structural PNG ZIP gzip bzip separation','separate_files',{'file':rel(carrier),'depth':'1'},lambda j:{'png','zip','gz','bz2'}<={r['format'] for r in j['data']['exports']})
        run('Hex range agrees with source bytes','hex_view',{'file':rel(carrier),'offset':'0xd','length':'128'},lambda j:bytes.fromhex(j['data']['hex'])==carrier.read_bytes()[13:141])
        pattern=fixture/'跨块搜索.bin';pattern.write_bytes(b'\0'*(1024**2-2)+b'flag{cross_chunk}'+b'\0'*8)
        run('Search crosses input chunks without duplicate offsets','byte_search',{'file':rel(pattern),'pattern':'flag{cross_chunk}','pattern_format':'utf8'},lambda j:j['data']['offsets']==[1024**2-2])
        run('UTF16LE byte search','byte_search',{'file':'08_memory/case_c/process_2460_excerpt.bin','pattern':'flag{','pattern_format':'utf16le'},lambda j:j['data']['offsets']==[284])
        run('Binary patch writes a copy','binary_patch',{'file':'02_png/broken_header.png','offset':'0','expected':b'BROKEN!!'.hex(),'replacement':'89504e470d0a1a0a'},lambda j:any(f['name']=='evidence/patched.png' for f in j['files']))
        run('Wrong expected bytes stop patching','binary_patch',{'file':'02_png/broken_header.png','expected':'00'*8,'replacement':'89504e470d0a1a0a'},expected='failed')
        result=run('Base64 decodes bytes through job API','codec',{'text':'ZmxhZ3twbGF0Zm9ybV9jb2RlY30=','operation':'base64_decode'},lambda j:j['data']['text']=='flag{platform_codec}')
        folder=jobs.get(result['id'])['folder']
        check('Private codec parameter file removed',not (folder/'_case_args.json').exists())
        check('Input text not copied into runtime report','ZmxhZ3twbGF0Zm9ybV9jb2RlY30=' not in (folder/'运行报告.txt').read_text(encoding='utf-8'))
        run('AES NIST decrypt through workbench','cipher',{'algorithm':'AES-ECB','direction':'decrypt','key':'000102030405060708090a0b0c0d0e0f','padding':'none','input_format':'hex','text':'69c4e0d86a7b0430d8cdb78070b4c55a'},lambda j:j['data']['hex']=='00112233445566778899aabbccddeeff')
        run('MD5 candidate verification','hash_tools',{'mode':'dictionary','target':'21232f297a57a5a743894a0e4a801fc3','words':'wrong\nadmin\ntraining','algorithm':'md5'},lambda j:j['data']['found'] and j['data']['candidate']=='admin')
        db=fixture/'places.sqlite';con=sqlite3.connect(db);con.execute('PRAGMA journal_mode=WAL');con.executescript('CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url TEXT,title TEXT);CREATE TABLE moz_historyvisits(place_id INTEGER,visit_date INTEGER);');con.execute('INSERT INTO moz_places VALUES(1,?,?)',('https://example.test/case','Training'));con.execute('INSERT INTO moz_historyvisits VALUES(1,1700000000000000)');con.commit()
        try:run('Browser history with live WAL snapshot','browser_history',{'file':rel(db)},lambda j:j['data']['tables'][0]['rows'][0][-1]=='2023-11-14 22:13:20')
        finally:con.close()
        flat=fixture/'disk-flat.vmdk';os.link(runtime.labs/'05_disk/tiny_fat16.dd',flat);descriptor=fixture/'disk.vmdk';sectors=flat.stat().st_size//512
        descriptor.write_text('# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\ncreateType="monolithicFlat"\nRW '+str(sectors)+' FLAT "disk-flat.vmdk" 0\nddb.adapterType="ide"\n',encoding='ascii')
        run('VMDK reads actual logical FAT directory','disk_inventory',{'file':rel(descriptor)},lambda j:j['data']['volumes'][0]['sector']==2048)
        converted=run('VMDK to RAW byte preserving conversion','disk_image_convert',{'file':rel(descriptor),'budget_mib':'16'},lambda j:j['data']['rows'][0][2]==initial)
        salvage=fixture/'salvage.img';data=bytearray(65536);data[4096:4096+len(png)]=png;data[16384:16384+len(zipbytes)]=zipbytes;salvage.write_bytes(data)
        recovered=run('PhotoRec actual recovery from damaged-layout carrier','disk_photorec',{'file':rel(salvage),'partition':'none','types':'png,zip','seconds':'60','budget_mib':'16'},lambda j:j['data']['recovered_files']>=2,timeout=90)
        check('PhotoRec recovers the original PNG byte sequence',any((runtime.labs/f['path']).read_bytes()==png for f in recovered['files'] if f['name'].lower().endswith('.png')))
        run('Read-only mount plan computes byte offset','disk_mount',{'file':'05_disk/tiny_fat16.dd','mode':'plan','sector':'2048'},lambda j:any(row==['字节偏移',1048576] for row in j['data']['rows']))
        run('Mount password is absent from result and report','disk_mount',{'file':'05_disk/tiny_fat16.dd','mode':'plan','method':'veracrypt','password':'PRIVATE_MOUNT_TEST'},lambda j:'PRIVATE_MOUNT_TEST' not in json.dumps(j,ensure_ascii=False))
        run('TrueCrypt uses a separate supported legacy mode','disk_mount',{'file':'05_disk/tiny_fat16.dd','mode':'plan','method':'truecrypt'},lambda j:'1.25.9' in json.dumps(j['data']) and '/truecrypt' in json.dumps(j['data']))
        run('Mount status has no side effects','disk_mount',{'file':'05_disk/tiny_fat16.dd','mode':'status'},lambda j:'driver_installed' in j['data'])
        from case_mount import kali_command
        ext=fixture/'ext-plan.img';ext.write_bytes(b'\0'*1080+b'\x53\xef'+b'\0'*16)
        check('Kali Ext mount plan disables journal replay','noload' in kali_command(ext,fixture,'imdisk',0)[2])
        check('Kali FAT plan omits Ext-only mount options','noload' not in kali_command(runtime.labs/'05_disk/tiny_fat16.dd',fixture,'imdisk',2048*512)[2])
        check('Kali TrueCrypt plan uses explicit compatibility mode','--truecrypt' in kali_command(ext,fixture,'truecrypt',0))
        dummy=fixture/'dummy.raw';dummy.write_bytes(b'\0'*512)
        for action,params in [('hex_view',{'file':'../index.html'}),('disk_mount',{'drive':'C'}),('disk_photorec',{'seconds':'99999'}),('cipher',{'source':'file','input_file':'../../index.html'}),('vol2_registry',{'file':rel(dummy),'profile':'Win7;whoami'})]:
            try:runtime.plan(action,params,runtime.outputs/'preview');check('Reject unsafe plan '+action,False)
            except (ValueError,OSError):check('Reject unsafe plan '+action,True)
        check('Source disk hash unchanged',hashlib.sha256((runtime.labs/'05_disk/tiny_fat16.dd').read_bytes()).hexdigest()==initial)
    finally:
        jobs.close()
        result=dict(date=date.today().isoformat(),passed=sum(v['pass_'] for v in records),total=len(records),tests=records,fixture_directory=str(fixture),system_mount_executed=False,driver_install_executed=False,kali_executed=False)
        (ROOT/'output/工作台新增功能验收.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='tests'},ensure_ascii=False))

if __name__=='__main__':main()
