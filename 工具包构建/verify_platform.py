"""End-to-end HTTP checks for fixed local-tool actions and file boundaries."""
from pathlib import Path
import hashlib,json,sys,threading,time,urllib.request,urllib.error,uuid,zipfile,sqlite3,tarfile,io,shutil
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(Path(__file__).resolve().parent))
from learning_server import App,Handler,ThreadingHTTPServer,ACTIONS

def main():
    test_root=ROOT/'output'/('平台API验收_'+uuid.uuid4().hex[:8]);(test_root/'labs').mkdir(parents=True)
    sys.path.insert(0,str(ROOT/'课件源码'))
    from build import exercises
    for name,data in exercises().items():
        p=test_root/'labs'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    shutil.copy2(ROOT/'index.html',test_root/'index.html')
    app=App(test_root,ROOT/'学员工具包_Windows64');server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True;server.app=app
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    base=f'http://127.0.0.1:{server.server_port}';checks=[];jobs=[]
    qa=app.runtime.labs/'inputs'/('_platform_qa_'+uuid.uuid4().hex[:10]);qa.mkdir(parents=True)
    from PIL import Image
    from pypdf import PdfWriter
    from pypdf.generic import NameObject,DictionaryObject,DecodedStreamObject
    own_png=qa/'自选图像 17x11.png';Image.new('RGB',(17,11),(24,90,160)).save(own_png)
    own_db=qa/'自选数据库.db'
    with sqlite3.connect(own_db) as db:
        db.execute('CREATE TABLE orders(order_no TEXT, amount INTEGER, note TEXT)')
        db.execute('INSERT INTO orders VALUES(?,?,?)',('A-2026',42,'不是 artifacts 表'))
    own_pdf=qa/'自选文档.pdf';writer=PdfWriter();page=writer.add_blank_page(200,150)
    font=DictionaryObject({NameObject('/Type'):NameObject('/Font'),NameObject('/Subtype'):NameObject('/Type1'),NameObject('/BaseFont'):NameObject('/Helvetica')})
    page[NameObject('/Resources')]=DictionaryObject({NameObject('/Font'):DictionaryObject({NameObject('/F1'):writer._add_object(font)})})
    stream=DecodedStreamObject();stream.set_data(b'BT /F1 12 Tf 10 100 Td (Independent PDF example 42) Tj ET')
    page[NameObject('/Contents')]=writer._add_object(stream);writer.add_metadata({'/Title':'Own uploaded PDF'});writer.add_attachment('memo.txt',b'Independent attachment')
    with own_pdf.open('wb') as f:writer.write(f)
    own_pe=qa/'python-copy.exe';shutil.copy2(app.runtime.python,own_pe)
    def relative(path):return path.relative_to(app.runtime.labs).as_posix()
    def request(path,body=None,token=True,headers=None,raw=None):
        h={'Authorization':'Bearer '+app.token} if token else {}
        if body is not None:h['Content-Type']='application/json'
        if headers:h.update(headers)
        data=json.dumps(body).encode('utf-8') if body is not None else raw
        req=urllib.request.Request(base+path,data=data,headers=h)
        try:
            with urllib.request.urlopen(req,timeout=10) as response:return response.status,json.loads(response.read())
        except urllib.error.HTTPError as exc:return exc.code,json.loads(exc.read())
    def check(name,ok,detail=''):
        checks.append(dict(name=name,pass_=bool(ok),detail=detail))
        print(('PASS ' if ok else 'FAIL ')+name,flush=True)
        if not ok:raise AssertionError(name+' '+str(detail))
    def run(action,params=None):
        code,job=request('/api/run',dict(action=action,params=params or {}));assert code==202,(action,job)
        jobs.append(job['id']);deadline=time.monotonic()+95
        while job['state'] in ('queued','running'):
            assert time.monotonic()<deadline,(action,'timeout')
            time.sleep(.12);_,job=request('/api/jobs/'+job['id'])
        return job
    snapshots={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in (app.runtime.labs/'01_file/unknown.dat',app.runtime.labs/'02_png/broken_width.png',app.runtime.labs/'04_archive/locked.zip',app.runtime.labs/'05_disk/tiny_fat16.dd',app.runtime.labs/'06_sqlite/case.db')}
    try:
        check('API authentication required',request('/api/state',token=False)[0]==403)
        check('Cross-origin requests rejected',request('/api/run',{'action':'base64','params':{}},headers={'Origin':'https://example.invalid'})[0]==403)
        check('Host header checked',request('/api/state',headers={'Host':'outside.invalid'})[0]==403)
        check('Path traversal rejected',request('/api/preview',{'action':'file_type','params':{'file':'../index.html'}})[0]==400)
        check('Unknown operations rejected',request('/api/run',{'action':'cmd.exe','params':{}})[0]==400)
        check('Nested parameter types rejected',request('/api/run',{'action':'hex','params':[]})[0]==400)
        _,state=request('/api/state');check('Catalog includes all operations',len(state['actions'])==len(ACTIONS) and len(ACTIONS)>=47)
        for meta in ACTIONS:
            if meta.get('ram') or meta.get('casework'):continue
            overrides={'pdf_read':{'file':relative(own_pdf)},'pe_read':{'file':relative(own_pe)}}
            job=run(meta['id'],overrides.get(meta['id']));expected='finding' if meta.get('expected_error') else 'completed'
            check('Run '+meta['id'],job['state']==expected,job.get('error') or job['text'][-300:])
            if meta['id']=='hex':check('Hex view preserves byte offsets',job['data']['rows'][0][0]=='0x00000200' and job['data']['rows'][0][1].startswith('50 4b 03 04'))
            if meta['id']=='base64':check('Base64 structured result',job['data']['text']=='flag{metadata_then_base64}')
            if meta['id']=='png_map':check('PNG CRC is visualized as BAD',not job['data']['chunks'][0]['valid'])
            if meta['id']=='png_check':check('Native report paths remain readable','\ufffd' not in job['text'])
            if meta['id']=='png_header':
                path=app.runtime.labs/next(f['path'] for f in job['files'] if f['name']=='fixed_header.png')
                check('PNG header repair matches reference',path.read_bytes()==(app.runtime.labs/'02_png/good.png').read_bytes())
            if meta['id']=='carve':
                file=next(f for f in job['files'] if f['name']=='carved.zip');again=run('zip_list',{'file':file['path']})
                check('Output can become the next tool input',again['state']=='completed' and 'answer.txt' in again['text'])
            if meta['id']=='disk_recover':
                file=next(f for f in job['files'] if f['name']=='recovered.bin');raw=(app.runtime.labs/file['path']).read_bytes()
                check('icat export preserves raw bytes',b'flag{deleted_entry_is_a_clue}' in raw and b'\x00' not in raw)
            if meta['id']=='sqlite_query':check('SQLite result is a table',job['data']['columns']==['id','name','note'] and 'flag{query_the_schema_first}' in job['data']['rows'][0])
        chinese=qa/'中文 附件.png';chinese.write_bytes((app.runtime.labs/'02_png/good.png').read_bytes())
        job=run('metadata',{'file':relative(chinese)})
        check('ExifTool preserves Unicode filenames',job['state']=='completed' and '中文 附件.png' in job['text'] and '\ufffd' not in job['text'])
        evil=qa/'outside.zip'
        with zipfile.ZipFile(evil,'w') as z:z.writestr('../outside.txt','bad')
        check('ZIP traversal blocked before extraction',request('/api/run',{'action':'zip_extract','params':{'file':relative(evil)}})[0]==400)
        wrong=qa/'preview_only.raw';wrong.write_bytes(b'\0'*512)
        for meta in ACTIONS:
            if not meta.get('ram'):continue
            params={'file':relative(wrong)}
            if meta['id'].startswith('vol2_'):
                params.update(profile='Win7SP1x86',pid='2104',address='0x1000')
            code,preview=request('/api/preview',{'action':meta['id'],'params':params})
            marker='volatility_2.6_win64_standalone.exe' if meta['id'].startswith('vol2_') else 'vol_pypykatz.pypykatz' if meta['id']=='vol_extra' else 'windows.'
            check('Plan only '+meta['id'],code==200 and marker in preview.get('command',''),str(preview))
        check('Synthetic CSV cannot be selected as RAM',request('/api/preview',{'action':'vol_info','params':{'file':'08_memory/case_a/pslist.csv'}})[0]==400)
        code,result=request('/api/upload?name=uploaded.txt',headers={'Content-Type':'application/octet-stream'},raw=b'local evidence only')
        check('Upload stays in inputs',code==200 and result['path'].startswith('inputs/') and (app.runtime.labs/result['path']).read_bytes()==b'local evidence only')
        upload_folder=str(Path(result['path']).parent)
        uploaded_folders=[upload_folder]
        job=run('auto_analyze',{'file':relative(own_png)})
        check('Independent PNG auto-routed by content',job['state']=='completed' and job['data']['identification']['kind']=='png' and job['data']['selected_workflow']=='image')
        check('Auto reports are downloadable artifacts',all(any(f['name'].endswith(n) for f in job['files']) for n in ('analysis.html','analysis.json','analysis.txt')))
        auto_id=job['id']
        job=run('auto_analyze',{'file':relative(own_db)})
        check('Independent SQLite table auto-discovered',job['state']=='completed' and any(t['title']=='预览表：orders' for s in job['data']['sections'] if s['id']=='workflow_database' for t in s['data']['tables']))
        wal_db=qa/'wal-case.db';wal_connection=sqlite3.connect(wal_db)
        try:
            wal_connection.execute('PRAGMA journal_mode=WAL');wal_connection.execute('CREATE TABLE live_records(value TEXT)');wal_connection.execute("INSERT INTO live_records VALUES('committed in WAL')");wal_connection.commit()
            wal_snapshots={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in qa.glob('wal-case.db*')}
            job=run('sqlite_query',{'file':relative(wal_db),'query':'SELECT value FROM live_records'})
            check('SQLite reads matching WAL through private copies',job['state']=='completed' and job['data']['rows']==[['committed in WAL']] and job['data'].get('companions'))
            check('SQLite WAL and SHM evidence remain byte-identical',all(hashlib.sha256(p.read_bytes()).hexdigest()==h for p,h in wal_snapshots.items()))
        finally:wal_connection.close()
        job=run('sqlite_query',{'file':relative(own_db),'query':'SELECT order_no,amount FROM orders WHERE amount > 40'})
        check('Custom SELECT works on a non-exercise schema',job['state']=='completed' and job['data']['rows']==[['A-2026',42]])
        before=hashlib.sha256(own_db.read_bytes()).hexdigest()
        for query in ('DELETE FROM orders','WITH x AS (SELECT 1) DELETE FROM orders','SELECT load_extension(\'missing\')','SELECT readfile(\'index.html\')','ATTACH DATABASE \'other.db\' AS other','.shell whoami','SELECT 1; DELETE FROM orders'):
            job=run('sqlite_query',{'file':relative(own_db),'query':query})
            check('Reject non-read-only SQL '+query[:40],job['state']=='failed')
        check('SQL attempts leave database unchanged',hashlib.sha256(own_db.read_bytes()).hexdigest()==before)
        job=run('auto_analyze',{'file':relative(own_pdf)})
        pdf=next(s['data'] for s in job['data']['sections'] if s['id']=='workflow_document')
        check('Independent PDF text and attachments detected',job['state']=='completed' and 'Independent PDF example 42' in pdf['preview'] and 'memo.txt' in pdf['attachments'])
        job=run('pe_read',{'file':relative(own_pe)})
        check('PE parser processes a real bundled binary statically',job['state']=='completed' and job['data']['sections']['rows'] and job['data']['entry_point'].startswith('0x'))
        own_text=qa/'自选事件.jsonl';own_text.write_text('{"event":"upload","ticket":7}\n{"event":"review","ticket":7}\n',encoding='utf-8')
        job=run('auto_analyze',{'file':relative(own_text)})
        check('JSONL analysis does not require exercise fields',job['state']=='completed' and any(s['id']=='workflow_text' and len(s['data']['tables'][0]['rows'])==2 for s in job['data']['sections']))
        job=run('lsb_custom',{'channels':'r','max_bytes':'64'})
        check('Parameterized LSB matches known channel order','flag{one_bit_one_clue}' in job['data']['preview'])
        rules='rule OwnRule { strings: $a = "Independent" condition: $a }'
        job=run('yara_scan',{'file':relative(own_pdf),'rules':rules})
        check('Custom YARA rule returns match offsets',job['state']=='completed' and job['data']['matched_rules']==['OwnRule'] and job['data']['rows'][0][2].startswith('0x'))
        job=run('yara_scan',{'file':relative(own_pdf),'rules':'include "index.html"\nrule X { condition: true }'})
        check('YARA includes cannot read arbitrary files',job['state']=='failed')
        job=run('archive_general',{'file':relative(evil),'mode':'extract'})
        check('Generic archive extraction blocks traversal',job['state']=='failed' and not (app.runtime.outputs/'outside.txt').exists())
        own_tar=qa/'自选压缩包.tar'
        with tarfile.open(own_tar,'w') as tar:
            info=tarfile.TarInfo('folder/memo.txt');info.size=20;tar.addfile(info,io.BytesIO(b'Independent archive!'))
        job=run('archive_general',{'file':relative(own_tar),'mode':'extract'})
        check('Non-ZIP archive can be extracted with 7-Zip',job['state']=='completed' and any(f['name'].endswith('extracted/folder/memo.txt') for f in job['files']))
        job=run('archive_general',{'file':'04_archive/locked.zip','mode':'test','password':'wrong-password'})
        check('Archive password failure is not reported as success',job['state']=='failed')
        link_tar=qa/'link.tar'
        with tarfile.open(link_tar,'w') as tar:
            info=tarfile.TarInfo('link');info.type=tarfile.SYMTYPE;info.linkname='../outside';tar.addfile(info)
        job=run('archive_general',{'file':relative(link_tar),'mode':'extract'})
        check('Generic archive extraction rejects links',job['state']=='failed')
        large=qa/'large_stream.bin'
        with large.open('wb') as f:f.seek(65*1024**2);f.write(b'flag{after_the_old_64MiB_limit}')
        job=run('strings',{'file':relative(large),'scan_mib':'0','keyword':'after_the_old'})
        check('Streaming strings reach beyond 64 MiB',job['state']=='completed' and not job['data']['partial'] and 'flag{after_the_old_64MiB_limit}' in job['data']['rows'][0][2])
        job=run('carve_range',{'file':relative(large),'offset':str(65*1024**2)})
        check('Large-file carving preserves exact range',job['state']=='completed' and (app.runtime.labs/next(f['path'] for f in job['files'] if f['name'].endswith('/carved.bin'))).read_bytes()==b'flag{after_the_old_64MiB_limit}')
        batch=uuid.uuid4().hex[:24]
        code,first=request('/api/upload?name=own.db&batch='+batch,headers={'Content-Type':'application/octet-stream'},raw=b'first copy')
        uploaded_folders.append(str(Path(first['path']).parent))
        code2,second=request('/api/upload?name=own.db-wal&batch='+batch,headers={'Content-Type':'application/octet-stream'},raw=b'companion')
        check('Same-batch companion files share a directory',code==200 and code2==200 and Path(first['path']).parent==Path(second['path']).parent)
        code,_=request('/api/upload?name=own.db&batch='+batch,headers={'Content-Type':'application/octet-stream'},raw=b'replacement')
        check('Duplicate upload cannot replace or delete an input',code==400 and (app.runtime.labs/first['path']).read_bytes()==b'first copy')
        code,empty=request('/api/upload?name=empty.bin',headers={'Content-Type':'application/octet-stream'},raw=b'')
        uploaded_folders.append(str(Path(empty['path']).parent))
        job=run('auto_analyze',{'file':empty['path']})
        check('Empty uploaded file produces an honest report',code==200 and job['state']=='completed' and job['data']['identification']['kind']=='empty')
        code,history=request('/api/jobs');check('History includes completed analysis',code==200 and any(j['id']==auto_id for j in history))
        saved=app.jobs.items.pop(auto_id);restored=app.jobs.get(auto_id)
        check('Finished reports can be restored from local history',restored['data']['identification']['kind']=='png' and restored['folder']==saved['folder'])
        job=run('auto_analyze',{'file':'05_disk/tiny_fat16.dd','workflow':'disk','profile':'quick'})
        check('Disk workflow validates and follows actual offsets',job['state']=='completed' and any(s['id']=='workflow_disk' and s['data']['volumes'][0]['sector']==2048 and s['data']['volumes'][0]['filesystem']=='FAT16' for s in job['data']['sections']))
        job=run('auto_analyze',{'file':relative(wrong),'workflow':'windows_memory','profile':'quick'})
        check('Invalid RAM stops after info and records diagnostics',job['state']=='finding' and any(s['id']=='vol_info' and s['data']['exit_code']!=0 for s in job['data']['sections']) and not any(s['id']=='vol_pslist' for s in job['data']['sections']))
        code,cancel=request('/api/run',{'action':'auto_analyze','params':{'file':relative(large),'profile':'full'}});jobs.append(cancel['id'])
        request('/api/cancel',{'id':cancel['id']})
        deadline=time.monotonic()+15
        while cancel['state'] in ('queued','running') and time.monotonic()<deadline:
            time.sleep(.1);_,cancel=request('/api/jobs/'+cancel['id'])
        check('An owned running task can be cancelled',cancel['state']=='cancelled')
        check('Original evidence unchanged',all(hashlib.sha256(p.read_bytes()).hexdigest()==digest for p,digest in snapshots.items()))
    finally:
        server.shutdown();server.server_close();app.jobs.close()
        report=dict(checks=checks,passed=sum(c['pass_'] for c in checks),total=len(checks),real_ram_parsed=False,kali_executed=False,
                    generated_jobs=jobs,qa_inputs=relative(qa),uploaded_inputs=locals().get('uploaded_folders',locals().get('upload_folder')))
        (ROOT/'output/学习平台API验收记录.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(passed=report['passed'],total=report['total']),ensure_ascii=False))

if __name__=='__main__':main()
