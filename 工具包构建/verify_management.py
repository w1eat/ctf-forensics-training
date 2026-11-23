"""Exercise management APIs against isolated inputs and artifacts, never course originals."""
from pathlib import Path
import argparse,copy,hashlib,http.client,json,os,shutil,socket,subprocess,sys,threading,time,urllib.request,urllib.error,uuid
from http.server import ThreadingHTTPServer
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'工具包构建'))
from learning_server import App,Handler,Jobs

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--serve',action='store_true');args=parser.parse_args()
    qa=ROOT/'output'/('管理功能验收_'+uuid.uuid4().hex[:8]);course=qa/'中文 资料';labs=course/'labs';labs.mkdir(parents=True)
    shutil.copytree(ROOT/'学员工具包_Windows64/labs/01_file',labs/'01_file')
    for p in ROOT.glob('*.html'):shutil.copy2(p,course/p.name)
    app=App(course,ROOT/'学员工具包_Windows64');server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.app=app
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();base='http://127.0.0.1:'+str(server.server_port)
    checks=[]
    def check(name,ok):
        checks.append(dict(name=name,pass_=bool(ok)));print(('PASS ' if ok else 'FAIL ')+name,flush=True)
        if not ok:raise AssertionError(name)
    def request(path,body=None,token=True,origin=None,raw=None):
        headers={'Authorization':'Bearer '+app.token} if token else {}
        if origin:headers['Origin']=origin
        if body is not None:headers['Content-Type']='application/json'
        if raw is not None:headers['Content-Type']='application/octet-stream'
        data=json.dumps(body).encode() if body is not None else raw
        try:
            with urllib.request.urlopen(urllib.request.Request(base+path,data=data,headers=headers),timeout=15) as r:return r.status,json.load(r)
        except urllib.error.HTTPError as e:return e.code,json.load(e)
    def upload(name,data=b'evidence',batch=None):
        path='/api/upload?name='+urllib.parse.quote(name)+(('&batch='+batch) if batch else '')
        code,value=request(path,raw=data);assert code==200,value;return value['path']
    def run(path):
        code,job=request('/api/run',dict(action='file_hash',params={'file':path}));assert code==202,job
        deadline=time.monotonic()+30
        while job['state'] in ('queued','running'):
            if time.monotonic()>deadline:raise TimeoutError('file_hash')
            time.sleep(.05);_,job=request('/api/jobs/'+job['id'])
        assert job['state']=='completed',job
        return job
    def active(source):
        identity=uuid.uuid4().hex[:16];folder=app.runtime.outputs/identity;folder.mkdir()
        job=dict(id=identity,action='file_hash',title='用于验证占用保护的任务',state='running',created='2026-10-22T10:00:00+08:00',duration=0,folder=folder,finished=False,plan={'source':source,'params':{'file':source.relative_to(labs).as_posix()}},process=None,cancel=False)
        app.jobs.items[identity]=job;return job
    def finish(job):
        job.update(state='completed',finished=True);(job['folder']/'_task.json').write_text(json.dumps({k:job[k] for k in ('id','title','action','state','created','duration')}),encoding='utf-8')
    def junction(link,target):
        assert link.resolve().is_relative_to(qa.resolve()) and target.resolve().is_relative_to(qa.resolve())
        if os.name=='nt':
            cmd=Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/cmd.exe'
            result=subprocess.run([str(cmd),'/d','/c','mklink','/J',str(link),str(target)],capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode:raise RuntimeError(result.stderr.decode('utf-8','replace'))
        else:link.symlink_to(target,target_is_directory=True)
    original=labs/'01_file/unknown.dat';original_hash=hashlib.sha256(original.read_bytes()).hexdigest()
    try:
        check('File deletion requires authentication',request('/api/files/delete',{'paths':['inputs/x/a']},token=False)[0]==403)
        check('History deletion requires authentication',request('/api/jobs/delete',{'ids':['a'*16]},token=False)[0]==403)
        check('Cross-origin deletion is rejected',request('/api/files/delete',{'paths':['inputs/x/a']},origin='https://example.invalid')[0]==403)
        check('GET cannot perform deletion',request('/api/files/delete')[0]==400)
        _,catalog=request('/api/state');check('Management capabilities are advertised',catalog['management']=={'delete_uploads':True,'delete_history':True})
        check('Original exercises are read-only',request('/api/files/delete',{'paths':['01_file/unknown.dat']})[0]==400)
        for paths in ([],['inputs/../01_file/unknown.dat'],['inputs//file'],['E:/other/file'],['inputs/x/a']*101,[None]):
            check('Invalid file selection '+str(paths)[:45],request('/api/files/delete',{'paths':paths})[0]==400)
        batch=uuid.uuid4().hex[:24];first=upload('中文 附件 & 一.txt',b'keep this byte sequence',batch);wal=upload('中文 附件 & 一.txt-wal',b'companion',batch)
        check('Mixed invalid selection deletes nothing',request('/api/files/delete',{'paths':[first,'01_file/unknown.dat']})[0]==400 and (labs/first).exists())
        busy=active(labs/first)
        check('Active primary input cannot be removed',request('/api/files/delete',{'paths':[first]})[0]==400)
        check('Active companion from same upload batch is protected',request('/api/files/delete',{'paths':[wal]})[0]==400)
        _,files=request('/api/files');check('File list marks imported and occupied files',next(f for f in files if f['path']==first)['in_use'] and next(f for f in files if f['path']==first)['deletable'])
        check('Active history cannot be removed',request('/api/jobs/delete',{'ids':[busy['id']]})[0]==400)
        unrelated=upload('unrelated.txt');code,deleted=request('/api/files/delete',{'paths':[unrelated]});check('Unrelated upload can be removed during another task',code==200 and deleted['deleted']==[unrelated] and not (labs/unrelated).exists())
        finish(busy);request('/api/jobs/delete',{'ids':[busy['id']]})
        partial_batch=uuid.uuid4().hex[:24];partial_path='inputs/'+partial_batch+'/in_progress.bin'
        sock=socket.create_connection(('127.0.0.1',server.server_port),timeout=10)
        sock.sendall(('POST /api/upload?name=in_progress.bin&batch='+partial_batch+' HTTP/1.1\r\nHost: 127.0.0.1:'+str(server.server_port)+'\r\nAuthorization: Bearer '+app.token+'\r\nContent-Type: application/octet-stream\r\nContent-Length: 32\r\nConnection: close\r\n\r\nx').encode())
        deadline=time.monotonic()+5
        while not (labs/partial_path).exists() and time.monotonic()<deadline:time.sleep(.02)
        check('File being uploaded cannot be deleted',request('/api/files/delete',{'paths':[partial_path]})[0]==400)
        sock.sendall(b'x'*31);response=http.client.HTTPResponse(sock);response.begin();assert response.status==200;response.read();sock.close();request('/api/files/delete',{'paths':[partial_path]})
        job=run(first);folder=app.runtime.outputs/job['id'];artifact=next(f['path'] for f in job['files'] if f['name']=='运行报告.txt')
        code,history=request('/api/jobs');check('History includes source attachment',code==200 and next(j for j in history if j['id']==job['id'])['input']==first)
        check('Invalid history ID is rejected',request('/api/jobs/delete',{'ids':['../outside']})[0]==400)
        check('Mixed invalid history selection changes nothing',request('/api/jobs/delete',{'ids':[job['id'],'../outside']})[0]==400 and folder.exists())
        if os.name=='nt':
            with (labs/artifact).open('rb') as held:
                code,locked=request('/api/jobs/delete',{'ids':[job['id']]})
                check('Locked output leaves a readable history record',code==200 and not locked['deleted'] and len(locked['failed'])==1 and (folder/'_task.json').is_file())
            app.jobs.items.pop(job['id']);restored=app.jobs.get(job['id'])
            check('Partially deleted record can be restored after a restart',restored['state']=='completed' and any(f['name']=='运行报告.txt' for f in restored['files']))
        reader=active(labs/artifact)
        check('Artifact used by another task protects parent history',request('/api/jobs/delete',{'ids':[job['id']]})[0]==400 and folder.exists())
        finish(reader);request('/api/jobs/delete',{'ids':[reader['id']]})
        code,result=request('/api/jobs/delete',{'ids':[job['id']]});check('Deleting history removes its own outputs',code==200 and result['deleted']==[job['id']] and not folder.exists())
        check('Deleting history preserves uploaded input',(labs/first).read_bytes()==b'keep this byte sequence')
        check('Deleted history cannot be reopened or resurrected',request('/api/jobs/'+job['id'])[0]==400 and not any(j['id']==job['id'] for j in request('/api/jobs')[1]))
        _,result=request('/api/files/delete',{'paths':[first,wal]});check('Batch upload deletion removes exactly selected files',set(result['deleted'])=={first,wal} and not (labs/first).exists() and not (labs/wal).exists())
        check('Empty upload batch folder is removed',not (labs/first).parent.exists())
        outside=qa/'保留目录';outside.mkdir();sentinel=outside/'do-not-delete.txt';sentinel.write_bytes(b'protected outside data')
        link=labs/'inputs'/uuid.uuid4().hex[:24];link.parent.mkdir(exist_ok=True);junction(link,outside)
        check('Upload junction cannot redirect deletion',request('/api/files/delete',{'paths':[link.relative_to(labs).as_posix()+'/do-not-delete.txt']})[0]==400 and sentinel.read_bytes()==b'protected outside data')
        assert link.is_junction() or link.is_symlink();link.rmdir() if link.is_junction() else link.unlink()
        linked_job=run('01_file/unknown.dat');linked_folder=app.runtime.outputs/linked_job['id'];link=linked_folder/'outside-link';junction(link,outside)
        check('History containing a junction is not traversed or deleted',request('/api/jobs/delete',{'ids':[linked_job['id']]})[0]==400 and sentinel.read_bytes()==b'protected outside data')
        assert link.is_junction() or link.is_symlink();link.rmdir() if link.is_junction() else link.unlink();request('/api/jobs/delete',{'ids':[linked_job['id']]})
        check('Original exercise bytes remain unchanged',hashlib.sha256(original.read_bytes()).hexdigest()==original_hash)
        # Seed a small, clearly named file and result for optional browser checks.
        seed=upload('界面验收_附件.txt',b'flag{management_ui_test}');seed_job=run(seed)
        check('Isolated browser fixtures are available',(labs/seed).is_file() and seed_job['state']=='completed')
        result=dict(date='2026-10-22',passed=sum(r['pass_'] for r in checks),total=len(checks),checks=checks,qa_root=str(qa),course=str(course),system_settings_changed=False,course_originals_deleted=False)
        (ROOT/'output/附件与历史管理API验收.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({k:v for k,v in result.items() if k!='checks'},ensure_ascii=False),flush=True)
        if args.serve:
            print('URL: '+base+'/index.html#token='+app.token,flush=True)
            try:thread.join()
            except KeyboardInterrupt:pass
    finally:server.shutdown();server.server_close();app.jobs.close()

if __name__=='__main__':main()
