"""Native workflow regression checks, independent fixtures and optional real image.

Every artifact stays under output/workflow_checks_*; user inputs are read-only.
No validation input or output is copied into student distributions.
"""
from pathlib import Path
import argparse,base64,hashlib,io,json,os,shutil,sqlite3,struct,subprocess,sys,time,uuid,zipfile
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(Path(__file__).resolve().parent))
from learning_server import Runtime
from forensic_workflows import targeted_scan,parse_fls,flatten_json

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image',type=Path);args=parser.parse_args()
    rt=Runtime(ROOT);qa=ROOT/'output'/('workflow_checks_'+uuid.uuid4().hex[:10]);qa.mkdir()
    checks=[];cases=[]
    def check(name,ok,details=''):
        checks.append(dict(name=name,pass_=bool(ok),details=details));print(('PASS ' if ok else 'FAIL ')+name,flush=True)
        if not ok:raise AssertionError(name+' '+str(details))
    def run(name,path,workflow='auto',**options):
        dest=qa/name;argv=[rt.python,str(ROOT/'工具包构建/analysis_engine.py'),'auto',str(path),'--out',str(dest),'--kit',str(rt.kit),'--workflow',workflow]
        for key,value in options.items():argv+=['--'+key.replace('_','-'),str(value)]
        before=hashlib.sha256(path.read_bytes()).hexdigest() if path.stat().st_size<32*1024**2 else None
        proc=subprocess.run(argv,env=rt.env,cwd=ROOT,capture_output=True,timeout=240)
        assert proc.returncode==0,(name,proc.stderr.decode('utf-8','replace')[-2000:])
        report=json.loads((dest/'analysis.json').read_text(encoding='utf-8'));cases.append(dict(name=name,folder=str(dest.relative_to(ROOT))))
        if before:assert hashlib.sha256(path.read_bytes()).hexdigest()==before
        return report,dest
    def flow(r,key):return next(s['data'] for s in r['sections'] if s['id']=='workflow_'+key)
    def contains(r,token):return any(f['value']==token for f in r['findings'])
    def archive_bytes(files):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as z:
            for name,data in files.items():z.writestr(name,data)
        return stream.getvalue()
    try:
        original=ROOT/'练习材料/05_disk/tiny_fat16.dd';raw=original.read_bytes()[2048*512:]
        part=qa/'raw-volume.img';part.write_bytes(raw)
        r,d=run('raw_fat',part,max_files=8)
        disk=flow(r,'disk')
        check('Raw FAT auto-recognized at sector zero',r['selected_workflow']=='disk' and disk['mode']=='filesystem_at_zero' and disk['volumes'][0]['sector']==0)
        check('Deleted entry exported with inode and source path',disk['volumes'][0]['deleted_entries']>=1 and contains(r,'flag{deleted_entry_is_a_clue}') and any(p.name.endswith('_ECRET.TXT') for p in d.rglob('*')))
        multi=qa/'two-volumes.img';mbr=bytearray(2048*512)
        for n,start in enumerate((2048,2048+len(raw)//512)):
            entry=bytearray(16);entry[4]=6;struct.pack_into('<II',entry,8,start,len(raw)//512);mbr[446+n*16:462+n*16]=entry
        mbr[510:512]=b'\x55\xaa';multi.write_bytes(mbr+raw+raw)
        r,d=run('multiple_partitions',multi,max_files=8)
        check('Both real partition offsets are followed',set(v['sector'] for v in flow(r,'disk')['volumes'])=={2048,18432})
        r,d=run('lsb_image',ROOT/'练习材料/03_lsb/quiet.png')
        check('Image workflow recovers LSB candidate',r['selected_workflow']=='image' and contains(r,'flag{one_bit_one_clue}') and any('b0 r xy msb' in f['source'] for f in r['findings']))
        check('Bitplanes and native zsteg log are saved',bool(list(d.rglob('r_bit0.png'))) and bool(list(d.rglob('zsteg.txt'))))
        r,d=run('metadata_base64',ROOT/'练习材料/public_examples/cat_demo.jpg')
        check('Metadata values feed strict Base64 decoding',contains(r,'flag{metadata_then_base64}'))
        from PIL import Image
        image=io.BytesIO();Image.new('RGB',(24,13),(10,40,90)).save(image,format='PNG')
        payload=archive_bytes({'memo.txt':'flag{png_tail_zip_child}'})
        tail=qa/'tail.png';tail.write_bytes(image.getvalue()+payload)
        r,d=run('png_tail',tail)
        check('PNG trailer object has a verified ZIP boundary',contains(r,'flag{png_tail_zip_child}') and any(p.name.startswith('embedded_') and p.suffix=='.zip' for p in d.rglob('*')))
        outer=qa/'nested.zip';outer.write_bytes(archive_bytes({'one.zip':archive_bytes({'answer.txt':'flag{nested_not_fixed_names}'})}))
        r,d=run('nested_archive',outer)
        check('Nested archive children are actually analysed',contains(r,'flag{nested_not_fixed_names}') and any(c['depth']==2 for c in r['children']))
        r,d=run('depth_zero',outer,depth=0)
        check('Depth zero does not claim child analysis',not r['children'] and not flow(r,'archive')['analysed_children'])
        r,d=run('encrypted_list_only',ROOT/'练习材料/04_archive/locked.zip')
        check('Encrypted archive is listed without guessing passwords','加密' in flow(r,'archive').get('skipped','') and not list(d.rglob('answer.txt')))
        r,d=run('encrypted_known_password',ROOT/'练习材料/04_archive/locked.zip',password='training2026')
        check('Known archive password enables child analysis',contains(r,'flag{dictionary_from_the_hint}'))
        bad=qa/'traversal.zip';bad.write_bytes(archive_bytes({'../outside.txt':'forbidden'}))
        r,d=run('traversal_blocked',bad)
        check('Recursive workflow preserves extraction path checks',bool(flow(r,'archive').get('error')) and not (qa/'outside.txt').exists())
        dbpath=qa/'own-schema.db'
        with sqlite3.connect(dbpath) as db:
            db.execute('CREATE TABLE "strange table"(event_code TEXT, payload TEXT)')
            db.execute('INSERT INTO "strange table" VALUES(?,?)',('A42','flag{query_any_actual_schema}'))
        r,d=run('database_search',dbpath)
        check('Database workflow discovers arbitrary quoted table',r['selected_workflow']=='database' and contains(r,'flag{query_any_actual_schema}') and flow(r,'database')['scanned_tables'][0]['table']=='strange table')
        log=qa/'events.jsonl';encoded=base64.b64encode(b'flag{decode_payload_then_correlate}').decode()
        log.write_text(json.dumps({'trace_id':'t42','timestamp':'2026-01-01T08:00:00+08:00','payload':encoded})+'\n'+json.dumps({'trace_id':'t42','timestamp':'2026-01-01T00:01:00Z','event':'done'})+'\n',encoding='utf-16')
        r,d=run('encoded_log',log)
        check('UTF16 log is decoded and payload is analysed',contains(r,'flag{decode_payload_then_correlate}') and flow(r,'text')['encoding']=='utf-16')
        check('Log correlation retains source rows and timezone',any(t['title'].startswith('带时区') and t['rows'][0][0]=='2026-01-01T00:00:00+00:00' for t in flow(r,'text')['tables']))
        from pypdf import PdfWriter
        pdf=qa/'document.pdf';writer=PdfWriter();writer.add_blank_page(200,100);writer.add_attachment('own-note.txt',b'flag{pdf_attachment_evidence}')
        with pdf.open('wb') as f:writer.write(f)
        r,d=run('pdf_attachment',pdf)
        check('PDF attachment is exported and searched',contains(r,'flag{pdf_attachment_evidence}') and flow(r,'document')['extracted_attachments'])
        office=qa/'sample.docx';office.write_bytes(archive_bytes({'[Content_Types].xml':'<Types/>','word/document.xml':'<document>flag{office_is_structured_zip}</document>'}))
        r,d=run('office_document',office)
        check('OOXML document flows through its real XML children',r['identification']['kind']=='office' and contains(r,'flag{office_is_structured_zip}'))
        carrier=qa/'carrier.dat';carrier.write_bytes(b'opaque\x00'*17+archive_bytes({'own.txt':'flag{validate_before_carving}','second.txt':'another entry'}))
        r,d=run('embedded_objects',carrier,workflow='embedded')
        check('Embedded ZIP is validated before child analysis',contains(r,'flag{validate_before_carving}') and flow(r,'embedded')['rows'])
        check('An interior ZIP local header is not a complete carved archive',len(flow(r,'embedded')['rows'])==1)
        large=qa/'large-data.bin'
        with large.open('wb') as f:f.write((b'ordinary words\n'*12000));f.seek(65*1024**2);f.write(b'flag{targeted_scan_past_limits}')
        scan=targeted_scan(large,['flag'],max_rows=2)
        check('Targeted scan ignores printable-row caps and 64MiB samples',scan['scanned_bytes']==large.stat().st_size and scan['flag_candidates'][0]['value']=='flag{targeted_scan_past_limits}' and scan['flag_candidates'][0]['offset']==hex(65*1024**2))
        # Budget test uses declared metadata, without expanding 160 MiB.
        huge=qa/'large-expansion.zip'
        with zipfile.ZipFile(huge,'w',zipfile.ZIP_DEFLATED) as z:
            for n in range(20):z.writestr(str(n)+'.bin',b'\0'*(8*1024**2))
        r,d=run('archive_budget',huge)
        check('Declared archive expansion respects shared 128MiB budget','预算' in flow(r,'archive').get('skipped','') and not list(d.rglob('extracted')))
        fixture=flatten_json([{'PID':21,'__children':[{'PID':35,'Args':'notepad memo.txt'}]}])
        check('Vol3 JSON tree flattening preserves actual PIDs',[v['PID'] for v in fixture]==[21,35])
        if args.image:
            image_path=args.image.resolve()
            with image_path.open('rb') as f:before=hashlib.file_digest(f,'sha256').hexdigest()
            r,d=run('user_partition_image',image_path,max_files=32)
            with image_path.open('rb') as f:after=hashlib.file_digest(f,'sha256').hexdigest()
            disk=flow(r,'disk');volumes=disk['volumes']
            check('User partition image auto-falls-back to a verified filesystem',disk['mode']=='filesystem_at_zero' and volumes[0]['sector']==0 and volumes[0]['filesystem'].lower()=='ext4')
            check('User image directory and deleted entries were traversed',volumes[0]['entries']>1000 and volumes[0]['deleted_entries']>0 and volumes[0]['exported']>0)
            check('User image preserved byte-for-byte',before==after)
            cases[-1].update(image_sha256=before,filesystem=volumes[0]['filesystem'],entries=volumes[0]['entries'],deleted_entries=volumes[0]['deleted_entries'],exported=volumes[0]['exported'],flag_candidates=len(r['findings']))
    finally:
        record=dict(passed=sum(v['pass_'] for v in checks),total=len(checks),checks=checks,cases=cases,validation_folder=str(qa.relative_to(ROOT)),real_ram_parsed=False,kali_executed=False)
        (ROOT/'output/通用取证流程验收记录.json').write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(dict(passed=record['passed'],total=record['total']),ensure_ascii=False))

if __name__=='__main__':main()
