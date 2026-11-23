"""Stage official recovery, read-only mount and cryptography components."""
from pathlib import Path
import concurrent.futures,hashlib,json,shutil,urllib.request,zipfile,sys,subprocess
ROOT=Path(__file__).resolve().parent.parent
CACHE=ROOT/'工具包构建/下载缓存'
KIT=ROOT/'学员工具包_Windows64'
HEAD={'User-Agent':'Forensics-Classroom/2026.10'}

def get(url):
    with urllib.request.urlopen(urllib.request.Request(url,headers=HEAD),timeout=60) as r:return r.read()

def fetch(name,url,expected=None):
    path=CACHE/name;path.parent.mkdir(parents=True,exist_ok=True)
    if not path.exists():
        temp=path.with_suffix(path.suffix+'.partial')
        with urllib.request.urlopen(urllib.request.Request(url,headers=HEAD),timeout=60) as src,temp.open('wb') as out:shutil.copyfileobj(src,out,1024*1024)
        temp.replace(path)
    digest=hashlib.file_digest(path.open('rb'),'sha256').hexdigest()
    if expected and digest!=expected:raise ValueError('SHA256 mismatch: '+name)
    print(name+' '+digest,flush=True)
    return dict(file=name,url=url,sha256=digest,bytes=path.stat().st_size)

def extract(archive,dest,prefix=''):
    dest.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(archive) as z:
        for entry in z.infolist():
            if entry.is_dir() or not entry.filename.startswith(prefix):continue
            name=entry.filename[len(prefix):];target=(dest/name).resolve()
            if not target.is_relative_to(dest.resolve()):raise ValueError('Unsafe archive path')
            target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(entry))

def main():
    lock=CACHE/'extra_tools.lock.json'
    if not lock.exists():
        vc=json.loads(get('https://api.github.com/repos/veracrypt/VeraCrypt/releases/tags/VeraCrypt_1.26.29'))
        assets={a['name']:a['browser_download_url'] for a in vc['assets']}
        sums_name=next(n for n in assets if 'sha256' in n.lower() and not n.endswith('.sig'))
        sums=get(assets[sums_name]).decode('utf-8');(CACHE/'VeraCrypt-1.26.29-SHA256SUMS.txt').write_text(sums,encoding='utf-8')
        def vc_hash(name):
            wanted='VeraCrypt Portable 1.26.29.exe' if name=='VeraCrypt.Portable.1.26.29.exe' else name
            return next(line.split()[0].lower() for line in sums.splitlines() if line.rstrip().endswith(wanted))
        crypto=json.loads(get('https://pypi.org/pypi/pycryptodome/4.1.0/json'))
        wheel=next(a for a in crypto['urls'] if a['filename'].endswith('cp39-abi3-win_amd64.whl'))
        im=json.loads(get('https://api.github.com/repos/LTRData/ImDisk/commits/master'))['sha']
        jobs=[('testdisk-7.2.win64.zip','https://www.cgsecurity.org/testdisk-7.2.win64.zip',None),
              ('testdisk-7.2.tar.bz2','https://www.cgsecurity.org/testdisk-7.2.tar.bz2',None),
              ('imdisk-2.1.2.zip','https://static.ltr-data.se/files/imdisk.zip',None),
              ('imdisk-2.1.2-inst.exe','https://static.ltr-data.se/files/imdiskinst.exe',None),
              ('imdisk-source-'+im[:12]+'.zip','https://codeload.github.com/LTRData/ImDisk/zip/'+im,None),
              ('VeraCrypt.Portable.1.26.29.exe',assets['VeraCrypt.Portable.1.26.29.exe'],vc_hash('VeraCrypt.Portable.1.26.29.exe')),
              ('VeraCrypt_1.26.29_Source.zip',assets['VeraCrypt_1.26.29_Source.zip'],vc_hash('VeraCrypt_1.26.29_Source.zip')),
              ('wheels/'+wheel['filename'],wheel['url'],wheel['digests']['sha256'])]
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            records=list(pool.map(lambda row:fetch(*row),jobs))
        lock.write_text(json.dumps(dict(date='2026-10-21',records=records),ensure_ascii=False,indent=2),encoding='utf-8')
    records=json.loads(lock.read_text(encoding='utf-8'))['records']
    if not any(r['file']=='VeraCrypt_Setup_x64_1.26.29.msi' for r in records):
        row=fetch('VeraCrypt_Setup_x64_1.26.29.msi','https://github.com/veracrypt/VeraCrypt/releases/download/VeraCrypt_1.26.29/VeraCrypt_Setup_x64_1.26.29.msi','5ba6426983123cfb92bc1f09bd888fdbc0f53f300d0d9c5da52ce3aee8d474f0')
        records.append(row);lock.write_text(json.dumps(dict(date='2026-10-21',records=records),ensure_ascii=False,indent=2),encoding='utf-8')
    legacy=[('VeraCrypt_Setup_x64_1.25.9.msi','206d31c2ed1a2b0390d4dfa12e74a9b9dae88658d1f9bfa1bb433b23e2b24fd8'),('VeraCrypt_1.25.9_Source.zip','21644d4c7918f2105928a264d0b95dcdfa5242fe100a21d9872313f74a3ccf7d')]
    for name,expected in legacy:
        if not any(r['file']==name for r in records):
            records.append(fetch(name,'https://github.com/veracrypt/VeraCrypt/releases/download/VeraCrypt_1.25.9/'+name,expected))
            lock.write_text(json.dumps(dict(date='2026-10-21',records=records),ensure_ascii=False,indent=2),encoding='utf-8')
    for row in records:
        path=CACHE/row['file']
        if hashlib.file_digest(path.open('rb'),'sha256').hexdigest()!=row['sha256']:raise ValueError('Changed cached tool: '+row['file'])
    extract(CACHE/'testdisk-7.2.win64.zip',KIT/'tools/testdisk',prefix='testdisk-7.2/')
    extract(CACHE/'imdisk-2.1.2.zip',KIT/'tools/imdisk')
    im_source=next(CACHE/r['file'] for r in records if r['file'].startswith('imdisk-source-'))
    with zipfile.ZipFile(im_source) as z:
        license=next(n for n in z.namelist() if n.endswith('/LICENSE.md'))
        (KIT/'tools/imdisk/LICENSE.md').write_bytes(z.read(license))
    shutil.copy2(CACHE/'imdisk-2.1.2-inst.exe',KIT/'tools/imdisk/install.exe')
    vc=KIT/'tools/veracrypt';vc.mkdir(parents=True,exist_ok=True)
    shutil.copy2(CACHE/'VeraCrypt.Portable.1.26.29.exe',vc/'VeraCrypt-Portable.exe')
    if not (vc/'VeraCrypt.exe').is_file():
        payload=CACHE/'veracrypt_msi_payload';payload.mkdir(exist_ok=True)
        seven=str(KIT/'tools/7zip/7z.exe')
        subprocess.run([seven,'x',str(CACHE/'VeraCrypt_Setup_x64_1.26.29.msi'),'-o'+str(payload),'-y'],check=True,stdout=subprocess.DEVNULL)
        decoded=payload/'files';decoded.mkdir(exist_ok=True)
        for cab in payload.glob('*.cab'):subprocess.run([seven,'x',str(cab),'-o'+str(decoded),'-y'],check=True,stdout=subprocess.DEVNULL)
        for name in ('VeraCrypt.exe','veracrypt.sys','veracryptDriver.sys','veracrypt.inf','veracrypt.cat','License.txt','LICENSE','NOTICE','VeraCrypt_User_Guide.chm','VeraCrypt_User_Guide_zh_cn.chm'):
            candidate=next((folder/name for folder in (payload,decoded) if (folder/name).is_file()),None)
            if candidate:shutil.copy2(candidate,vc/name)
    for name in ('VeraCrypt.exe','veracrypt.sys','License.txt','LICENSE','NOTICE'):
        if not (vc/name).is_file():raise FileNotFoundError('VeraCrypt runtime incomplete: '+name)
    old=KIT/'tools/veracrypt_legacy';old.mkdir(parents=True,exist_ok=True)
    if not (old/'VeraCrypt.exe').is_file():
        payload=CACHE/'veracrypt_legacy_msi_payload';payload.mkdir(exist_ok=True)
        subprocess.run([str(KIT/'tools/7zip/7z.exe'),'x',str(CACHE/'VeraCrypt_Setup_x64_1.25.9.msi'),'-o'+str(payload),'-y'],check=True,stdout=subprocess.DEVNULL)
        for name in ('VeraCrypt.exe','veracrypt.sys','veracryptDriver.sys','veracrypt.inf','veracrypt.cat','License.txt','LICENSE','NOTICE','VeraCrypt_User_Guide.chm'):
            if (payload/name).is_file():shutil.copy2(payload/name,old/name)
    for name in ('VeraCrypt.exe','veracrypt.sys','License.txt'):
        if not (old/name).is_file():raise FileNotFoundError('TrueCrypt compatibility runtime incomplete: '+name)
    with zipfile.ZipFile(CACHE/'VeraCrypt_1.26.29_Source.zip') as z:
        for n in z.namelist():
            if n.endswith('/License.txt') and ('src/' in n or n.count('/')<2):
                (vc/'License.txt').write_bytes(z.read(n));break
    source=KIT/'licenses/source';source.mkdir(parents=True,exist_ok=True)
    for row in records:
        if row['file'].endswith(('.tar.bz2','Source.zip')) or row['file'].startswith('imdisk-source-'):shutil.copy2(CACHE/row['file'],source/Path(row['file']).name)
        if row['file'].endswith('.whl'):
            extract(CACHE/row['file'],KIT/'runtime/python/Lib/site-packages');shutil.copy2(CACHE/row['file'],source/Path(row['file']).name)
    (KIT/'tools/EXTRA_SOURCES.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Extra forensic tools staged.',flush=True)

if __name__=='__main__':main()
