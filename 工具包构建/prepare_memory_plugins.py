"""Stage pinned community plugins and their isolated runtime dependencies."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,subprocess,sys,tarfile,urllib.request,zipfile
ROOT=Path(__file__).resolve().parent.parent
CACHE=ROOT/'工具包构建/下载缓存/memory_plugins'
KIT=ROOT/'学员工具包_Windows64'
LOCAL=Path(r'E:\CTF\ctf工具箱\数字取证')

def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def unpack(wheel,target):
    with zipfile.ZipFile(wheel) as z:
        for item in z.infolist():
            if item.is_dir():continue
            path=(target/item.filename).resolve()
            if not path.is_relative_to(target.resolve()):raise ValueError('Invalid dependency path')
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(z.read(item))

def lock():
    path=CACHE/'memory_plugins.lock.json'
    if not path.exists():
        records=json.loads((CACHE/'sources.json').read_text(encoding='utf-8'))
        for f in sorted(CACHE.glob('pycryptodomex-3.9.9*.whl')):
            expected={'pycryptodomex-3.9.9-cp27-cp27mu-manylinux1_x86_64.whl':'3642252d7bfc4403a42050e18ba748bedebd5a998a8cba89665a4f42aea4c380','pycryptodomex-3.9.9-cp27-cp27m-win32.whl':'d2d1388595cb5d27d9220d5cbaff4f37c6ec696a25882eb06d224d241e6e93fb','pycryptodomex-3.9.9-cp27-cp27m-win_amd64.whl':'a1d38a96da57e6103423a446079ead600b450cf0f8ebf56a231895abf77e7ffc'}[f.name]
            if sha(f)!=expected:raise ValueError('PyCryptodomex upstream hash mismatch')
            records.append(dict(file=f.name,url='https://pypi.org/project/pycryptodomex/3.9.9/',sha256=expected))
        for name in ('py27_ctypes_util.py','py27_LICENSE'):
            records.append(dict(file=name,url='https://github.com/python/cpython/tree/v2.7.18',sha256=sha(CACHE/name)))
        for f in sorted((CACHE/'pypykatz_wheels').glob('*.whl')):
            # Record the exact upstream PyPI artifact, not just a locally computed hash.
            name,version=f.name.split('-')[:2]
            with urllib.request.urlopen('https://pypi.org/pypi/'+name+'/'+version+'/json',timeout=30) as response:meta=json.load(response)
            asset=next(a for a in meta['urls'] if a['filename']==f.name)
            if sha(f)!=asset['digests']['sha256']:raise ValueError('Dependency hash mismatch '+f.name)
            records.append(dict(file='pypykatz_wheels/'+f.name,url=asset['url'],sha256=asset['digests']['sha256']))
        path.write_text(json.dumps(dict(date='2026-10-21',records=records),ensure_ascii=False,indent=2),encoding='utf-8')
    value=json.loads(path.read_text(encoding='utf-8'))
    for r in value['records']:
        if sha(CACHE/r['file'])!=r['sha256']:raise ValueError('Pinned plugin/dependency changed '+r['file'])
    assert sha(CACHE/'construct-2.8.22.tar.gz')=='8977b75fc396eaf9e3ba269db0d46d13944bd8fd7e2b5539a4c4d990b6d6dded'
    return value

def stage_vol2(folder,platforms=('win64','linux64')):
    plugins=folder/'extra_plugins';plugins.mkdir(parents=True,exist_ok=True)
    deps=folder/'extra_deps';deps.mkdir(exist_ok=True)
    bootstrap="""# Classroom compatibility: isolate Construct and Cryptodome; no algorithm changes.
import os, sys, struct, ctypes
_addon_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_addon_arch = ('win' if os.name == 'nt' else 'linux') + str(struct.calcsize('P') * 8)
sys.path.insert(0, os.path.join(_addon_root, 'extra_deps', _addon_arch))
ctypes.__path__.append(os.path.join(_addon_root, 'extra_deps', 'stdlib', 'ctypes'))
import volatility.conf as _addon_conf
if not getattr(_addon_conf.PyFlagOptionParser, '_community_path_help', False):
    _addon_original_help = _addon_conf.PyFlagOptionParser.print_help
    def _addon_print_help(self, file=sys.stdout):
        for option in self.option_list:
            if option.dest == 'plugins':
                option.metavar = 'COMMUNITY_PLUGIN_DIRECTORY'
        return _addon_original_help(self, file)
    _addon_conf.PyFlagOptionParser.print_help = _addon_print_help
    _addon_conf.PyFlagOptionParser._community_path_help = True
"""
    original=(CACHE/'vol2_mimikatz.py').read_text(encoding='utf-8')
    adapted=original.replace('import construct',bootstrap+'\nimport construct').replace('from Crypto.Cipher import','from Cryptodome.Cipher import')
    (plugins/'mimikatz.py').write_text(adapted,encoding='utf-8')
    shutil.copy2(CACHE/'vol2_bitlocker.py',plugins/'bitlocker.py')
    for platform in platforms:
        target=deps/platform;target.mkdir(exist_ok=True)
        with tarfile.open(CACHE/'construct-2.8.22.tar.gz') as t:
            for member in t.getmembers():
                name=member.name.partition('/')[2]
                if member.isfile() and (name.startswith('construct/') or name.lower().startswith(('license','readme'))):
                    dest=target/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(t.extractfile(member).read())
        suffix={'win64':'win_amd64.whl','win32':'win32.whl','linux64':'manylinux1_x86_64.whl'}[platform]
        wheel=next(CACHE.glob('pycryptodomex-3.9.9*'+suffix));unpack(wheel,target)
    ctypes_folder=deps/'stdlib/ctypes';ctypes_folder.mkdir(parents=True,exist_ok=True)
    shutil.copy2(CACHE/'py27_ctypes_util.py',ctypes_folder/'util.py')
    shutil.copy2(CACHE/'py27_LICENSE',deps/'stdlib/LICENSE-Python-2.7.txt')

def plugin_files(folder):
    folder.mkdir(parents=True,exist_ok=True)
    shutil.copy2(CACHE/'vol3_vol_pypykatz.py',folder/'vol_pypykatz.py')
    shutil.copy2(CACHE/'vol3_bitlocker.py',folder/'bitlocker.py')

def main(local=False):
    records=lock()
    stage_vol2(KIT/'tools/volatility2')
    plugin_files(KIT/'tools/volatility3_extra')
    # Keep community modules separate so the basic classroom mode does not load them.
    core=KIT/'runtime/python/Lib/site-packages/volatility3/plugins'
    for name,cached in [('vol_pypykatz.py','vol3_vol_pypykatz.py'),('bitlocker.py','vol3_bitlocker.py')]:
        old=core/name
        if old.is_file() and sha(old)==sha(CACHE/cached):old.unlink()
    for wheel in (CACHE/'pypykatz_wheels').glob('*.whl'):unpack(wheel,KIT/'runtime/python/Lib/site-packages')
    info=KIT/'tools/memory_plugins';info.mkdir(parents=True,exist_ok=True)
    (info/'SOURCES.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')
    notices=info/'licenses';notices.mkdir(exist_ok=True)
    shutil.copy2(KIT/'tools/volatility2/windows/LICENSE.txt',notices/'GPL-2.0.txt')
    shutil.copy2(CACHE/'vol3_pypykatz_LICENSE',notices/'pypykatz-plugin-MIT.txt')
    shutil.copy2(CACHE/'vol3_bitlocker_LICENSE',notices/'bitlocker-GPL-3.0.txt')
    (info/'PATCHES.md').write_text('# Community plugin compatibility\n\nVol2 mimikatz retains the pinned upstream analysis code. Added a relative dependency search path, an isolated Cryptodome namespace, CPython 2.7 ctypes.util for the frozen executable, and an ASCII plugin-path help label for Windows paths containing Chinese characters. Construct 2.8.22 and PyCryptodomex 3.9.9 stay in the Vol2 dependency directory; the Python 3 runtime uses its own separate packages.\n\nThe Vol3 plugins and both BitLocker sources are unmodified. BitLocker output is a candidate and must be validated against the encrypted volume; no host key acquisition or live LSASS access is exposed by the workbench.\n',encoding='utf-8')
    source=KIT/'licenses/source/volatility-community';source.mkdir(parents=True,exist_ok=True)
    for r in records['records']:
        item=CACHE/r['file'];dest=source/r['file'];dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(item,dest)
    if local:
        vol2=LOCAL/'volatility-master/volatility-master';vol3=LOCAL/'volatility3'
        if not (vol2/'vol.exe').is_file() or not (vol3/'venv/Scripts/python.exe').is_file():raise FileNotFoundError('Local Volatility roots changed')
        stage_vol2(vol2,('win64',))
        # No existing core plugins or old root plugins are overwritten.
        plugin_files(vol3/'volatility3/plugins')
        subprocess.run([str(vol3/'venv/Scripts/python.exe'),'-m','pip','install','--no-index','--find-links',str(CACHE/'pypykatz_wheels311'),'pypykatz==0.6.13'],check=True)
        (vol2/'vol2.cmd').write_text('@echo off\nsetlocal DisableDelayedExpansion\nset "PYTHONIOENCODING="\nset "PYTHONUTF8="\n"%~dp0vol.exe" --plugins="%~dp0extra_plugins" --cache-directory=out/vol2_cache %*\n@exit /b %errorlevel%\n',encoding='ascii',newline='\r\n')
        (vol3/'vol3.cmd').write_text('@echo off\nsetlocal\nset "PYTHONUTF8=1"\n"%~dp0venv\\Scripts\\python.exe" "%~dp0vol.py" --cache-path="%~dp0." %*\n@exit /b %errorlevel%\n',encoding='ascii',newline='\r\n')
        for folder in (vol2,vol3):
            shutil.copytree(info,folder/'community_plugin_info',dirs_exist_ok=True)
        print('Local Vol2 and Vol3 extensions installed.',flush=True)
    print('Memory community plugins staged.',flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--local',action='store_true');args=parser.parse_args();main(args.local)
