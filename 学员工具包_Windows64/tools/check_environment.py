"""Read-only smoke checks for the distributed portable toolkit."""
from pathlib import Path
import hashlib, importlib, importlib.metadata, json, os, subprocess, sys
ROOT=Path(__file__).resolve().parent.parent
sys.stdout.reconfigure(encoding='utf-8',errors='replace')
sys.stderr.reconfigure(encoding='utf-8',errors='replace')
errors=[]
def check(name, callback):
    try:
        detail=callback()
        print(f'[PASS] {name} {detail or ""}')
    except Exception as exc:
        errors.append(name)
        print(f'[FAIL] {name}: {exc}')
def run(args, contains=None, env=None):
    task_env=os.environ.copy()
    if 'volatility_2.6' in str(args[0]):
        task_env.pop('PYTHONIOENCODING',None);task_env.pop('PYTHONUTF8',None)
    if env:task_env.update(env)
    result=subprocess.run([str(a) for a in args],capture_output=True,timeout=40,env=task_env)
    output=(result.stdout+result.stderr).decode('utf-8',errors='replace')
    if result.returncode!=0:raise RuntimeError(f'exit={result.returncode}: {output[-300:]}')
    if contains and contains not in output:raise RuntimeError(f'Expected text not found: {contains}')
    return output.splitlines()[0] if output.splitlines() else ''
def imports():
    for name in ('PIL','pypdf','pefile','yara','capstone','Crypto','sqlite3','volatility3'):importlib.import_module(name)
    return 'Pillow / pypdf / pefile / yara / capstone / Crypto / SQLite / Vol3'
check('Python',lambda: sys.version.split()[0])
check('Python dependencies',imports)
check('7-Zip',lambda:run([ROOT/'tools/7zip/7z.exe','i'],'26.04'))
check('ExifTool',lambda:run([ROOT/'tools/exiftool/exiftool.exe','-ver'],'13.59'))
check('SQLite CLI',lambda:run([ROOT/'tools/sqlite/sqlite3.exe','--version'],'3.54.1'))
check('TSK mmls',lambda:run([ROOT/'tools/sleuthkit/bin/mmls.exe','-V'],'4.14.0'))
check('BusyBox',lambda:run([ROOT/'tools/busybox/busybox.exe','--list'],'xxd'))
check('pngcheck + zlib',lambda:run([ROOT/'tools/pngcheck/pngcheck.exe','-v',ROOT/'labs/02_png/good.png'],'No errors detected'))
check('Volatility 3 CLI',lambda:run([sys.executable,ROOT/'tools/volatility3/vol.py','windows.dumpfiles','-h'],'--virtaddr'))
check('Volatility 2 standalone',lambda:run([ROOT/'tools/volatility2/windows/volatility_2.6_win64_standalone.exe','--info'],'Win7SP1x86'))
check('Volatility 2 cmdscan',lambda:run([ROOT/'tools/volatility2/windows/volatility_2.6_win64_standalone.exe','cmdscan','-h'],'CommandCountMax'))
check('Vol2 community mimikatz',lambda:run([ROOT/'tools/volatility2/windows/volatility_2.6_win64_standalone.exe','--plugins='+str(ROOT/'tools/volatility2/extra_plugins'),'--cache-directory=out/vol2_cache','mimikatz','-h'],'mimikatz offline'))
check('Vol2 community BitLocker',lambda:run([ROOT/'tools/volatility2/windows/volatility_2.6_win64_standalone.exe','--plugins='+str(ROOT/'tools/volatility2/extra_plugins'),'--cache-directory=out/vol2_cache','bitlocker','-h'],'FVEK'))
check('Vol3 community pypykatz',lambda:run([sys.executable,ROOT/'tools/volatility3/vol.py','-p',ROOT/'tools/volatility3_extra','vol_pypykatz.pypykatz','-h'],'vol_pypykatz.pypykatz'))
check('Vol3 community BitLocker',lambda:run([sys.executable,ROOT/'tools/volatility3/vol.py','-p',ROOT/'tools/volatility3_extra','bitlocker.BitlockerFVEKScan','-h'],'--tags'))
check('PhotoRec',lambda:run([ROOT/'tools/testdisk/photorec_win.exe','/version'],'7.2',env={'__COMPAT_LAYER':'RunAsInvoker'}))
check('Case workbench CLI',lambda:run([sys.executable,ROOT/'tools/casework.py','-h'],'--labs'))
def mount_files():
    for name in ('tools/imdisk/cli/amd64/imdisk.exe','tools/imdisk/sys/amd64/imdisk.sys','tools/imdisk/install.exe','tools/veracrypt/VeraCrypt.exe','tools/veracrypt/veracrypt.sys','tools/veracrypt_legacy/VeraCrypt.exe','tools/veracrypt_legacy/veracrypt.sys','tools/mount_ops.ps1'):
        if not (ROOT/name).is_file():raise FileNotFoundError(name)
    return 'mount programs present; no driver installation or system mount performed'
check('Read-only mount runtime files',mount_files)
if (ROOT/'runtime/ruby/bin/ruby.exe').exists():
    check('Ruby',lambda:run([ROOT/'runtime/ruby/bin/ruby.exe','-v']))
    check('zsteg',lambda:run([ROOT/'runtime/ruby/bin/ruby.exe',ROOT/'runtime/ruby/bin/zsteg','--help'],'Usage'))
    check('zsteg image scan',lambda:run([ROOT/'runtime/ruby/bin/ruby.exe',ROOT/'runtime/ruby/bin/zsteg','--no-file',ROOT/'labs/03_lsb/quiet.png'],'b1,r,lsb,xy'))
def hashes():
    expected=(ROOT/'labs/SHA256SUMS.txt').read_text(encoding='utf-8').splitlines()
    for line in expected:
        digest,name=line.split('  ',1)
        target=(ROOT/'labs'/name).resolve()
        if not target.is_relative_to((ROOT/'labs').resolve()):raise ValueError('Invalid manifest path')
        actual=hashlib.sha256(target.read_bytes()).hexdigest()
        if actual!=digest:raise ValueError('Mismatch: '+name)
    return f'{len(expected)} exercise files'
check('Exercise SHA256',hashes)
print('\nNo real RAM image is bundled. Vol3 image parsing requires matching symbols.')
print(f'\nResult: {"PASS" if not errors else "FAIL"} ({len(errors)} failures)')
raise SystemExit(bool(errors))
