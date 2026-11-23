"""Copy selected portable components; generate per-session command launchers."""
from pathlib import Path
import shutil, sys, zipfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
from prepare_core import KIT,ROOT,CACHE,unzip

def write(path,text,bom=False):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(text,encoding='utf-8-sig' if bom else 'utf-8',newline='\n')

def wrapper(name,command):
    write(KIT/'bin'/(name+'.cmd'),'@echo off\n'+command+' %*\n@exit /b %errorlevel%\n')

def main():
    import prepare_volatility2
    prepare_volatility2.main()
    import prepare_extra_tools
    prepare_extra_tools.main()
    import prepare_memory_plugins
    prepare_memory_plugins.main()
    import prepare_bootstrap
    prepare_bootstrap.main()
    for name in ('finspect.py','check_environment.py','serve_local.py','learning_server.py','tool_tasks.py','analysis_engine.py','forensic_workflows.py','casework.py','case_catalog.py','case_crypto.py','case_carving.py','case_disk.py','case_mount.py','case_memory.py','mount_ops.ps1'):
        shutil.copy2(ROOT/'工具包构建'/name,KIT/'tools'/name)
    shutil.copy2(CACHE/'busybox64u.exe',KIT/'tools/busybox/busybox.exe')
    sys.path.insert(0,str(ROOT/'课件源码'))
    from build import exercises
    for name,data in exercises().items():
        target=KIT/'labs'/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(data)
    cyber=Path(r'E:\CTF\ctf工具箱\编码解码\CyberChef_v9.28.0')
    shutil.copytree(cyber,KIT/'tools/CyberChef',dirs_exist_ok=True)
    shutil.copy2(CACHE/'CyberChef-LICENSE',KIT/'tools/CyberChef/LICENSE')
    source=KIT/'licenses/source';source.mkdir(parents=True,exist_ok=True)
    for name in ('7z2604-source.7z','busybox-source-full.zip','pngcheck-v4.0.1.zip','zlib-1.3.1.tar.gz'):
        shutil.copy2(CACHE/name,source/name)
    if zipfile.is_zipfile(CACHE/'tsk-source.zip'):
        shutil.copy2(CACHE/'tsk-source.zip',source/'sleuthkit-4.14.0-source.zip')
    else:
        print('Pending TSK source archive')
    # Original Python wheels are an additional offline dependency source.
    for wheel in (CACHE/'wheels').glob('*.whl'):
        shutil.copy2(wheel,source/wheel.name)
    for name in ('strings','xxd','grep','dd','base64','sha256sum'):
        wrapper(name,'\"%~dp0..\\tools\\busybox\\busybox.exe\" '+name)
    wrapper('finspect','\"%~dp0..\\runtime\\python\\python.exe\" \"%~dp0..\\tools\\finspect.py\"')
    wrapper('analyze','\"%~dp0..\\runtime\\python\\python.exe\" \"%~dp0..\\tools\\analysis_engine.py\"')
    wrapper('7z','\"%~dp0..\\tools\\7zip\\7z.exe\"')
    wrapper('exiftool','\"%~dp0..\\tools\\exiftool\\exiftool.exe\"')
    wrapper('sqlite3','\"%~dp0..\\tools\\sqlite\\sqlite3.exe\"')
    wrapper('pngcheck','\"%~dp0..\\tools\\pngcheck\\pngcheck.exe\"')
    wrapper('vol3','\"%~dp0..\\runtime\\python\\python.exe\" \"%~dp0..\\tools\\volatility3\\vol.py\" -p \"%~dp0..\\tools\\volatility3_extra\"')
    write(KIT/'bin/vol2.cmd',('@echo off\nsetlocal DisableDelayedExpansion\nset "PYTHONIOENCODING="\nset "PYTHONUTF8="\n"%~dp0..\\tools\\volatility2\\windows\\volatility_2.6_win64_standalone.exe" --plugins="%~dp0..\\tools\\volatility2\\extra_plugins" --cache-directory=out/vol2_cache %*\n@exit /b %errorlevel%\n').replace('\n','\r\n'))
    wrapper('zsteg','"%~dp0..\\runtime\\ruby\\bin\\ruby.exe" "%~dp0..\\runtime\\ruby\\bin\\zsteg" --no-file')
    wrapper('casework',r'"%~dp0..\runtime\python\python.exe" "%~dp0..\tools\casework.py"')
    wrapper('imdisk',r'"%~dp0..\tools\imdisk\cli\amd64\imdisk.exe"')
    wrapper('veracrypt',r'"%~dp0..\tools\veracrypt\VeraCrypt.exe"')
    write(KIT/'bin/photorec.cmd','@echo off\nsetlocal\nset "__COMPAT_LAYER=RunAsInvoker"\n"%~dp0..\\tools\\testdisk\\photorec_win.exe" %*\n@exit /b %errorlevel%\n')
    write(KIT/'env.ps1',r'''$env:CTF_KIT_ROOT = $PSScriptRoot
$paths = @(
    (Join-Path $PSScriptRoot 'bin'),
    (Join-Path $PSScriptRoot 'runtime\python'),
    (Join-Path $PSScriptRoot 'tools\sleuthkit\bin')
)
if (Test-Path (Join-Path $PSScriptRoot 'runtime\ruby\bin\ruby.exe')) {
    $paths += (Join-Path $PSScriptRoot 'runtime\ruby\bin')
    $env:GEM_HOME = Join-Path $PSScriptRoot 'runtime\ruby\lib\ruby\gems\3.3.0'
    $env:GEM_PATH = $env:GEM_HOME
    $env:RUBYOPT = '-EUTF-8'
}
$env:PATH = ($paths -join ';') + ';' + $env:PATH
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:LANG = 'C'
$env:LC_ALL = 'C'
$env:LC_CTYPE = 'C'
$v3 = Join-Path $PSScriptRoot 'tools\volatility3\vol.py'
$img = '.\memory.raw'
Set-Location -LiteralPath (Join-Path $PSScriptRoot 'labs')
New-Item -ItemType Directory -Force -Path '.\out' | Out-Null
Write-Host 'CTF Forensics classroom | Windows x64 | portable tools' -ForegroundColor Green
Write-Host ('Tools: ' + $PSScriptRoot)
Write-Host 'CWD: labs | python / 7z / exiftool / sqlite3 / pngcheck / mmls / fls / icat'
Write-Host 'Helpers: finspect / strings / xxd / grep / dd / base64 / vol3 / vol2'
Write-Host 'Run: python $v3 -h'
Write-Host 'UTF-16LE: finspect strings INPUT --encoding utf16le'
Write-Host 'Commands affect this terminal session only.'
''',True)
    write(KIT/'01_启动课堂终端.cmd','@echo off\nchcp 65001 >nul\npowershell.exe -NoLogo -NoProfile -NoExit -ExecutionPolicy Bypass -File \"%~dp0env.ps1\"\n')
    write(KIT/'03_环境自检.cmd','@echo off\nchcp 65001 >nul\nset LANG=C\nset LC_ALL=C\nset PYTHONUTF8=1\n\"%~dp0runtime\\python\\python.exe\" \"%~dp0tools\\check_environment.py\"\npause\n')
    write(KIT/'04_启动离线CyberChef.cmd','@echo off\nchcp 65001 >nul\n\"%~dp0runtime\\python\\python.exe\" \"%~dp0tools\\serve_local.py\"\npause\n')
    print('Classroom staged',KIT)

if __name__=='__main__':main()
