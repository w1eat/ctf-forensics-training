"""Stage a PowerShell-only installer and the Microsoft-signed C++ runtime."""
from pathlib import Path
import hashlib,json,shutil
ROOT=Path(__file__).resolve().parent.parent
KIT=ROOT/'学员工具包_Windows64'
CACHE=ROOT/'工具包构建/下载缓存'

def launcher(mode='Setup',check_only=False):
    lines=['@echo off','chcp 65001 >nul','setlocal DisableDelayedExpansion',
        'set "CTF_SETUP_PS=%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"',
        'if exist "%SystemRoot%\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe" set "CTF_SETUP_PS=%SystemRoot%\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe"',
        'set "CTF_SETUP_SCRIPT=%~dp0tools\\bootstrap.ps1"',
        'if not exist "%CTF_SETUP_SCRIPT%" for /d %%D in ("%~dp0*") do if exist "%%~fD\\tools\\bootstrap.ps1" set "CTF_SETUP_SCRIPT=%%~fD\\tools\\bootstrap.ps1"',
        'if not exist "%CTF_SETUP_SCRIPT%" set "CTF_SETUP_SCRIPT=%~dp0bootstrap.ps1"',
        'if not exist "%CTF_SETUP_SCRIPT%" (',
        '  echo Missing bootstrap.ps1. Extract the complete Windows toolkit first.',
        '  pause','  exit /b 20',')',
        '"%CTF_SETUP_PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CTF_SETUP_SCRIPT%" -Mode '+mode+' -WorkspaceRoot "%~dp0."'+(' -NoLaunch' if check_only else '')+' %*',
        'set "CTF_SETUP_EXIT=%errorlevel%"',
        ('pause' if check_only else 'if errorlevel 20 pause'),
        'exit /b %CTF_SETUP_EXIT%']
    return '\r\n'.join(lines)+'\r\n'

def main():
    source=json.loads((CACHE/'VC_redist.source.json').read_text(encoding='utf-8'))
    with (CACHE/'VC_redist.x64.exe').open('rb') as stream:actual=hashlib.file_digest(stream,'sha256').hexdigest()
    if actual!=source['sha256']:raise ValueError('VC++ redistributable hash changed')
    if source['source']!='https://aka.ms/vs/17/release/vc_redist.x64.exe':raise ValueError('Unexpected VC++ runtime source')
    target=KIT/'setup/vendor';target.mkdir(parents=True,exist_ok=True)
    shutil.copy2(CACHE/'VC_redist.x64.exe',target/'VC_redist.x64.exe')
    shutil.copy2(CACHE/'VC_redist.source.json',target/'VC_redist.source.json')
    (target/'README-Microsoft-VC.md').write_text('# Microsoft Visual C++ x64 Redistributable\n\nOriginal Microsoft installer, redistributed without modification. The installer contains the Microsoft license terms. Source and exact SHA256 are recorded in VC_redist.source.json. The bootstrap also verifies the Microsoft Authenticode signature before installation.\n\nOfficial information: https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist\nLicense terms: https://visualstudio.microsoft.com/license-terms/vs2022-cruntime/\n\nThe runtime is optional when the bundled applications already run. Installation may require Windows administrator consent and does not disable antivirus or install forensic mounting drivers.\n',encoding='utf-8')
    for filename in ('bootstrap.ps1','setup_probe.py'):
        raw=(ROOT/'工具包构建'/filename).read_text(encoding='utf-8-sig')
        (KIT/'tools'/filename).write_text(raw,encoding='utf-8-sig' if filename.endswith('.ps1') else 'utf-8',newline='\n')
    for folder in (ROOT,KIT):
        for name,mode,check in [('00_一键配置并启动.cmd','Setup',False),('05_环境检查与修复.cmd','Repair',True),('06_仅基础工具启动.cmd','Basic',False)]:
            (folder/name).write_bytes(launcher(mode,check).encode('utf-8'))
    print('New-user environment bootstrap staged.',flush=True)

if __name__=='__main__':main()
