"""Create curated student and instructor releases, excluding test output and caches."""
from pathlib import Path
import hashlib, html, importlib, json, shutil, sys, zipfile
ROOT=Path(__file__).resolve().parent.parent
SOURCE=ROOT/'课件源码'
KIT=ROOT/'学员工具包_Windows64'
CACHE=ROOT/'工具包构建/下载缓存'
sys.path[:0]=[str(SOURCE),str(ROOT/'工具包构建')]

def write(path,text):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(text,encoding='utf-8',newline='\n')

def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def selected():
    for p in sorted(KIT.rglob('*')):
        if not p.is_file():continue
        rel=p.relative_to(KIT).as_posix()
        if '__pycache__' in p.parts or p.suffix in ('.pyc','.pyo'):continue
        if rel.startswith(('labs/out/','labs/inputs/','runtime/ruby/share/ri/','runtime/ruby/lib/ruby/gems/3.3.0/doc/')):continue
        yield p,rel

def manifest():
    entries=[
        ('Microsoft Visual C++ x64 Redistributable','14.44.35211.0','Microsoft redistributable license; terms embedded in installer','https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist','VC_redist.x64.exe','setup/vendor/VC_redist.x64.exe','setup/vendor/README-Microsoft-VC.md'),
        ('Vol2 mimikatz community plugin','fb55ab3edc94 + loader compatibility','GPL-2.0-or-later','https://github.com/dfirfpi/hotoloti',None,'tools/volatility2/extra_plugins/mimikatz.py','tools/memory_plugins/licenses/GPL-2.0.txt'),
        ('Vol2 BitLocker community plugin','d1c1790045ea','GPL-2.0-or-later','https://github.com/elceef/bitlocker',None,'tools/volatility2/extra_plugins/bitlocker.py','tools/memory_plugins/licenses/GPL-2.0.txt'),
        ('Vol3 pypykatz community plugin','1b722f00f709 / pypykatz 0.6.13','MIT','https://github.com/skelsec/pypykatz-volatility3',None,'tools/volatility3_extra/vol_pypykatz.py','tools/memory_plugins/licenses/pypykatz-plugin-MIT.txt'),
        ('Vol3 BitLocker community plugin','d2afab51fea4','GPL-3.0','https://github.com/lorelyai/volatility3-bitlocker',None,'tools/volatility3_extra/bitlocker.py','tools/memory_plugins/licenses/bitlocker-GPL-3.0.txt'),
        ('PhotoRec / TestDisk','7.2','GPL-2.0-or-later','https://www.cgsecurity.org/wiki/TestDisk_Download','testdisk-7.2.win64.zip','tools/testdisk/photorec_win.exe','tools/testdisk/COPYING.txt'),
        ('ImDisk','2.1.2','MIT-style with GPL and third-party notices','https://www.ltr-data.se/opencode.html','imdisk-2.1.2.zip','tools/imdisk/cli/amd64/imdisk.exe','tools/imdisk/LICENSE.md'),
        ('VeraCrypt','1.26.29','VeraCrypt / TrueCrypt and component licenses','https://veracrypt.io/en/Downloads.html','VeraCrypt_Setup_x64_1.26.29.msi','tools/veracrypt/VeraCrypt.exe','tools/veracrypt/License.txt'),
        ('VeraCrypt TrueCrypt compatibility','1.25.9','VeraCrypt / TrueCrypt and component licenses','https://github.com/veracrypt/VeraCrypt/releases/tag/VeraCrypt_1.25.9','VeraCrypt_Setup_x64_1.25.9.msi','tools/veracrypt_legacy/VeraCrypt.exe','tools/veracrypt_legacy/License.txt'),
        ('PyCryptodome','4.1.0','BSD / Public domain and component notices','https://pypi.org/project/pycryptodome/4.1.0/','wheels/pycryptodome-4.1.0-cp39-abi3-win_amd64.whl','runtime/python/Lib/site-packages/Crypto/__init__.py','runtime/python/Lib/site-packages/pycryptodome-4.1.0.dist-info/licenses/LICENSE.rst'),
        ('Python','3.13.16','PSF','https://www.python.org/downloads/release/python-31316/','python-3.13.16-embed-amd64.zip','runtime/python/python.exe','runtime/python/LICENSE.txt'),
        ('Pillow','11.3.0','MIT-CMU','https://pypi.org/project/pillow/11.3.0/','wheels/pillow-11.3.0-cp313-cp313-win_amd64.whl','runtime/python/Lib/site-packages/PIL/Image.py','runtime/python/Lib/site-packages/pillow-11.3.0.dist-info/licenses/LICENSE'),
        ('pypdf','6.21.1','BSD-3-Clause','https://pypi.org/project/pypdf/6.21.1/','wheels/pypdf-6.21.1-py3-none-any.whl','runtime/python/Lib/site-packages/pypdf/__init__.py','runtime/python/Lib/site-packages/pypdf-6.21.1.dist-info/licenses/LICENSE'),
        ('pefile','2024.8.26','MIT','https://pypi.org/project/pefile/2024.8.26/','wheels/pefile-2024.8.26-py3-none-any.whl','runtime/python/Lib/site-packages/pefile.py','runtime/python/Lib/site-packages/pefile-2024.8.26.dist-info/LICENSE'),
        ('yara-python','4.5.4','BSD-3-Clause','https://pypi.org/project/yara-python/4.5.4/','wheels/yara_python-4.5.4-cp313-cp313-win_amd64.whl','runtime/python/Lib/site-packages/yara.cp313-win_amd64.pyd','runtime/python/Lib/site-packages/yara_python-4.5.4.dist-info/licenses/LICENSE'),
        ('Volatility 3','2.28.2','Volatility Software License 1.0','https://pypi.org/project/volatility3/2.28.2/','wheels/volatility3-2.28.2-py3-none-any.whl','runtime/python/Lib/site-packages/volatility3/cli/__init__.py','tools/volatility3/LICENSE.txt'),
        ('Volatility 2','2.6 standalone','GPL-2.0-or-later','https://downloads.volatilityfoundation.org/releases/2.6/','volatility_2.6_win64_standalone.zip','tools/volatility2/windows/volatility_2.6_win64_standalone.exe','tools/volatility2/windows/LICENSE.txt'),
        ('7-Zip','26.04','LGPL with additional notices; see License.txt','https://sourceforge.net/projects/sevenzip/files/7-Zip/26.04/','7z2604-sf.exe','tools/7zip/7z.exe','tools/7zip/License.txt'),
        ('ExifTool','13.59','Perl Artistic / GPL; bundled Perl notices preserved','https://sourceforge.net/projects/exiftool/files/exiftool-13.59_64.zip/','exiftool-13.59_64.zip','tools/exiftool/exiftool.exe','tools/exiftool/exiftool_files/LICENSE'),
        ('SQLite','3.54.1','Public domain','https://sqlite.org/2026/sqlite-tools-win-x64-3540100.zip','sqlite-tools-win-x64-3540100.zip','tools/sqlite/sqlite3.exe',None),
        ('The Sleuth Kit','4.14.0','CPL / IPL and component licenses','https://github.com/sleuthkit/sleuthkit/releases/tag/sleuthkit-4.14.0','tsk-api.zip','tools/sleuthkit/bin/fls.exe','tools/sleuthkit/licenses/cpl1.0.txt'),
        ('pngcheck','4.0.1 + static zlib 1.3.1','MIT-style / zlib','https://github.com/pnggroup/pngcheck/releases/tag/v4.0.1','pngcheck-v4.0.1.zip','tools/pngcheck/pngcheck.exe','tools/pngcheck/LICENSE'),
        ('BusyBox for Windows','1.38.0-FRP-6075-g169694ebd Unicode x64','GPL-2.0','https://frippery.org/busybox/','busybox64u.exe','tools/busybox/busybox.exe','licenses/source/busybox-source-full.zip'),
        ('RubyInstaller','3.3.12-1 x64','Ruby / BSD and component licenses','https://github.com/oneclick/rubyinstaller2/releases/tag/RubyInstaller-3.3.12-1','ruby-api.7z','runtime/ruby/bin/ruby.exe','runtime/ruby/LICENSE.txt'),
        ('zsteg','0.2.14','MIT (upstream README and gemspec declaration)','https://rubygems.org/gems/zsteg/versions/0.2.14','gems/zsteg-0.2.14.gem','runtime/ruby/bin/zsteg','runtime/ruby/lib/ruby/gems/3.3.0/gems/zsteg-0.2.14/README.md'),
        ('CyberChef','9.28.0','Apache-2.0','https://github.com/gchq/CyberChef/tree/v9.28.0',None,'tools/CyberChef/CyberChef_v9.28.0.html','tools/CyberChef/LICENSE'),
    ]
    result=[]
    for name,version,license,url,archive,binary,notice in entries:
        assert (KIT/binary).is_file(),binary
        result.append(dict(name=name,version=version,license=license,source=url,
                           upstream_archive=archive,
                           upstream_archive_sha256=digest(CACHE/archive) if archive else None,
                           entry=binary,entry_sha256=digest(KIT/binary),license_location=notice))
        if name=='Volatility 2':
            entry='tools/volatility2/linux/volatility_2.6_lin64_standalone'
            result[-1]['additional_entries']=[dict(platform='Linux x64',entry=entry,entry_sha256=digest(KIT/entry),upstream_archive='volatility_2.6_lin64_standalone.zip',upstream_archive_sha256=digest(CACHE/'volatility_2.6_lin64_standalone.zip'),license_location='tools/volatility2/linux/LICENSE.txt')]
    return result

def tool_navigation():
    return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=index.html"><title>统一学习入口</title></head><body><a href="index.html">打开统一学习平台 index.html</a></body></html>'

def main():
    checks=json.loads((ROOT/'output/工具与题解验收记录.json').read_text(encoding='utf-8-sig'))
    assert len(checks)==39 and all(c['pass'] for c in checks)
    shutil.copy2(SOURCE/'distribution_readme.md',ROOT/'README.md')
    import prepare_volatility2
    prepare_volatility2.main()
    import prepare_extra_tools
    prepare_extra_tools.main()
    import prepare_memory_plugins
    prepare_memory_plugins.main()
    import build
    build.main()
    import stage_classroom
    stage_classroom.main()
    from portal import build_portal,WINDOWS_LAUNCHER,KALI_LAUNCHER
    from render_handouts import render
    for name in ('index.html','Volatility3_内存镜像分析.html','工具包使用指南.html','工具包使用指南.md','CTF取证基础_学员讲义.html','CTF取证基础_学员讲义.md','Volatility3_内存镜像分析_命令与题解.html','Volatility3_内存镜像分析_命令与题解.md'):
        shutil.copy2(ROOT/name,KIT/name)
    for name in ('课堂课件.html','学员任务单.md','学员任务单.html','讲师手册.md','讲师手册.html','讲师题解_逐题讲解.md','讲师题解_逐题讲解.html','学习平台使用指南.md','学习平台使用指南.html','CTF取证基础_学员练习.zip','Volatility3_例题与命令.zip'):
        shutil.copy2(ROOT/name,KIT/name)
    for suffix in ('.md','.html'):shutil.copy2(ROOT/('自动化取证流程指南'+suffix),KIT/('自动化取证流程指南'+suffix))
    for suffix in ('.md','.html'):shutil.copy2(ROOT/('Volatility2_兼容分析指南'+suffix),KIT/('Volatility2_兼容分析指南'+suffix))
    for suffix in ('.md','.html'):shutil.copy2(ROOT/('PPT解题思路与工作台指南'+suffix),KIT/('PPT解题思路与工作台指南'+suffix))
    for suffix in ('.md','.html'):shutil.copy2(ROOT/('Volatility_社区插件使用指南'+suffix),KIT/('Volatility_社区插件使用指南'+suffix))
    for suffix in ('.md','.html'):shutil.copy2(ROOT/('环境安装与故障排查'+suffix),KIT/('环境安装与故障排查'+suffix))
    shutil.copy2(ROOT/'00_一键安装_Kali.sh',KIT/'00_一键安装_Kali.sh')
    write(KIT/'index.html',build_portal('windows'))
    write(KIT/'00_启动学习平台.cmd',WINDOWS_LAUNCHER)
    write(KIT/'启动学习平台.sh',KALI_LAUNCHER)
    write(KIT/'README.md',(ROOT/'工具包使用指南.md').read_text(encoding='utf-8'))
    write(KIT/'学员任务单.html',render((SOURCE/'problem_set.md').read_text(encoding='utf-8'),'学员任务单'))
    shutil.copy2(ROOT/'文件观察实验台.html',KIT/'文件观察实验台.html')
    write(KIT/'02_工具导航.html',tool_navigation())
    records=manifest()
    write(KIT/'TOOL_MANIFEST.json',json.dumps(dict(platform='Windows 10/11 x64',date='2026-10-21',tools=records),ensure_ascii=False,indent=2))
    notice='''# 第三方工具说明\n\n各组件按自己的许可证分发，原始许可与版权通知保留在对应目录。这里是课程选择的独立工具集合，未修改第三方源码；pngcheck 仅做静态编译，zsteg 启动器传入 --no-file。\n\n7-Zip 使用 GNU LGPL，附有其他组件的说明；来源与源码入口 https://www.7-zip.org/ 。其对应源代码随包保存。Volatility 3 使用 Volatility Software License 1.0，原文在 tools/volatility3/LICENSE.txt，亦见 https://www.volatilityfoundation.org/license/vsl-v1.0 。SQLite 为公共领域软件，见 https://sqlite.org/copyright.html 。\n\n'''
    for record in records:
        notice+='## '+record['name']+' '+record['version']+'\n\n许可：'+record['license']+'\n\n来源：'+record['source']+'\n\n许可位置：'+str(record['license_location'] or '公共领域声明入口见上文')+'\n\n'
    notice+='## 依赖与源码\n\nPython 的第三方依赖许可位于 runtime/python/Lib/site-packages/*dist-info，原始 wheel 在 licenses/source。Ruby 与原生依赖通知在 runtime/ruby 下，zsteg 及 iostruct、zpng、prime、rainbow 的 gem 内带源码，原始 gem 在 licenses/source。CyberChef 的 Apache-2.0 与 worker 依赖通知均保留。\n\nBusyBox 的对应源码是 commit 169694ebd，位于 source/busybox-source-full.zip。pngcheck、zlib、TSK、7-Zip 的对应源码也在 source。课堂自制脚本和实验台保留可编辑源码。\n'
    notice+='zsteg 上游 gem 未提供独立 LICENSE.txt，其 README 的 License 段及 gemspec 声明 MIT；原声明、作者信息与源码均原样保留。\n'
    write(KIT/'licenses/第三方工具说明.md',notice)
    # Upstream Ruby runtime stores its own complete license tree; locate real names.
    for record in records:
        loc=record['license_location']
        if loc and not (KIT/loc).exists():
            candidates=[str(p.relative_to(KIT)) for p in (KIT/record['entry']).parent.rglob('*') if p.is_file() and p.name.lower().startswith(('license','copying'))]
            raise RuntimeError('Missing license location: '+record['name']+' '+loc)
    items=list(selected())
    write(KIT/'SHA256SUMS.txt',''.join(digest(p)+'  '+rel+'\n' for p,rel in items if rel!='SHA256SUMS.txt'))
    items=list(selected())
    target=ROOT/'学员工具与练习_Windows64.zip'
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6,allowZip64=True) as z:
        for p,rel in items:
            info=zipfile.ZipInfo('学员工具包_Windows64/'+rel,(2026,10,21,12,0,0))
            info.compress_type=zipfile.ZIP_STORED if p.suffix.lower() in ('.zip','.7z','.whl','.gem','.gz','.xz') else zipfile.ZIP_DEFLATED
            info.external_attr=(0o100755 if rel=='tools/volatility2/linux/volatility_2.6_lin64_standalone' else 0o100644)<<16
            with p.open('rb') as inp,z.open(info,'w') as out:shutil.copyfileobj(inp,out,1024*1024)
    # Instructor release includes the complete course package plus validation record.
    with zipfile.ZipFile(ROOT/'CTF取证基础_完整培训包.zip') as existing:
        package={name:existing.read(name) for name in existing.namelist()}
    package['验证记录/工具与题解验收记录.json']=(ROOT/'output/工具与题解验收记录.json').read_bytes()
    handout_check=ROOT/'output/学员讲义验收记录.json'
    if handout_check.exists():
        handout_result=json.loads(handout_check.read_text(encoding='utf-8-sig'))
        assert handout_result['windows_powershell_syntax']=='pass'
        assert handout_result['kali_bash_syntax']=='pass'
        package['验证记录/学员讲义验收记录.json']=handout_check.read_bytes()
    platform_check=ROOT/'output/学习平台API验收记录.json'
    if platform_check.exists():
        record=json.loads(platform_check.read_text(encoding='utf-8'))
        assert record['passed']==record['total'] and record['total']>=50
        # Keep the distributable record compact; temporary task ids are local.
        package['验证记录/学习平台API验收记录.json']=json.dumps({k:v for k,v in record.items() if k not in ('generated_jobs','qa_inputs','uploaded_inputs')},ensure_ascii=False,indent=2).encode('utf-8')
    ui_check=ROOT/'output/通用文件分析页面验收.json'
    if ui_check.is_file():package['验证记录/通用文件分析页面验收.json']=ui_check.read_bytes()
    workflow_check=ROOT/'output/通用取证流程验收记录.json'
    if workflow_check.is_file():
        record=json.loads(workflow_check.read_text(encoding='utf-8'));assert record['passed']==record['total'] and record['total']>=20
        package['验证记录/通用取证流程验收记录.json']=json.dumps({k:v for k,v in record.items() if k not in ('cases','validation_folder')},ensure_ascii=False,indent=2).encode('utf-8')
    compatibility_check=ROOT/'output/Volatility2_兼容功能验收.json'
    if compatibility_check.is_file():
        record=json.loads(compatibility_check.read_text(encoding='utf-8'));assert record['passed']==record['total'] and record['total']>=15
        compact={k:v for k,v in record.items() if k not in ('validation_folder','checks')}
        compact['checks']=[{k:v for k,v in row.items() if k!='detail'} for row in record['checks']]
        package['验证记录/Volatility2_兼容功能验收.json']=json.dumps(compact,ensure_ascii=False,indent=2).encode('utf-8')
    compatibility_ui=ROOT/'output/Volatility2_页面验收.json'
    if compatibility_ui.is_file():package['验证记录/Volatility2_页面验收.json']=compatibility_ui.read_bytes()
    for name in ('工作台新增功能验收.json','工作台加解密向量验收.json','工作台界面验收.json','工作台内存扩展验收.json','Volatility社区插件验收.json','Volatility社区插件界面验收.json','新手环境安装验收.json'):
        check_file=ROOT/'output'/name
        if check_file.is_file():
            record=json.loads(check_file.read_text(encoding='utf-8-sig'))
            if 'total' in record:assert record['total']==record['passed'],name
            package['验证记录/'+name]=json.dumps({k:v for k,v in record.items() if k not in ('fixture_directory','validation_folder')},ensure_ascii=False,indent=2).encode('utf-8')
    write(ROOT/'Volatility3_Windows离线符号_说明.md','''# Windows 离线符号集合\n\n本文件为工作区已有 Volatility 3 上游符号集合的原样转存，通过 7-Zip 完整性校验。不是内存镜像，不保证是最新集合，也不保证涵盖每个 Windows 构建。\n\n放入学员工具包 runtime/python/Lib/site-packages/volatility3/symbols，命名为 windows.zip，保持 ZIP 形式即可。课前应使用授课镜像运行 windows.info 验证匹配。\n\n上游来源入口：https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip\n\nVolatility Software License 1.0：https://www.volatilityfoundation.org/license/vsl-v1.0\n\nSHA256：'''+digest(ROOT/'Volatility3_Windows离线符号.zip')+'\n\n字节数：839727133\n')
    package['Volatility3_Windows离线符号_说明.md']=(ROOT/'Volatility3_Windows离线符号_说明.md').read_bytes()
    (ROOT/'讲师课件与逐题题解.zip').write_bytes(build.archive_bytes(package))
    names=('学员工具与练习_Windows64.zip','CTF取证基础_学员讲义与练习.zip','CTF取证基础_Kali学习资料.zip','CTF取证基础_完整培训包.zip','讲师课件与逐题题解.zip','CTF取证基础_学员练习.zip','Volatility3_例题与命令.zip','Volatility3_Windows离线符号.zip')
    releases=[dict(file=n,bytes=(ROOT/n).stat().st_size,sha256=digest(ROOT/n)) for n in names]
    write(ROOT/'分发包_SHA256SUMS.txt',''.join(r['sha256']+'  '+r['file']+'\n' for r in releases))
    result=dict(student_files=len(items),student_uncompressed_bytes=sum(p.stat().st_size for p,_ in items),
                max_zip_entry_length=max(len('学员工具包_Windows64/'+rel) for _,rel in items),checks=39,releases=releases)
    write(ROOT/'output/分发包清单.json',json.dumps(result,ensure_ascii=False,indent=2))
    print(json.dumps(result,ensure_ascii=False))
    import finalize_delivery
    finalize_delivery.main()

if __name__=='__main__':main()

