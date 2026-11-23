"""Curate the final delivery after package_release.py; keep editable sources."""
from pathlib import Path, PurePosixPath
import hashlib, json, shutil, sys, zipfile
from datetime import date

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / '课件源码'
KIT = ROOT / '学员工具包_Windows64'
sys.path[:0] = [str(SOURCE), str(ROOT / '工具包构建')]
RELEASES = ('学员工具与练习_Windows64.zip', 'CTF取证基础_Kali学习资料.zip',
            '讲师课件与逐题题解.zip', 'Volatility3_Windows离线符号.zip',
            'CTF取证基础_学员练习.zip', 'Volatility3_例题与命令.zip')
OBSOLETE = ('CTF取证基础_学员讲义与练习.zip', 'CTF取证基础_完整培训包.zip')

WINDOWS_README = '''# CTF 取证基础 · Windows 完整工具包

适用：Windows 10/11 x64。无需预装 Python 2、Python 3 或 Ruby。

1. 完整解压到可写目录，不要在压缩包内运行。
2. 双击“00_一键配置并启动.cmd”，等待检查并自动打开浏览器。
3. 从 index.html 阅读讲义、做题、看题解或进入可视化工具台。

工具台顶部可切换“分析工具 / 附件管理 / 分析历史”；左上角可收起导航。附件与历史列表提供搜索、多选和删除。

工具台支持上传自己的文件。保留启动窗口，结束时关闭窗口。

启动失败时运行“05_环境检查与修复.cmd”；社区插件不可用时运行“06_仅基础工具启动.cmd”。排查步骤见“环境安装与故障排查.html”。

题目附件在 labs，上传文件在 labs/inputs，结果在 labs/out。手动命令使用“01_启动课堂终端.cmd”。

内存基础题为合成输出练习；真实内存分析需自行准备镜像及匹配符号。第三方工具来源与许可见 TOOL_MANIFEST.json、licenses；完整性校验见 SHA256SUMS.txt。
'''
KALI_README = '''# CTF 取证基础 · Kali 学习资料

1. 完整解压，在目录内打开 Bash。
2. 首次运行：bash 00_一键安装_Kali.sh（安装依赖需要网络和 sudo）。
3. 后续运行：bash 启动学习平台.sh。

index.html 是讲义、题目、题解及工具台的统一入口。题目在 labs，上传文件在 labs/inputs，输出在 labs/out。

本包不含 Windows 运行环境。Windows 学员使用另发的“学员工具与练习_Windows64.zip”。内存读题材料是合成输出，真实分析需另备镜像和符号。安装排错见“环境安装与故障排查.html”。
'''
INSTRUCTOR_README = '''# CTF 取证基础 · 讲师资料

打开 index.html 统一查看课件、讲义、15 道例题及完整题解。课堂投影使用“课堂课件.html”；备课参考“讲师手册.html”和“讲师题解_逐题讲解.html”。

Windows 学员发“学员工具与练习_Windows64.zip”，Kali 学员发“CTF取证基础_Kali学习资料.zip”。本包保存课件与工具台维护源码，不含 Windows 完整运行环境。

练习附件在练习材料；修改讲义和界面使用课件源码，修改工具服务使用工具包构建。公开题复现来源与内存合成材料的说明随题目保留。
'''

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding='utf-8', newline='\n')

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def duplicate_markdown(path, parent):
    return (path.parent == parent and path.suffix == '.md' and
            path.name != 'README.md' and path.with_suffix('.html').is_file())

def selected():
    for p in sorted(KIT.rglob('*')):
        if not p.is_file():
            continue
        rel = p.relative_to(KIT).as_posix()
        if '__pycache__' in p.parts or p.suffix in ('.pyc', '.pyo'):
            continue
        if rel.startswith(('labs/out/', 'labs/inputs/', 'runtime/ruby/share/ri/',
                           'runtime/ruby/lib/ruby/gems/3.3.0/doc/')):
            continue
        if duplicate_markdown(p, KIT):
            continue
        yield p, rel

def zip_info(name, previous=None):
    info = zipfile.ZipInfo(name, previous.date_time if previous else (2026, 10, 21, 12, 0, 0))
    info.compress_type = (zipfile.ZIP_STORED if PurePosixPath(name).suffix.lower()
                          in ('.zip', '.7z', '.whl', '.gem', '.gz', '.xz') else zipfile.ZIP_DEFLATED)
    info.external_attr = (previous.external_attr if previous else
                         (0o100755 if name.endswith('volatility_2.6_lin64_standalone') else 0o100644) << 16)
    return info

def thin_zip(path, distribution, readme):
    from portal import build_portal
    overlay = {'index.html': build_portal(distribution).encode('utf-8'), 'README.md': readme.encode('utf-8')}
    for p in ROOT.glob('*.html'):
        if p.name != 'index.html':
            overlay[p.name] = p.read_bytes()
    for name in ('learning_server.py','case_catalog.py','case_disk.py','casework.py'):
        overlay['tools/'+name]=(ROOT/'工具包构建'/name).read_bytes()
    if distribution == 'course':
        for parent in (SOURCE, ROOT / '工具包构建'):
            for p in parent.iterdir():
                if p.is_file() and p.suffix in ('.py', '.ps1', '.sh', '.html', '.css', '.js', '.md', '.json'):
                    overlay[parent.name + '/' + p.name] = p.read_bytes()
    temp = path.with_suffix('.delivery.tmp')
    assert temp.resolve().is_relative_to(ROOT.resolve())
    with zipfile.ZipFile(path) as old, zipfile.ZipFile(temp, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as new:
        names = set(old.namelist())
        for info in old.infolist():
            name = info.filename
            pos = PurePosixPath(name)
            if (info.is_dir() or name in overlay or name in OBSOLETE or name == 'CTF取证基础_Kali学习资料.zip' or name.startswith('验证记录/') or
                ('__pycache__' in pos.parts) or pos.suffix in ('.pyc', '.pyo') or
                (len(pos.parts) == 1 and pos.suffix == '.md' and name != 'README.md' and pos.with_suffix('.html').as_posix() in names)):
                continue
            assert not pos.is_absolute() and '..' not in pos.parts, name
            with old.open(info) as src, new.open(zip_info(name, info), 'w') as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
        for name, raw in sorted(overlay.items()):
            new.writestr(zip_info(name), raw)
    temp.replace(path)

def main():
    from portal import build_portal
    write(ROOT / 'README.md', (SOURCE / 'distribution_readme.md').read_text(encoding='utf-8'))
    for name in ('learning_server.py','case_catalog.py','case_disk.py','casework.py'):
        shutil.copy2(ROOT/'工具包构建'/name,KIT/'tools'/name)
    for p in ROOT.glob('*.html'):
        if p.name!='index.html':shutil.copy2(p,KIT/p.name)
    write(ROOT / 'index.html', build_portal('workspace'))
    write(KIT / 'index.html', build_portal('windows'))
    write(KIT / 'README.md', WINDOWS_README)
    thin_zip(ROOT / 'CTF取证基础_Kali学习资料.zip', 'study', KALI_README)
    thin_zip(ROOT / '讲师课件与逐题题解.zip', 'course', INSTRUCTOR_README)
    items = list(selected())
    write(KIT / 'SHA256SUMS.txt', ''.join(digest(p) + '  ' + rel + '\n' for p, rel in items if rel != 'SHA256SUMS.txt'))
    items = list(selected())
    target = ROOT / '学员工具与练习_Windows64.zip'
    temp = target.with_suffix('.delivery.tmp')
    with zipfile.ZipFile(temp, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as z:
        for p, rel in items:
            with p.open('rb') as src, z.open(zip_info('学员工具包_Windows64/' + rel), 'w') as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
    temp.replace(target)
    releases = [dict(file=name, bytes=(ROOT / name).stat().st_size, sha256=digest(ROOT / name)) for name in RELEASES]
    write(ROOT / '分发包_SHA256SUMS.txt', ''.join(row['sha256'] + '  ' + row['file'] + '\n' for row in releases))
    from learning_server import ACTIONS
    from case_recipes import RECIPES
    record = dict(date=date.today().isoformat(), student_files=len(items), student_uncompressed_bytes=sum(p.stat().st_size for p, _ in items),
                  operations=len(ACTIONS), guided_routes=len(RECIPES), worked_cases=15, releases=releases,
                  public_docs='HTML; editable sources retained in instructor package')
    write(ROOT / 'output/分发包清单.json', json.dumps(record, ensure_ascii=False, indent=2))
    print(json.dumps(record, ensure_ascii=False), flush=True)

if __name__ == '__main__':
    main()
