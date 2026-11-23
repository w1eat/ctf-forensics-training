"""Build an offline, self-contained course and deterministic synthetic exercises.
Run: python 课件源码/build.py     (Python 3.9+, Pillow for JPEG training fixtures)
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import html
import io
import ipaddress
import json
from pathlib import Path
import struct
import zipfile
import zlib
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from content import GROUPS, SLIDES

ROOT = Path(__file__).resolve().parent.parent
SOURCE = Path(__file__).resolve().parent
LAB_ROOT = ROOT / "练习材料"
FIXED_TIME = (2026, 10, 18, 9, 0, 0)


def write(path: Path, content: str | bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8", newline="\n")


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xffffffff)


def make_png() -> bytes:
    width, height = 256, 160
    scanlines = bytearray()
    for y in range(height):
        scanlines.append(0)
        for x in range(width):
            rgb = (235, 243, 233)
            if x % 16 == 0 or y % 16 == 0:
                rgb = (216, 229, 216)
            if 29 <= x < 228 and 28 <= y < 132:
                rgb = (25, 57, 52)
            if 44 <= x < 166 and 43 <= y < 50:
                rgb = (155, 215, 171)
            if 44 <= x < 207 and 64 <= y < 70:
                rgb = (91, 135, 109)
            if 44 <= x < 187 and 82 <= y < 88:
                rgb = (91, 135, 109)
            if 44 <= x < 145 and 100 <= y < 106:
                rgb = (232, 186, 112)
            scanlines.extend(rgb)
    flag = base64.b64encode(b"flag{file_type_before_extension}")
    return (b"\x89PNG\r\n\x1a\n"
            + png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + png_chunk(b"tEXt", b"Title\x00CTF Foundation - File Identity")
            + png_chunk(b"tEXt", b"Comment\x00" + flag)
            + png_chunk(b"IDAT", zlib.compress(bytes(scanlines), 9))
            + png_chunk(b"IEND", b""))


def archive_bytes(files: dict[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100755 if name.endswith('tools/volatility2/linux/volatility_2.6_lin64_standalone') else 0o100644) << 16
            archive.writestr(info, data)
    return stream.getvalue()


def exercises():
    from assets import exercises as create_exercises
    return create_exercises(make_png())


def icon(name):
    paths = {
        "grid": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
        "book": '<path d="M3 4h6a4 4 0 0 1 3 2 4 4 0 0 1 3-2h6v15h-6a4 4 0 0 0-3 2 4 4 0 0 0-3-2H3z"/><path d="M12 6v15"/>',
        "notes": '<path d="M5 3h14v18H5zM8 8h8M8 12h8M8 16h5"/>',
        "expand": '<path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5"/>',
        "print": '<path d="M7 8V3h10v5M7 17H3V8h18v9h-4M7 13h10v8H7zM17 10h1"/>',
        "download": '<path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/>',
    }
    return f'<svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">{paths[name]}</svg>'


def build_html(zip_data, slides=None, groups=None, download_name="CTF取证基础_学员练习.zip"):
    slides = SLIDES if slides is None else slides
    from command_platforms import annotate_slides
    slides, command_audit = annotate_slides(slides)
    groups = GROUPS if groups is None else groups
    css = (SOURCE / "theme.css").read_text(encoding="utf-8")
    js = (SOURCE / "app.js").read_text(encoding="utf-8")
    chapter_nav = ""
    for i, (name, english, _) in enumerate(groups):
        count = sum(1 for slide in slides if slide["group"] == i)
        chapter_nav += f'<button class="chapter" data-chapter="{i}"><span class="ch-no">{i:02}</span><span>{name}</span><small>{count:02}</small></button>'
    slide_html = ""
    for i, slide in enumerate(slides):
        group = slide["group"]
        group_name, english, _ = groups[group]
        header = ""
        if slide["kind"] not in ("cover", "closing"):
            header = f'<header class="slide-header"><div class="eyebrow">{group:02} / {english}</div><h2>{html.escape(slide["title"])}</h2><p class="slide-subtitle">{html.escape(slide["subtitle"])}</p></header>'
        heading = f'<h2 class="sr-only">{html.escape(slide["title"])}</h2>' if slide["kind"] == "closing" else ""
        slide_html += f'''<article class="slide {slide['kind']}{' active' if i == 0 else ''}" id="slide-{i+1}" data-title="{html.escape(slide['title'], quote=True)}" data-chapter="{group}" data-chapter-name="{group_name}" aria-label="第 {i+1} 页：{html.escape(slide['title'], quote=True)}">
{header}{heading}<div class="slide-body">{slide['body']}</div>
<aside class="notes"><strong>讲师备注 / PRESENTER NOTES</strong><p>{html.escape(slide['notes'])}</p></aside>
<footer class="slide-footer"><span>证据实验室 / CTF 取证基础</span><span>{group_name} <b>— {i+1:02}</b></span></footer></article>'''
    return f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="CTF 数字取证基础专项培训：{len(slides)} 页离线课件，工具与命令详解、基础练习、Vol3 教学例题与自测。"><meta name="color-scheme" content="light"><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 40 40'%3E%3Crect width='40' height='40' rx='8' fill='%23152c2e'/%3E%3Cpath d='M10 12h8v8h-8zm12 0h8v8h-8zM10 24h8v8h-8z' fill='%239bddbb'/%3E%3Cpath d='M22 24h8v8h-8z' fill='%23e3a950'/%3E%3C/svg%3E"><title>CTF 取证基础 · 证据实验室</title><style>{css}</style></head>
<body><a class="skip-link" href="#main">跳到课件内容</a>
<aside class="rail" aria-label="章节导航"><div class="brand"><div class="brand-mark" aria-hidden="true"><i></i><i></i><i></i><i></i></div><div><strong>证据实验室</strong><small>FORENSICS CLASSROOM</small></div></div><div class="rail-label">COURSE CHAPTERS</div><nav class="chapters">{chapter_nav}</nav><div class="rail-bottom"><div class="lesson-tag"><span class="counter-dot"></span>基础专项 · {sum(g[2] for g in groups)} MIN</div><p>先识别，再定位。<br>每个结论，都有证据。</p><p>离线课件 / 2026.10</p></div></aside>
<div class="app"><header class="topbar"><div class="breadcrumb">基础培训<span id="top-chapter">起步与方法</span></div><div class="top-actions">
<a class="tool-btn student-handout" href="index.html" target="_top" title="讲义、题目、题解与可视化工具台">统一入口</a>
<button class="tool-btn" data-overview title="总览与搜索（O）" aria-label="总览与搜索">{icon('grid')}<span class="tool-label optional">总览</span></button>
<button class="tool-btn" id="reading-toggle" title="阅读模式（R）" aria-label="切换阅读模式" aria-pressed="false">{icon('book')}<span class="tool-label optional">阅读</span></button>
<button class="tool-btn" id="notes-toggle" title="讲师备注（N）" aria-label="切换讲师备注" aria-pressed="false">{icon('notes')}<span class="tool-label optional">备注</span></button>
<button class="tool-btn" id="fullscreen-toggle" title="全屏演示（F）" aria-label="全屏演示" aria-pressed="false">{icon('expand')}<span class="tool-label optional">演示</span></button>
<button class="tool-btn" id="print" title="打印全部课件，或另存为 PDF" aria-label="打印或另存为PDF">{icon('print')}<span class="tool-label hide-mobile">打印</span></button>
<button class="tool-btn primary" data-download title="下载练习与命令材料">{icon('download')}<span class="tool-label">练习材料</span></button>
</div></header>
<main class="deck" id="main" tabindex="-1">{slide_html}</main>
<footer class="nav-footer"><div class="progress-wrap"><div class="progress" id="progress"></div></div><div class="hint"><kbd>←</kbd><kbd>→</kbd> 翻页 <span class="extra-key">· <kbd>O</kbd> 总览 · <kbd>N</kbd> 备注 · <kbd>F</kbd> 演示</span></div><div class="chapter-now" id="chapter-now">起步与方法</div><div class="nav-controls"><button class="arrow-btn" id="prev" aria-label="上一页" title="上一页（←）">←</button><div class="page-count"><b id="current-page">01</b> / {len(slides):02}</div><button class="arrow-btn" id="next" aria-label="下一页" title="下一页（→）">→</button></div></footer></div>
<dialog class="overview" id="overview" aria-labelledby="overview-title"><div class="overview-top"><div class="overview-heading"><h2 id="overview-title">课程总览</h2><button class="close-btn" id="close-overview" aria-label="关闭总览">×</button></div><input class="search-input" id="slide-search" type="search" aria-label="搜索课件内容" placeholder="搜索知识点：文件头、Vol3、时间线…" autocomplete="off"></div><div class="overview-grid" id="overview-grid"></div></dialog>
<div class="toast" id="toast" role="status" hidden></div><div class="sr-only" id="slide-announcement" aria-live="polite"></div>
<script id="practice-data" data-filename="{html.escape(download_name, quote=True)}" type="application/octet-stream">{base64.b64encode(zip_data).decode('ascii')}</script><script>{js}</script>
</body></html>'''


def main():
    from render_handouts import render, explicit_markdown
    write(ROOT/'Timeline0_partition4_题解.html',render((SOURCE/'timeline0_solution.md').read_text(encoding='utf-8'),'Timeline 0 · partition4.img 实战题解'))
    tools_guide=SOURCE/'tools_guide.md'
    if tools_guide.is_file():write(ROOT/'工具包使用指南.md',tools_guide.read_bytes())
    from case_recipes import guide as casework_guide
    write(ROOT/'PPT解题思路与工作台指南.md',explicit_markdown(casework_guide()))
    write(ROOT/'PPT解题思路与工作台指南.html',render((ROOT/'PPT解题思路与工作台指南.md').read_text(encoding='utf-8'),'PPT 解题思路与工作台指南'))
    write(ROOT/'Volatility_社区插件使用指南.md',explicit_markdown((SOURCE/'memory_plugins_guide.md').read_text(encoding='utf-8')))
    write(ROOT/'Volatility_社区插件使用指南.html',render((ROOT/'Volatility_社区插件使用指南.md').read_text(encoding='utf-8'),'Volatility 社区插件使用指南'))
    write(ROOT/'环境安装与故障排查.md',explicit_markdown((SOURCE/'setup_guide.md').read_text(encoding='utf-8')))
    write(ROOT/'环境安装与故障排查.html',render((ROOT/'环境安装与故障排查.md').read_text(encoding='utf-8'),'环境安装与故障排查'))
    write(ROOT/'00_一键安装_Kali.sh',(ROOT/'工具包构建/setup_kali.sh').read_text(encoding='utf-8'))
    write(ROOT / '讲师题解_逐题讲解.md', explicit_markdown((SOURCE / '逐题题解.md').read_text(encoding='utf-8')))
    files = exercises()
    for name, data in files.items():
        write(LAB_ROOT / name, data)
    practice_zip = archive_bytes(files)
    write(ROOT / "CTF取证基础_学员练习.zip", practice_zip)
    write(ROOT / "课堂课件.html", build_html(practice_zip))
    from assets import manual as make_manual
    manual = make_manual(SLIDES, GROUPS)
    write(ROOT / "讲师手册.md", manual)
    from memory_module import build_memory_slides, memory_files, memory_handout
    memory_data = memory_files()
    memory_zip = archive_bytes(memory_data)
    write(ROOT / "Volatility3_例题与命令.zip", memory_zip)
    memory_slides = build_memory_slides()
    for slide in memory_slides:
        slide["group"] = 0
    write(ROOT / "Volatility3_内存镜像分析.html", build_html(memory_zip, memory_slides, [("Vol3 内存镜像", "VOLATILITY 3", 45)], "Volatility3_例题与命令.zip"))
    write(ROOT / "Volatility3_内存镜像分析_命令与题解.md", memory_handout())
    from student_handout import build_markdown, NAME
    write(ROOT / (NAME + '.md'), explicit_markdown(build_markdown()))
    write(ROOT/'学员任务单.md',(SOURCE/'problem_set.md').read_bytes())
    write(ROOT/'学习平台使用指南.md',(SOURCE/'platform_guide.md').read_bytes())
    write(ROOT/'自动化取证流程指南.md',(SOURCE/'workflow_guide.md').read_bytes())
    write(ROOT/'Volatility2_兼容分析指南.md',explicit_markdown((SOURCE/'volatility2_guide.md').read_text(encoding='utf-8')))
    lab=(ROOT/'工具包构建/实验台.html').read_text(encoding='utf-8')
    lab=lab.replace('<body>','<body><a href="index.html" target="_top" style="display:block;padding:10px 20px;background:#17392f;color:#ecf3df;font:12px Microsoft YaHei;text-decoration:none">← 返回统一学习入口</a>',1)
    write(ROOT/'文件观察实验台.html',lab)
    for name in (NAME, "Volatility3_内存镜像分析_命令与题解", "讲师题解_逐题讲解", "工具包使用指南", "学员任务单", "讲师手册", "学习平台使用指南", "自动化取证流程指南", "Volatility2_兼容分析指南"):
        source = ROOT / (name + ".md")
        if source.exists():
            write(ROOT / (name + ".html"), render(source.read_text(encoding="utf-8"), name))
    from portal import build_portal,WINDOWS_LAUNCHER,KALI_LAUNCHER
    write(ROOT/'index.html',build_portal('workspace'))
    write(ROOT/'00_启动学习平台.cmd',WINDOWS_LAUNCHER)
    write(ROOT/'启动学习平台.sh',KALI_LAUNCHER)
    # Small student releases share labs/ layout, without Windows executables.
    student_package = {NAME + suffix: (ROOT / (NAME + suffix)).read_bytes() for suffix in ('.md', '.html')}
    student_package['Volatility3_内存镜像分析_命令与题解.html'] = (ROOT / 'Volatility3_内存镜像分析_命令与题解.html').read_bytes()
    student_package['index.html']=build_portal('study').encode('utf-8')
    student_package['启动学习平台.sh']=KALI_LAUNCHER.encode('utf-8')
    student_package['README.md'] = ('# CTF 取证基础 · 学员学习资料\n\nindex.html 是讲义、课件、15 道题目、完整题解和工具的统一入口。Kali 按讲义安装原生工具后，在 Bash 运行：bash 启动学习平台.sh。Windows 使用另发的完整工具包，双击 00_启动学习平台.cmd。\n\n练习附件在 labs，输出放 out/platform_runs。此学习资料包额外附 Vol2 Linux 独立兼容工具，不含其他二进制运行时和真实 RAM。\n').encode('utf-8')
    for name in ('课堂课件.html','Volatility3_内存镜像分析.html','工具包使用指南.md','工具包使用指南.html','学员任务单.md','学员任务单.html','讲师手册.md','讲师手册.html','讲师题解_逐题讲解.md','讲师题解_逐题讲解.html','学习平台使用指南.md','学习平台使用指南.html','文件观察实验台.html','Volatility3_内存镜像分析_命令与题解.md'):
        student_package[name]=(ROOT/name).read_bytes()
    for suffix in ('.md','.html'):student_package['自动化取证流程指南'+suffix]=(ROOT/('自动化取证流程指南'+suffix)).read_bytes()
    for suffix in ('.md','.html'):student_package['Volatility2_兼容分析指南'+suffix]=(ROOT/('Volatility2_兼容分析指南'+suffix)).read_bytes()
    for suffix in ('.md','.html'):student_package['PPT解题思路与工作台指南'+suffix]=(ROOT/('PPT解题思路与工作台指南'+suffix)).read_bytes()
    for suffix in ('.md','.html'):student_package['Volatility_社区插件使用指南'+suffix]=(ROOT/('Volatility_社区插件使用指南'+suffix)).read_bytes()
    for suffix in ('.md','.html'):student_package['环境安装与故障排查'+suffix]=(ROOT/('环境安装与故障排查'+suffix)).read_bytes()
    student_package['00_一键安装_Kali.sh']=(ROOT/'00_一键安装_Kali.sh').read_bytes()
    for item in (ROOT/'学员工具包_Windows64/tools/volatility2').rglob('*'):
        if item.is_file() and 'windows' not in item.parts and not any(p.startswith('win') and p in ('win32','win64') for p in item.parts) and '__pycache__' not in item.parts and item.suffix not in ('.pyc','.pyo'):
            student_package[item.relative_to(ROOT/'学员工具包_Windows64').as_posix()]=item.read_bytes()
    for folder in ('tools/volatility3_extra','tools/memory_plugins'):
        for item in (ROOT/'学员工具包_Windows64'/folder).rglob('*'):
            if item.is_file() and '__pycache__' not in item.parts and item.suffix not in ('.pyc','.pyo'):
                student_package[item.relative_to(ROOT/'学员工具包_Windows64').as_posix()]=item.read_bytes()
    student_package['licenses/source/volatility-2.6-source.zip']=(ROOT/'工具包构建/下载缓存/volatility-2.6-source.zip').read_bytes()
    student_package['CTF取证基础_学员练习.zip']=practice_zip
    student_package['Volatility3_例题与命令.zip']=memory_zip
    for name in ('learning_server.py','tool_tasks.py','finspect.py','analysis_engine.py','forensic_workflows.py','casework.py','case_catalog.py','case_crypto.py','case_carving.py','case_disk.py','case_mount.py','case_memory.py','mount_ops.ps1'):
        student_package['tools/'+name]=(ROOT/'工具包构建'/name).read_bytes()
    student_package.update({'labs/' + name: data for name, data in files.items()})
    for name in ('CTF取证基础_学员讲义与练习.zip', 'CTF取证基础_Kali学习资料.zip'):
        write(ROOT / name, archive_bytes(student_package))
    package = {"index.html": (ROOT / "index.html").read_bytes(),
               '课堂课件.html':(ROOT/'课堂课件.html').read_bytes(),
               '00_启动学习平台.cmd':WINDOWS_LAUNCHER.encode('utf-8'),
               '启动学习平台.sh':KALI_LAUNCHER.encode('utf-8'),
               "讲师手册.md": (ROOT / "讲师手册.md").read_bytes(),
               "CTF取证基础_学员练习.zip": practice_zip}
    # Course-only archives have every resource but no portable Windows runtime.
    package['index.html']=build_portal('course').encode('utf-8')
    for name in ("Volatility3_内存镜像分析.html", "Volatility3_例题与命令.zip", "Volatility3_内存镜像分析_命令与题解.md", "Volatility3_内存镜像分析_命令与题解.html", NAME + '.md', NAME + '.html', 'CTF取证基础_学员讲义与练习.zip', 'CTF取证基础_Kali学习资料.zip'):
        package[name] = (ROOT / name).read_bytes()
    for name in ("讲师题解_逐题讲解.md", "讲师题解_逐题讲解.html", "工具包使用指南.md", "工具包使用指南.html"):
        if (ROOT / name).exists():
            package[name] = (ROOT / name).read_bytes()
    for name in ('学员任务单.md','学员任务单.html','讲师手册.html','学习平台使用指南.md','学习平台使用指南.html','文件观察实验台.html'):
        package[name]=(ROOT/name).read_bytes()
    for suffix in ('.md','.html'):package['自动化取证流程指南'+suffix]=(ROOT/('自动化取证流程指南'+suffix)).read_bytes()
    for suffix in ('.md','.html'):package['Volatility2_兼容分析指南'+suffix]=(ROOT/('Volatility2_兼容分析指南'+suffix)).read_bytes()
    for suffix in ('.md','.html'):package['PPT解题思路与工作台指南'+suffix]=(ROOT/('PPT解题思路与工作台指南'+suffix)).read_bytes()
    package.update({k:v for k,v in student_package.items() if k.startswith(('tools/volatility2/','tools/volatility3_extra/','tools/memory_plugins/','Volatility_社区插件使用指南','licenses/source/volatility-2.6'))})
    package['00_一键安装_Kali.sh']=(ROOT/'00_一键安装_Kali.sh').read_bytes()
    for suffix in ('.md','.html'):package['环境安装与故障排查'+suffix]=(ROOT/('环境安装与故障排查'+suffix)).read_bytes()
    if (ROOT / "README.md").exists():
        package["README.md"] = (ROOT / "README.md").read_bytes()
    for name, data in files.items():
        package[f"练习材料/{name}"] = data
    for name in ("build.py", "content.py", "assets.py", "memory_module.py", "render_handouts.py", "problem_set.md", "逐题题解.md", "theme.css", "app.js", "command_platforms.py", "student_handout.py", "student_foundations.md", "student_memory.md", "finspect.py", "distribution_readme.md",'portal.py','portal.html','portal.css','portal.js','platform_guide.md','workflow_guide.md','volatility2_guide.md','case_recipes.py','memory_plugins_guide.md','setup_guide.md','workbench.js','workbench.css','workspace_management.js','workspace_management.css','tools_guide.md','timeline0_solution.md'):
        package[f"课件源码/{name}"] = (SOURCE / name).read_bytes()
    for name in ('learning_server.py','tool_tasks.py','analysis_engine.py','forensic_workflows.py','prepare_volatility2.py','prepare_extra_tools.py','prepare_memory_plugins.py','prepare_bootstrap.py','bootstrap.ps1','setup_probe.py','setup_kali.sh','casework.py','case_catalog.py','case_crypto.py','case_carving.py','case_disk.py','case_mount.py','case_memory.py','mount_ops.ps1','实验台.html'):
        package['工具包构建/'+name]=(ROOT/'工具包构建'/name).read_bytes()
    write(ROOT / "CTF取证基础_完整培训包.zip", archive_bytes(package))
    from command_platforms import annotate_slides
    _, audit = annotate_slides(SLIDES)
    write(ROOT / 'output/命令环境标注记录.json', json.dumps(audit, ensure_ascii=False, indent=2))
    print(json.dumps({"slides": len(SLIDES), "minutes": sum(g[2] for g in GROUPS), "html_bytes": (ROOT / "index.html").stat().st_size,
                      "practice_zip_bytes": len(practice_zip), "output": str(ROOT / "index.html")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
