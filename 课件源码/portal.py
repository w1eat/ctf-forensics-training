"""Generate the single index.html for resources, exercises, solutions and real tools."""
from pathlib import Path
import html,json,re,sys
SOURCE=Path(__file__).resolve().parent;ROOT=SOURCE.parent
sys.path.insert(0,str(ROOT/'工具包构建'))
from learning_server import ACTIONS,GROUPS,WORKFLOW_CATALOG
from case_recipes import RECIPES,CATEGORIES

RESOURCES=[
 ('timeline-case','Timeline 0 实战题解','用实际 partition4.img 复现：文件时间线、1985 年离群记录、定向导出与 Base64；附判断依据和双系统命令。','Timeline0_partition4_题解.html','实战补充 / 时间线'),
 ('setup','环境安装与故障排查','首次运行的一键配置、包内运行时、VC++ 与防护拦截排查。','环境安装与故障排查.html','新手开始'),
 ('memory-plugins','Volatility 社区插件','mimikatz / pypykatz、BitLocker 与 Editbox 的安装、命令与结果判读。','Volatility_社区插件使用指南.html','Vol2 / Vol3 · 社区扩展'),
 ('casework','按题意选择解题工作流',f'两份 PPT 对应的 {len(RECIPES)} 条路线、Windows / Kali 能力表、恢复、分离、加解密与挂载的用法。','PPT解题思路与工作台指南.html',f'{len(RECIPES)} 条路线 / 工具操作'),
 ('student','学员讲义','概念、工具参数、Windows / Kali 命令和 15 个案例的判断依据、验证与排错。','CTF取证基础_学员讲义.html','26 节知识 + 15 案例'),
 ('slides','课堂课件','适合投影、连续阅读、搜索和自测的主课件。','课堂课件.html','81 页 / 210 MIN'),
 ('memory','Volatility 3 专题','系统 → 进程 → 参数 / 历史 → 文件 / 映射页 → 验证。','Volatility3_内存镜像分析.html','18 页 / Vol3'),
 ('tasks','题目任务单','15 个基础案例，先独立完成并记录证据。','学员任务单.html','先做题，再看解法'),
 ('memory_notes','Vol3 命令与题解','解释如何从进程、参数、文件对象与编码选择路线，附 3 道读题解法和双系统命令。','Volatility3_内存镜像分析_命令与题解.html','Windows / Kali'),
 ('memory_compat','Vol2 兼容分析与排错','旧 Windows 控制台兼容错误、profile 验证、命令历史和导出；含真实镜像验证示例。','Volatility2_兼容分析指南.html','Windows / Kali · 独立版'),
 ('guide','工具包使用指南','启动工具、路径、依赖、Windows 参数差异与排错。','工具包使用指南.html','入门必读'),
 ('answers','逐题参考题解','15 题逐步解释线索、假设、工具选择、输出含义、失败分支与举一反三。','讲师题解_逐题讲解.html','15 案例 / 思路与验证'),
 ('manual','讲师手册','课程安排、逐页备注与答案，供课程复习或授课参考。','讲师手册.html','参考资料'),
 ('lab','文件观察实验台','浏览器选文件，查看十六进制、图像通道与位平面。','文件观察实验台.html','纯浏览器运行'),
 ('platform','本地工具台使用指南','如何启动、导入附件、运行工具、复用输出与保存报告。','学习平台使用指南.html','从 index.html 开始'),
 ('workflows','自动化取证流程指南','磁盘、嵌套附件、图片、数据库、日志、文档和 Vol3 的步骤、范围与命令。','自动化取证流程指南.html','10 个流程入口'),
]
TOOLS=[
 ('Vol2 社区扩展','mimikatz / BitLocker','旧系统 WDigest 与 FVEK 候选分析；含隔离依赖。Editbox 使用已有标准插件。','tools/volatility2/extra_plugins/mimikatz.py','vol2_extra','GPL-2.0-or-later'),
 ('Vol3 社区扩展','pypykatz 0.6.13 / BitLocker','离线 LSASS 凭据表格与 BitLocker 池扫描；保留完整原始结果。','tools/volatility3_extra/vol_pypykatz.py','vol_extra','MIT / GPL-3.0'),
 ('PhotoRec / TestDisk','7.2','按签名恢复数据；镜像文件可在工具台直接运行，保留日志与输出。','tools/testdisk/photorec_win.exe','disk_photorec','GPL-2.0-or-later'),
 ('ImDisk','2.1.2','RAW 分区只读挂载与卸载，含驱动安装包和对应源码。','tools/imdisk/cli/amd64/imdisk.exe','disk_mount','MIT-style / GPL 组件'),
 ('VeraCrypt / TrueCrypt 兼容','1.26.29 / 1.25.9','已知口令的加密容器只读挂载；保留原始便携包、运行文件与许可。','tools/veracrypt/VeraCrypt.exe','disk_mount','VeraCrypt / TrueCrypt 许可'),
 ('PyCryptodome','4.1.0','AES、DES、3DES、RC4、MD4 / NTLM 等字节运算，Windows 运行时已集成。','runtime/python/Lib/site-packages/Crypto/__init__.py','cipher','BSD / Public domain 与组件许可'),
 ('Volatility 3','2.28.2','Windows 内存镜像，11 个常用插件的帮助和工作流。','tools/volatility3/vol.py','vol_help','Python / VSL'),
 ('Volatility 2','2.6 独立版','旧镜像兼容：imageinfo → profile / KDBG → 进程 / 历史 → 文件与内存导出。','tools/volatility2/windows/volatility_2.6_win64_standalone.exe','vol2_help','GPL-2.0-or-later'),
 ('ExifTool','13.59','图片与文件元数据；显示字段组和重复标签。','tools/exiftool/exiftool.exe','metadata','Perl Artistic / GPL'),
 ('7-Zip','26.04','ZIP / 7z / RAR / TAR 等格式的列表、校验与提取。','tools/7zip/7z.exe','archive_general','LGPL 与组件许可'),
 ('pngcheck','4.0.1','PNG 结构、CRC、图像数据完整性检查。','tools/pngcheck/pngcheck.exe','png_check','MIT-style / zlib'),
 ('zsteg / Ruby','0.2.14 / 3.3.12','PNG / BMP LSB 枚举；Windows 自动使用 --no-file。','runtime/ruby/bin/zsteg','lsb_scan','MIT / Ruby'),
 ('The Sleuth Kit','4.14.0','mmls → fsstat → fls / istat → icat；分区与文件恢复。','tools/sleuthkit/bin/mmls.exe','disk_partitions','CPL / IPL 与组件许可'),
 ('SQLite','3.54.1 CLI / 3.50.4 Python','任意数据库结构、表数据预览和自定义只读 SQL。','tools/sqlite/sqlite3.exe','sqlite_tables','Public domain'),
 ('BusyBox','1.38.0','xxd、strings、grep、dd、base64 等 Windows 命令。','tools/busybox/busybox.exe','hex','GPL-2.0'),
 ('Python / Pillow','3.13.16 / 11.3.0','随包运行时；CRC、LSB、日志、雕刻和小字典脚本。','runtime/python/python.exe','lsb_extract','PSF / MIT-CMU'),
 ('finspect','课堂源码','常见签名、字符串、PNG CRC、小字典与原始字节保存。','tools/finspect.py','file_type','随包可编辑源码'),
 ('自动分析引擎','课堂源码','上传文件后按内容分流，输出带扫描范围、命令与后续建议的 HTML / JSON 报告。','tools/analysis_engine.py','auto_analyze','随包可编辑源码'),
 ('YARA','yara-python 4.5.4','内置线索规则、粘贴自定义规则或导入 .yar；匹配位置可视化。','runtime/python/Lib/site-packages/yara.cp313-win_amd64.pyd','yara_scan','BSD-3-Clause'),
 ('pypdf','6.21.1','PDF 页数、元数据、附件名称与正文提取。','runtime/python/Lib/site-packages/pypdf/__init__.py','pdf_read','BSD-3-Clause'),
 ('pefile','2024.8.26','PE 静态节表、导入、入口与尾随数据偏移。','runtime/python/Lib/site-packages/pefile.py','pe_read','MIT'),
 ('CyberChef','9.28.0','离线编码、解码与数据转换。','tools/CyberChef/CyberChef_v9.28.0.html',None,'Apache-2.0'),
]
CASE_CONFIG={
 1:('inspect','file_type',{'file':'01_file/unknown.dat'},['01_file/unknown.dat']),
 2:('image','png_map',{'file':'02_png/broken_width.png'},['02_png/broken_width.png']),
 3:('image','lsb_extract',{'file':'03_lsb/quiet.png'},['03_lsb/quiet.png']),
 4:('archive','signatures',{'file':'04_archive/carrier.bin'},['04_archive/carrier.bin']),
 5:('disk','disk_partitions',{'file':'05_disk/tiny_fat16.dd'},['05_disk/tiny_fat16.dd']),
 6:('disk','sqlite_tables',{'file':'06_sqlite/case.db'},['06_sqlite/case.db']),
 7:('disk','timeline',{'file':'07_logs/audit.jsonl'},['07_logs/access.log','07_logs/audit.jsonl']),
 8:('inspect','strings',{'file':'public_examples/garden_demo.jpg'},['public_examples/garden_demo.jpg','public_examples/SOURCES.md']),
 9:('inspect','metadata',{'file':'public_examples/cat_demo.jpg'},['public_examples/cat_demo.jpg','public_examples/SOURCES.md']),
 10:('image','png_header',{'file':'02_png/broken_header.png'},['02_png/broken_header.png','02_png/good.png']),
 11:('archive','zip_flags',{'file':'04_archive/flagged.zip'},['04_archive/flagged.zip']),
 12:('archive','zip_dictionary',{'file':'04_archive/locked.zip'},['04_archive/locked.zip','04_archive/words.txt']),
 13:('memory','strings',{'file':'08_memory/case_a/cmdline.csv'},['08_memory/case_a/pslist.csv','08_memory/case_a/cmdline.csv']),
 14:('memory','strings',{'file':'08_memory/case_b/exported_memo.txt'},['08_memory/case_b/cmdline.csv','08_memory/case_b/handles.csv','08_memory/case_b/filescan.txt','08_memory/case_b/exported_memo.txt']),
 15:('memory','strings',{'file':'08_memory/case_c/process_2460_excerpt.bin','encoding':'utf16le'},['08_memory/case_c/pslist.csv','08_memory/case_c/cmdline.csv','08_memory/case_c/process_2460_excerpt.bin']),
}

WINDOWS_LAUNCHER='''@echo off
chcp 65001 >nul
setlocal DisableDelayedExpansion
set "CTF_FORENSICS_MODE=full"
set "CTF_BOOTSTRAP=%~dp0tools\\bootstrap.ps1"
if not exist "%CTF_BOOTSTRAP%" for /d %%D in ("%~dp0*") do if exist "%%~fD\\tools\\bootstrap.ps1" set "CTF_BOOTSTRAP=%%~fD\\tools\\bootstrap.ps1"
if exist "%CTF_BOOTSTRAP%" (
  "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CTF_BOOTSTRAP%" -Mode Launch -WorkspaceRoot "%~dp0." -NoLaunch -NoBrowser -NonInteractive
  if errorlevel 20 exit /b 20
  if errorlevel 10 set "CTF_FORENSICS_MODE=basic"
)
set "CTF_PLATFORM_PY="
if exist "%~dp0runtime\\python\\python.exe" set "CTF_PLATFORM_PY=%~dp0runtime\\python\\python.exe"
if not defined CTF_PLATFORM_PY for /d %%D in ("%~dp0*") do if exist "%%~fD\\runtime\\python\\python.exe" set "CTF_PLATFORM_PY=%%~fD\\runtime\\python\\python.exe"
if not defined CTF_PLATFORM_PY (
  echo This package does not include the Windows runtime. Use the complete Windows toolkit.
  pause
  exit /b 20
)
set "CTF_PLATFORM_SERVER=%~dp0tools\\learning_server.py"
if not exist "%CTF_PLATFORM_SERVER%" for /d %%D in ("%~dp0*") do if exist "%%~fD\\learning_server.py" set "CTF_PLATFORM_SERVER=%%~fD\\learning_server.py"
if not exist "%CTF_PLATFORM_SERVER%" (
  echo Missing learning_server.py. Extract the complete package first.
  pause
  exit /b 1
)
"%CTF_PLATFORM_PY%" "%CTF_PLATFORM_SERVER%" --root "%~dp0." %*
if errorlevel 1 pause
'''.replace('\n','\r\n')
KALI_LAUNCHER='''#!/usr/bin/env bash
set -euo pipefail
platform_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
platform_python=python3
if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
  platform_python="$VIRTUAL_ENV/bin/python"
elif [[ -x "$platform_root/.runtime/kali/venv/bin/python" ]]; then
  platform_python="$platform_root/.runtime/kali/venv/bin/python"
elif [[ -x "$HOME/ctf-forensics/.venv/bin/python" ]]; then
  platform_python="$HOME/ctf-forensics/.venv/bin/python"
fi
if [[ -d "$platform_root/.runtime/kali/gems" ]]; then
  export GEM_HOME="$platform_root/.runtime/kali/gems"
  export GEM_PATH="$GEM_HOME"
  export PATH="$GEM_HOME/bin:$(dirname -- "$platform_python"):$PATH"
fi
platform_server="$platform_root/tools/learning_server.py"
if [[ ! -f "$platform_server" ]]; then
  platform_server="$platform_root/工具包构建/learning_server.py"
fi
exec "$platform_python" "$platform_server" --root "$platform_root" "$@"
'''

def fragment(markdown,identity):
    from render_handouts import render
    page=render(markdown,'题解')
    body=re.search(r'<main[^>]*>.*?<div class="meta">.*?</div>(.*?)<footer>',page,re.S)[1]
    return re.sub(r'id="s(\d+)"',lambda m:f'id="answer-{identity}-{m[1]}"',body)

def case_records():
    from student_handout import case_sections
    solutions=dict(case_sections());text=(SOURCE/'problem_set.md').read_text(encoding='utf-8-sig')
    matches=list(re.finditer(r'^## (\d{2}) · (.+)$',text,re.M));result=[]
    for i,m in enumerate(matches):
        n=int(m[1]);end=matches[i+1].start() if i+1<len(matches) else len(text)
        task=text[m.end():end].strip();group,action,params,attachments=CASE_CONFIG[n]
        result.append(dict(id=n,title=m[2],task=task,group=group,action=action,params=params,attachments=attachments,solution=fragment(solutions[n],n)))
    assert len(result)==15
    return result

def build_portal(distribution='workspace'):
    from render_handouts import REASONING_STYLE
    toolkit='学员工具包_Windows64/' if distribution=='workspace' else ''
    labs='练习材料/' if distribution in ('workspace','course') else 'labs/'
    includes_tools=distribution in ('workspace','windows')
    cases=case_records();escape=html.escape;resources='';case_html='';tools=''
    for identity,title,description,href,tag in RESOURCES:
        resources+=f'<article class="resource-card" data-search="{escape(title+description)}"><span class="eyebrow">{escape(tag)}</span><h3>{escape(title)}</h3><p>{escape(description)}</p><div class="card-actions"><button class="text-btn" data-doc="{identity}">在这里阅读 ↗</button><a href="{href}" target="_blank" rel="noopener">独立打开</a></div></article>'
    for row in cases:
        n=row['id'];attachments=''.join(f'<a href="{escape(labs+name)}" download>{escape(Path(name).name)}</a>' for name in row['attachments'])
        case_html+=f'''<article class="case-card" id="case-{n}" data-group="{row['group']}" data-search="{escape(row['title']+row['task'])}"><div class="case-heading"><span class="case-number">{n:02}</span><div><span class="eyebrow">{'合成内存输出读题' if n>=13 else '基础练习'}</span><h3>{escape(row['title'])}</h3></div><label class="done-label"><input type="checkbox" data-complete="{n}">已完成</label></div><p>{escape(row['task'])}</p><div class="attachments">{attachments}</div><div class="card-actions"><button class="btn small" data-case-tool="{n}">使用对应工具</button><button class="text-btn" data-answer="{n}">阅读思路与题解 ↓</button></div><details class="solution" id="solution-{n}"><summary>解题思路、命令、结果判读与排错</summary><div class="solution-body">{row['solution']}</div></details></article>'''
    for name,version,description,entry,action,license in TOOLS:
        buttons=f'<button class="btn small" data-action="{action}">进入工具台</button>' if action else ''
        if name=='CyberChef' and includes_tools:buttons+=f'<a class="btn small" href="{toolkit+entry}" target="_blank" rel="noopener">打开离线 CyberChef ↗</a>'
        if includes_tools:buttons+=f'<a class="text-btn" href="{toolkit+entry}" download>程序 / 源码</a>'
        path=toolkit+entry if includes_tools else '二进制另见 Windows 完整包；Kali 按讲义安装原生工具'
        tools+=f'<article class="resource-card" data-search="{escape(name+description)}"><span class="eyebrow">{escape(version)} · {escape(license)}</span><h3>{escape(name)}</h3><p>{escape(description)}</p><code class="tool-path">{escape(path)}</code><div class="card-actions">{buttons}</div></article>'
    data=dict(distribution=distribution,resources=[dict(id=i,title=t,description=d,href=h,tag=g) for i,t,d,h,g in RESOURCES],
              actions=ACTIONS,groups=GROUPS,workflows=[dict(id=i,title=t,description=d) for i,t,d in WORKFLOW_CATALOG],recipes=RECIPES,recipe_categories=CATEGORIES,cases=[{k:v for k,v in r.items() if k!='solution'} for r in cases],toolkit=toolkit,labs=labs)
    downloads=[('CTF取证基础_学员练习.zip','全部练习附件与辅助脚本'),('Volatility3_例题与命令.zip','三道合成内存输出读题')]
    if distribution=='workspace':downloads=[('学员工具与练习_Windows64.zip','Windows 学员：工具、运行环境、讲义与练习'),('CTF取证基础_Kali学习资料.zip','Kali 学员：资料、安装脚本与练习'),('讲师课件与逐题题解.zip','讲师：课件、完整题解与维护源码'),('Volatility3_Windows离线符号.zip','可选 Windows 符号集合 · 约 801 MiB'),('Volatility3_Windows离线符号_说明.md','匹配符号与离线使用说明'),('分发包_SHA256SUMS.txt','交付文件 SHA256 校验值')]+downloads
    if includes_tools:downloads=[(toolkit+'00_一键配置并启动.cmd','Windows 首次配置与启动'),(toolkit+'05_环境检查与修复.cmd','环境报告与 VC++ 检查'),(toolkit+'06_仅基础工具启动.cmd','社区扩展不可用时启动基础工具')]+downloads
    download_html=''.join(f'<a href="{html.escape(name)}" download>{html.escape(name)}<span>{html.escape(description)} ↗</span></a>' for name,description in downloads)
    template=(SOURCE/'portal.html').read_text(encoding='utf-8')
    script=(SOURCE/'portal.js').read_text(encoding='utf-8').replace('/* WORKBENCH_EXTENSIONS */',(SOURCE/'workbench.js').read_text(encoding='utf-8'))
    script=script.replace('/* MANAGEMENT_EXTENSIONS */',(SOURCE/'workspace_management.js').read_text(encoding='utf-8'))
    replacements={'__STYLE__':(SOURCE/'portal.css').read_text(encoding='utf-8')+(SOURCE/'workbench.css').read_text(encoding='utf-8')+(SOURCE/'workspace_management.css').read_text(encoding='utf-8')+REASONING_STYLE,'__SCRIPT__':script,
                  '__DATA__':json.dumps(data,ensure_ascii=False).replace('<','\\u003c'), '__RESOURCES__':resources,'__CASES__':case_html,'__TOOLS__':tools,
                  '__TOOL_PREFIX__':toolkit,'__ACTION_COUNT__':str(len(ACTIONS)), '__DOWNLOADS__':download_html}
    for key,value in replacements.items():template=template.replace(key,value)
    if not includes_tools:template=re.sub(r'<a\b[^>]*data-full-toolkit[^>]*>.*?</a>','',template,flags=re.S)
    return template
