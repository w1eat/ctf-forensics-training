"""Loopback-only classroom tool runner. No shell commands are accepted from HTTP.

Python standard library only. All subprocesses use fixed executables/argv lists.
See https://docs.python.org/3.13/library/subprocess.html and library/http.server.html.
"""
from __future__ import annotations
import argparse, concurrent.futures, datetime as dt, hashlib, hmac, json, mimetypes, os
from pathlib import Path, PurePosixPath
import re, secrets, shutil, signal, stat, subprocess, sys, threading, time, urllib.parse, uuid, webbrowser, zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0,str(Path(__file__).resolve().parent))
from forensic_workflows import WORKFLOW_CATALOG,DEFAULT_KEYWORDS

MAX_REPORT=2*1024*1024
GROUPS=[('automation','自动化分析'),('inspect','文件与编码'),('image','图片与隐写'),('archive','压缩包与雕刻'),('disk','磁盘与数据库'),('memory','Volatility 3'),('memory2','Volatility 2 · 兼容分析')]
GROUPS += [('crypto','编码与加解密'),('mount','镜像只读挂载')]
def field(key,label,default='',kind='text',hint='',options=None):
    row=dict(key=key,label=label,default=default,type=kind,hint=hint)
    if options:row['options']=options
    return row
FILE=lambda value:field('file','输入附件',value,'file','从练习附件或导入文件中选择；输出不会覆盖输入。')
PID=field('pid','进程 PID','2460','text','换镜像后，先根据 pslist / pstree 确认实际 PID。')
PLUGIN=['info','pslist','pstree','psscan','cmdline','cmdscan','consoles','filescan','handles','dumpfiles','memmap']
ACTIONS=[]
def action(key,group,title,tool,description,fields,command,**extra):
    ACTIONS.append(dict(id=key,group=group,title=title,tool=tool,description=description,fields=fields,command=command,**extra))
action('auto_analyze','automation','自动分析上传文件','综合分析引擎','按内容识别文件，串联摘要、熵、字符串、元数据与格式解析，生成 HTML / JSON 报告。任何附件均可作为输入。',[
 FILE('01_file/unknown.dat'),field('profile','扫描范围','standard','select','quick：前 4 MiB；standard：前 64 MiB；full：全文件。摘要和整体熵始终扫描全文件。',['quick','standard','full']),
 field('workflow','分析流程','auto','select','自动识别磁盘 / 裸文件系统及常见附件，也可明确指定工作流。',[r[0] for r in WORKFLOW_CATALOG]),field('keywords','检索关键词',DEFAULT_KEYWORDS,hint='英文或中文逗号分隔，最多 16 个；用于全文件及导出内容的线索检索。'),field('max_files','最多自动导出 / 分析文件','32',hint='1～100；总展开 / 导出预算 128 MiB，单文件 16 MiB。'),field('depth','子文件分析深度','2','select',options=['0','1','2','3']),field('password','已知附件口令（如需）','')],
 'python analysis_engine.py auto {file} --profile {profile} --workflow {workflow} --out {output}',output='analysis',engine=True)
action('file_type','inspect','识别文件格式','finspect','从签名判断常见格式，再用内部结构验证。',[FILE('01_file/unknown.dat')],'finspect type {file}')
action('file_hash','inspect','计算 SHA256','Python','流式计算摘要，记录原件与副本的一致性。',[FILE('01_file/unknown.dat')],'python tool_tasks.py hash {file}')
action('keyword_search','inspect','全文件关键词 / flag 检索','流式分析','不受普通字符串表展示条数限制，扫描整份文件的 UTF-8 / UTF-16LE 关键词与常见 flag 形态。',[FILE('04_archive/carrier.bin'),field('keywords','关键词',DEFAULT_KEYWORDS)],'python analysis_engine.py search {file} --keywords {keywords}',engine=True)
action('hex','inspect','十六进制与偏移','xxd','按字节查看指定范围，偏移从 0 开始。',[FILE('04_archive/carrier.bin'),field('offset','字节偏移','0x200',hint='十进制或 0x 十六进制；与分区扇区数不同。'),field('length','查看字节数','128',hint='1～65536；默认显示 128 字节。')],'xxd -g 1 -s {offset} -l {length} {file}')
action('strings','inspect','检索可读字符串','Python 流式扫描','记录字节偏移，可搜索关键词；0 表示扫描完整文件。输出最多 2000 条。',[FILE('public_examples/garden_demo.jpg'),field('encoding','文本编码','ascii','select','仅 ASCII 可打印字符及其 UTF-16LE 表示。',['ascii','utf16le','both']),field('minimum','最小字符数','4'),field('keyword','包含关键词',''),field('scan_mib','扫描上限 MiB','64',hint='0：全文件；默认前 64 MiB，结果明确记录覆盖范围。')],'python analysis_engine.py strings {file}',engine=True)
action('metadata','inspect','读取元数据','ExifTool','保留字段组、重复标签和未知字段，查找内容来源。',[FILE('public_examples/cat_demo.jpg')],'exiftool -a -u -G1 {file}')
action('base64','inspect','Base64 解码','Python','严格检查 Base64，输出解码字节与 UTF-8 文本。',[field('text','待解码文本','ZmxhZ3ttZXRhZGF0YV90aGVuX2Jhc2U2NH0=','textarea')],'python tool_tasks.py base64 {text}')
action('signatures','inspect','扫描嵌入签名','finspect','签名仅是候选，需要继续检查边界与完整性。',[FILE('04_archive/carrier.bin')],'finspect scan {file}')
action('png_check','image','检查 PNG 完整性','pngcheck','读取块结构、CRC 与图像数据；发现故意损坏时会报告异常。',[FILE('02_png/broken_width.png')],'pngcheck -v {file}',expected_error=True)
action('png_map','image','可视化 PNG 块与 CRC','Python','展示块偏移、长度、保存值与计算值。',[FILE('02_png/broken_width.png')],'python tool_tasks.py pngmap {file}',structured=True)
action('png_width','image','恢复练习 PNG 宽度','Python','适用于“只改宽度，原 CRC 保留，宽度 1～4096”的练习条件。',[FILE('02_png/broken_width.png')],'python tools/recover_width.py {file} {output}',output='fixed_width.png')
action('png_header','image','修复已知 PNG 文件头','finspect','只恢复前 8 字节签名，生成副本后还需 pngcheck 验证。',[FILE('02_png/broken_header.png')],'finspect patch-png-header {file} {output}',output='fixed_header.png')
action('lsb_scan','image','zsteg 扫描 LSB','zsteg','枚举常见 PNG/BMP 位平面，结合文字与题意验证。',[FILE('03_lsb/quiet.png')],'zsteg {file}')
action('lsb_extract','image','提取红通道最低位','Python / Pillow','本课约定：R 低位、逐行扫描、输出字节高位在前。',[FILE('03_lsb/quiet.png')],'python tools/extract_lsb.py {file} {output}',output='lsb.bin')
action('zip_list','archive','查看压缩包目录','7-Zip','先看文件名、大小和压缩信息，再决定提取路线。',[FILE('04_archive/locked.zip')],'7z l {file}')
action('zip_test','archive','验证 ZIP 与 CRC','7-Zip','用实际解压与 CRC 验证口令和结构。',[FILE('04_archive/locked.zip'),field('password','练习口令','training2026')],'7z t {file} -p{password}')
action('zip_extract','archive','解压 ZIP 到新目录','7-Zip','输出保存在本次任务目录，随后可下载或继续分析。',[FILE('04_archive/locked.zip'),field('password','练习口令','training2026')],'7z x {file} -p{password} -o{output} -y',output='extracted')
action('carve','archive','按偏移雕刻文件','Python','复制已确认的字节范围；本题 ZIP 从 0x200 开始到 EOF。',[FILE('04_archive/carrier.bin'),field('offset','起始字节偏移','0x200'),field('length','复制长度','',hint='留空表示直到 EOF；不是任意文件都满足此边界。')],'python tools/carve.py {file} {output} --offset {offset}',output='carved.zip')
action('zip_flags','archive','检查 ZIP 加密标志','Python','比较本地文件头和中央目录，不凭 bit 0 断定伪加密。',[FILE('04_archive/flagged.zip')],'python tools/zip_flags.py inspect {file}')
action('zip_clear','archive','修正练习 ZIP 标志','Python','仅适用已知内容未加密的经典单卷 ZIP；不是解密。',[FILE('04_archive/flagged.zip')],'python tools/zip_flags.py clear {file} {output}',output='flags_fixed.zip')
action('zip_dictionary','archive','小字典恢复 ZIP 口令','finspect','只尝试指定候选，并要求每个文件解压和 CRC 都成功。',[FILE('04_archive/locked.zip'),field('wordlist','候选字典','04_archive/words.txt','file')],'finspect tryzip {file} {wordlist} --limit 1000')
action('disk_partitions','disk','查看磁盘分区','TSK / mmls','先确认分区起点与扇区大小，再使用 fls / icat。',[FILE('05_disk/tiny_fat16.dd')],'mmls {file}')
action('disk_files','disk','列文件与删除项','TSK / fls','-o 使用扇区数；删除项不等于内容一定能恢复。',[FILE('05_disk/tiny_fat16.dd'),field('sector','分区起始扇区','2048'),field('deleted','仅列删除项','yes','select',options=['yes','no'])],'fls -r -o {sector} {file}')
action('disk_recover','disk','按元数据编号导出','TSK / icat','将原始 stdout 直接保存为字节，避免文本重定向损坏。',[FILE('05_disk/tiny_fat16.dd'),field('sector','分区起始扇区','2048'),field('sector_size','扇区字节数','512','select',options=['512','4096']),field('inode','元数据编号','4')],'icat -r -b {sector_size} -o {sector} {file} {inode}',output='recovered.bin',binary=True)
action('sqlite_tables','disk','SQLite 表与字段','SQLite','只读打开数据库，先查看结构，再构造查询。',[FILE('06_sqlite/case.db')],'sqlite3 -readonly {file} .schema')
action('sqlite_query','disk','自定义只读 SQL 查询','SQLite / Python','适用任意 SQLite 数据库；先查看结构，再用实际字段编写 SELECT / WITH。只读查询最多返回 1000 行。',[FILE('06_sqlite/case.db'),field('query','SQL 查询','SELECT id,name,note FROM artifacts WHERE deleted=1;','textarea','示例仅对应练习库；上传自己的数据库后请修改表名与条件。'),field('rows','最多返回行数','200')],'python analysis_engine.py sqlite {file} --query {query}',engine=True)
action('timeline','disk','按 UTC+8 关联审计事件','Python','逐行读取 JSONL，保留 request_id 与业务状态。',[FILE('07_logs/audit.jsonl')],'python tools/timeline.py {file}')
action('vol_help','memory','查看 Vol3 插件帮助','Volatility 3','无需真实镜像，先理解插件输入、选项与输出。',[field('plugin','Windows 插件','dumpfiles','select',options=PLUGIN)],'python $v3 windows.{plugin} -h')
action('vol_info','memory','① 确认系统与符号','Volatility 3','真实 Windows 内存镜像；CSV 和模拟片段不能用于此处。',[FILE('memory.raw')],'python $v3 -f {file} windows.info',ram=True)
action('vol_processes','memory','② 盘点进程','Volatility 3','先 pslist / pstree，有矛盾再用 psscan 复核。',[FILE('memory.raw'),field('plugin','进程视图','pslist','select',options=['pslist','pstree','psscan'])],'python $v3 -f {file} windows.{plugin}',ram=True)
action('vol_cmdline','memory','③ 查看启动参数','Volatility 3','cmdline 是启动参数，不等于所有历史输入。',[FILE('memory.raw'),PID],'python $v3 -f {file} windows.cmdline --pid {pid}',ram=True)
action('vol_history','memory','③ 查看控制台历史','Volatility 3','结合系统与终端实现，不能把无结果解释为从未执行。',[FILE('memory.raw'),field('plugin','插件','cmdscan','select',options=['cmdscan','consoles'])],'python $v3 -f {file} windows.{plugin}',ram=True)
action('vol_files','memory','④ 查找文件对象','Volatility 3','filescan 的 Offset 含义依系统和版本，先确认层与地址类型。',[FILE('memory.raw')],'python $v3 -f {file} windows.filescan',ram=True)
action('vol_handles','memory','④ 查看进程文件句柄','Volatility 3','按 PID 将路径与对象联系起来，再决定怎样导出。',[FILE('memory.raw'),PID],'python $v3 -f {file} windows.handles --pid {pid}',ram=True)
action('vol_dumpfiles','memory','⑤ 导出文件缓存','Volatility 3','按已确认的虚拟或物理 FILE_OBJECT 地址导出；可能缺页。',[FILE('memory.raw'),field('address_type','对象地址类型','virtual','select',options=['virtual','physical']),field('address','FILE_OBJECT 地址','0xffffa10200123070')],'python $v3 -f {file} -o {output} windows.dumpfiles --virtaddr {address}',ram=True,output='files')
action('vol_memmap','memory','⑤ 导出进程映射页','Volatility 3','导出后检查 ASCII / UTF-16LE；文件偏移不是进程虚拟地址。',[FILE('memory.raw'),PID],'python $v3 -f {file} -o {output} windows.memmap --pid {pid} --dump',ram=True,output='process')
action('sqlite_preview','disk','按表名预览数据库','SQLite / Python','任意表名均可；精确匹配当前数据库中的真实表，不拼接外部 SQL。',[FILE('06_sqlite/case.db'),field('table','表名','artifacts'),field('rows','最多返回行数','200')],'python analysis_engine.py sqlite {file} --table {table}',engine=True)
action('text_preview','inspect','预览文本与结构化日志','Python','支持任意字段的 CSV、TSV、JSON、JSONL 和文本；预览前 4 MiB，不假定练习的审计字段。',[FILE('07_logs/audit.jsonl'),field('encoding','文本编码','utf-8-sig','select',options=['utf-8-sig','utf-16','utf-16le','gb18030','latin-1']),field('rows','最多返回行数','200')],'python analysis_engine.py text {file} --encoding {encoding}',engine=True)
action('pdf_read','inspect','PDF 文字与元数据','pypdf','读取页数、元数据、附件名称并导出文字；图片型 PDF 需要另外 OCR。',[FILE('01_file/unknown.dat'),field('password','PDF 口令（如需）','')],'python analysis_engine.py pdf {file} --out {output}',output='pdf',engine=True)
action('pe_read','inspect','PE 静态结构','pefile','读取节、导入、入口 RVA 与 overlay 偏移；输入文件不会被执行。',[FILE('01_file/unknown.dat')],'python analysis_engine.py pe {file}',engine=True)
action('yara_scan','inspect','YARA 规则扫描','yara-python','内置三条教学线索规则；可粘贴自己的规则，或导入 .yar / .yara 文件。输入限 256 MiB，单次匹配限 20 秒。',[FILE('public_examples/garden_demo.jpg'),field('rules','自定义 YARA 规则（可留空）','','textarea','留空使用内置规则；禁用 include，规则限 64 KiB。'),field('rules_file','已导入规则文件（可选）','','optional_file','选规则文件时优先使用文件；只读 UTF-8 源码。')],'python analysis_engine.py yara {file}',engine=True)
action('lsb_custom','image','自选参数提取位流','Pillow','适用自己的 PNG / BMP 等图片；选择通道、位、扫描顺序和组字节顺序。',[FILE('03_lsb/quiet.png'),field('channels','通道','r','select',options=['r','g','b','a','rgb','bgr','rgba']),field('bit','通道位数','0','select','0 为最低位。',[str(i) for i in range(8)]),field('order','像素扫描顺序','xy','select','xy 逐行，yx 逐列。',['xy','yx']),field('byte_order','组字节顺序','msb','select','msb：先取得的位放字节高位；lsb：放低位。',['msb','lsb']),field('max_bytes','最多提取字节','1048576')],'python analysis_engine.py lsb {file} --out {output}',output='lsb',engine=True)
action('image_planes','image','导出选定位平面','Pillow','选择通道和位，导出黑白 PNG；位平面限 400 万像素。',[FILE('03_lsb/quiet.png'),field('channels','通道','rgb','select',options=['r','g','b','a','rgb','rgba']),field('bit','通道位数','0','select',options=[str(i) for i in range(8)])],'python analysis_engine.py planes {file} --out {output}',output='planes',engine=True)
action('archive_general','archive','通用压缩包分析 / 提取','7-Zip','支持 7-Zip 能识别的 ZIP、7z、RAR、TAR、GZIP 等格式。提取前检查目录、路径、链接和展开总量。',[FILE('04_archive/locked.zip'),field('mode','操作','list','select','提取最多 2048 项、展开总量 512 MiB；不自动尝试口令。',['list','test','extract']),field('password','口令（如需）','')],'python analysis_engine.py archive {file} --mode {mode} --out {output}',output='archive',engine=True)
action('carve_range','archive','通用字节范围雕刻','Python 流式复制','从任意文件复制指定范围到 carved.bin，可处理大于 64 MiB 的文件；不覆盖原件。',[FILE('04_archive/carrier.bin'),field('offset','起始字节偏移','0'),field('length','复制字节数','',hint='空值表示到 EOF；需要自己验证目标格式的结束边界。')],'python analysis_engine.py carve {file} --offset {offset} --out {output}',output='carved',engine=True)
action('disk_fsstat','disk','查看文件系统结构','TSK / fsstat','在 mmls 确认分区起点后，查看文件系统类型、块大小和布局。无分区表的文件系统镜像可用 0。',[FILE('05_disk/tiny_fat16.dd'),field('sector','分区起始扇区','2048')],'fsstat -o {sector} {file}')
action('disk_istat','disk','查看元数据项详情','TSK / istat','按当前镜像的元数据编号查看时间、大小和数据块；编号不能从别的题目照抄。',[FILE('05_disk/tiny_fat16.dd'),field('sector','分区起始扇区','2048'),field('inode','元数据编号','4')],'istat -o {sector} {file} {inode}')

PROFILE2=field('profile','已验证的 Vol2 profile','',hint='先运行 imageinfo 取得候选，再用 kdbgscan / pslist 核对；不能仅凭 6.1 猜测 x86 / x64。')
PLUGIN2=['all','imageinfo','kdbgscan','pslist','pstree','psscan','cmdline','cmdscan','consoles','filescan','dumpfiles','memdump']
action('vol2_help','memory2','Vol2：帮助与可用 profiles','Volatility 2','独立程序已带旧版运行时；不需要把 Vol3 的 Python 3 改成 Python 2。',[field('plugin','帮助项目','all','select',options=PLUGIN2)],'vol2 --info')
action('vol2_identify','memory2','Vol2 ① 识别 / 核对 profile','Volatility 2','imageinfo 只给候选；用 KDBG、系统架构和进程视图交叉验证。',[FILE('memory.raw'),field('plugin','识别步骤','imageinfo','select',options=['imageinfo','kdbgscan']),field('profile','候选 profile（可留空）','',hint='imageinfo 首次运行留空；已取得候选时可指定它运行 kdbgscan。')],'vol2 -f {file} {plugin}',ram=True)
action('vol2_processes','memory2','Vol2 ② 进程与启动参数','Volatility 2','使用当前镜像确认的 profile；PID 可留空查看全部，psscan 不接受 PID 过滤。',[FILE('memory.raw'),PROFILE2,field('plugin','进程视图','pslist','select',options=['pslist','pstree','psscan','cmdline']),field('pid','PID（可留空）','',hint='pslist / pstree / cmdline 可按一个实际 PID 过滤。')],'vol2 -f {file} --profile={profile} {plugin}',ram=True)
action('vol2_history','memory2','Vol2 ③ 命令历史 / 控制台','Volatility 2','适合已验证支持的旧 Windows 镜像；cmdscan 查历史输入，consoles 还可能恢复屏幕输出。',[FILE('memory.raw'),PROFILE2,field('plugin','历史插件','cmdscan','select',options=['cmdscan','consoles'])],'vol2 -f {file} --profile={profile} {plugin}',ram=True)
action('vol2_files','memory2','Vol2 ④ 扫描文件对象','Volatility 2','记录当前 Vol2 filescan 的 Offset(P)，再使用对应的 -Q 导出。',[FILE('memory.raw'),PROFILE2],'vol2 -f {file} --profile={profile} filescan',ram=True)
action('vol2_dumpfiles','memory2','Vol2 ⑤ 按物理偏移导出缓存','Volatility 2','-Q 使用本次 Vol2 filescan 的物理 FILE_OBJECT 偏移；不要直接套用 Vol3 的虚拟地址。',[FILE('memory.raw'),PROFILE2,field('address','Vol2 filescan 的 Offset(P)','',hint='十进制或 0x 十六进制；必须来自当前镜像。')],'vol2 -f {file} --profile={profile} dumpfiles -Q {address} -D {output}',ram=True,output='files')
action('vol2_memdump','memory2','Vol2 ⑤ 导出指定进程内存','Volatility 2','先从当前进程列表确认 PID；导出文件可能含缺页，不等于磁盘上的完整原文件。',[FILE('memory.raw'),PROFILE2,field('pid','已确认的 PID','')],'vol2 -f {file} --profile={profile} memdump -p {pid} -D {output}',ram=True,output='process')

from case_catalog import register as register_case_actions
register_case_actions(action,field,FILE)
PLUGIN.extend(['mftscan.MFTScan','mftscan.ResidentData','mftscan.ADS','registry.hivelist','registry.printkey','registry.hashdump','netscan','truecrypt.Passphrase','malware.malfind','envars','dlllist'])
PLUGIN2.extend(['clipboard','notepad','mftparser','hivelist','printkey','hashdump','truecryptsummary','truecryptpassphrase','truecryptmaster','netscan','screenshot'])
PLUGIN2.extend(['mimikatz','bitlocker','editbox'])
PLUGIN.extend(['vol_pypykatz.pypykatz','bitlocker.BitlockerFVEKScan'])

class InputError(ValueError):pass

def volatility_compatibility(text,source):
    """Classify the specific plugin structure error without hiding the traceback."""
    if 'NotImplementedError' not in text or 'This version of Windows is not supported:' not in text:return None
    return dict(kind='volatility_compatibility',message='此 Vol3 插件不支持镜像中的 Windows / 控制台结构。PDB 扫描完成不代表每个插件都支持该系统；这也不是“没有历史记录”。',
                note='保留原始诊断，先用 Vol2 imageinfo 取得候选 profile，再核对 KDBG / 进程视图。不要自动套用 Win7SP1x64 或照抄别题 PID。',
                next_actions=[dict(title='用 Vol2 识别当前镜像 profile',action='vol2_identify',params=dict(file=source)),dict(title='查看 Vol2 profiles 与帮助',action='vol2_help',params=dict(plugin='all'))])
def confined(base,path,must_exist=True):
    value=str(path)
    if not value or any(ord(c)<32 for c in value):raise InputError('请选择一个有效文件。')
    value=value.replace('\\','/')
    if any(p in ('..','') for p in value.split('/')) or ':' in value or value.startswith('/'):
        raise InputError('请使用工作区附件列表中的相对路径。')
    target=(base/value).resolve()
    if not target.is_relative_to(base.resolve()):raise InputError('路径超出附件目录。')
    if must_exist and not target.is_file():raise InputError('附件不存在，请先导入或刷新文件列表。')
    return target

def is_link(path):
    return path.is_symlink() or getattr(path,'is_junction',lambda:False)()

def managed_path(base,value,directory=False,must_exist=True):
    """Validate the literal path and all ancestors before a managed mutation."""
    if not isinstance(value,str):raise InputError('文件路径格式错误。')
    value=value.replace('\\','/')
    if not value or ':' in value or any(ord(c)<32 for c in value) or any(p in ('','.','..') for p in value.split('/')):
        raise InputError('请使用附件列表中的相对路径。')
    target=base.joinpath(*value.split('/'))
    for parent in (base,*reversed(target.relative_to(base).parents),target):
        item=parent if parent.is_absolute() else base/parent
        if is_link(item):raise InputError('不允许通过链接或目录联接删除文件。')
    resolved=target.resolve()
    if not resolved.is_relative_to(base) or resolved==base:raise InputError('删除范围超出当前资料目录。')
    if must_exist and not (resolved.is_dir() if directory else resolved.is_file()):raise InputError('文件或记录不存在，请刷新列表。')
    return resolved

def checked_tree(folder):
    """Do not traverse a junction while validating a recursive deletion."""
    for parent,dirs,files in os.walk(folder,topdown=True,followlinks=False):
        for name in dirs+files:
            item=Path(parent)/name
            if is_link(item):raise InputError('分析目录包含链接，请先在本地核对，未执行删除。')

def selection(value,label):
    if not isinstance(value,list) or not 1<=len(value)<=100 or any(not isinstance(v,str) for v in value):
        raise InputError(label+'必须是 1～100 项的列表。')
    return list(dict.fromkeys(value))

class Runtime:
    def __init__(self,root,kit=None):
        self.root=Path(root).resolve()
        self.kit=Path(kit).resolve() if kit else (self.root/'学员工具包_Windows64' if (self.root/'学员工具包_Windows64').is_dir() else self.root)
        self.labs=(self.root/'labs' if (self.root/'labs').is_dir() else self.root/'练习材料').resolve()
        if not self.labs.is_dir():raise InputError('找不到 labs / 练习材料。请完整解压资料包。')
        if not self.labs.is_relative_to(self.root):raise InputError('附件目录必须在当前学习资料目录中。')
        self.outputs=(self.labs/'out/platform_runs').resolve()
        if not self.outputs.is_relative_to(self.labs):raise InputError('输出目录不能指向附件目录之外。')
        self.outputs.mkdir(parents=True,exist_ok=True)
        self.windows=os.name=='nt';self.python=str(self.kit/'runtime/python/python.exe') if self.windows else sys.executable
        self.community_enabled=os.environ.get('CTF_FORENSICS_MODE','full')!='basic'
        if not Path(self.python).is_file():self.python=sys.executable
        self.env=os.environ.copy();self.env.update(PYTHONUTF8='1',PYTHONIOENCODING='utf-8',LANG='C',LC_ALL='C',LC_CTYPE='C')
        if self.windows:
            ruby=self.kit/'runtime/ruby'
            self.env.update(GEM_HOME=str(ruby/'lib/ruby/gems/3.3.0'),GEM_PATH=str(ruby/'lib/ruby/gems/3.3.0'),RUBYOPT='-EUTF-8')
            self.env['PATH']=';'.join([str(self.kit/'runtime/python'),str(ruby/'bin'),str(self.kit/'tools/sleuthkit/bin'),os.environ.get('SystemRoot',r'C:\Windows')+'\\System32'])
        self.actions={row['id']:row for row in ACTIONS}

    def tool(self,name):
        if name=='python':return [self.python]
        if name=='helper':return [self.python,str(self.kit/'tools/finspect.py' if (self.kit/'tools/finspect.py').is_file() else self.labs/'tools/finspect.py')]
        if name=='tasks':return [self.python,str(self.kit/'tools/tool_tasks.py' if (self.kit/'tools/tool_tasks.py').is_file() else self.root/'工具包构建/tool_tasks.py')]
        if name=='engine':return [self.python,str(self.kit/'tools/analysis_engine.py' if (self.kit/'tools/analysis_engine.py').is_file() else self.root/'工具包构建/analysis_engine.py')]
        if name=='vol':
            extra=self.kit/'tools/volatility3_extra'
            if self.windows:base=[self.python,str(self.kit/'tools/volatility3/vol.py')]
            else:
                entry=shutil.which('vol');base=[entry] if entry else [self.python,'-c','from volatility3.cli import main; main()']
            return base+(['-p',str(extra)] if self.community_enabled and extra.is_dir() else [])
        if name=='vol2':
            path=self.kit/('tools/volatility2/windows/volatility_2.6_win64_standalone.exe' if self.windows else 'tools/volatility2/linux/volatility_2.6_lin64_standalone')
            if not path.is_file():raise InputError('缺少 Vol2 独立程序，请完整解压含兼容工具的新版资料包。')
            if not self.windows and not os.access(path,os.X_OK):raise InputError('请在资料包根目录按兼容指南为 Vol2 Linux 程序执行 chmod +x，再重新运行。')
            return [str(path)]+(['--plugins='+str(self.kit/'tools/volatility2/extra_plugins')] if self.community_enabled else [])
        if self.windows:
            paths={'7z':'tools/7zip/7z.exe','exiftool':'tools/exiftool/exiftool.exe','pngcheck':'tools/pngcheck/pngcheck.exe',
                   'mmls':'tools/sleuthkit/bin/mmls.exe','fls':'tools/sleuthkit/bin/fls.exe','icat':'tools/sleuthkit/bin/icat.exe','fsstat':'tools/sleuthkit/bin/fsstat.exe','istat':'tools/sleuthkit/bin/istat.exe','sqlite3':'tools/sqlite/sqlite3.exe'}
            if name=='xxd':return [str(self.kit/'tools/busybox/busybox.exe'),'xxd']
            if name=='zsteg':return [str(self.kit/'runtime/ruby/bin/ruby.exe'),str(self.kit/'runtime/ruby/bin/zsteg'),'--no-file']
            path=self.kit/paths[name]
            if not path.is_file():raise InputError('缺少工具 '+name+'，请使用完整 Windows 工具包。')
            return [str(path)]
        entry=shutil.which(name) or (shutil.which('7zz') if name=='7z' else None)
        if not entry:raise InputError('未安装 '+name+'；请按 Kali 环境准备章节安装。')
        return [entry]

    def files(self):
        result=[]
        for p in sorted(self.labs.rglob('*')):
            if not p.is_file() or '__pycache__' in p.parts:continue
            if is_link(p) or not p.resolve().is_relative_to(self.labs):continue
            rel=p.relative_to(self.labs).as_posix()
            if rel.startswith('out/') and p.name.startswith('_'):continue
            if rel.startswith('tools/') or (not rel.startswith('inputs/') and p.suffix.lower() in ('.py','.md')) or p.name=='SHA256SUMS.txt':continue
            if len(result)>=4000:break
            try:info=p.stat()
            except OSError:continue
            result.append(dict(path=rel,bytes=info.st_size,generated=rel.startswith('out/'),deletable=rel.startswith('inputs/'),modified=info.st_mtime))
        return result

    def catalog(self):
        return dict(actions=ACTIONS,groups=GROUPS,community_enabled=self.community_enabled,host='Windows · PowerShell' if self.windows else 'Kali / Linux · Bash',
                    root=str(self.root),labs=str(self.labs),kit=str(self.kit),files=self.files(),management=dict(delete_uploads=True,delete_history=True))

    def number(self,params,key,default,lo=0,hi=2**48):
        raw=str(params.get(key,default)).strip()
        try:value=int(raw,0) if raw.lower().startswith('0x') else int(raw,10)
        except ValueError:raise InputError(key+' 必须是十进制或 0x 十六进制整数。')
        if not lo<=value<=hi:raise InputError(key+' 超出允许范围。')
        return str(value)

    def inode(self,value):
        value=str(value).strip()
        if not re.fullmatch(r'\d{1,20}(?:-\d{1,20}){0,2}',value):raise InputError('元数据编号应为 inode，或 NTFS 的 编号-类型-属性编号。')
        return value

    def plan(self,key,params,folder):
        if not isinstance(key,str) or not isinstance(params,dict):raise InputError('操作与参数格式错误。')
        if key not in self.actions:raise InputError('未知的工具操作。')
        meta=self.actions[key];p={f['key']:str(params.get(f['key'],f['default'])) for f in meta['fields']}
        if not self.community_enabled and (key in ('vol_extra','vol2_extra') or (key in ('vol_help','vol2_help') and p.get('plugin') in ('mimikatz','bitlocker','vol_pypykatz.pypykatz','bitlocker.BitlockerFVEKScan'))):
            raise InputError('当前为基础模式，社区扩展已暂停。先运行“05_环境检查与修复.cmd”核对报告，再使用完整模式启动。')
        for f in meta['fields']:
            if f['type']=='select' and p[f['key']] not in f['options']:raise InputError('选项无效：'+f['label'])
        src=confined(self.labs,p['file']) if 'file' in p else None
        if (meta.get('ram') or key=='memory_triage') and src.suffix.lower() not in ('.raw','.mem','.vmem','.dmp','.bin'):
            raise InputError('这里需要真实 RAM（.raw/.mem/.vmem/.dmp）。CSV 和模拟片段请到案例区读题。')
        small={'png_width','png_header','lsb_scan','lsb_extract','carve','zip_flags','zip_clear','zip_dictionary'}
        if src and key in small and src.stat().st_size>64*1024*1024:raise InputError('此教学操作限 64 MiB 附件。大内存请先用 Vol3 定向分析。')
        out=folder/meta.get('output','result.bin');s=str(src) if src else '';output=str(out)
        t=self.tool;argv=[];binary=False;argument_file=None
        if key in ('disk_partitions','disk_files','disk_recover','disk_fsstat','disk_istat'):
            from case_disk import image_source
            s=str(image_source(src))
        if meta.get('casework'):
            if p.get('source')=='file':
                if not p.get('input_file'):raise InputError('选择附件作为输入后，请选择一个文件。')
                src=confined(self.labs,p['input_file'])
            for optional in ('wordlist','keyfile'):
                if p.get(optional):p[optional]=str(confined(self.labs,p[optional]))
            bounds={'max_files':(1,256),'budget_mib':(1,16384 if key=='disk_image_convert' else 1024),'seconds':(10,600),'rows':(1,5000),'scan_mib':(0,1048576),'sector_size':(512,4096),'depth':(0,3)}
            for name,(lo,hi) in bounds.items():
                if name in p:p[name]=self.number(p,name,0,lo,hi)
            if key in ('hex_view','binary_patch','byte_search'):
                p['offset']=self.number(p,'offset',0,0,src.stat().st_size)
            if key=='hex_view':p['length']=self.number(p,'length',256,16,4096)
            if key=='disk_mount' and p.get('pim'):p['pim']=self.number(p,'pim',0,0,2**31-1)
            if 'sector' in p and p['sector'].strip():p['sector']=self.number(p,'sector',0)
            p['_file']=str(src) if src else ''
            entry=self.kit/'tools/casework.py'
            if not entry.is_file():entry=self.root/'工具包构建/casework.py'
            args_path=folder/'_case_args.json';argument_file=(args_path,json.dumps(p,ensure_ascii=False))
            argv=t('python')+[str(entry),meta['casework'],'--args',str(args_path),'--out',output,'--kit',str(self.kit),'--labs',str(self.labs)]
        elif meta.get('engine') or key in ('file_type','signatures','png_map','sqlite_tables'):
            engine_tasks={'auto_analyze':'auto','keyword_search':'search','file_type':'probe','signatures':'scan','png_map':'png','sqlite_tables':'sqlite','sqlite_query':'sqlite','sqlite_preview':'sqlite','text_preview':'text','pdf_read':'pdf','pe_read':'pe','yara_scan':'yara','lsb_custom':'lsb','image_planes':'planes','archive_general':'archive','carve_range':'carve'}
            argv=t('engine')+[engine_tasks.get(key,key),s,'--out',str(out if meta.get('output') else folder),'--kit',str(self.kit)]
            if key=='auto_analyze':argv+=['--profile',p['profile'],'--workflow',p['workflow'],'--keywords',p['keywords'],'--max-files',self.number(p,'max_files',32,1,100),'--depth',p['depth'],'--password',p['password']]
            if key=='keyword_search':argv+=['--keywords',p['keywords']]
            if key=='strings':argv+=['--encoding',p['encoding'],'--minimum',self.number(p,'minimum',4,1,128),'--keyword',p['keyword'],'--limit',str(int(self.number(p,'scan_mib',64,0,2**20))*1024**2)]
            if key in ('sqlite_query','sqlite_preview'):
                argv+=['--rows',self.number(p,'rows',200,1,1000)]
                if key=='sqlite_query':
                    if len(p['query'])>16384:raise InputError('SQL 限 16384 个字符。')
                    argv+=['--query',p['query']]
                else:argv+=['--table',p['table']]
            if key=='text_preview':argv+=['--encoding',p['encoding'],'--rows',self.number(p,'rows',200,1,1000)]
            if key=='pdf_read':argv+=['--password',p['password']]
            if key=='archive_general':argv+=['--mode',p['mode'],'--password',p['password']]
            if key=='yara_scan':
                if p['rules_file']:
                    rules_file=confined(self.labs,p['rules_file'])
                    if rules_file.stat().st_size>65536:raise InputError('YARA 规则限 64 KiB。')
                    argv+=['--rules',str(rules_file)]
                elif p['rules'].strip():
                    if len(p['rules'].encode('utf-8'))>65536:raise InputError('YARA 规则限 64 KiB。')
                    argument_file=(folder/'_rules.yar',p['rules']);argv+=['--rules',str(argument_file[0])]
            if key in ('lsb_custom','image_planes'):
                argv+=['--channels',p['channels'],'--bit',p['bit']]
                if key=='lsb_custom':argv+=['--order',p['order'],'--byte-order',p['byte_order'],'--bytes',self.number(p,'max_bytes',1048576,1,16*1024**2)]
            if key=='carve_range':
                argv+=['--offset',self.number(p,'offset',0)]
                if p['length'].strip():argv+=['--length',self.number(p,'length',0,1)]
        elif key=='file_type':argv=t('helper')+['type',s]
        elif key=='file_hash':argv=t('tasks')+['hash',s]
        elif key=='hex':argv=t('xxd')+['-g','1','-s',self.number(p,'offset',0),'-l',self.number(p,'length',128,1,65536),s]
        elif key=='strings':argv=t('helper')+['strings',s,'--encoding',p['encoding'],'-n',self.number(p,'minimum',4,1,128)]
        elif key=='metadata':
            # Perl's Windows argv conversion is code-page dependent. A UTF-8
            # argument file with an ASCII relative path preserves Unicode names.
            if self.windows:
                args_path=folder/'_exiftool.args'
                argument_file=(args_path,'-a\n-u\n-G1\n./'+src.relative_to(self.labs).as_posix()+'\n')
                argv=t('exiftool')+['-charset','filename=UTF8','-@',args_path.relative_to(self.labs).as_posix()]
            else:argv=t('exiftool')+['-a','-u','-G1',s]
        elif key=='base64':
            if len(p['text'])>65536:raise InputError('Base64 输入限 65536 个字符。')
            argv=t('tasks')+['base64',p['text']]
        elif key=='signatures':argv=t('helper')+['scan',s]
        elif key=='png_check':argv=t('pngcheck')+['-v',s]
        elif key=='png_map':argv=t('tasks')+['pngmap',s]
        elif key=='png_width':argv=t('python')+[str(self.labs/'tools/recover_width.py'),s,output]
        elif key=='png_header':argv=t('helper')+['patch-png-header',s,output]
        elif key=='lsb_scan':argv=t('zsteg')+[s]
        elif key=='lsb_extract':argv=t('python')+[str(self.labs/'tools/extract_lsb.py'),s,output]
        elif key in ('zip_list','zip_test','zip_extract'):
            argv=t('7z')+[{'zip_list':'l','zip_test':'t','zip_extract':'x'}[key],s]
            if key!='zip_list':argv+=['-p'+(p['password'] or '__no_password_supplied__')]
            if key=='zip_extract':
                validate_zip(src);argv+=['-o'+output,'-y']
        elif key=='carve':
            offset=self.number(p,'offset',512);argv=t('python')+[str(self.labs/'tools/carve.py'),s,output,'--offset',offset]
            if p['length'].strip():argv+=['--length',self.number(p,'length',0)]
        elif key in ('zip_flags','zip_clear'):
            argv=t('python')+[str(self.labs/'tools/zip_flags.py'),'inspect' if key=='zip_flags' else 'clear',s]
            if key=='zip_clear':argv+=[output]
        elif key=='zip_dictionary':
            validate_zip(src);word=confined(self.labs,p['wordlist'])
            if word.stat().st_size>65536:raise InputError('仅使用小字典（不超过 64 KiB / 1000 行）。')
            argv=t('helper')+['tryzip',s,str(word),'--limit','1000']
        elif key=='disk_partitions':argv=t('mmls')+[s]
        elif key=='disk_files':argv=t('fls')+['-r']+(['-d'] if p['deleted']=='yes' else [])+['-o',self.number(p,'sector',2048),s]
        elif key=='disk_fsstat':argv=t('fsstat')+['-o',self.number(p,'sector',2048),s]
        elif key=='disk_istat':argv=t('istat')+['-o',self.number(p,'sector',2048),s,self.inode(p['inode'])]
        elif key=='disk_recover':
            native=t('icat')+['-r','-b',p['sector_size'],'-o',self.number(p,'sector',2048),s,self.inode(p['inode'])]
            argv=t('helper')+['savebin',output,'--']+native
        elif key=='sqlite_tables':argv=t('sqlite3')+['-readonly',s,'.schema']
        elif key=='sqlite_query':argv=t('sqlite3')+['-readonly','-json',s,'SELECT id,name,note FROM artifacts WHERE deleted=1;']
        elif key=='timeline':argv=t('python')+[str(self.labs/'tools/timeline.py'),s]
        elif key.startswith('vol2_'):
            profile=p.get('profile','').strip()
            if profile and not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{1,79}',profile):raise InputError('profile 只能是 Vol2 --info 中的名称，不接受路径、空格或附加参数。')
            if key not in ('vol2_help','vol2_identify') and not profile:raise InputError('先用 Vol2 imageinfo 取得候选，并用 kdbgscan / pslist 验证，然后填写 profile。')
            # Keep the Python 2 help formatter's cache option ASCII. Its UTF-8
            # writer cannot format a Windows code-page path containing Chinese.
            argv=t('vol2')+['--cache-directory='+os.path.relpath(folder/'_vol2_cache',self.labs)]
            if key=='vol2_help':argv+=['--info'] if p['plugin']=='all' else [p['plugin'],'-h']
            else:
                argv+=['-f',s]
                if profile:argv+=['--profile='+profile]
                plugin={'vol2_identify':p.get('plugin'),'vol2_processes':p.get('plugin'),'vol2_history':p.get('plugin'),'vol2_files':'filescan','vol2_dumpfiles':'dumpfiles','vol2_memdump':'memdump','vol2_artifacts':p.get('plugin'),'vol2_registry':p.get('plugin'),'vol2_extra':p.get('plugin')}[key]
                argv+=[plugin]
                if key=='vol2_processes' and p['pid'].strip():
                    if plugin=='psscan':raise InputError('Vol2 psscan 不接受 PID 过滤；请清空 PID，或改用 pslist / pstree / cmdline。')
                    argv+=['-p',self.number(p,'pid',0,0,2**32-1)]
                if key=='vol2_memdump':argv+=['-p',self.number(p,'pid',0,0,2**32-1)]
                if key=='vol2_dumpfiles':argv+=['-Q',hex(int(self.number(p,'address',0,0,2**64-1)))]
                if key=='vol2_registry' and plugin=='printkey':
                    if p['address'].strip():argv+=['-o',hex(int(self.number(p,'address',0,0,2**64-1)))]
                    if p['key'].strip():argv+=['-K',p['key']]
                if key=='vol2_extra':
                    if plugin=='editbox' and p['pid'].strip():argv+=['-p',self.number(p,'pid',0,0,2**32-1)]
                    if plugin in ('bitlocker','editbox') and p['dump']=='yes':argv+=['-D',output]
                elif meta.get('output') and (key!='vol2_artifacts' or plugin in ('mftparser','screenshot','truecryptmaster')):argv+=['-D',output]
        elif key=='vol_help':argv=t('vol')+[(p['plugin'] if p['plugin'] in ('vol_pypykatz.pypykatz','bitlocker.BitlockerFVEKScan') else 'windows.'+p['plugin']),'-h']
        elif key=='vol_extra':
            argv=t('vol')+['--offline','-q','-r','json','-o',output,'-f',s,p['plugin']]
            if p['plugin']=='bitlocker.BitlockerFVEKScan':
                if p['dump']=='yes':argv+=['--dump']
                tags=[x.strip() for x in p['tags'].split(',') if x.strip()]
                if len(tags)>8 or any(not re.fullmatch('[A-Za-z0-9_ ]{4}',x) for x in tags):raise InputError('池标签限最多 8 个四字节 ASCII 标签。')
                if tags:argv+=['--tags']+tags
        elif key.startswith('vol_'):
            argv=t('vol')+['-f',s]
            plugin={'vol_info':'info','vol_processes':p.get('plugin'),'vol_cmdline':'cmdline','vol_history':p.get('plugin'),'vol_files':'filescan','vol_handles':'handles','vol_dumpfiles':'dumpfiles','vol_memmap':'memmap','vol_artifacts':p.get('plugin'),'vol_registry':'registry.'+p.get('plugin','')}[key]
            if meta.get('output'):argv+=['-o',output]
            argv+=['windows.'+plugin]
            if key in ('vol_cmdline','vol_handles','vol_memmap'):argv+=['--pid',self.number(p,'pid',2460,0,2**32-1)]
            if key=='vol_memmap':argv+=['--dump']
            if key=='vol_dumpfiles':
                address=self.number(p,'address',0,0,2**64-1)
                argv+=['--virtaddr' if p['address_type']=='virtual' else '--physaddr',hex(int(address))]
            if key=='vol_registry' and p['plugin']=='printkey':
                if p['address'].strip():argv+=['--offset',hex(int(self.number(p,'address',0,0,2**64-1)))]
                if p['key'].strip():argv+=['--key',p['key']]
        else:raise InputError('此操作尚未接入。')
        if not Path(argv[0]).is_file():raise InputError('工具入口不存在，请完整解压工具包。')
        if any('\x00' in x or len(x)>131072 for x in argv):raise InputError('参数无效。')
        command=format_command(argv,self.windows)
        if binary:command+='  [stdout 按原始字节保存为 '+output+']'
        return dict(argv=argv,command=command,binary=binary,output=out,source=src,meta=meta,params=p,argument_file=argument_file,timeout=1200 if key=='memory_triage' else 900 if meta.get('ram') or key=='auto_analyze' or meta.get('casework') else 120)

def format_command(argv,windows):
    if windows:return '& '+' '.join("'"+x.replace("'","''")+"'" for x in argv)
    import shlex
    return shlex.join(argv)

def validate_zip(path):
    try:
        with zipfile.ZipFile(path) as z:
            infos=z.infolist()
            if len(infos)>2048 or sum(i.file_size for i in infos)>512*1024*1024:raise InputError('此课堂解压操作限 2048 个条目、展开总量 512 MiB。')
            for i in infos:
                n=i.filename.replace('\\','/')
                if n.startswith('/') or ':' in n or '..' in PurePosixPath(n).parts or stat.S_ISLNK(i.external_attr>>16):raise InputError('压缩包包含目录外路径或链接，未执行解压。')
    except zipfile.BadZipFile:raise InputError('该操作只接受经典 ZIP；其他格式可先用“查看压缩包目录”。')

def read_report(path):
    if not path.is_file():return ''
    with path.open('rb') as stream:data=stream.read(MAX_REPORT+1)
    suffix='\n[网页预览已截断；完整日志在任务目录中。]' if len(data)>MAX_REPORT else ''
    raw=data[:MAX_REPORT]
    try:decoded=raw.decode('utf-8')
    except UnicodeDecodeError as exc:
        # Native Windows utilities may use the system ANSI code page when stdout
        # is redirected; Python helpers and ExifTool's arg-file mode emit UTF-8.
        if os.name=='nt' and not (suffix and exc.reason=='unexpected end of data'):
            decoded=raw.decode('mbcs','replace')
        else:decoded=raw.decode('utf-8','replace')
    return decoded+suffix

class Jobs:
    def __init__(self,runtime):
        self.runtime=runtime;self.lock=threading.RLock();self.items={};self.uploading=set()
        self.pool=concurrent.futures.ThreadPoolExecutor(max_workers=2,thread_name_prefix='classroom')

    def submit(self,key,params):
        with self.lock:
            if sum(not j.get('finished',True) for j in self.items.values())>=2:
                raise InputError('已有两个任务在运行，请等待完成或停止其中一个。')
            identity=uuid.uuid4().hex[:16];folder=self.runtime.outputs/identity
            plan=self.runtime.plan(key,params,folder)
            folder.mkdir()
            if key.startswith('vol2_'):(folder/'_vol2_cache').mkdir()
            if plan.get('argument_file'):
                path,content=plan['argument_file'];path.write_text(content,encoding='utf-8',newline='\n')
            if plan['meta'].get('output') and not plan['output'].suffix:plan['output'].mkdir()
            job=dict(id=identity,action=key,title=plan['meta']['title'],state='queued',command=plan['command'],
                     created=dt.datetime.now().astimezone().isoformat(),exit_code=None,text='',error='',duration=0,
                     files=[],data=None,folder=folder,plan=plan,process=None,cancel=False,finished=False)
            job['input']=plan['source'].relative_to(self.runtime.labs).as_posix() if plan['source'] else ''
            self.items[identity]=job
            self.pool.submit(self.execute,job)
            return self.public(job)

    def public(self,job):
        fields=('id','action','title','state','command','created','exit_code','text','error','duration','files','data')
        result={key:job[key] for key in fields}
        # Publish terminal state only when parsing, artifact discovery and the
        # report have finished. Fast polling must not observe completed + data=None.
        if not job.get('finished',True) and result['state'] not in ('queued','running'):result['state']='running'
        result['host']='Windows · PowerShell' if self.runtime.windows else 'Kali / Linux · Bash'
        result['input']=job.get('input','')
        progress=job['folder']/'analysis/_progress.json'
        if progress.is_file():
            try:result['progress']=json.loads(progress.read_text(encoding='utf-8'))
            except (ValueError,OSError):pass
        return result

    def get(self,identity):
        if not re.fullmatch('[0-9a-f]{16}',identity):raise InputError('任务不存在。')
        folder=managed_path(self.runtime.outputs,identity,directory=True)
        if identity not in self.items:
            record=folder/'_task.json'
            if not record.is_file():raise InputError('任务不存在。')
            value=json.loads(record.read_text(encoding='utf-8'));value.update(folder=folder,process=None,cancel=False)
            if value.get('state') in ('queued','running'):value.update(state='interrupted',error='上次服务关闭时任务尚未完成；可重新运行。')
            self.items[identity]=value
        return self.items[identity]

    def history(self):
        with self.lock:
            folders=sorted((p for p in self.runtime.outputs.iterdir() if p.is_dir() and not is_link(p) and re.fullmatch('[0-9a-f]{16}',p.name)),key=lambda p:p.stat().st_mtime,reverse=True)[:500]
            result=[]
            for folder in folders:
                try:
                    job=self.items.get(folder.name)
                    if job is None:
                        job=json.loads((folder/'_task.json').read_text(encoding='utf-8'))
                        if job.get('state') in ('queued','running'):job['state']='interrupted'
                    row={k:job[k] for k in ('id','title','action','state','created','duration')}
                    row['input']=job.get('input','')
                    if not job.get('finished',True):row['state']='running'
                    result.append(row)
                except (ValueError,OSError,KeyError):pass
            return result

    def in_use(self,target):
        for pending in self.uploading:
            if pending==target or pending.parent==target.parent:return True
        for job in self.items.values():
            if job.get('finished',True) and job['state'] not in ('queued','running'):continue
            plan=job.get('plan',{});paths=[plan.get('source')]
            for value in plan.get('params',{}).values():
                if isinstance(value,str) and value.replace('\\','/').startswith(('inputs/','out/platform_runs/')):
                    try:paths.append(confined(self.runtime.labs,value,False))
                    except InputError:pass
            for source in filter(None,paths):
                source=Path(source)
                if source==target or source.is_relative_to(target):return True
                # SQLite WAL/SHM and other companions from the same upload batch.
                if target.is_relative_to(self.runtime.labs/'inputs') and source.parent==target.parent:return True
        return False

    def files(self):
        with self.lock:
            files=self.runtime.files()
            for row in files:
                row['in_use']=self.in_use(self.runtime.labs/row['path']) if row['deletable'] else False
            return files

    def delete_uploads(self,paths):
        paths=selection(paths,'附件');targets=[]
        with self.lock:
            for value in paths:
                normalized=value.replace('\\','/')
                if not normalized.startswith('inputs/'):raise InputError('只能删除自己导入的附件；练习原件和分析输出不在此处删除。')
                target=managed_path(self.runtime.labs,normalized)
                if self.in_use(target):raise InputError('附件或同批伴随文件正在上传或分析，请等待完成或停止对应任务。')
                targets.append((normalized,target))
            deleted=[];failed=[]
            for value,target in targets:
                try:
                    target.unlink();deleted.append(value)
                    if target.parent!=self.runtime.labs/'inputs':
                        try:target.parent.rmdir()
                        except OSError:pass
                except OSError as exc:failed.append(dict(path=value,error=str(exc)))
            return dict(deleted=deleted,failed=failed)

    def delete_history(self,identities):
        identities=selection(identities,'记录');targets=[]
        with self.lock:
            for identity in identities:
                job=self.get(identity)
                if not job.get('finished',True) or job['state'] in ('queued','running'):
                    raise InputError('运行中的任务不能删除，请先停止并等待任务结束。')
                folder=managed_path(self.runtime.outputs,identity,directory=True)
                if self.in_use(folder):raise InputError('该记录的导出文件正被其他任务使用，请等待对应任务结束。')
                checked_tree(folder);targets.append((identity,folder))
            deleted=[];failed=[]
            for identity,folder in targets:
                record=folder/'_task.json';saved_record=record.read_bytes() if record.is_file() else None
                try:
                    # Keep metadata until every artifact has been removed. A
                    # locked Windows file must not orphan the remaining report.
                    for child in folder.iterdir():
                        if child.name=='_task.json':continue
                        target=managed_path(folder,child.name,directory=child.is_dir())
                        if target.is_dir():shutil.rmtree(target)
                        else:target.unlink()
                    record.unlink(missing_ok=True);folder.rmdir();self.items.pop(identity,None);deleted.append(identity)
                except OSError as exc:
                    job=self.items.get(identity)
                    if folder.is_dir():
                        try:
                            if job:
                                job['files']=[f for f in job.get('files',[]) if confined(folder,f['name'],False).is_file()]
                                record.write_text(json.dumps(self.public(job),ensure_ascii=False,indent=2),encoding='utf-8')
                            elif not record.exists() and saved_record is not None:record.write_bytes(saved_record)
                        except (OSError,ValueError):pass
                    failed.append(dict(id=identity,error='未能完全删除；'+('记录已保留。' if record.is_file() else '请核对输出目录。')+str(exc)))
            return dict(deleted=deleted,failed=failed)

    def stop(self,job):
        job['cancel']=True
        proc=job.get('process')
        if proc is not None and proc.poll() is None:
            if os.name=='nt':
                exe=str(Path(os.environ.get('SystemRoot',r'C:\Windows'))/'System32/taskkill.exe')
                subprocess.run([exe,'/PID',str(proc.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                               creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),timeout=10)
            else:
                try:os.killpg(proc.pid,signal.SIGTERM)
                except ProcessLookupError:pass

    def execute(self,job):
        plan=job['plan'];folder=job['folder'];start=time.monotonic();job['state']='running'
        stdout=folder/'_stdout.log';stderr=folder/'_stderr.log';capture=plan['output'] if plan['binary'] else stdout
        try:
            if job['cancel']:
                job['state']='cancelled';return
            with capture.open('wb') as stream,stderr.open('wb') as errors:
                environment=self.runtime.env.copy()
                if job['action'].startswith('vol2_'):
                    # The Python 2 standalone uses Windows argv in the system
                    # code page. A Python 3 UTF-8 stdout codec breaks its help
                    # formatter and image paths containing Chinese characters.
                    environment.pop('PYTHONIOENCODING',None);environment.pop('PYTHONUTF8',None)
                proc=subprocess.Popen(plan['argv'],cwd=self.runtime.labs,env=environment,stdin=subprocess.DEVNULL,
                                      stdout=stream,stderr=errors,shell=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),start_new_session=os.name!='nt')
                job['process']=proc
                while proc.poll() is None:
                    job['duration']=round(time.monotonic()-start,2)
                    if job['cancel']:
                        self.stop(job);job['state']='cancelled';break
                    if job['duration']>plan['timeout']:
                        self.stop(job);job['state']='timeout';job['error']='达到本次操作的运行时限，请缩小范围后再运行。';break
                    if not plan['binary'] and stdout.stat().st_size>16*1024*1024:
                        self.stop(job);job['state']='failed';job['error']='报告超过 16 MiB，已停止；请缩小检索范围。';break
                    time.sleep(.15)
                proc.wait(timeout=15);job['exit_code']=proc.returncode
            text=read_report(stdout);error_text=read_report(stderr)
            if plan['binary'] and plan['output'].is_file():
                with plan['output'].open('rb') as f:preview=f.read(4096)
                text='已按原始字节保存：'+plan['output'].name+'\n'+str(plan['output'].stat().st_size)+' bytes\n\n'+preview.decode('utf-8','replace')
            job['text']=text+('\n\n[stderr / 诊断信息]\n'+error_text if error_text else '')
            if job['action']=='disk_recover' and plan['output'].is_file():
                with plan['output'].open('rb') as f:job['text']+='\n[导出内容预览]\n'+f.read(4096).decode('utf-8','replace')
            if job['state']=='running':
                job['state']='completed' if job['exit_code']==0 else ('finding' if plan['meta'].get('expected_error') else 'failed')
            if job['exit_code']==0 and job['action'] in ('file_hash','base64','png_map','sqlite_query'):
                try:job['data']=json.loads(text)
                except ValueError:pass
                if job['action']=='sqlite_query' and isinstance(job['data'],list):
                    rows=job['data'];columns=list(rows[0]) if rows else []
                    job['data']=dict(columns=columns,rows=[[row[c] for c in columns] for row in rows])
            if job['exit_code']==0 and plan['meta'].get('json_grid'):
                try:
                    from forensic_workflows import flatten_json
                    grid=json.loads(text[text.index('['):]);rows=flatten_json(grid);columns=list(dict.fromkeys(k for r in rows for k in r if not k.startswith('__')))
                    job['data']=dict(columns=columns,rows=[[r.get(k,'') for k in columns] for r in rows[:500]],note='仅对离线镜像执行社区插件；空结果、候选值和解析成功含义不同，须结合原证据验证。')
                    (folder/'社区插件完整结果.json').write_text(json.dumps(grid,ensure_ascii=False,indent=2),encoding='utf-8')
                except ValueError:pass
            result_path=(plan['output'] if plan['meta'].get('output') else folder)/'result.json'
            if job['exit_code']==0 and result_path.is_file():
                try:job['data']=json.loads(result_path.read_text(encoding='utf-8'))
                except (ValueError,OSError):pass
            if job['action']=='auto_analyze' and isinstance(job['data'],dict):
                sections=job['data'].get('sections',[])
                findings=sum(s.get('status')=='failed' or (isinstance(s.get('data'),dict) and s['data'].get('exit_code',0)!=0) for s in sections)
                if findings:job['state']='finding';job['error']=f'报告已生成，其中 {findings} 项未成功；请查看对应诊断与覆盖范围。'
            if plan['meta'].get('casework') and isinstance(job['data'],dict) and (job['data'].get('partial') or (job['data'].get('operation')=='photorec' and job['data'].get('limited'))):
                job['state']='finding';job['error']='已保留本次结果，其中有步骤未完成或达到预算；请查看各步骤状态。'
            if job['action'].startswith('vol_') and job['exit_code']!=0:
                diagnostic=volatility_compatibility(job['text'],job.get('input',''))
                if diagnostic:job['data']=diagnostic;job['error']='Vol3 插件结构不兼容；可使用下面的 Vol2 识别入口继续，先验证 profile。'
            if job['action']=='metadata':
                rows=[]
                for line in text.splitlines():
                    m=re.match(r'\[([^]]+)\]\s+(.+?)\s+: (.*)',line)
                    if m:rows.append(list(m.groups()))
                if rows:job['data']=dict(columns=['字段组','标签','值'],rows=rows)
            if job['action']=='hex' and plan['source']:
                offset=int(self.runtime.number(plan['params'],'offset',0));length=int(self.runtime.number(plan['params'],'length',128))
                with plan['source'].open('rb') as f:f.seek(offset);raw=f.read(length)
                job['data']=dict(columns=['字节偏移','十六进制','ASCII'],rows=[
                    [f'0x{offset+i:08x}',raw[i:i+16].hex(' '),''.join(chr(x) if 32<=x<127 else '.' for x in raw[i:i+16])]
                    for i in range(0,len(raw),16)])
        except Exception as exc:
            job['state']='failed';job['error']=str(exc)
        finally:
            job['duration']=round(time.monotonic()-start,2)
            report=('操作：'+job['title']+'\n运行环境：'+('Windows PowerShell' if self.runtime.windows else 'Kali Bash')+
                    '\n创建时间：'+job['created']+'\n状态：'+job['state']+'\n退出码：'+str(job['exit_code'])+
                    '\n命令：'+job['command']+'\n\n'+job['error']+'\n'+job['text'])
            if plan.get('argument_file') and not plan['meta'].get('private_arguments'):report+='\n\nUTF-8 参数文件内容：\n'+plan['argument_file'][1]
            if plan.get('argument_file') and plan['meta'].get('private_arguments'):
                plan['argument_file'][0].unlink(missing_ok=True)
                report+='\n参数文件含私密输入，未写入本报告并已清理。'
            (folder/'运行报告.txt').write_text(report,encoding='utf-8')
            job['files']=[dict(name=p.relative_to(folder).as_posix(),bytes=p.stat().st_size,
                               path=p.relative_to(self.runtime.labs).as_posix()) for p in sorted(folder.rglob('*'))
                          if p.is_file() and not p.name.startswith('_')][:2000]
            with self.lock:
                job['finished']=True
                (folder/'_task.json').write_text(json.dumps(self.public(job),ensure_ascii=False,indent=2),encoding='utf-8')

    def close(self):
        for job in list(self.items.values()):
            if job['state'] in ('running','queued'):self.stop(job)
        self.pool.shutdown(wait=True,cancel_futures=False)

class Handler(BaseHTTPRequestHandler):
    server_version='ForensicsClassroom/1.0'
    def log_message(self,*args):pass  # Local access tokens are never written to logs.
    @property
    def app(self):return self.server.app
    def json(self,value,status=200):
        data=json.dumps(value,ensure_ascii=False).encode('utf-8')
        self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def end_headers(self):
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Cache-Control','no-store')
        super().end_headers()
    def local(self):
        host=self.headers.get('Host','')
        if host not in ('127.0.0.1:'+str(self.server.server_port),'localhost:'+str(self.server.server_port)):
            raise PermissionError('不接受这个 Host。')
        origin=self.headers.get('Origin')
        if origin and origin not in ('http://'+host,):raise PermissionError('只接受本机学习平台页面发起的操作。')
    def authorized(self):
        self.local();query=urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        supplied=self.headers.get('Authorization','').removeprefix('Bearer ') or query.get('token',[''])[0]
        if not hmac.compare_digest(supplied,self.app.token):raise PermissionError('请使用启动器打开的学习平台页面。')
    def body(self):
        if self.headers.get('Content-Type','').split(';')[0]!='application/json':raise InputError('需要 JSON 请求。')
        size=int(self.headers.get('Content-Length','0'))
        if not 0<size<=256*1024:raise InputError('请求大小无效。')
        value=json.loads(self.rfile.read(size))
        if not isinstance(value,dict):raise InputError('参数格式错误。')
        return value
    def file_response(self,path,attachment=False):
        mime=mimetypes.guess_type(str(path))[0] or 'application/octet-stream'
        self.send_response(200);self.send_header('Content-Type',mime)
        self.send_header('Content-Length',str(path.stat().st_size))
        if attachment:self.send_header('Content-Disposition',"attachment; filename*=UTF-8''"+urllib.parse.quote(path.name))
        self.end_headers()
        with path.open('rb') as f:shutil.copyfileobj(f,self.wfile,1024*1024)
    def do_GET(self):
        try:
            self.local();url=urllib.parse.urlsplit(self.path);path=urllib.parse.unquote(url.path);query=urllib.parse.parse_qs(url.query)
            if path=='/api/state':
                self.authorized();value=self.app.runtime.catalog();value['files']=self.app.jobs.files();return self.json(value)
            if path=='/api/files':
                self.authorized();return self.json(self.app.jobs.files())
            if path=='/api/jobs':
                self.authorized();return self.json(self.app.jobs.history())
            if path.startswith('/api/jobs/'):
                self.authorized();return self.json(self.app.jobs.public(self.app.jobs.get(path.rsplit('/',1)[1])))
            if path=='/api/file':
                self.authorized();target=confined(self.app.runtime.labs,query.get('path',[''])[0])
                return self.file_response(target,attachment=target.suffix.lower() not in ('.png','.jpg','.jpeg','.bmp','.gif'))
            if path.startswith('/results/'):
                self.authorized();parts=path.split('/',3)
                if len(parts)!=4:raise InputError('输出路径无效。')
                job=self.app.jobs.get(parts[2]);return self.file_response(confined(job['folder'],parts[3]),attachment=True)
            rel=path.lstrip('/') or 'index.html';target=confined(self.app.runtime.root,rel)
            # Evidence files are downloads, never executable HTML documents.
            evidence=target.is_relative_to(self.app.runtime.labs)
            if target.is_relative_to(self.app.runtime.root/'output') or '/__pycache__/' in target.as_posix():raise PermissionError('不提供临时验证文件。')
            self.file_response(target,attachment=evidence or target.suffix.lower() not in ('.html','.css','.js','.json','.svg','.png','.jpg','.jpeg','.ico','.wasm'))
        except (PermissionError,InputError,ValueError,OSError) as exc:
            self.json(dict(error=str(exc)),403 if isinstance(exc,PermissionError) else 400)
        except (BrokenPipeError,ConnectionResetError):pass
    def do_POST(self):
        try:
            self.authorized();url=urllib.parse.urlsplit(self.path)
            if url.path=='/api/upload':
                size=int(self.headers.get('Content-Length','0'))
                if not 0<=size<=2*1024**3:raise InputError('导入文件限 2 GiB；更大的真实镜像可先复制到 labs/inputs 再刷新。')
                if self.headers.get('Content-Type','').split(';')[0]!='application/octet-stream':raise InputError('导入格式不正确。')
                name=urllib.parse.parse_qs(url.query).get('name',['attachment.bin'])[0]
                name=re.sub(r'[\\/:*?"<>|\x00-\x1f]','_',name).strip(' .')[:140] or 'attachment.bin'
                if name.split('.')[0].upper() in {'CON','PRN','AUX','NUL',*[f'COM{i}' for i in range(1,10)],*[f'LPT{i}' for i in range(1,10)]}:name='_'+name
                batch=urllib.parse.parse_qs(url.query).get('batch',[''])[0]
                if batch and not re.fullmatch('[0-9a-f]{24}',batch):raise InputError('导入批次编号无效。')
                folder=self.app.runtime.labs/'inputs'/(batch or uuid.uuid4().hex[:12])
                if not folder.is_relative_to(self.app.runtime.labs):raise InputError('导入目录不能指向附件目录之外。')
                with self.app.jobs.lock:
                    target=managed_path(self.app.runtime.labs,folder.relative_to(self.app.runtime.labs).as_posix()+'/'+name,must_exist=False)
                    if target in self.app.jobs.uploading:raise InputError('同名文件正在上传，请稍后重试。')
                    folder.mkdir(parents=True,exist_ok=True);self.app.jobs.uploading.add(target)
                remaining=size;self.connection.settimeout(90);created=False
                try:
                    with target.open('xb') as f:
                        created=True
                        while remaining:
                            chunk=self.rfile.read(min(1024*1024,remaining))
                            if not chunk:raise InputError('导入未完成，请重新选择文件。')
                            f.write(chunk);remaining-=len(chunk)
                except Exception:
                    if created:target.unlink(missing_ok=True)
                    raise
                finally:
                    with self.app.jobs.lock:self.app.jobs.uploading.discard(target)
                return self.json(dict(path=target.relative_to(self.app.runtime.labs).as_posix(),bytes=size))
            data=self.body()
            if url.path=='/api/files/delete':return self.json(self.app.jobs.delete_uploads(data.get('paths')))
            if url.path=='/api/jobs/delete':return self.json(self.app.jobs.delete_history(data.get('ids')))
            if url.path=='/api/preview':
                plan=self.app.runtime.plan(data.get('action'),data.get('params',{}),self.app.runtime.outputs/'<本次任务>')
                return self.json(dict(command=plan['command'],host='Windows · PowerShell' if self.app.runtime.windows else 'Kali / Linux · Bash'))
            if url.path=='/api/run':return self.json(self.app.jobs.submit(data.get('action'),data.get('params',{})),202)
            if url.path=='/api/cancel':
                job=self.app.jobs.get(str(data.get('id')));self.app.jobs.stop(job);return self.json(self.app.jobs.public(job))
            raise InputError('接口不存在。')
        except (PermissionError,InputError,ValueError,OSError,TypeError) as exc:
            self.json(dict(error=str(exc)),403 if isinstance(exc,PermissionError) else 400)
        except (BrokenPipeError,ConnectionResetError):pass

class App:
    def __init__(self,root,kit=None):
        self.token=secrets.token_urlsafe(32);self.runtime=Runtime(root,kit);self.jobs=Jobs(self.runtime)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',default=str(Path(__file__).resolve().parent.parent));parser.add_argument('--kit')
    parser.add_argument('--port',type=int,default=0);parser.add_argument('--no-browser',action='store_true')
    args=parser.parse_args();app=App(args.root,args.kit)
    server=ThreadingHTTPServer(('127.0.0.1',args.port),Handler);server.daemon_threads=True;server.app=app
    url=f'http://127.0.0.1:{server.server_port}/index.html#token={app.token}'
    print('Forensics Classroom / local tools',flush=True)
    print('URL: '+url,flush=True);print('Keep this window open. Ctrl+C stops the service.',flush=True)
    if not args.no_browser:webbrowser.open(url)
    try:server.serve_forever(poll_interval=.25)
    except KeyboardInterrupt:pass
    finally:app.jobs.close();server.server_close()

if __name__=='__main__':main()
