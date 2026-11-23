"""Volatility 3 curriculum and clearly synthetic output-reading examples."""
import base64
import csv
import io
import json
import random

VOL3_PATH = r'..\tools\volatility3\vol.py'
CASE_FLAGS = {'a':'flag{read_the_command_line}','b':'flag{follow_the_file_object}','c':'flag{utf16_is_still_text}'}
GUIDE = 'https://volatility3.readthedocs.io/en/stable/getting-started-windows-tutorial.html'
DUMP = 'https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/dumpfiles.html'
FILES = 'https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/filescan.html'
MEMMAP = 'https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/memmap.html'


def build_memory_slides():
    from content import code,cols,panel,callout,table,steps,ref,hints,flag_form
    slides=[]
    def add(title,subtitle,body,notes):
        slides.append(dict(group=5,title=title,subtitle=subtitle,body=body,notes=notes,kind=''))
    def command(title,subtitle,commands,explanation,notes,source=None):
        body=cols(code('PowerShell · 先完成本节环境设置',commands),explanation)
        if source:body+=ref(*source)
        add(title,subtitle,body,notes)

    add('Volatility 3：拿到镜像后先做什么？','先建立系统与进程视图，再围绕题意深入。',
        '<div class="process"><div><b>01 / SYSTEM</b><h4>确认系统</h4><p>windows.info<br>镜像、层、符号</p></div><div><b>02 / PROCESS</b><h4>盘点进程</h4><p>pslist / pstree<br>必要时 psscan</p></div><div><b>03 / CONTEXT</b><h4>看上下文</h4><p>cmdline / 历史<br>参数、文件路径</p></div><div><b>04 / EXTRACT</b><h4>定向提取</h4><p>dumpfiles / memmap<br>按文件或 PID</p></div><div><b>05 / VERIFY</b><h4>检索复核</h4><p>文字、格式、编码<br>证据位置与 flag</p></div></div>'
        +callout('<strong>先问题目要什么。</strong>启动参数查 cmdline；打开过的文件走 filescan / handles → dumpfiles；编辑器文本可走进程映射页 → 字符串检索。')
        +panel('本节安排','<p>约 45 分钟，主线使用 Volatility 3，旧镜像兼容排错另见 index.html 中的 Vol2 指南。附三个基础例题的<strong>教学输出与模拟导出片段</strong>，用于讲解思路；这些材料不是可供 Volatility 解析的完整 RAM 镜像。</p>','mint'),
        '开场让学员复述五步。不要无方向地运行全部插件。本课不读取用户目录内已有的大镜像；真实镜像由授课者或主办方另行提供。')

    add('工具入口：先确认 Vol3 能正常启动','课前准备 Python 3、源码依赖与适用符号；参数以本机帮助为准。',
        cols(code('PowerShell · 替换成自己的 vol.py 路径',rf"""$v3 = '{VOL3_PATH}'
python $v3 -h
python $v3 windows.dumpfiles -h
python $v3 windows.memmap -h"""),
        table(['片段','含义'],[('python $v3','用 Python 3 调用 vol.py'),('-f 镜像','指定输入'),('windows.插件','选择对象与分析内容'),('--pid / --dump','插件选项，放在插件名后'),('-o 输出目录','全局选项，放在插件名前')]))
        +callout('工具包使用 <strong>Volatility 3 Framework 2.28.2</strong>。从包内课堂终端执行；11 个插件的帮助及所用选项已检查。实际解析仍依赖镜像与符号适配。')
        +ref('Volatility 3 官方 Windows 教程',GUIDE),
        '先实际运行 -h。$v3 只是入口路径变量；其他电脑要替换。python 未指向配好依赖的解释器时，用该 Python 3 的完整路径。')

    command('准备：镜像副本、目录与参数约定','后续沿用 $v3 和 $img；示例 PID、地址、路径必须按实际输出替换。',
        r"""$img = '.\memory.raw'
New-Item -ItemType Directory -Force -Path .\out, .\out\files, .\out\proc | Out-Null
Get-FileHash -LiteralPath $img -Algorithm SHA256
Get-Item -LiteralPath $img | Select-Object Name,Length""",
        steps([('准备工作副本','memory.raw 是示例名，替换成题目提供的 .raw / .mem / .vmem / .dmp 等实际文件。'),
               ('保留关联材料','虚拟机镜像若附带 .vmss / .vmsn 等元数据，一并保留；扩展名不决定系统类型。'),
               ('固定工作目录','原件不覆盖，报告与导出结果统一放到 out/。')]),
        '本包未提供 memory.raw。取得真实镜像才运行 Volatility 命令；教学 CSV 和二进制片段不能改后缀冒充 RAM。')

    command('第 1 步：windows.info 确认解析条件','成功建立内存层与符号，是后续结果可解释的前提。',
        r"""python $v3 -f $img windows.info
# 保存文本报告
python $v3 -f $img windows.info | Out-File -Encoding utf8 .\out\info.txt""",
        table(['观察点','如何判断','下一步'],[('系统 / 架构','与题意、采集来源合理对应','记录系统线索'),('层 / 符号','是否满足内核层与符号要求','进入进程分析'),('Unsatisfied requirement','区分输入、层和符号问题','先解决解析条件')])
        +callout('Windows 符号可能自动下载；离线课堂提前准备适用缓存。下载失败不等于镜像损坏。'),
        '本课聚焦 Windows；windows.info 不是面向所有操作系统的通用识别器。先阅读完整报错，避免在符号问题未解决时继续解释异常输出。',
        ('Volatility 3 官方 Windows 教程',GUIDE))

    command('第 2 步：先盘点进程，再选目标 PID','pslist 看列表，pstree 看父子关系；名称只是分析起点。',
        """python $v3 -f $img windows.pslist
python $v3 -f $img windows.pstree
python $v3 -f $img windows.pslist --pid 2460""",
        table(['字段','用来回答什么'],[('PID / PPID','进程是谁，由谁启动'),('ImageFileName','定位题意相关的编辑器、解释器或文档程序'),('CreateTime / ExitTime','创建、退出与题目时间是否匹配'),('父子关系','与启动它的终端或解释器能否对应')])
        +callout('<strong>2460 是教学 PID。</strong>在其他镜像上先读实际输出；PID 可能重用，需要结合名称与时间。'),
        '让学员先圈出目标 PID，再查 cmdline。进程名陌生、父进程缺失都不足以单独判定恶意。',('Vol3 Windows 教程',GUIDE))

    command('补充检查：什么时候再跑 psscan？','题目涉及退出进程、遗漏进程或列表矛盾时，再交叉检查。',
        """python $v3 -f $img windows.psscan
python $v3 -f $img windows.psscan --pid 2460""",
        panel('列表与扫描有何不同','<p><strong>pslist：</strong>沿进程列表发现对象。</p><p><strong>psscan：</strong>扫描内存中的进程对象候选，也可能发现已退出或残留对象。</p>','mint')
        +callout('“psscan 有、pslist 没有”只能形成待验证线索。继续检查退出时间、路径、上下文与可访问内存。'),
        'psscan 不是每道题都必须执行。不要把两份输出的差异直接当作隐藏进程证明。')

    command('第 3 步：cmdline 把 PID 变成线索','进程名告诉你程序；命令行可能给出参数、脚本和文档路径。',
        """python $v3 -f $img windows.cmdline
python $v3 -f $img windows.cmdline --pid 2460
python $v3 -f $img windows.cmdline --pid 3180""",
        code('教学摘要 · 非真实镜像实测输出',r"""2460  notepad.exe C:\Users\CTF\Desktop\memo.txt
3180  python.exe show_note.py --note [编码文本]""")
        +steps([('有编码参数','保留原值，识别编码后还原；对应例题 A。'),('有文件路径','按文件名查 filescan，并核对 handles；对应例题 B。'),('参数不可读','再按题意查历史或进程映射页，不强求每个进程都有结果。')]),
        'cmdline 看启动参数，不等于交互式命令历史。进程退出、内存缺页、不可读命令行都可能导致无结果。')

    command('另一条路：命令历史与控制台','题目问“输入过什么命令”时，再尝试以下插件。',
        """python $v3 -f $img windows.cmdscan
python $v3 -f $img windows.consoles""",
        table(['插件','侧重点','如何处理'],[('windows.cmdscan','命令历史结构','保留命令与控制台线索'),('windows.consoles','控制台结构及可恢复缓冲区','核对输入、输出与上下文'),('无结果','可能缺失、覆盖或不受支持','改查关联文件、进程或其他证据')])
        +callout('插件存在不等于适用于所有 Windows 构建、终端实现或 PowerShell 历史。结合本机帮助、系统版本与实际输出判断。'),
        '本机两插件的帮助均通过。不承诺读取全部终端历史，也不把 consoles 当作 cmdline 的同义命令。',
        ('Vol3 cmdscan 官方实现','https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/cmdscan.html'))

    command('第 4 步：按文件名定位文件对象','filescan 找全局候选，handles 帮助关联目标进程。',
        r"""python $v3 -f $img windows.filescan | Out-File -Encoding utf8 .\out\filescan.txt
Select-String -Path .\out\filescan.txt -Pattern 'memo[.]txt'
python $v3 -f $img windows.handles --pid 2460""",
        steps([('保存扫描结果','先保存一次，后续检索文件名或路径，避免反复全镜像扫描。'),('核对对象类型','handles 可能含 File、Key、Mutant 等，先确认目标是 File。'),('抄录完整证据','记录 PID、对象地址、路径、工具版本与地址层，再决定导出方式。')])
        +callout('文件对象存在，不保证全部文件内容仍驻留在内存；filescan 的 Offset 也不是文件在磁盘中的偏移。'),
        'Offset 不一定总处于同一种地址层。下一页优先按 PID 与路径筛选；按地址导出时要单独确认地址类型。',
        ('Vol3 filescan 官方实现',FILES))

    command('第 4 步：按 PID 与名称导出文件缓存','仍可从目标进程关联到文件时，先保留上下文地筛选。',
        r"""python $v3 -f $img -o .\out\files windows.dumpfiles --pid 2460 --filter 'memo[.]txt$' --ignore-case
Get-ChildItem -LiteralPath .\out\files
Get-FileHash -Path .\out\files\* -Algorithm SHA256""",
        table(['选项 / 输出','怎么理解'],[('-o','插件内容文件的输出目录'),('--pid','限制进程关联范围'),('--filter / --ignore-case','按正则筛选路径，按需忽略大小写'),('.dat / .img / .vacb','可能是不同缓存来源，应重新识别内容')])
        +callout('检查插件成功/失败报告、非空输出、类型和内容。无结果时回到对象线索，确认是否应按地址导出。'),
        'PID 和文件名来自教学设定，真实镜像上替换。缓存导出可能缺页、残留或有多个来源，不能随意称为完整磁盘原件。',('Vol3 dumpfiles 参数',DUMP))

    command('按地址导出：先确认物理还是虚拟','不能仅凭十六进制长相，或仅凭一列叫 Offset，就决定参数。',
        r"""# 已确认是虚拟 _FILE_OBJECT 地址的教学示例
python $v3 -f $img -o .\out\files windows.dumpfiles --virtaddr 0xffffa10200123070
# 已确认是物理 _FILE_OBJECT 地址时才使用
python $v3 -f $img -o .\out\files windows.dumpfiles --physaddr 0x3e92c070""",
        panel('两种参数对应不同的层','<p><strong>--virtaddr：</strong>虚拟 _FILE_OBJECT 地址。</p><p><strong>--physaddr：</strong>物理 _FILE_OBJECT 地址。</p><p>filescan 的扫描层与目标 Windows 版本、实现有关，需要结合版本与上下文确认。</p>','mint')
        +callout('这里是两种已确认条件下的示例，不能把同一个数值换参数盲试。对象地址不是 PID，也不是文件内容起点。'),
        'Vol3 的 poolscanner 对 Windows 10 和较早系统选择不同扫描层，不能固定声称全部 Offset 都是物理地址。例题 B 明确给的是虚拟地址。',
        ('Vol3 dumpfiles 地址参数',DUMP))

    command('导出进程：映射页与程序本体不同','找编辑器文本，通常先考虑可读映射页；程序本体是另一个目标。',
        r"""python $v3 -f $img -o .\out\proc windows.memmap --pid 2460 --dump
# 题目要可执行映像时再选择
python $v3 -f $img -o .\out\proc windows.pslist --pid 2460 --dump""",
        table(['路径','得到什么','典型用途'],[('dumpfiles','可恢复的文件缓存','文档、压缩包等'),('memmap --dump','可读取的进程映射段','编辑器文本、进程内线索'),('pslist --dump','进程可执行映像','需要程序本体的题')])
        +callout('命名与可恢复范围以实际报告为准。导出可能缺页或改变布局，内部偏移不能直接当作原镜像地址。'),
        '帮助已核对 memmap 的 --pid/--dump 和 pslist 的 --dump。可执行映像不是整个进程可用地址空间。',
        ('Vol3 memmap 官方实现',MEMMAP))

    add('第 5 步：检索 ASCII 与 UTF-16LE，再复核','优先在定向导出的对象中查找，保留位置与上下文。',
        cols(code('Linux Bash · GNU strings，替换为实际导出文件',"""strings -a -t x process_dump.bin | grep 'flag{'
strings -a -e l -t x process_dump.bin | grep 'flag{'"""),
        code('PowerShell · 本题模拟片段的检索',r"""python .\08_memory\search_excerpt.py .\08_memory\case_c\process_2460_excerpt.bin"""))
        +steps([('检查编码','ASCII 可能漏掉 UTF-16LE；也可用十六进制查看器做 Unicode 搜索。'),('验证含义','确认完整 flag、上下文与题意；历史残留不自动代表当前操作。'),('记录坐标系','写清偏移属于原镜像、文件导出还是进程导出。')])
        +callout('search_excerpt.py 只扫描两种文本表示，不能解析 RAM、定位进程或替代 Volatility。'),
        '先用普通 strings，再用 -e l 检索例题 C。原镜像全局 strings 可作补充，但单独的文本命中无法归属到某个 PID。')

    encoded=base64.b64encode(CASE_FLAGS['a'].encode()).decode()
    add('内存例题 A：启动参数里的编码线索','自制教学输出读题 · pslist → cmdline → 解码与复核。',
        cols(code('case_a/cmdline.csv 的教学摘要',f'3180 / python.exe\nshow_note.py --note {encoded}')
             +code('真实镜像上对应的命令',"""python $v3 -f $img windows.pslist
python $v3 -f $img windows.cmdline --pid 3180"""),
             '<p><strong>为什么这样查：</strong>先用进程清单确认对象，再按同一 PID 关联 Args，避免把其他同名进程的参数算到本题。--note 后的值才是编码线索；提取原值后解码，核对完整 flag。python.exe 这个名字本身不能证明恶意，读取参数也无需执行脚本。</p>'
             +code('Python 3 · 对参数解码',f'import base64\nprint(base64.b64decode("{encoded}").decode())')
             +flag_form('mem-a',CASE_FLAGS['a']))
        +callout('case_a 提供合成 CSV 摘要，不是 RAM；真实镜像才使用上面的 Volatility 命令。'),
        '答案 flag{read_the_command_line}。要求说清先列表、后指定 PID 查询参数的理由。教学设定中的脚本不需要也不应该执行。')

    add('内存例题 B：打开过的 memo.txt','自制教学输出读题 · 进程 → 文件对象 → 缓存导出。',
        cols(steps([('为什么查参数','PID 2460 提到 Desktop\\memo.txt，所以先追文件线索。'),('为什么核对对象','handles 关联进程与 File 对象，filescan 提供同一虚拟对象候选；同名路径本身不足以证明归属。'),('为什么导出缓存','要找文档内容，因此用 dumpfiles；按已确认的地址类型导出后，检查实际文件、完整性和来源。')])
             +flag_form('mem-b',CASE_FLAGS['b']),
             code('真实镜像上的操作顺序',r"""python $v3 -f $img windows.handles --pid 2460
python $v3 -f $img windows.filescan
python $v3 -f $img -o .\out\files windows.dumpfiles --virtaddr 0xffffa10200123070""")
             +code('读取本题模拟导出结果',r"""Get-Content .\08_memory\case_b\exported_memo.txt"""))
        +callout('本题摘要和导出文本均为合成。盘符与设备卷的对应关系未提供，路径后缀相同只形成候选；handles 与 filescan 的同一对象地址是另一个关联依据。完整题解见 index.html 案例 14。'),
        '答案 flag{follow_the_file_object}。虚拟地址 0xffffa10200123070 不能原样交给 --physaddr；例题明确给出了其类型。')

    add('内存例题 C：没有保存的记事本文本','自制教学输出读题 · 按进程映射页继续找文本。',
        cols(code('真实镜像上的下一步',r"""python $v3 -f $img windows.pslist
python $v3 -f $img -o .\out\proc windows.memmap --pid 2460 --dump""")
             +code('检索教学片段',r"""python .\08_memory\search_excerpt.py .\08_memory\case_c\process_2460_excerpt.bin"""),
             steps([('先确认假设','题目给了编辑文字与进程片段；无文件参数本身不能证明未保存。'),('为什么选映射页','目标是编辑缓冲区。memmap --dump 包含可访问进程页，pslist --dump 的程序映像不能替代。'),('为什么换编码','字符后交替出现 00，考虑 UTF-16LE；ASCII 未命中并不能否定文字存在。')])
             +hints('先检查文本编码，不急着换复杂插件。','字符后交替出现 00，可尝试 UTF-16LE。')
             +flag_form('mem-c',CASE_FLAGS['c']))
        +callout('process_2460_excerpt.bin 是模拟进程片段，不能交给 Volatility 解析；PID 归属也是教学设定，不是片段本身可证明的信息。'),
        '答案 flag{utf16_is_still_text}。Linux 使用 strings -a -e l -t x，Windows 用配套脚本或十六进制工具。')

    add('常见题型：先选入口，再确定下一步','不用每题都跑完全部插件，按所求对象选路径。',
        table(['题目问什么','先运行','后做什么'],[('系统 / 进程','info → pslist → pstree','有矛盾再 psscan'),('启动参数 / 脚本路径','cmdline --pid 实际PID','提取原值 → 识别编码'),('输入过的命令','cmdscan / consoles','核对终端、支持范围与上下文'),('打开过的文件','handles / filescan','dumpfiles → 格式、大小与内容校验'),('编辑器文字','pslist → 确认 PID','memmap --dump → 两种编码检索'),('程序本体','确认 PID 与所求对象','pslist --dump → 后续识别')])
        +callout('完整命令与三道例题题解见随包 <strong>Volatility3_内存镜像分析_命令与题解.md</strong>。'),
        '随机给一个题意，让学员说出第一条命令、为何选择下一条命令。强调方法，不强制所有题目执行同一套命令。')

    add('排错与记录：让每一步都能复现','按输入、符号、参数和范围排查，最后形成证据记录。',
        table(['现象','优先检查','下一步'],[('启动失败 / 插件不存在','入口、Python、依赖、本机 -h','先让帮助正常显示'),('层或符号要求未满足','格式、完整性、支持与符号缓存','解决解析条件'),('filescan 有、导出为空','地址类型、对象残留、缓存页','核对地址或进程关联'),('导出后打不开','成功报告、大小、缺页与来源','重新识别可恢复范围'),('没有 flag','PID、题意、对象、编码','根据证据调整入口')])
        +callout('<strong>最小记录：</strong>镜像哈希、Vol3 版本、系统、PID、对象地址及类型、命令、导出文件哈希、命中位置与 flag。'),
        '插件帮助与选项已核对；本课未对未提供的真实内存镜像作端到端运行承诺。总结先让结果可解释，再让路径可复现。')
    assert len(slides)==18
    return slides


def _legacy_memory_handout():
    return r"""# Volatility 3 内存镜像分析：命令与题解

主线使用 Volatility 3，聚焦 Windows 内存镜像；旧镜像兼容排错另见 Volatility2_兼容分析指南.html。课堂主工具：Volatility 3 Framework 2.28.2。
顺序：确认系统 → 盘点进程 → 命令行/历史 → 定向导出 → 检索与验证。

## 材料说明

本包不附大型 RAM。08_memory 的 CSV、对象摘要与片段为自制教学材料，不是镜像实测输出，不可改后缀交给 Volatility。
Volatility 命令用于授课者另行提供的真实镜像；例题实际读取命令在后半部分。
PID 2460、3180、对象地址与文件名均为示例，其他镜像上必须重新从输出取得。

## 0. PowerShell 环境设置

从学员工具包的课堂终端执行，默认位于 labs。若使用自己的环境，替换工具和镜像路径。

~~~powershell
$v3 = '..\tools\volatility3\vol.py'
$img = '.\memory.raw'
python $v3 -h
python $v3 windows.dumpfiles -h
New-Item -ItemType Directory -Force -Path .\out, .\out\files, .\out\proc | Out-Null
Get-FileHash -LiteralPath $img -Algorithm SHA256
~~~

全局 -f、-o 在插件前；插件 --pid、--dump、--filter 在插件后。
python 应指向配好依赖的 Python 3。源码版调用 vol.py；pip 的 console 入口通常为 vol，是否在 PATH 中需确认。

## 1. 确认系统与解析条件

~~~powershell
python $v3 -f $img windows.info
python $v3 -f $img windows.info | Out-File -Encoding utf8 .\out\info.txt
~~~

看系统、架构、镜像层与符号。先解决 Unsatisfied requirement，再解释其他结果。
Windows 可能自动下载符号；离线准备缓存。虚拟机配套 .vmss/.vmsn 等元数据应保留。

## 2. 盘点进程

~~~powershell
python $v3 -f $img windows.pslist
python $v3 -f $img windows.pstree
# 涉退出进程或列表矛盾时再交叉检查
python $v3 -f $img windows.psscan
~~~

记录 PID、PPID、名称、创建/退出时间。psscan 的额外对象可能是退出残留，不能单独证明隐藏进程。

## 3. 看参数、命令历史与控制台

~~~powershell
python $v3 -f $img windows.cmdline --pid 2460
python $v3 -f $img windows.cmdline --pid 3180
python $v3 -f $img windows.cmdscan
python $v3 -f $img windows.consoles
~~~

cmdline 是启动参数；cmdscan/consoles 尝试恢复历史或控制台上下文，支持范围依系统与终端实现而异。
有路径就找文件，有编码就保留原值再转换；空结果不证明没有操作。

## 4A. 定位与导出文件缓存

~~~powershell
python $v3 -f $img windows.filescan | Out-File -Encoding utf8 .\out\filescan.txt
Select-String -Path .\out\filescan.txt -Pattern 'memo[.]txt'
python $v3 -f $img windows.handles --pid 2460
python $v3 -f $img -o .\out\files windows.dumpfiles --pid 2460 --filter 'memo[.]txt$' --ignore-case
Get-ChildItem -LiteralPath .\out\files
~~~

优先带着进程与路径上下文导出。对象残留不保证文件完整。按地址导出前确认所在层，不能仅凭 Offset 列名决定。

~~~powershell
# 已确认虚拟 _FILE_OBJECT 地址
python $v3 -f $img -o .\out\files windows.dumpfiles --virtaddr 0xffffa10200123070
# 已确认物理 _FILE_OBJECT 地址
python $v3 -f $img -o .\out\files windows.dumpfiles --physaddr 0x3e92c070
~~~

两条命令适用于不同已确认条件，不是换参数盲试同一个数值。
filescan 的扫描层会受目标系统与实现影响；查看版本和上下文。
核对插件成功/失败报告；.dat/.img/.vacb 等缓存输出须按内容重新识别。

## 4B. 导出进程中的文本

~~~powershell
python $v3 -f $img -o .\out\proc windows.memmap --pid 2460 --dump
~~~

memmap --dump 导出可读映射段。下面是可执行映像导出，目标不同：

~~~powershell
python $v3 -f $img -o .\out\proc windows.pslist --pid 2460 --dump
~~~

## 5. 检索和验证

Linux Bash（GNU strings），替换为插件实际导出文件：

~~~bash
strings -a -t x process_dump.bin | grep 'flag{'
strings -a -e l -t x process_dump.bin | grep 'flag{'
~~~

Windows 可用十六进制工具 Unicode 搜索；本包另提供只扫描片段文本的 Python：

~~~powershell
python .\08_memory\search_excerpt.py .\08_memory\case_c\process_2460_excerpt.bin
Get-FileHash -Path .\out\files\* -Algorithm SHA256
~~~

命中位置注明属于原镜像、文件导出或进程导出；不要直接当作物理内存地址。

## 教学例题 A：启动参数

先从 case_a/pslist.csv 找 python.exe PID 3180，再读 cmdline.csv 的 --note，做一次 Base64 解码。
不执行命令行中的脚本。

~~~powershell
Import-Csv .\08_memory\case_a\cmdline.csv | Where-Object { $_.PID -eq '3180' }
python -c "import base64; print(base64.b64decode('ZmxhZ3tyZWFkX3RoZV9jb21tYW5kX2xpbmV9').decode())"
~~~

答案 flag{read_the_command_line}。

## 教学例题 B：打开过的文件

case_b 的 cmdline、handles、filescan 指向 PID 2460 的 memo.txt；对象地址明确为虚拟。
再与模拟导出结果对应，说明 dumpfiles 的输入与输出。

~~~powershell
Get-Content .\08_memory\case_b\filescan.txt
Import-Csv .\08_memory\case_b\handles.csv
Get-Content .\08_memory\case_b\exported_memo.txt
~~~

答案 flag{follow_the_file_object}。模拟输出不代表本课从真实 RAM 完成过恢复。

## 教学例题 C：编辑器文本

case_c 的 notepad.exe 没有已保存文档路径，走 PID → memmap → 两种编码检索。

~~~powershell
python .\08_memory\search_excerpt.py .\08_memory\case_c\process_2460_excerpt.bin
~~~

答案 flag{utf16_is_still_text}。该片段为 UTF-16LE，PID 归属来自教学设定。

## 最小证据记录

镜像哈希、Vol3 版本、系统、PID、对象地址及类型、完整命令、导出文件与哈希、命中位置、原值/转换、flag。

## 官方参考

- Windows 教程：https://volatility3.readthedocs.io/en/stable/getting-started-windows-tutorial.html
- dumpfiles：https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/dumpfiles.html
- filescan：https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/filescan.html
- memmap：https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/memmap.html

本机 11 个相关插件帮助与所用参数已核对；未对未提供的真实镜像作端到端运行承诺。
"""


def _csv(rows):
    stream=io.StringIO(newline='')
    writer=csv.DictWriter(stream,fieldnames=list(rows[0]))
    writer.writeheader();writer.writerows(rows)
    return stream.getvalue().encode('utf-8')


SEARCH_SCRIPT = r'''"""Search ASCII/UTF-16LE flags in an excerpt. Does not parse RAM or infer a PID."""
from pathlib import Path
import argparse,re
p=argparse.ArgumentParser(description=__doc__);p.add_argument('input');a=p.parse_args()
data=Path(a.input).read_bytes();found=False
patterns=[('ASCII',rb'flag\{[ -~]{1,100}?\}'),('UTF-16LE',rb'f\x00l\x00a\x00g\x00\{\x00(?:[\x20-\x7e]\x00){1,100}?\}\x00')]
for encoding,pattern in patterns:
    for match in re.finditer(pattern,data):
        found=True;text=match.group().decode('ascii' if encoding=='ASCII' else 'utf-16le')
        print(encoding,'offset-in-input='+hex(match.start()),text)
if not found:print('No matching text in the two supported representations.')
'''


def memory_handout():
    from student_handout import memory_notes
    from render_handouts import explicit_markdown
    return explicit_markdown(memory_notes())


def memory_files():
    processes=[
        dict(PID=4,PPID=0,ImageFileName='System',CreateTime='2026-10-18T01:00:00Z',ExitTime=''),
        dict(PID=1800,PPID=700,ImageFileName='explorer.exe',CreateTime='2026-10-18T01:01:00Z',ExitTime=''),
        dict(PID=2460,PPID=1800,ImageFileName='notepad.exe',CreateTime='2026-10-18T01:05:00Z',ExitTime=''),
        dict(PID=3180,PPID=1800,ImageFileName='python.exe',CreateTime='2026-10-18T01:07:00Z',ExitTime=''),
    ]
    base='08_memory/';encoded=base64.b64encode(CASE_FLAGS['a'].encode()).decode()
    files={
        base+'case_a/pslist.csv':_csv(processes),
        base+'case_a/cmdline.csv':_csv([
            dict(PID=2460,Process='notepad.exe',Args=r'notepad.exe C:\Users\CTF\Desktop\memo.txt'),
            dict(PID=3180,Process='python.exe',Args=rf'python.exe C:\Users\CTF\Desktop\show_note.py --note {encoded}')]),
        base+'case_b/cmdline.csv':_csv([dict(PID=2460,Process='notepad.exe',Args=r'notepad.exe C:\Users\CTF\Desktop\memo.txt')]),
        base+'case_b/filescan.txt':b'TEACHING SUMMARY ONLY; virtual FILE_OBJECT address is explicitly specified.\nOffset Name\n0xffffa10200123070 \\Device\\HarddiskVolume2\\Users\\CTF\\Desktop\\memo.txt\n',
        base+'case_b/handles.csv':_csv([dict(PID=2460,Process='notepad.exe',Type='File',VirtualObject='0xffffa10200123070',Name=r'\Device\HarddiskVolume2\Users\CTF\Desktop\memo.txt')]),
        base+'case_b/exported_memo.txt':('Synthetic cached-file export for discussion only.\n'+CASE_FLAGS['b']+'\n').encode(),
        base+'case_c/pslist.csv':_csv([processes[2]]),
        base+'case_c/cmdline.csv':_csv([dict(PID=2460,Process='notepad.exe',Args='notepad.exe')]),
        base+'search_excerpt.py':SEARCH_SCRIPT.encode(),
        base+'Volatility3_内存镜像分析_命令与题解.md':memory_handout().encode(),
    }
    rng=random.Random(20261019)
    prefix=bytes(rng.randrange(0,32) for _ in range(256))
    files[base+'case_c/process_2460_excerpt.bin']=prefix+('Unsaved note: '+CASE_FLAGS['c']+'\0').encode('utf-16le')+bytes(256)
    files[base+'PROVENANCE.json']=json.dumps({
        'kind':'synthetic output-reading cases; not a RAM image',
        'target':'Windows; Volatility 3 workflow',
        'cases':{'a':{'pid':3180,'object':'startup arguments'},
                 'b':{'pid':2460,'file':'memo.txt','address':'0xffffa10200123070','address_type':'virtual FILE_OBJECT'},
                 'c':{'pid':2460,'encoding':'UTF-16LE','excerpt_only':True}}
    },ensure_ascii=False,indent=2).encode()
    files[base+'README.md']='''# Volatility 3 内存专题 · 教学例题

本目录是三个合成输出读题例题，不含真实 RAM。CSV 是教学摘要，文本和二进制是模拟导出片段。
不要改后缀当成内存镜像，也不能用这些片段代替实际内存解析。

A：从列表找到 PID 3180，再读启动参数，识别编码后还原 flag。
B：关联 PID 2460、memo.txt、虚拟文件对象与模拟导出结果，说明导出步骤。
C：选择记事本进程映射页路线，用 ASCII / UTF-16LE 检索模拟片段。

课件同时给出取得真实镜像后应运行的 Volatility 3 命令；实际读取例题的命令与题解见同目录手册。
从练习材料根目录执行：python ./08_memory/search_excerpt.py ./08_memory/case_c/process_2460_excerpt.bin
该脚本只使用 Python 3 标准库，不解析 RAM、不推断 PID。
'''.encode()
    return files
