# Volatility 3 内存镜像分析 · 学员讲义

按命令框标签选择 Windows PowerShell 或 Kali Bash，不能混用变量与路径语法。Windows 先从工具包启动课堂终端，默认目录为 labs；Kali 先准备 Python 3 环境并进入资料包的 labs。示例输出只供阅读。

## 16 / 内存分析：宿主系统与镜像系统不是一回事

Volatility 3 读取内存镜像，从其中恢复系统、进程、参数、文件缓存和映射页等对象。你可以在 Windows 或 Kali 上运行它；插件名 windows.info 中的 windows 指被分析的 Windows 镜像，不是要求你的分析电脑也必须是 Windows。

| 分析电脑 | 运行入口 | 被分析对象 |
|---|---|---|
| Windows PowerShell | python $v3 | 一份 Windows 内存镜像 |
| Kali Bash | 虚拟环境中的 vol | 同一份 Windows 内存镜像 |

本包的 08_memory 是合成输出读题材料：CSV 是教学摘要，文本和二进制是模拟导出片段。它们可以用来练习阅读、关联和编码检索，不能改后缀当成 RAM 交给 Volatility。

后面带“真实 RAM”标识的命令，只有取得真正的镜像后才执行。镜像还可能需要匹配符号以及 .vmss/.vmsn 等配套信息。先建立可解释的解析条件，再看进程或文件结果。

## 17 / Vol3 环境与变量：两条系统路线

Windows：打开配套课堂终端后，$v3 已指向包内 Vol3 入口。先看帮助，不需要真实镜像：

**运行环境：Windows · PowerShell｜从 labs 运行；先完成对应系统的环境准备**

~~~powershell
python $v3 -h
python $v3 windows.dumpfiles -h
python $v3 windows.memmap -h
~~~

Kali：在前面的 Python 3 环境基础上建立独立虚拟环境，固定使用本课版本。--system-site-packages 允许读取已经由 apt 安装的 Python 库：

**运行环境：Kali Linux · Bash｜环境准备 · 选择自己的目录**

~~~bash setup
python3 -m venv --system-site-packages "$HOME/ctf-forensics/.venv"
source "$HOME/ctf-forensics/.venv/bin/activate"
python3 -m pip install "volatility3==2.28.2"
command -v vol
vol -h
vol windows.dumpfiles -h
vol windows.memmap -h
~~~

新开 Kali 终端后，重新执行 source 那一行再使用 vol。没有激活虚拟环境时，系统中同名命令可能来自不同安装。2.28.2 是 Volatility 3 的框架版本号；本课主线使用 Vol3，另附 Volatility 2.6 独立版用于旧镜像兼容分析。

例如 cmdscan / consoles 报 NotImplementedError 且提示系统版本不支持时，先区分插件结构不兼容与系统 / 符号未解析。保留诊断，再用 Vol2 imageinfo 提取候选、kdbgscan / pslist 验证 profile，随后运行 cmdscan / consoles。不能只从 6.1 7601 推断 x86 或 x64。完整 Windows、CMD、Kali 命令和 Challenge.raw 的实测节选见“Volatility2_兼容分析指南.html”，index.html 中可直接打开。

取得真实镜像后，在 labs 放好工作副本。将示例 memory.raw 改成实际路径，再设置输入和输出目录：

**运行环境：Windows · PowerShell｜从 labs 运行 · 需要另备真实 RAM**

~~~powershell ram
$img = '.\memory.raw'
Get-FileHash -LiteralPath $img -Algorithm SHA256
New-Item -ItemType Directory -Force -Path .\out\files,.\out\proc | Out-Null
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行 · 需要另备真实 RAM**

~~~bash ram
img='./memory.raw'
sha256sum "$img"
mkdir -p out/files out/proc
~~~

全局 -f 指定镜像，-o 指定导出目录，它们放在插件名前；--pid、--dump、--filter 等插件选项放在插件名后。下面的 PID 2460/3180 和地址是示例，换镜像后重新从实际结果取得。

## 18 / Vol3 第一步：确认系统和解析条件

**运行环境：Windows · PowerShell｜从 labs 运行 · 需要另备真实 RAM**

~~~powershell ram
python $v3 -f $img windows.info
python $v3 -f $img windows.info | Out-File -Encoding utf8 .\out\info.txt
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行 · 需要另备真实 RAM**

~~~bash ram
vol -f "$img" windows.info
vol -f "$img" windows.info > out/info.txt
~~~

你要看的是系统/架构、内核层与符号是否能建立、输出是否符合采集来源。Unsatisfied requirement 表示解析条件尚未满足，不能把后续插件失败解释为“没有进程”或“没有文件”。

离线解析需要适用符号。独立 Windows 符号 ZIP 只是一个集合，不保证覆盖每个系统构建；镜像的 PDB 标识必须匹配。先对实际练习镜像运行 info，确认后再进入下一步。

## 19 / Vol3 第二步：先盘点进程，再挑目标

**运行环境：Windows · PowerShell｜从 labs 运行 · 需要另备真实 RAM**

~~~powershell ram
python $v3 -f $img windows.pslist
python $v3 -f $img windows.pstree
python $v3 -f $img windows.psscan
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行 · 需要另备真实 RAM**

~~~bash ram
vol -f "$img" windows.pslist
vol -f "$img" windows.pstree
vol -f "$img" windows.psscan
~~~

| 插件 | 从输出看什么 | 怎样决定下一步 |
|---|---|---|
| pslist | PID、PPID、名称、创建/退出时间 | 建立活动进程视图，选择与题意相关的 PID |
| pstree | 父子进程关系 | 结合时间和参数理解上下文 |
| psscan | 扫描得到的进程对象 | 有退出进程线索或列表矛盾时补充检查 |

psscan 的额外命中可能只是已退出残留，不能单独证明“隐藏进程”。进程名也不自动说明用途或恶意性，必须结合参数、父进程、时间与文件线索判断。

## 20 / Vol3 第三步：参数、命令历史与控制台

**运行环境：Windows · PowerShell｜从 labs 运行 · 需要另备真实 RAM**

~~~powershell ram
python $v3 -f $img windows.cmdline --pid 2460
python $v3 -f $img windows.cmdline --pid 3180
python $v3 -f $img windows.cmdscan
python $v3 -f $img windows.consoles
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行 · 需要另备真实 RAM**

~~~bash ram
vol -f "$img" windows.cmdline --pid 2460
vol -f "$img" windows.cmdline --pid 3180
vol -f "$img" windows.cmdscan
vol -f "$img" windows.consoles
~~~

cmdline 是进程启动参数；cmdscan/consoles 尝试恢复控制台历史或上下文，两者不能互相代替。现代终端、系统版本和页面保存情况会影响结果。

有文档路径就继续找文件对象，有编码参数就保留原值后解码。不要直接执行镜像参数中出现的脚本；你分析的是证据，不需要重现进程的行为。

## 21 / Vol3 第四步 A：打开过的文件与缓存

先把文件名与进程、句柄对应：

**运行环境：Windows · PowerShell｜从 labs 运行 · 需要另备真实 RAM**

~~~powershell ram
python $v3 -f $img windows.cmdline --pid 2460
python $v3 -f $img windows.handles --pid 2460
python $v3 -f $img windows.filescan | Out-File -Encoding utf8 .\out\filescan.txt
Select-String -Path .\out\filescan.txt -Pattern 'memo[.]txt'
python $v3 -f $img -o .\out\files windows.dumpfiles --pid 2460 --filter 'memo[.]txt$' --ignore-case
Get-ChildItem -LiteralPath .\out\files
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行 · 需要另备真实 RAM**

~~~bash ram
vol -f "$img" windows.cmdline --pid 2460
vol -f "$img" windows.handles --pid 2460
vol -f "$img" windows.filescan > out/filescan.txt
grep -n 'memo[.]txt' out/filescan.txt
vol -f "$img" -o out/files windows.dumpfiles --pid 2460 --filter 'memo[.]txt$' --ignore-case
ls -l out/files
~~~

handles 可能列出 File、Key、Mutant 等对象，先确认对象类型。filescan 给出候选文件对象，不证明对应文件全部内容仍驻留在内存；它的 Offset 也不是磁盘文件偏移。

按地址导出前，必须明确它是虚拟还是物理 FILE_OBJECT 地址。本例给出的是已确认的虚拟地址：

**运行环境：Windows · PowerShell｜从 labs 运行 · 需要另备真实 RAM**

~~~powershell ram
python $v3 -f $img -o .\out\files windows.dumpfiles --virtaddr 0xffffa10200123070
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行 · 需要另备真实 RAM**

~~~bash ram
vol -f "$img" -o out/files windows.dumpfiles --virtaddr 0xffffa10200123070
~~~

只有当实际证据明确给出物理 FILE_OBJECT 地址时才使用 --physaddr。filescan 的扫描层与目标系统和实现有关，不能仅凭列名叫 Offset 就决定地址类型，更不能把同一个数值换参数盲试后当作可靠结论。

导出的 .dat/.img/.vacb 等文件可能来自不同缓存来源。检查插件报告、非空大小、签名、内容与上下文；能导出不代表完整、最新或与磁盘原件完全一致。

## 22 / Vol3 第四步 B：没有保存的编辑器文字

如果题目指向记事本等进程，但没有对应已保存文件，可以考虑导出可读映射页：

**运行环境：Windows · PowerShell｜从 labs 运行 · 需要另备真实 RAM**

~~~powershell ram
python $v3 -f $img -o .\out\proc windows.memmap --pid 2460 --dump
Get-ChildItem -LiteralPath .\out\proc
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行 · 需要另备真实 RAM**

~~~bash ram
vol -f "$img" -o out/proc windows.memmap --pid 2460 --dump
ls -l out/proc
~~~

memmap --dump 面向可读进程映射段；pslist --dump 侧重可执行映像，不等于整个进程地址空间。寻找文档文字时，不应只导出 exe 后就断定文字不存在。

先看实际生成的文件名，再替换检索命令中的文件路径。下面假定导出文件名为 pid.2460.dmp：

**运行环境：Windows · PowerShell｜从 labs 运行 · 需要另备真实 RAM**

~~~powershell ram
finspect strings .\out\proc\pid.2460.dmp --encoding ascii
finspect strings .\out\proc\pid.2460.dmp --encoding utf16le
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行 · 需要另备真实 RAM**

~~~bash ram
strings -a -t x out/proc/pid.2460.dmp | grep 'flag{'
strings -a -e l -t x out/proc/pid.2460.dmp | grep 'flag{'
~~~

finspect 用于小型教学文件，会把输入读入内存；大型真实导出宜用适用的流式工具。其 UTF-16LE 模式针对由可打印 ASCII 字符组成的宽字符串，足以提取本课 flag，不是通用中文文本恢复器。

Windows 程序常把字符保存为 UTF-16LE。例如 f 可能表现为 66 00；连续 ASCII 搜索可能漏掉这种文字。检索为空也可能是缺页、被换出或内容被覆盖，不能只据空结果否定题意。

## 23 / Vol3 最后一步：验证来源与坐标系

命中 flag 后还要回答：来自哪个输入、哪个 PID/对象、哪条命令、哪次导出，字节偏移属于哪里。原镜像物理偏移、进程虚拟地址、导出文件偏移不可混用。

| 题目要找什么 | 先用什么 | 再做什么 |
|---|---|---|
| 系统与进程 | info → pslist → pstree | 必要时 psscan 交叉核对 |
| 启动时的脚本或参数 | cmdline --pid 实际 PID | 保留原值、识别编码 |
| 输入过的命令 | cmdscan / consoles | 核对支持范围与上下文 |
| 打开过的文件 | handles / filescan | dumpfiles、内容识别与完整性评估 |
| 编辑器中未保存的文字 | 确认 PID | memmap --dump、ASCII/UTF-16LE 检索 |

最小记录：镜像 SHA256、Vol3 版本、目标系统、PID、对象地址与地址类型、完整命令、导出文件与哈希、命中位置、转换步骤和结论。

### 社区插件：账号口令与加密卷线索

课程已安装 Vol3 pypykatz、Vol2 mimikatz 和两代 BitLocker 扩展，完整命令与支持范围见 [Volatility 社区插件使用指南](Volatility_社区插件使用指南.html)。mimikatz / pypykatz 解析支持的 LSASS 结构，hashdump 得到的 NTLM 则是摘要；两种结果不能混为“已经得到明文密码”。先核对系统、LSASS 进程与页面可读性，再选择对应版本插件。

Windows 使用课程终端的启动器，自动加载额外插件和隔离依赖：

**运行环境：Windows · PowerShell｜从 labs 运行 · 需要另备真实 RAM**

~~~powershell ram
vol3 -f $img vol_pypykatz.pypykatz
# 示例 profile 必须改成当前镜像已核对的值
vol2 -f $img --profile=Win7SP1x86 mimikatz
~~~

Kali 先按社区插件指南在当前 Python 3 环境安装 pypykatz；以下命令的工作目录仍为 labs：

**运行环境：Kali Linux · Bash｜从 labs 运行 · 需要另备真实 RAM**

~~~bash ram
vol -p ../tools/volatility3_extra -f "$img" vol_pypykatz.pypykatz
../tools/volatility2/linux/volatility_2.6_lin64_standalone \
  --plugins=../tools/volatility2/extra_plugins \
  -f "$img" --profile=Win7SP1x86 mimikatz
~~~

BitLocker 的 FVEK 候选必须关联同题加密卷并核对算法；它不是普通口令，也不能直接作为 VeraCrypt keyfile。插件能够加载、能够解析镜像和实际恢复到可验证内容是三个不同结论。



## 案例 13 · 内存读题 A：先看进程，再看启动参数

### 本题任务

读取 08_memory/case_a 的合成摘要，找出带编码参数的进程，给出 PID、参数来源与解码结果。此目录不是内存镜像。

### 解题思路：为什么从这里开始

题目问的是启动参数中的编码信息，所以先在进程清单里定位对象，再读取同一 PID 的 Args。python.exe 只是进程名，不能据此认定恶意；真正引导下一步的是 --note 后的可疑参数值。解码是读取数据，无需执行参数里的脚本。

### 每一步在验证什么

| 要回答的问题 | 选择这一步的理由 | 看到什么才继续 |
|---|---|---|
| 先建立进程视图：pslist 与父子关系 | 如果直接在所有文本中搜 flag，容易丢失信息属于哪个进程、由什么上下文启动。 | 本题 PID 3180 为 python.exe，父进程为 PID 1800 的 explorer.exe；保留这些背景再查参数。 |
| 按 PID 读取 cmdline | 同名进程可以同时存在，必须用当前样本的 PID 关联，不能按第几行或只按 python.exe 认定。 | cmdline.csv 的 PID 3180 对应 show_note.py --note，编码串来自 Args 中这个参数。 |
| 提取 --note 原值再做 Base64 验证 | 编码类型要由参数和内容判断；--note 是该脚本的参数，不能当成 PowerShell -EncodedCommand 套用 UTF-16LE 规则。 | 本题一次 Base64 解码得到可读 flag；原值、解码方法与进程关联都能复述。 |
| 换成真实 RAM 时先 info 再定向查询 | Vol3 需要先建立有效内核层和符号；进程列表及 pstree 决定实际 PID 与上下文，随后才是 cmdline --pid。 | 以真实输出确认对象后查询；CSV 是已提供的摘要，不能充当 Volatility 可解析的镜像。 |

### 如果没有得到预期结果

命令行为空不等于进程没启动过或从未带参数，相关页面可能缺失或已变化。只有怀疑遗漏、退出或隐藏对象时再用 psscan 补充；池扫描命中还需判断对象有效性。不要把启动参数当成用户在终端输入过的全部命令历史。

### 本题的材料读取命令

**运行环境：Windows · PowerShell｜从 labs 运行；先完成对应系统的环境准备**

~~~powershell
Import-Csv .\08_memory\case_a\pslist.csv | Format-Table
Import-Csv .\08_memory\case_a\cmdline.csv | Where-Object { $_.PID -eq '3180' } | Format-List *
finspect decode64 ZmxhZ3tyZWFkX3RoZV9jb21tYW5kX2xpbmV9
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行；先完成对应系统的环境准备**

~~~bash
cat ./08_memory/case_a/pslist.csv
grep -n '^3180,' ./08_memory/case_a/cmdline.csv
printf '%s' 'ZmxhZ3tyZWFkX3RoZV9jb21tYW5kX2xpbmV9' | base64 -d
printf '\n'
~~~

### 怎样判读

pslist.csv 有 PID=3180 的 python.exe，父进程 PID=1800 的 explorer.exe。cmdline.csv 对应行的 Args 显示 show_note.py 的 --note 参数，参数为 Base64。解码得到：

**运行环境：示例输出 / 数据 · 不执行｜用于比较与判读，无需输入终端**

~~~text
flag{read_the_command_line}
~~~

这里的证据是启动参数中携带的信息，不是证明 Python 进程一定恶意。进程名、父子关系、时间、参数应一起看。

### 换成真实 RAM 后的 Vol3 顺序

取得真正的 Windows 内存镜像后，再运行以下命令。$img 必须替换为实际镜像，不可指向本题 CSV：

**运行环境：Windows · PowerShell｜从 labs 运行 · 需要另备真实 RAM**

~~~powershell ram
$img = '.\memory.raw'
Get-FileHash -LiteralPath $img -Algorithm SHA256
python $v3 -f $img windows.info
python $v3 -f $img windows.pslist
python $v3 -f $img windows.pstree
python $v3 -f $img windows.cmdline --pid 3180
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行 · 需要另备真实 RAM**

~~~bash ram
img='./memory.raw'
sha256sum "$img"
vol -f "$img" windows.info
vol -f "$img" windows.pslist
vol -f "$img" windows.pstree
vol -f "$img" windows.cmdline --pid 3180
~~~

先确认 info 能建立内核层与匹配符号，再用 pslist 建立进程清单，用 pstree 看父子关系，最后定向查 cmdline。实际 PID 以新镜像输出为准。

若怀疑已经退出或不在活动链表中的进程，再补充 windows.psscan。psscan 的残留命中不等于进程仍在运行；cmdline 也不等于交互命令历史，二者应区分。

### 举一反三

若参数是 PowerShell 的 -EncodedCommand，应结合该参数约定检查编码；本题脚本的 --note 没有这种约定，不能套用相同规则。
## 案例 14 · 内存读题 B：从进程跟到文件对象

### 本题任务

读取 08_memory/case_b 的合成摘要，关联记事本进程、memo.txt、文件对象地址及模拟导出结果，并写出真实 RAM 下的导出命令。

### 解题思路：为什么从这里开始

题目给了文件路径，因此优先沿“哪个进程引用哪个文件对象”的路线找内容。cmdline 提供启动时的路径线索，handles 把当前进程连到 File 对象，filescan 再提供对象候选；最后导出的是可恢复的文件缓存。每一步解决的问题不同，路径、PID 与对象地址不能互相替代。

### 每一步在验证什么

| 要回答的问题 | 选择这一步的理由 | 看到什么才继续 |
|---|---|---|
| 从参数提出文件假设 | notepad.exe 的启动参数出现 memo.txt，说明这个路径值得追踪，但还不能证明缓存内容完整或等同于磁盘当前版本。 | 本题 PID 2460 的参数提到 C:\Users\CTF\Desktop\memo.txt。 |
| 查 handles，建立 PID → File 对象关系 | Type=File 的句柄比仅在全镜像搜到同名路径更能说明目标进程与对象的联系。 | 本题 VirtualObject 为 0xffffa10200123070，Name 以同一用户目录和 memo.txt 结尾。 |
| 对照 filescan 并确认地址类型 | 全局扫描可能有重名或残留对象；对象地址相同是 handles 与 filescan 的重要交叉依据。 | 本题两份摘要明确标为同一虚拟 FILE_OBJECT 地址，因此选择 --virtaddr。真实输出须另行确认扫描层和地址含义。 |
| 导出后检查文件，而不止看命令成功 | dumpfiles 读取可恢复缓存，可能产生多个数据来源的导出，部分页面缺失时也可能留下不完整文件。 | 先列出实际导出文件，再识别、读内容并记录来源；本题 exported_memo.txt 是预先给出的模拟导出，含完整 flag。 |

### 如果没有得到预期结果

句柄不存在时，文件可能已关闭，可补查 filescan，但进程归属的证据会变弱。本题没提供盘符与设备卷映射；C: 路径与 \Device\HarddiskVolume2 路径的相同后缀只能形成候选联系，不能单凭名称证明是同一卷。真实分析还应核对卷映射或文件标识。导出失败不能随意把虚拟地址换成 --physaddr，也不能宣称“文件不存在”。

### 本题的材料读取命令

**运行环境：Windows · PowerShell｜从 labs 运行；先完成对应系统的环境准备**

~~~powershell
Import-Csv .\08_memory\case_b\cmdline.csv | Format-List *
Import-Csv .\08_memory\case_b\handles.csv | Where-Object { $_.PID -eq '2460' -and $_.Type -eq 'File' } | Format-List *
Get-Content -LiteralPath .\08_memory\case_b\filescan.txt
Get-Content -LiteralPath .\08_memory\case_b\exported_memo.txt
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行；先完成对应系统的环境准备**

~~~bash
cat ./08_memory/case_b/cmdline.csv
grep -n '^2460,' ./08_memory/case_b/handles.csv
cat ./08_memory/case_b/filescan.txt
cat ./08_memory/case_b/exported_memo.txt
~~~

### 怎样判读

记事本 PID=2460，命令行提到 C:\Users\CTF\Desktop\memo.txt。handles 的 Type=File，Name 对应 memo.txt；VirtualObject 与 filescan 教学摘要中的地址相同：0xffffa10200123070。这个例题明确将地址定义为虚拟 FILE_OBJECT 地址。

模拟导出文件中的答案为：

**运行环境：示例输出 / 数据 · 不执行｜用于比较与判读，无需输入终端**

~~~text
flag{follow_the_file_object}
~~~

证据关系是“PID → 打开路径 → File 句柄/文件对象 → 缓存导出内容”。PID 不是对象地址，文件路径也不能直接代替地址参数。

### 换成真实 RAM 后的 Vol3 顺序

完成 windows.info、pslist、pstree 后：

**运行环境：Windows · PowerShell｜从 labs 运行 · 需要另备真实 RAM**

~~~powershell ram
python $v3 -f $img windows.cmdline --pid 2460
python $v3 -f $img windows.handles --pid 2460
python $v3 -f $img windows.filescan
New-Item -ItemType Directory -Force -Path .\out\files | Out-Null
python $v3 -f $img -o .\out\files windows.dumpfiles --virtaddr 0xffffa10200123070
Get-ChildItem -LiteralPath .\out\files
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行 · 需要另备真实 RAM**

~~~bash ram
vol -f "$img" windows.cmdline --pid 2460
vol -f "$img" windows.handles --pid 2460
vol -f "$img" windows.filescan
mkdir -p out/files
vol -f "$img" -o out/files windows.dumpfiles --virtaddr 0xffffa10200123070
ls -l out/files
~~~

dumpfiles 的 -o 是全局选项，放在插件名之前；--virtaddr 是插件选项，放在插件名之后。输出文件名以实际列表为准，不要假定固定为 memo.txt。

若实际使用的是明确的物理 FILE_OBJECT 地址，应改用 --physaddr。filescan 的 Offset 不能一律称为物理地址，具体扫描层随系统/实现而异；先判断输出地址语义。不能因一条命令失败就随意换地址类型并将结果当成可靠证据。

### 导出后的验证

先识别文件类型，分别检查 DataSectionObject/ImageSectionObject/SharedCacheMap 相关导出是否存在；能导出不代表完整或最新。若缓存页缺失、文件已关闭或有多个版本，需注明恢复范围，再与命令行、路径、时间交叉验证。

### 举一反三

真实 filescan 若明确给出物理 FILE_OBJECT 偏移，应使用相应物理地址参数。先说明地址来源和含义，再写导出命令。
## 案例 15 · 内存读题 C：映射页中的 UTF-16LE

### 本题任务

08_memory/case_c 中的记事本命令行没有文件路径，材料提供了模拟的进程映射页片段。定位文本及其在该片段中的字节偏移，说明真实 RAM 应走哪条路线。

### 解题思路：为什么从这里开始

题目提供了“编辑器文字与进程片段”的线索，目标是文字缓冲区，而不是 notepad.exe 的程序本体。命令行没有文档路径只是一条支持继续查看进程页的线索，单靠它不能证明文字一定未保存。选择了正确对象后，还要按存储编码检索。

### 每一步在验证什么

| 要回答的问题 | 选择这一步的理由 | 看到什么才继续 |
|---|---|---|
| 先确认 PID 与题目假设 | 进程名可能重复；命令行无路径也可能是启动后才打开文件，不能直接推出没有磁盘文件。 | 本题明确给出 PID 2460 的模拟映射页片段；其进程归属来自题目设定，不是靠片段里的文字反推。 |
| 真实 RAM 选择 memmap --dump | 要找编辑文字，应检查可读进程映射页；pslist --dump 导出的可执行映像主要用于程序本体分析，不能覆盖所有编辑缓冲区。 | 保留当前镜像的映射表与实际导出文件列表，再对导出结果检索。 |
| ASCII 与 UTF-16LE 分别检查 | 66 00 6c 00 61 00 67 00 这样的交替零字节会打断普通 ASCII 连续串；每两个字节组成一个小端编码单元。 | UTF-16LE 路线找到完整 flag，而 ASCII 无结果本身不能否定文本存在。 |
| 把字符串起点换算成 flag 起点并核对字节 | 整段宽字符串起点与其中子串起点不同，工具结果必须明确坐标系。 | 本题字符串从 0x100 开始，前缀 14 个字符占 28 字节，所以 flag 位于 0x11c；用 xxd 检查该处原字节。 |

### 如果没有得到预期结果

两种编码都无命中时，考虑检索词、输入范围、缺页、换出、覆盖或其他编码，并写明未能恢复，不等于从未输入。0x11c 只属于本题片段；映射回进程虚拟地址或原 RAM 偏移需实际映射关系，不能直接照抄这个数值。

### 本题可直接运行的命令

**运行环境：Windows · PowerShell｜从 labs 运行；先完成对应系统的环境准备**

~~~powershell
Import-Csv .\08_memory\case_c\pslist.csv | Format-Table
Import-Csv .\08_memory\case_c\cmdline.csv | Format-List *
finspect strings .\08_memory\case_c\process_2460_excerpt.bin --encoding ascii
finspect strings .\08_memory\case_c\process_2460_excerpt.bin --encoding utf16le
python .\08_memory\search_excerpt.py .\08_memory\case_c\process_2460_excerpt.bin
xxd -g 1 -s 0x11c -l 64 .\08_memory\case_c\process_2460_excerpt.bin
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行；先完成对应系统的环境准备**

~~~bash
cat ./08_memory/case_c/pslist.csv
cat ./08_memory/case_c/cmdline.csv
strings -a -t x ./08_memory/case_c/process_2460_excerpt.bin
strings -a -e l -t x ./08_memory/case_c/process_2460_excerpt.bin
python3 ./08_memory/search_excerpt.py ./08_memory/case_c/process_2460_excerpt.bin
xxd -g 1 -s 0x11c -l 64 ./08_memory/case_c/process_2460_excerpt.bin
~~~

### 怎样判读

PID=2460 的 notepad.exe 没有传入文档路径。模拟片段中，flag 文本按 UTF-16LE 存储，字节形如 66 00 6c 00 61 00 67 00。ASCII 连续字符串检索可能漏掉它；UTF-16LE 检索找到：

**运行环境：示例输出 / 数据 · 不执行｜用于比较与判读，无需输入终端**

~~~text
offset-in-input = 0x11c
flag{utf16_is_still_text}
~~~

0x11c 为十进制 284，含义仅是“该模拟输入文件中的字节偏移”，不是原始 RAM 物理偏移，也不是进程虚拟地址。
finspect 先打印整段可打印宽字符串的起点 0x100；其中前缀“Unsaved note: ”占 28 字节，所以 flag 从 0x11c 开始。search_excerpt.py 定向匹配 flag 并报告其准确起点。

### 换成真实 RAM 后的 Vol3 顺序

先完成 info、pslist、pstree、cmdline，确认目标 PID，再导出进程映射页：

**运行环境：Windows · PowerShell｜从 labs 运行 · 需要另备真实 RAM**

~~~powershell ram
New-Item -ItemType Directory -Force -Path .\out\proc | Out-Null
python $v3 -f $img -o .\out\proc windows.memmap --pid 2460 --dump
Get-ChildItem -LiteralPath .\out\proc
finspect strings .\out\proc\pid.2460.dmp --encoding ascii
finspect strings .\out\proc\pid.2460.dmp --encoding utf16le
~~~

**运行环境：Kali Linux · Bash｜从 labs 运行 · 需要另备真实 RAM**

~~~bash ram
mkdir -p out/proc
vol -f "$img" -o out/proc windows.memmap --pid 2460 --dump
ls -l out/proc
strings -a -t x out/proc/pid.2460.dmp | grep 'flag{'
strings -a -e l -t x out/proc/pid.2460.dmp | grep 'flag{'
~~~

导出文件名须先以实际列表为准。memmap --dump 导出可访问的进程映射页；pslist --dump 侧重进程可执行映像，不能把两者混用来证明记事本文档文字不存在。

### 自检与排错

先解释为什么 cmdline 无路径仍值得查看进程内存：文本可能尚未保存，也可能只存在于缓冲区。再说明为何检索无结果不等于未出现过：页可能缺失、被换出、编码不同或已经覆盖。

如需把导出偏移映射回虚拟地址，应保存 memmap 映射表，按实际导出段和地址对应关系换算；本例没有这份真实映射，不做推断。

### 举一反三

命中导出文件第 N 个字节时，先查导出映射再讨论虚拟地址；原镜像偏移、导出偏移与进程地址不是同一坐标。
