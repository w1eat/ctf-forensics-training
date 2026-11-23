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

~~~powershell
python $v3 -h
python $v3 windows.dumpfiles -h
python $v3 windows.memmap -h
~~~

Kali：在前面的 Python 3 环境基础上建立独立虚拟环境，固定使用本课版本。--system-site-packages 允许读取已经由 apt 安装的 Python 库：

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

~~~powershell ram
$img = '.\memory.raw'
Get-FileHash -LiteralPath $img -Algorithm SHA256
New-Item -ItemType Directory -Force -Path .\out\files,.\out\proc | Out-Null
~~~

~~~bash ram
img='./memory.raw'
sha256sum "$img"
mkdir -p out/files out/proc
~~~

全局 -f 指定镜像，-o 指定导出目录，它们放在插件名前；--pid、--dump、--filter 等插件选项放在插件名后。下面的 PID 2460/3180 和地址是示例，换镜像后重新从实际结果取得。

## 18 / Vol3 第一步：确认系统和解析条件

~~~powershell ram
python $v3 -f $img windows.info
python $v3 -f $img windows.info | Out-File -Encoding utf8 .\out\info.txt
~~~

~~~bash ram
vol -f "$img" windows.info
vol -f "$img" windows.info > out/info.txt
~~~

你要看的是系统/架构、内核层与符号是否能建立、输出是否符合采集来源。Unsatisfied requirement 表示解析条件尚未满足，不能把后续插件失败解释为“没有进程”或“没有文件”。

离线解析需要适用符号。独立 Windows 符号 ZIP 只是一个集合，不保证覆盖每个系统构建；镜像的 PDB 标识必须匹配。先对实际练习镜像运行 info，确认后再进入下一步。

## 19 / Vol3 第二步：先盘点进程，再挑目标

~~~powershell ram
python $v3 -f $img windows.pslist
python $v3 -f $img windows.pstree
python $v3 -f $img windows.psscan
~~~

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

~~~powershell ram
python $v3 -f $img windows.cmdline --pid 2460
python $v3 -f $img windows.cmdline --pid 3180
python $v3 -f $img windows.cmdscan
python $v3 -f $img windows.consoles
~~~

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

~~~powershell ram
python $v3 -f $img windows.cmdline --pid 2460
python $v3 -f $img windows.handles --pid 2460
python $v3 -f $img windows.filescan | Out-File -Encoding utf8 .\out\filescan.txt
Select-String -Path .\out\filescan.txt -Pattern 'memo[.]txt'
python $v3 -f $img -o .\out\files windows.dumpfiles --pid 2460 --filter 'memo[.]txt$' --ignore-case
Get-ChildItem -LiteralPath .\out\files
~~~

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

~~~powershell ram
python $v3 -f $img -o .\out\files windows.dumpfiles --virtaddr 0xffffa10200123070
~~~

~~~bash ram
vol -f "$img" -o out/files windows.dumpfiles --virtaddr 0xffffa10200123070
~~~

只有当实际证据明确给出物理 FILE_OBJECT 地址时才使用 --physaddr。filescan 的扫描层与目标系统和实现有关，不能仅凭列名叫 Offset 就决定地址类型，更不能把同一个数值换参数盲试后当作可靠结论。

导出的 .dat/.img/.vacb 等文件可能来自不同缓存来源。检查插件报告、非空大小、签名、内容与上下文；能导出不代表完整、最新或与磁盘原件完全一致。

## 22 / Vol3 第四步 B：没有保存的编辑器文字

如果题目指向记事本等进程，但没有对应已保存文件，可以考虑导出可读映射页：

~~~powershell ram
python $v3 -f $img -o .\out\proc windows.memmap --pid 2460 --dump
Get-ChildItem -LiteralPath .\out\proc
~~~

~~~bash ram
vol -f "$img" -o out/proc windows.memmap --pid 2460 --dump
ls -l out/proc
~~~

memmap --dump 面向可读进程映射段；pslist --dump 侧重可执行映像，不等于整个进程地址空间。寻找文档文字时，不应只导出 exe 后就断定文字不存在。

先看实际生成的文件名，再替换检索命令中的文件路径。下面假定导出文件名为 pid.2460.dmp：

~~~powershell ram
finspect strings .\out\proc\pid.2460.dmp --encoding ascii
finspect strings .\out\proc\pid.2460.dmp --encoding utf16le
~~~

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

~~~powershell ram
vol3 -f $img vol_pypykatz.pypykatz
# 示例 profile 必须改成当前镜像已核对的值
vol2 -f $img --profile=Win7SP1x86 mimikatz
~~~

Kali 先按社区插件指南在当前 Python 3 环境安装 pypykatz；以下命令的工作目录仍为 labs：

~~~bash ram
vol -p ../tools/volatility3_extra -f "$img" vol_pypykatz.pypykatz
../tools/volatility2/linux/volatility_2.6_lin64_standalone \
  --plugins=../tools/volatility2/extra_plugins \
  -f "$img" --profile=Win7SP1x86 mimikatz
~~~

BitLocker 的 FVEK 候选必须关联同题加密卷并核对算法；它不是普通口令，也不能直接作为 VeraCrypt keyfile。插件能够加载、能够解析镜像和实际恢复到可验证内容是三个不同结论。

