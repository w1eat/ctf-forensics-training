# Volatility 2：旧镜像兼容分析与排错

本课主流程使用 Volatility 3。遇到旧 Windows 镜像的控制台结构不受当前 Vol3 插件支持时，使用随包 Volatility 2.6 独立版交叉验证。两套工具并存；Vol2 的 profile、插件名和地址参数与 Vol3 不同。

## 01 / 先看错误发生在哪一步

~~~text
Progress: 100.00 PDB scanning finished
NotImplementedError: This version of Windows is not supported: 6.1 15.7601!
~~~

如果调用链位于 windows.cmdscan → windows.consoles → determine_conhost_version，表示插件找不到适用的控制台结构映射。PDB 扫描结束只说明那一步完成，不保证每个插件都支持目标系统。这里的 6.1 与 7601 不能单独确定系统是 x86 还是 x64；15 也不是“Windows 15”。

保留完整报错；先尝试同一镜像的 windows.info、pslist 和 cmdline，区分系统解析与单个插件支持的问题。Missing requirements、符号下载失败和页面缺失属于其他排查方向，不应全部归为这个兼容错误。无结果也不能直接解释成“从未执行命令”。

## 02 / 从 index.html 使用兼容工具

启动本地学习平台，在“可视化工具台”的左侧找到“Volatility 2 · 兼容分析”。除帮助、扩展与注册表外，基础操作包括：帮助与 profiles、识别 / 核对 profile、进程与参数、命令历史 / 控制台、文件扫描、文件缓存导出、进程内存导出。

先选择自己的真实内存镜像，运行“识别 / 核对 profile”的 imageinfo。取得候选后，填入候选名称运行 kdbgscan，再用 pslist 检查进程名、PID、时间和系统架构是否合理。确认后才能把同一 profile 填入其他 Vol2 操作。界面不会替所有镜像默认填写 Win7SP1x64。

Vol3 单项工具出现上面的特定错误时，结果区会保留原始诊断，并提供“用 Vol2 识别当前镜像 profile”的按钮，自动带入同一附件。切换工具不会自动执行，也不会把 Vol3 的 PID 或对象地址冒充 Vol2 的扫描结果。

## 03 / Windows：启动与检查

完整 Windows 包已含 tools/volatility2/windows 下的独立 EXE、原始许可与说明，不需要另装 Python 2。双击 01_启动课堂终端.cmd 后使用 vol2，工作目录为 labs。vol2 与 python $v3 是两个独立入口。

~~~powershell
vol2 --info
vol2 imageinfo -h
vol2 cmdscan -h
vol2 consoles -h
vol2 dumpfiles -h
~~~

从工具包根目录手动准备同一环境：

~~~powershell root
. .\env.ps1
vol2 --info
~~~

--info 列出已包含的 profiles 和插件；imageinfo 是分析镜像并给出候选。不要用 Python 3 执行 Vol2 的 vol.py，也不要用 Vol3 的 windows.cmdscan.CmdScan 当作 Vol2 插件名。

## 04 / 实例：Challenge.raw 的识别与历史恢复

本节针对 MemLabs Lab 0 — Never Too Late Mister 的 Challenge.raw；它是需自行准备的真实镜像，不在本包的合成 08_memory 材料中。已验证文件大小 1048510464 字节，SHA256 为 14036106a7588118da2cd896866b63336f81db5d98e414665a95959608a8f225。文件名相同不代表内容相同，先核对哈希。

### 解题思路：先验证解析条件，再恢复历史

题目现象是 Vol3 的控制台插件不支持当前结构，并非整份镜像无法分析。首先要回答“Vol2 用什么布局解释这些内存字节”，然后才能相信它恢复的历史。profile 相当于选择结构定义，选择错误可能产生空输出或看似合理的错误字段，因此不能从报错数字直接猜一个 x64 profile。

| 要回答的问题 | 选择这一步的理由 | 看到什么才继续 |
|---|---|---|
| 是否为同一份镜像 | 先核对大小与 SHA256，避免把同名文件的结果混在一起 | 指纹与本节所列值一致；其他附件重新识别 |
| 可能是什么系统布局 | imageinfo 提供候选 profile、内核地址空间和服务包线索 | IA32 指向 32 位；候选仍需交叉验证 |
| 候选是否解释得通 | kdbgscan 核对内核调试器结构，再用 pslist 检查进程清单 | 6.1.7601、32bit、SP1、有效 KDBG 与合理进程结果相互支持 |
| 输入过什么命令 | cmdscan 尝试恢复历史结构，解决的问题不同于 cmdline 的启动参数 | 对照所属控制台、CommandCount 和有效历史条目 |
| 屏幕还留下什么上下文 | consoles 补查控制台屏幕内容，可看到仅靠历史未必能回答的输出 | 输入、输出与其他证据对应后再解释 |

把工作副本放入 labs，再执行下面的 Windows PowerShell 命令：

~~~powershell ram
$img = '.\Challenge.raw'
Get-FileHash -LiteralPath $img -Algorithm SHA256
vol2 -f $img imageinfo
~~~

本镜像的实际输出节选：

~~~text
Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86
AS Layer1            : IA32PagedMemoryPae (Kernel AS)
Image Type (Service Pack) : 1
~~~

IA32 指 32 位系统，候选不是最终结论。以下 Win7SP1x86 是对这份镜像核对后可用的选择，换题时重新识别，不照抄。

~~~powershell ram
$profile = 'Win7SP1x86'
vol2 -f $img --profile=$profile kdbgscan
vol2 -f $img --profile=$profile pslist
vol2 -f $img --profile=$profile cmdscan
vol2 -f $img --profile=$profile consoles
~~~

本次 kdbgscan 显示 6.1.7601 32bit、Service Pack 1、有效 KDBG owner tag 和 34 个进程。cmdscan 在 conhost.exe 的 PID 2104 下恢复到一条有效历史命令；consoles 还恢复了控制台屏幕内容：

~~~text
CommandProcess: conhost.exe Pid: 2104
CommandCount: 1
Cmd #0: C:\Python27\python.exe C:\Users\hello\Desktop\demon.py.txt
~~~

### 怎样从这段输出决定下一步

这是输出节选，省略了对象地址。历史显示在 conhost.exe PID 2104 下，是因为控制台宿主保存相关历史或屏幕结构；不要因没有显示在名为 cmd.exe 的进程下面就否定它。Cmd #0 提供了 Python 解释器和 demon.py.txt 的完整路径，所以接下来查文件对象与缓存，目标是读取脚本如何处理数据，无需执行脚本。扩展名 .txt 也不能单独决定它是否含 Python 源码。

cmdscan 说明恢复到了历史线索，consoles 的可恢复屏幕内容则能提供输入输出上下文。如果看到一串十六进制字符，应先保留原值，再结合恢复脚本的算法和编码约定判断如何还原，不能只凭外观猜异或密钥或反复解码。

扫描还可能打印其他槽位中的乱码或残留；本节 CommandCount: 1 是判断有效历史范围的线索之一，不能把所有 Cmd # 行都算作有效历史，更不能据此断言均已执行。要对照所属进程、结构有效性、consoles 与其他证据。

### 如果没有得到预期结果

profile 的结构检查和进程结果互相矛盾时，回到候选核对；进程正常而 cmdscan/consoles 为空时，考虑控制台页面缺失、覆盖或终端实现差异，并改查 cmdline、关联文件或进程内存。空输出不代表没有使用过终端。不同镜像的 PID、文件对象地址和 profile 都必须重新取得。

在已经把 bin 加入 PATH 的 Windows CMD 中，同一已验证镜像可这样运行。此处是 CMD，不使用 PowerShell 的 $img 变量：

~~~cmd ram
vol2 -f Challenge.raw imageinfo
vol2 -f Challenge.raw --profile=Win7SP1x86 pslist
vol2 -f Challenge.raw --profile=Win7SP1x86 cmdscan
vol2 -f Challenge.raw --profile=Win7SP1x86 consoles
~~~

## 05 / 常见后续：进程、文件对象与导出

先从当前镜像取得 PID 和 Offset(P)，再输入导出命令。以下 PowerShell 命令沿用上一步的 $img 与已验证 $profile：

~~~powershell ram
vol2 -f $img --profile=$profile pstree
vol2 -f $img --profile=$profile psscan
vol2 -f $img --profile=$profile cmdline
vol2 -f $img --profile=$profile filescan
New-Item -ItemType Directory -Force -Path .\out\vol2_files,.\out\vol2_proc | Out-Null
$physicalOffset = Read-Host '输入当前 Vol2 filescan 的物理 Offset(P)'
vol2 -f $img --profile=$profile dumpfiles -Q $physicalOffset -D .\out\vol2_files
$processId = [int](Read-Host '输入当前进程列表中已确认的 PID')
vol2 -f $img --profile=$profile memdump -p $processId -D .\out\vol2_proc
~~~

Vol2 dumpfiles 的 -Q 是物理 FILE_OBJECT 偏移，-D 是导出目录；不要把 Vol3 windows.dumpfiles 的 --virtaddr、--physaddr 或全局 -o 原样挪过来。memdump 的 -p 是进程 PID；它导出进程内存，不保证还原磁盘上的完整原文件。保留原输出、导出文件哈希与对象来源，继续检查 ASCII / UTF-16LE 文字、文件头和内容完整性。

## 06 / Kali：随包 Linux 独立版

学习资料包额外带有官方 Linux x64 独立程序。先在解压后的资料包根目录执行 chmod；同一权限也供 HTML 工具台调用。下列函数只作用于当前 Bash 会话。Linux 旧版独立程序的宿主库兼容性需课前检查，本次未在 Kali 实机运行。

~~~bash root
vol2_entry="$PWD/tools/volatility2/linux/volatility_2.6_lin64_standalone"
chmod +x "$vol2_entry"
vol2() { "$vol2_entry" "$@"; }
vol2 --info
cd labs
vol2 -f ./Challenge.raw imageinfo
~~~

仅对本节已核对的 Challenge.raw 示例，使用：

~~~bash ram
img='./Challenge.raw'
profile='Win7SP1x86'
sha256sum "$img"
vol2 -f "$img" --profile="$profile" kdbgscan
vol2 -f "$img" --profile="$profile" pslist
vol2 -f "$img" --profile="$profile" cmdscan
vol2 -f "$img" --profile="$profile" consoles
~~~

遇到 Linux 加载器或共享库报错，先核对 Linux x64 宿主与隔离环境；不能用 pip install volatility3 替换这个程序，也不能将 Windows EXE 当成 Kali 原生程序运行。现代 Windows 镜像仍先用 Vol3，Vol2 也有自己的支持范围。

## 07 / 来源、许可与验证范围

Windows / Linux 独立版和对应源码均来自 Volatility Foundation 的 2.6 发布目录，下载 SHA256 与官方 hashes.txt 对照。原始 GPL-2.0-or-later 许可与作者说明保留在各平台工具目录；源码在 licenses/source/volatility-2.6-source.zip，来源与哈希另见 tools/volatility2/SOURCES.json。

Windows 上已实跑 imageinfo、kdbgscan、pslist、cmdscan、consoles，运行前后输入 SHA256 一致。该结果只对应上文指纹的镜像。Kali 的命令提供为独立平台路线，未宣称已实机验证。

- 官方命令与参数：https://github.com/volatilityfoundation/volatility/wiki/Command-Reference
- 官方下载与校验表：https://downloads.volatilityfoundation.org/releases/2.6/hashes.txt
- Vol3 控制台结构选择的实现：https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/consoles.py
- MemLabs Lab 0 来源：https://github.com/stuxnet999/MemLabs/tree/master/Lab%200

社区扩展已安装：Vol2 mimikatz / BitLocker，Vol3 pypykatz / BitLocker；Editbox 使用 Vol2 内置实现。启动器自动加载对应插件与依赖，命令和排错见“Volatility_社区插件使用指南.html”。
