# CTF 取证基础 · Windows 工具包使用指南

本包可分析自己的附件，也覆盖本课基础练习和内存输出读题。目标环境为 Windows 10/11 x64；核心命令免安装，Python、Ruby 与依赖已一并提供，无需学员逐项执行 pip 或 gem 安装。

从 index.html 进入全部讲义、题目、题解、工具与下载。双击“00_一键配置并启动.cmd”后，可拖入或多选自己的文件，自动识别类型并排队分析，也可选择 77 项单独操作，并可按 21 条题意路线逐步运行。结果包括表格、原始输出、HTML / JSON 分析报告和后续建议；历史记录可重新打开。详细步骤见“学习平台使用指南”和“PPT 解题思路与工作台指南”。本指南的命令均为 Windows PowerShell；Kali 学员使用学习资料包并按讲义准备原生工具。

## 第一次使用

1. 将“学员工具与练习_Windows64.zip”完整解压到可写目录，例如 D:\CTFClass。不要直接在压缩包预览窗口运行。
2. 双击 00_启动学习平台.cmd，浏览器自动打开 index.html；保留启动窗口。
3. 从首页阅读讲义、做题或运行工具。网页结果保存在 labs/out/platform_runs，每次任务使用新目录。
4. 要手工执行讲义命令，可先双击 03_环境自检.cmd，再双击 01_启动课堂终端.cmd，PowerShell 自动进入 labs。
5. 课堂课件.html 是原来的 81 页主课件；内存专题为 18 页。所有页面都由 index.html 索引。

启动脚本只为当前终端设置 PATH 等变量，不改系统环境变量，不需要管理员权限。关闭终端即可结束该课堂环境。

如果已有 PowerShell，可从包根目录执行：

~~~powershell root
. .\env.ps1
python --version
python $v3 -h
~~~

$v3 由环境脚本设置为包内 vol.py 的完整路径。不要复制讲师电脑上的 E:\CTF 路径。真实内存操作前另设置 $img 为实际镜像文件。

## 工具与入口

| 工具 | 包内位置 | 课堂命令 / 用途 |
|---|---|---|
| Python 3.13.16 x64 | runtime/python | python；运行所有配套脚本 |
| Pillow 11.3.0 | Python 的 Lib/site-packages | 图片像素与 LSB；已配置 |
| pypdf 6.21.1 | Python 的 Lib/site-packages/pypdf | PDF 页数、元数据、附件名称与文字提取 |
| pefile 2024.8.26 | Python 的 Lib/site-packages/pefile.py | PE 节、导入、入口与 overlay 静态解析 |
| yara-python 4.5.4 | Python 的 Lib/site-packages | 内置 / 自定义 YARA 规则与匹配偏移 |
| Volatility 3 2.28.2 | tools/volatility3/vol.py；源码在 Python site-packages/volatility3 | python $v3；内存镜像分析 |
| Volatility 2.6 独立版 | tools/volatility2/windows；bin/vol2.cmd | vol2；旧镜像 profile、命令历史、文件与进程导出；不另装 Python 2 |
| 7-Zip 26.04 x64 | tools/7zip | 7z；列目录、测试、解压；7zFM.exe 为图形界面 |
| ExifTool 13.59 x64 | tools/exiftool | exiftool；字段与元数据 |
| SQLite 3.54.1 x64 | tools/sqlite | sqlite3；只读 SQL 和点命令 |
| The Sleuth Kit 4.14.0 | tools/sleuthkit/bin | mmls、fsstat、fls、istat、icat；分区与文件恢复 |
| pngcheck 4.0.1 | tools/pngcheck | pngcheck；PNG 块与 CRC 检查 |
| Ruby 3.3.12 与 zsteg 0.2.14 | runtime/ruby | zsteg；PNG/BMP LSB 分析 |
| BusyBox for Windows 1.38.0-FRP-6075 | tools/busybox | strings、xxd、grep、dd、base64、sha256sum |
| CyberChef 9.28.0 离线版 | tools/CyberChef | 双击 04_启动离线CyberChef.cmd |
| 文件观察实验台 | 文件观察实验台.html | 浏览器选文件，十六进制与图片位平面 |
| finspect 教学助手 | tools/finspect.py | 常见签名、PNG CRC、编码、字节保存、小字典 |
| 通用分析引擎 | tools/analysis_engine.py；bin/analyze.cmd | analyze；自动分流、流式字符串、任意 SQLite 查询、可调 LSB、报告 |

Vol3 同时配好 pefile、yara-python、capstone、pycryptodome。通用 SQL 界面使用 Python sqlite3 3.50.4 的只读连接，独立 SQLite CLI 为 3.54.1；两种入口版本分别标明。原始 Python wheel、zsteg gem、许可与所需源码均保留。完整文件哈希见 SHA256SUMS.txt，版本与来源见 TOOL_MANIFEST.json。

Vol2 是兼容工具，与 Vol3 共存。官方 Windows / Linux 独立程序、原始许可、官方校验表与对应源码已随包保留；Kali 学习资料也带 Linux 独立程序，需要按指南设置执行权限。Vol3 的 cmdscan / consoles 报“系统版本不支持”时，先用 Vol2 imageinfo 和 kdbgscan / pslist 验证 profile，再继续历史恢复；不要固定套用 Win7SP1x64。Windows 的 Challenge.raw 识别、进程和控制台恢复已经实跑，Kali 未实机验证。详见 index.html 中的“Vol2 兼容分析与排错”。

pngcheck 由上游 4.0.1 原始源码与 zlib 1.3.1 静态编译，构建说明和源码随包提供。不是本机旧版 2.x 的复制件。
Windows 的 zsteg 启动器默认加 --no-file，启用其内置文本/LSB 检查与定向提取，关闭对外部 Unix file 程序的调用。该参数属于上游原生选项，未修改 gem 源码；如需文件魔数识别，应在已配好 file 的环境使用完整分析。

## 新增恢复、解密与挂载工具

| 工具 | 包内位置 | 用法 |
|---|---|---|
| PhotoRec / TestDisk 7.2 | tools/testdisk；bin/photorec.cmd | 镜像签名恢复，保留完整依赖、许可与源码 |
| ImDisk 2.1.2 | tools/imdisk | RAW 分区只读挂载；按需安装驱动，支持卸载 |
| VeraCrypt 1.26.29 / 旧格式兼容 1.25.9 | tools/veracrypt | 已知口令、PIM / keyfile 容器只读挂载，附官方便携包 |
| PyCryptodome 4.1.0 | Python Lib/site-packages/Crypto | AES、DES、3DES、RC4、MD4 / NTLM 等运算 |
| 按题意工作流 | index.html → 可视化工具台 → 解题流程 | 21 条路线覆盖 PPT 中的常见判断与后续步骤 |

顶部选择当前附件。左侧“解题流程”解释每一步的理由，“全部工具”可自由搜索 77 项操作。右侧使用“结构与结果 / 导出文件 / 原始输出 / 运行命令”切换视图；选择真实导出文件作为下一步输入。内存路线可以切换 Vol3 / Vol2，profile 与地址随当前镜像分别记录。

普通分析和镜像恢复免管理员；系统只读挂载与首次驱动安装可能需要 UAC。工具台先显示准备信息，只处理本工作区创建的挂载记录；Windows 不原生识别 Ext4，使用 TSK 或 Kali。恢复出的未知脚本不会被自动执行。

## 课件命令与 Windows 对照

| 课件中的工具/操作 | 本包可直接使用的入口 |
|---|---|
| GNU file | finspect type 文件；只识别常见课堂格式，也可 exiftool -FileType 文件 |
| xxd -g 1 -l 64 文件 | 同名 BusyBox 命令可用 |
| GNU strings -a 文件 | strings -n 4 文件 |
| GNU strings -a -e l 文件 | finspect strings 文件 --encoding utf16le |
| grep -n / grep -E | BusyBox grep，或 PowerShell Select-String |
| binwalk 类分离 | 工具台“自动分离嵌入文件”：结构定界、导出与来源清单；复杂格式可用 PhotoRec / 7-Zip 补充 |
| dd 按字节分离 | 包内 dd，或 python tools/carve.py 输入 输出 --offset 0x200 |
| 010 Editor / WinHex 类查看 | 工具台“交互式十六进制查看”，支持分页、搜索、单字节选择与副本补丁；也可用浏览器实验台 |
| StegSolve 通道/位平面 | 文件观察实验台，选择 R/G/B/A 与位 0～7 |
| Autopsy 磁盘题 | 包内 TSK 的 mmls → fls → icat 路线；Autopsy GUI 可另行选装 |
| John Jumbo 小字典恢复 | 本课使用 finspect tryzip 和 7z 验证；John 命令保留作扩展讲解 |
| steghide | 本课不设依赖 steghide 的实操题；课件中的命令供已安装的环境拓展 |

这里明确标注了替代工具的范围。finspect 的签名扫描不具备 binwalk 的完整识别与递归提取能力，文件观察实验台也不是通用可写十六进制编辑器。本包包含的工具足以完成任务单中 15 个案例的本地操作。

## 常用命令

~~~powershell
finspect type .\01_file\unknown.dat
xxd -g 1 -l 64 .\01_file\unknown.dat
exiftool -a -u -G1 .\01_file\unknown.dat
pngcheck -v .\02_png\broken_width.png
zsteg .\03_lsb\quiet.png
7z l .\04_archive\locked.zip
mmls .\05_disk\tiny_fat16.dd
fls -r -d -o 2048 .\05_disk\tiny_fat16.dd
sqlite3 -readonly .\06_sqlite\case.db ".tables"
python $v3 windows.dumpfiles -h
~~~

损坏 PNG 的检查命令报 CRC 错误是预期现象，应在工作副本上修复后重新检查。

UTF-16LE 与编码：

~~~powershell
finspect strings .\08_memory\case_c\process_2460_excerpt.bin --encoding utf16le
finspect decode64 ZmxhZ3ttZXRhZGF0YV90aGVuX2Jhc2U2NH0=
~~~

finspect strings 针对小型教学附件，会把输入读入内存；UTF-16LE 模式提取由可打印 ASCII 字符组成的宽字符串，足以读本课 flag，不是完整中文 Unicode 文本恢复器。很大的真实内存导出可使用已安装的 GNU strings -e l 等流式工具。

## 保存结果与保留证据

普通文本报告：

~~~powershell
python $v3 -f $img windows.pslist | Out-File -Encoding utf8 .\out\pslist.txt
~~~

二进制导出不可依赖 PowerShell 5.1 的“>”。本包提供直接保存 stdout 字节的助手：

~~~powershell
finspect savebin .\out\recovered.txt -- icat.exe -r -o 2048 .\05_disk\tiny_fat16.dd 4
~~~

可复现的分离使用 carve.py 或 dd，先验证偏移与长度，输出到新文件。练习输入哈希见 labs/SHA256SUMS.txt。

## 图形观察与 CyberChef

双击“文件观察实验台.html”，选一个附件。十六进制偏移支持十进制及 0x；搜索可选择 UTF-8、UTF-16LE 或十六进制字节。图片选择 R/G/B/A 后，可把模式切换到“单个位平面”。该页面不上传文件。

CyberChef 使用 Worker，部分浏览器不允许从 file 地址启动它。因此“04_启动离线CyberChef.cmd”会在本机 127.0.0.1 的随机端口启动 Python 静态服务并打开浏览器。只提供工具包目录；关闭命令窗口或 Ctrl+C 停止。运行期间保持窗口打开。

## Vol3 的镜像与符号

工具包已提供 Vol3 与本课需要的依赖。08_memory 是合成输出读题材料，未包含真实 RAM；不能运行 windows.info 来解析这些 CSV 或片段。

真实内存分析时先取得实际镜像及匹配符号：

~~~powershell
$img = '.\memory.raw'
python $v3 -f $img windows.info
python $v3 -f $img windows.pslist
python $v3 -f $img windows.pstree
python $v3 -f $img windows.cmdline
~~~

另提供“Volatility3_Windows离线符号.zip”作为独立大文件。把此文件复制到 runtime/python/Lib/site-packages/volatility3/symbols，命名为 windows.zip，可保持 ZIP 形态供 Vol3 使用，不必展开里面的 PDB 目录。

该符号集合不能保证覆盖所有系统。若 windows.info 提示缺少符号，应按镜像的 PDB 标识匹配，允许联网时使用 Vol3 正常符号获取机制。预先对授课镜像运行 info，成功后将对应缓存一并准备，才能保证该镜像的离线演示。

## 常见排错

- 命令找不到：重新打开“01_启动课堂终端.cmd”，确认当前目录为 labs；不要在普通终端直接照抄相对路径。
- Python 导入失败：用工具包的 python，先做环境自检；不必在系统 Python 中重复安装依赖。
- 包内位置含中文或空格：启动器使用相对根目录和带引号路径；命令中含空格的输入文件名仍需用引号。
- ExifTool 报文件名编码问题：优先从 labs 使用 ASCII 相对文件名；课堂终端已设置普通 C locale。
- 命令执行成功但没有匹配：先检查输入、编码、参数与对象类型，空输出不等于证据不存在。
- Vol3 插件报 Unsatisfied requirement：先解决镜像层或匹配符号，不要继续把其他插件的失败解释为“没有进程/文件”。

## 分发与来源

本包仅打包为本课选择的工具和依赖，没有复制个人配置、真实证据或现有商业软件目录。各第三方工具沿用其原许可证。licenses/第三方工具说明.md 提供来源与许可索引，TOOL_MANIFEST.json 提供版本和校验值。

源码中也保留了课堂脚本、启动脚本、实验台页面与构建脚本，方便讲师修改。工具清单中标注的拓展工具并未包含可执行文件，授课时以已提供并通过自检的路线为准。

旧 TrueCrypt 容器在挂载方式选择“TrueCrypt · 1.25.9 兼容模式”。1.26.29 已不支持该模式；请按容器实际格式选择。

社区扩展已安装：Vol2 mimikatz / BitLocker，Vol3 pypykatz / BitLocker；Editbox 使用 Vol2 内置实现。启动器自动加载对应插件与依赖，命令和排错见“Volatility_社区插件使用指南.html”。

首次使用请完整解压 Windows 工具包，双击“00_一键配置并启动.cmd”。无需预装 Python 2 / 3；脚本检查包内依赖并生成报告。排错运行“05_环境检查与修复.cmd”，社区插件不可用时使用“06_仅基础工具启动.cmd”。详细步骤见“环境安装与故障排查.html”。
