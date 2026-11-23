# CTF 取证学习平台 · 学员使用指南

index.html 是讲义、课件、15 道题目、完整题解和全部工具的统一入口。工具台既能处理练习，也能导入你自己的文件。题目的文件名、表名、PID 和偏移不是通用答案。

## 01 / 启动平台

Windows：完整解压“学员工具与练习_Windows64.zip”，双击“00_一键配置并启动.cmd”。浏览器打开 index.html 并显示“本地工具已连接”后即可运行工具。保留启动窗口，结束时按 Ctrl+C。工作区根目录也有同名启动器。

直接双击 index.html 可以阅读全部资料，并使用纯浏览器文件观察实验台。要调用 Python / EXE，必须使用启动器打开的本机网址；普通 HTML 页面不能直接启动本机程序。

Windows 包已带 Python、Ruby、Pillow、Volatility 3、Volatility 2 独立版、ExifTool、7-Zip、pngcheck、TSK、SQLite、zsteg、YARA、pypdf、pefile、BusyBox、PhotoRec、ImDisk、VeraCrypt、PyCryptodome 和离线 CyberChef，无需逐项联网安装。

Kali 先按学员讲义安装原生工具，再准备 Python 依赖。在 Kali Bash 执行以下环境准备命令：

~~~bash setup
python3 -m venv --system-site-packages "$HOME/ctf-forensics/.venv"
"$HOME/ctf-forensics/.venv/bin/python" -m pip install Pillow volatility3==2.28.2 pypdf==6.21.1 pefile==2024.8.26 yara-python==4.5.4 pycryptodome==4.1.0 pypykatz==0.6.13
bash 启动学习平台.sh
~~~

Kali 资料包包含平台源码和练习，不含 Windows 二进制。上述安装需要网络；本次未进行 Kali 实机验证。页面中的实际命令会标明 Windows PowerShell 或 Kali / Linux Bash。

## 02 / 上传自己的文件并自动分析

工具台顶部有“分析工具 / 附件管理 / 分析历史”三个页面；上传队列与历史列表不会占用分析画布。点击左上角“收起导航”隐藏左侧栏目，再点击“展开导航”恢复，刷新页面后保持该状态。

1. 进入“可视化工具台”，点击顶部“附件管理”，拖入文件或点击“导入附件”多选文件，并按需要调整扫描范围。每批最多 64 个，单文件最多 2 GiB。
2. 默认勾选“导入后自动分析”。同批文件先全部复制到 inputs 的同一子目录，再按顺序分析；重名文件会报错，不替换已有附件。
3. “按内容自动判断”会识别常见磁盘 / 裸文件系统、图片、压缩包、SQLite、PDF、Office、PE 与文本。也可用流程卡片明确选择；真实 Windows 内存需要选择 Vol3 流程。
4. 切回顶部“分析工具”，查看阶段进度、结构化结果和诊断。结果区可下载 analysis.html、analysis.json、analysis.txt、各项结果和原生工具日志；上传队列中的“查看结果”也能直接打开结果。
5. 点击顶部“分析历史”重开之前的结果，支持按附件、操作、编号搜索及按状态筛选；重启平台后，记录仍保存在原目录。列表分页展示，最多读取最近 500 条。

规则文件 .yar / .yara 与 -wal / -shm 伴随文件仅导入，不自动作为独立题目分析。SQLite 主库及匹配的 WAL / SHM 应同批选择，保持原文件名。导入后也可在“当前分析文件”里选其他附件，点击“分析当前文件”。

超过 2 GiB 的镜像可手动复制到 labs/inputs（工具包）或练习材料/inputs（工作区），点击“刷新附件”。导入是复制到本机工作目录，不会把附件发送到外部站点。不要在分析期间修改输入。

“附件管理”的列表可按来源、文件名或路径筛选；选择“用于分析”可切回工具台并保留当前解题步骤。导入附件支持单个删除或勾选后批量删除，每次最多 100 项；确认框会列出删除对象。这里删除的是工具包 inputs 中的导入副本，已有分析报告保留，课程练习原件只读。

“分析历史”支持单条或多选删除；删除记录会同时删除该次分析的报告和导出文件，原始输入附件保留。运行中的任务不能删除；附件或同批伴随文件正在上传、排队或分析时，也须等待对应任务结束。某次结果正被另一任务作为输入时，先完成该任务再删除其来源记录。

## 03 / 自动流程具体做什么

| 输入 / 流程 | 自动步骤 | 继续判断 |
|---|---|---|
| 所有文件 | 文件头与类型候选 → 全文件摘要、字节熵 → 字符串与签名 | 签名是候选；熵高不能直接认定加密 |
| 图片 | 适用格式的元数据、尺寸 / 模式、缩略图；PNG 额外检查块边界与 CRC | 隐写参数、尾随对象边界与验证 |
| 压缩包 | 目录 / 加密检查、受限提取、嵌套附件识别与递归分析 | 口令、深度和总预算 |
| SQLite | 结构、WAL 副本、表预览、逐表关键词检索 | 查询最多前 20 表各 1000 行，按实际字段继续查询 |
| PDF / Office | 正文 / 元数据、受限附件提取、Office XML / 子文件检索 | 扫描型 PDF 需 OCR，未知口令需另外处理 |
| PE | 节、导入、入口 RVA、overlay 偏移 | 静态线索不能单独证明恶意，样本不会被运行 |
| CSV / TSV / JSON / JSONL / 文本 | 按实际结构预览，不要求固定业务字段 | 编码、时区、关联键与字段含义 |
| Windows 内存（明确选择） | Vol3 --offline：info 成功后 → pslist → pstree → cmdline → filescan | 匹配符号、当前 PID / FILE_OBJECT 与后续导出 |
| 磁盘 / 分区镜像 | 分区探测、偏移 0 回退验证、目录 / 删除项、候选导出、内容检索 | 按清单和实际编号继续定向提取 |

标准 / 完整分析还对不超过 256 MiB 的附件运行内置 YARA 教学规则。快速分析跳过元数据和 YARA。常见流程会继续导出和检索符合预算的派生文件。自动流程不猜测口令，不修改输入，也不自动修复未知损坏。各步骤、命令与边界见 [自动化取证流程指南](自动化取证流程指南.html)。

## 04 / 扫描范围和限制

| 操作 | 范围 / 上限 |
|---|---|
| 摘要与整体字节熵 | 始终覆盖全文件；按 1 MiB 分窗，图形最多显示前 256 窗，JSON 最多保留前 4096 窗 |
| 快速 / 标准 / 完整的字符串与签名 | 分别是前 4 MiB / 前 64 MiB / 全文件流式遍历 |
| 独立字符串操作 | 扫描上限设为 0 表示全文件；最多 2000 条 |
| 自动字符串 / 签名结果 | 分别最多 1000 / 2000 条，记录是否截断 |
| PDF / PE 解析 | 输入最多 64 MiB；PDF 最多 100 页、约 2 MiB 文本 |
| YARA | 输入最多 256 MiB，规则最多 64 KiB，匹配限 20 秒 |
| 图片位流 / 位平面 | 输入最多 64 MiB；位流限 2000 万像素，位平面限 400 万像素 |
| 单项压缩包提取 | 最多 2048 项、声明展开总量 512 MiB；拒绝目录外路径和链接 |
| 自动流程导出 / 展开 | 默认 32 文件，可调 1～100；单文件 16 MiB，总预算 128 MiB，递归深度默认 2 |
| SQLite / 文本预览 | 查询最多 1000 行；文本读取前 4 MiB，最多显示 1000 行 |

报告明确记录扫描字节数、总大小、跳过、截断和失败。未命中不代表不存在隐藏内容。字符串扫描仅提取 ASCII 可打印字符及其 UTF-16LE 表示；中文正文优先用“预览文本与结构化日志”选择正确编码。

## 05 / 按题意选择路线，或自由使用工具

左侧“全部工具”提供 77 项操作，可搜索工具名；“解题流程”提供按两份 PPT 整理的 21 条路线。切换工具时保留当前文件、滚动位置和工具列表焦点；先核对参数和“实际执行命令”的系统标签，再运行。

“Volatility 2 · 兼容分析”提供帮助、识别、历史、导出、注册表与社区扩展入口。Vol3 控制台插件遇到特定版本结构不兼容时，结果区会提供 Vol2 profile 识别按钮，保留同一输入和原始报错。先 imageinfo → kdbgscan / pslist 核对 profile，再运行 cmdscan / consoles。不会替所有镜像固定选择 x64 profile；文件导出使用当前 Vol2 filescan 的物理 Offset(P)。详细命令、真实镜像验证与 Windows / Kali 区别见“Volatility2_兼容分析指南.html”。

SQLite：先“SQLite 表与字段”，再“按表名预览数据库”或“自定义只读 SQL 查询”。输入真实表名，例如 orders，并使用自己的字段。平台拒绝写入、ATTACH、扩展加载和 Shell 点命令。deleted=1 只是部分数据库的业务标记，不是通用结构，也不等于物理删除恢复。

图片：先元数据和结构，再 zsteg。“自选参数提取位流”支持 r / g / b / a / rgb / bgr / rgba、位 0～7、xy 逐行 / yx 逐列，以及 msb / lsb 组字节顺序。提取不会遇 NUL 自动停止，应按题目条件判断真实长度；位平面可导出黑白 PNG。

压缩包：“通用压缩包分析 / 提取”支持 list / test / extract。填写已知口令；具体支持格式取决于 7-Zip。损坏或无法确定展开大小时先读诊断。“修正练习 ZIP 标志”“恢复练习 PNG 宽度”仍是有明确前提的教学操作，不适用于任意文件。

YARA：留空使用内置规则；也可粘贴规则或从附件中选择导入的 .yar 文件。选择规则文件时优先使用文件，禁用 include。表格显示规则、标识和字节偏移，命中结果应结合上下文验证。

SQLite 检测到同名 WAL 时，会先复制主库和伴随文件，在临时副本中读取并记录伴随文件摘要，避免 SQLite 更新原件 SHM。分析时应使用已稳定保存的同一组附件，不能混用不同时间点的主库和 WAL。

结果区“作为下一步输入”会把导出文件交给通用分析入口，也可再选择左侧工具。十六进制和雕刻使用字节偏移；TSK 分区起点使用扇区数，不能混用。

## 06 / 在终端复现

Windows PowerShell：先双击“01_启动课堂终端.cmd”，当前目录为 labs。analyze 是包内脚本入口，--kit .. 指工具包根目录。sample.bin 换成实际路径：

~~~powershell
analyze auto '.\inputs\sample.bin' --profile standard --workflow auto --out '.\out\my_analysis' --kit '..'
analyze strings '.\inputs\sample.bin' --encoding both --keyword 'flag{' --limit 0 --out '.\out\my_strings'
analyze sqlite '.\inputs\case.db' --query 'SELECT name,type FROM sqlite_schema' --out '.\out\my_query'
analyze archive '.\inputs\sample.7z' --mode list --kit '..' --out '.\out\my_archive'
~~~

Kali Bash：在解压的资料根目录进入 labs；tools/analysis_engine.py 与 Windows 为同一份源码：

~~~bash
cd labs
"$HOME/ctf-forensics/.venv/bin/python" ../tools/analysis_engine.py auto ./inputs/sample.bin --profile standard --workflow auto --out ./out/my_analysis --kit ..
"$HOME/ctf-forensics/.venv/bin/python" ../tools/analysis_engine.py strings ./inputs/sample.bin --encoding both --keyword 'flag{' --limit 0 --out ./out/my_strings
"$HOME/ctf-forensics/.venv/bin/python" ../tools/analysis_engine.py sqlite ./inputs/case.db --query 'SELECT name,type FROM sqlite_schema' --out ./out/my_query
~~~

手工运行时为每次分析指定新目录。网页会自动生成独立任务目录。运行报告保留命令和参数文件内容；Windows ExifTool 使用 UTF-8 参数文件读取中文路径。

## 07 / 内存分析与保存

08_memory 的 CSV、文本和模拟片段是读题练习，不是真实 RAM。自动 Windows 内存流程使用 --offline：先准备匹配符号，info 成功才继续。缺少符号会保留失败原因，不能解释为“没有进程”。需要在线获取符号时，在 Vol3 单项操作或终端中按讲义执行。

盘点后根据当前镜像的实际 PID 和对象地址选择 cmdline、cmdscan / consoles、handles、dumpfiles 或 memmap。虚拟 / 物理地址类型必须重新确认。独立符号集合不是镜像，不保证覆盖每个构建。

输入在 labs / 练习材料的 inputs；输出在 out/platform_runs/任务编号。每个任务有“运行报告.txt”，保留系统、命令、状态、退出码与输出。analysis.html 可单独阅读，analysis.json 便于后续处理。

本地服务只监听 127.0.0.1，使用固定工具入口与经过校验的参数，无任意 Shell 命令接口。单项通常限时 120 秒，自动分析最多 900 秒，内存题分流最多 1200 秒；可停止当前任务或取消后续队列。日志超过限制时停止并保留已有结果。

工具原理可继续查阅 [YARA Python 官方文档](https://yara.readthedocs.io/en/stable/yarapython.html)、[Python sqlite3 文档](https://docs.python.org/3.13/library/sqlite3.html)、[pypdf 官方文档](https://pypdf.readthedocs.io/en/stable/) 和随包源码。工具版本与许可证由首页“全部工具”索引。

社区扩展已安装：Vol2 mimikatz / BitLocker，Vol3 pypykatz / BitLocker；Editbox 使用 Vol2 内置实现。启动器自动加载对应插件与依赖，命令和排错见“Volatility_社区插件使用指南.html”。

首次使用请完整解压 Windows 工具包，双击“00_一键配置并启动.cmd”。无需预装 Python 2 / 3；脚本检查包内依赖并生成报告。排错运行“05_环境检查与修复.cmd”，社区插件不可用时使用“06_仅基础工具启动.cmd”。详细步骤见“环境安装与故障排查.html”。
