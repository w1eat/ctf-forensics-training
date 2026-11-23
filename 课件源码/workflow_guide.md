# 自动化取证流程 · 学员指南

从 index.html 的“可视化工具台”导入自己的附件，选择流程卡片或保留“自动选择流程”。每一步都保存结果、实际命令和诊断。命中是线索，最终结论要结合题干与证据验证。

## 01 / 先理解三层结果

第一层是原件观察：类型候选、全文件摘要、字节熵、可读字符串和签名。第二层是格式分析：文件系统、PNG 块、压缩包目录、数据库表或内存对象。第三层是派生证据：恢复文件、提取附件、解码结果及相应的来源位置。

普通字符串表有展示数量与抽样范围；专门的“全文件关键词 / flag 检索”会继续流式扫描整个输入，不会因为前面已经显示很多普通字符串而停在前半段。ASCII / UTF-16LE 的 flag 形态只是候选，不等于系统已解出完整题目。

## 02 / 磁盘与分区镜像

流程：识别结构 → mmls 查分区 → fsstat 验证起点 → fls 递归列目录与删除项 → 按规则选候选 → istat 检查大小 → icat 导出 → 搜索内容与继续识别。

完整磁盘含分区表；已经切出的分区可能直接从 Ext4、FAT、NTFS 等文件系统开始。如果 mmls 没有结果，平台会继续用 fsstat 验证偏移 0；成功后按裸文件系统分析，不会只凭 mmls 失败认定镜像损坏。

目录结果保留元数据编号、文件类型、删除标记和路径。自动优先关注关键词文件、删除项、用户目录、历史文件与常见文本 / 文档 / 压缩格式。完整目录在 file_inventory.csv 中；候选导出清单含原路径、inode、命令、大小和 SHA256。

起始扇区必须来自当前镜像。界面的后续按钮会代入已验证的实际起点；NTFS 元数据编号也支持 49-128-5 这样的属性形式。不要把练习的 2048 或 inode 4 当作通用参数。

Windows PowerShell：在工具包根目录运行环境脚本，随后当前目录为 labs。下面以自己的分区镜像为例：

~~~powershell root
. .\env.ps1
analyze auto '.\inputs\partition.img' --workflow disk --max-files 32 --depth 2 --kit '..' --out '.\out\disk_case'
fsstat -o 0 '.\inputs\partition.img'
fls -r -p -o 0 '.\inputs\partition.img'
~~~

Kali Bash：已按讲义准备原生工具与 Python 环境，从资料根目录执行：

~~~bash
cd labs
"$HOME/ctf-forensics/.venv/bin/python" ../tools/analysis_engine.py auto ./inputs/partition.img --workflow disk --max-files 32 --depth 2 --kit .. --out ./out/disk_case
fsstat -o 0 ./inputs/partition.img
fls -r -p -o 0 ./inputs/partition.img
~~~

这两组命令中的 0 只适用于已经确认从文件系统开始的分区镜像。完整磁盘应使用自己验证的扇区值。删除目录项不保证内容可完整恢复；导出失败、部分内容和未导出项要一起记录。

### 时间线题：补查 MACB

题名或题干提示 Timeline、某时刻的变更，或者普通目录和关键词没有直接线索时，进入工具台“文件时间线与异常变更”路线。运行“文件时间线 / MACB”，自动验证起点，按最早 / 最晚时间观察离群记录，再按 UTC 日期、路径和时间类型筛选。完整匹配结果保存在 CSV；可从候选行直接查看 inode 或导出文件。

M 是内容修改、A 是访问、C 是元数据变更、B 是创建（文件系统支持时）。C 不是创建。异常时间只决定检查优先级，需继续验证文件内容；CSV / body 的整数秒与 istat 的纳秒显示也不同。本次真实 `partition4.img` 的时间线、导出和 Base64 解码演示见统一入口的“Timeline 0 实战题解”。

此时间线需要在工具台主动选择，自动分析的“磁盘”模式仍是目录盘点与受限候选导出。

## 03 / 压缩包与多层附件

流程：7-Zip 列目录 → 识别加密与展开大小 → 检查路径和链接 → 受限提取 → 识别子文件 → 在所选深度内继续分析。

标准 / 完整模式会继续提取符合预算的附件。快速模式只看目录。已加密且未提供口令时保留目录和加密状态，不自动尝试密码。已知口令可以在“检索、导出预算与已知口令”中填写。

Windows PowerShell，已在课堂终端的 labs：

~~~powershell
analyze auto '.\inputs\case.zip' --workflow archive --depth 2 --max-files 32 --kit '..' --out '.\out\archive_case'
~~~

Kali Bash，当前目录 labs：

~~~bash
"$HOME/ctf-forensics/.venv/bin/python" ../tools/analysis_engine.py auto ./inputs/case.zip --workflow archive --depth 2 --max-files 32 --kit .. --out ./out/archive_case
~~~

深度 0 表示根附件可提取，但不继续分析子文件；深度 1 可分析第一层，深度 2 可继续处理嵌套附件。相同内容通过摘要去重，递归次数与大小受统一预算约束。

## 04 / 图片与隐写

流程：ExifTool 元数据 → 元数据编码候选 → 图像尺寸 / 模式 → PNG 块与 CRC → 尾随对象 → 低位平面 → 常用 LSB 提取 → 关键词与 flag 形态复核。

自动位流先检查 bit 0、逐行 xy、先取位放字节高位 msb，通道为 r / g / b / rgb / bgr；小型 PNG / BMP 还调用 zsteg 枚举。结果不是对所有隐写方法的穷尽，未命中时用“自选参数提取位流”改变通道、位数、扫描与组字节顺序。

PNG 尾部签名会继续检查对象边界。例如 ZIP 必须有可解析的 EOCD 与中央目录，PNG 必须有有效块边界和 CRC。签名命中本身不能证明完整对象。自动流程不会覆盖原图，也不会对未知损坏直接套用宽度修复脚本。

## 05 / SQLite 数据库

流程：识别 SQLite → 检查同名 WAL / SHM → 在临时副本读取 → 查询真实表结构 → 表预览 → 逐表文本检索 → 定位到表、查询结果行与字段。

表名、字段和软删除标志都来自当前数据库。普通表默认最多检索前 1000 行，最多 20 表；结果会记录截断或无法读取的表。报告中的“查询结果行号”是本次查询位置，不承诺它等于 rowid。

主库和匹配的 -wal / -shm 同批导入并保持原名。不能混用不同时间点的附件。后续从“自定义只读 SQL 查询”构造自己的 SELECT；deleted=1 只在业务确实定义该字段时才有相应含义。

## 06 / 文本、日志与编码

流程：识别 UTF-8 / 带 BOM 的 UTF-16 等编码 → 预览实际结构 → 搜索关键词 → 严格 Base64 / Hex 一层解码 → 汇总关联键和时间。

JSONL 的 request_id、trace_id、session_id、user、event 等实际字段可用于关联统计。带时区的 ISO 时间统一展示 UTC，同时保留原值与行号；缺失时区时不擅自补 UTC+8。统计读取前 4 MiB、最多 20000 行，不代表已经遍历整个日志的所有业务事件。

编码候选最多 24 个，输出包含方法、原始文本字符位置、解码预览与派生文件。字符位置不是原件字节偏移。不能因为文本看起来像 Base64，就把它当作加密或有效答案。

## 07 / PDF、Office 与 PE

PDF：页数与元数据 → 提取文字 → 搜索 / 编码候选 → 列出并受限导出附件 → 分析附件。扫描图片型 PDF 没有可提取文字时仍需 OCR。

Office Open XML：识别 ZIP 结构、[Content_Types].xml 与 word / xl / ppt 目录 → 受限提取 XML 与其他附件 → 检索内容与嵌套对象。不会执行宏，也不把“文档里存在某个字符串”直接解释成可见正文。

PE：静态读取节、导入、入口与熵 → 导出有边界的 overlay → 搜索签名并验证嵌入对象 → YARA / 字符串复核。整个流程不运行样本。

## 08 / 内存镜像（Vol3 主流程，Vol2 兼容入口）

流程：windows.info 验证真实镜像、系统层与匹配符号 → pslist / pstree → cmdline → filescan → 用关键词把实际进程、启动参数与文件对象关联起来。

自动流程使用 --offline 和 JSON 渲染。info 未成功则停止后续插件，保留诊断；成功后用当前输出中的 PID 生成后续操作，避免带入教学样例的 PID 或地址。

导出前仍要核对对象类型。handles、dumpfiles、memmap 按报告线索定向运行；不会自动导出所有进程内存与全部文件缓存。CSV、模拟片段不是真实 RAM。Vol3 成功路径的现场演示仍需提前使用授课镜像验证符号。

cmdscan / consoles 若报告特定 Windows / 控制台结构不支持，可从结果按钮进入 Vol2 兼容分析：imageinfo → kdbgscan / pslist 验证 profile → cmdscan / consoles → filescan → 按实际物理偏移导出。Vol2 不会自动套用某个 profile，Windows 的 Challenge.raw 兼容路径已经实跑；详见“Volatility2_兼容分析指南.html”。

## 09 / 范围、预算与下一步

| 项目 | 默认范围 / 上限 |
|---|---|
| 全文件摘要、整体熵 | 覆盖完整输入 |
| 普通字符串与签名 | 快速前 4 MiB、标准前 64 MiB、完整为全文件 |
| 专门关键词 / flag 检索 | 标准 / 完整及磁盘、数据库、文本流程覆盖全文件；其他快速流程扫描前 4 MiB |
| 已验证文件系统 | 最多 8 个；其余保留分区信息与限制说明 |
| 目录视图 | 表格每文件系统前 500 行，完整列表保留在 CSV / 原始日志；超大日志仍受日志上限约束 |
| 自动导出 / 子文件分析 | 默认 32 个，可调 1～100；单文件 16 MiB，总展开 / 导出 128 MiB |
| 子文件递归 | 默认 2 层，可调 0～3 层；内容摘要去重 |
| 自动位平面 / zsteg | 位平面最多 400 万像素；自动 zsteg 最多 100 万像素 |
| 自动雕刻 | PNG / 经典 ZIP / PDF，可验证边界，单对象 16 MiB |

报告的“下一步”按钮会携带当前原件路径、实际分区起点或已关联 PID。目录里有候选但未导出时，可从完整清单取得元数据编号，继续定向提取。出现“需复核”时先读对应诊断，不把未运行、达到预算、缺符号和“确实没有内容”混为一谈。

运行结果可下载为 analysis.html / analysis.json / analysis.txt，各项 CSV、派生文件和原生工具日志也在同一任务目录。Windows 与 Kali 的命令在页面和代码框中分别标明，不能跨 Shell 原样照抄。

原理参考：[TSK fls 手册](https://www.sleuthkit.org/sleuthkit/man/fls.html)、[TSK 文件系统分析说明](https://wiki.sleuthkit.org/FS-Analysis/)、[Volatility 3 命令行手册](https://volatility3.readthedocs.io/en/latest/vol-cli.html)。
