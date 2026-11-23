# CTF 数字取证基础 · 学员讲义

本讲义用于课前预习、课堂操作和课后复盘。学完后，你应能从文件内容判断格式，定位隐藏信息，恢复简单损坏或删除的内容，并按明确顺序使用 Volatility 3 分析 Windows 内存镜像。

index.html 是全部讲义、题目、题解和工具的统一入口。Windows 首次双击“00_一键配置并启动.cmd”后，可在页面选择附件、填写参数并运行常用工具；需要手工复现命令时，再打开“01_启动课堂终端.cmd”。

学习范围：文件识别、元数据、图片与 LSB、压缩包、磁盘与 SQLite、Volatility 3、日志关联。网络流量取证不在本讲范围内，内存主线使用 Volatility 3；旧镜像的插件结构不兼容时，另用随包 Volatility 2 验证，步骤见兼容分析指南。

## 01 / 怎样使用这份讲义

每个主题按“概念 → 工具与参数 → 操作 → 结果判读 → 练习”展开。先理解命令要处理的对象，再选与你当前终端一致的代码框。同一道题的 Windows 和 Kali 路线是两种可选做法，不需要轮流执行。

后半部分有 15 个案例及参考解法。先完成题目并写下观察，再阅读结果。提交答案时，同时记录输入哈希、关键字段或偏移、命令和验证方法；只记住 flag 不能说明你掌握了解法。

| 命令框标签 | 应在哪里操作 | 需要准备什么 |
|---|---|---|
| Windows · PowerShell | Windows PowerShell 5.1 或 PowerShell 7 | 先打开配套课堂终端，默认进入 labs |
| Windows · CMD | cmd.exe 的命令提示符 | 仅执行明确标注 CMD 的代码框 |
| Kali Linux · Bash | Kali 的 Bash 终端 | 完成下方 Kali 环境准备；默认工作目录为 labs |
| Python 3 源码 | 文本编辑器中保存为 .py | 用对应系统的 Python 3 运行，不能直接当 Shell 命令粘贴 |
| SQLite SQL | 已进入 sqlite3 后的交互终端 | SQL 以分号结束；不是 PowerShell/Bash 命令 |
| 示例输出 / 数据 | 阅读、比较结果 | 不执行；其中的提示符、flag、十六进制值都不是命令 |

“Windows Terminal”是终端窗口软件，里面可能运行 PowerShell、CMD 或 WSL。判断环境要看实际 Shell，不能只看窗口名称。Kali 默认终端也可能使用 Zsh；本讲所有 Kali 代码按 Bash 编写。

代码框里不写 PS>、$、# 等提示符，避免误复制。命令中的 $img 是变量；行首 # 开始的说明是 PowerShell/Bash 注释。示例里的 PID、对象地址、文件名只适用于说明中的材料，换镜像时需要重新确认。

## 02 / Windows：准备学习环境

完整解压“学员工具与练习_Windows64.zip”。第一次使用的详细说明见 [环境安装与故障排查](环境安装与故障排查.html)。在文件夹中先双击“00_一键配置并启动.cmd”，自动检查后进入网页；需要手工命令时再双击“01_启动课堂终端.cmd”。启动器会打开 PowerShell、设置包内工具路径并进入 labs；不需要在系统中重复安装 Python 或 Ruby。

如需在已有 PowerShell 中载入环境，先进入工具包根目录，再执行：

~~~powershell root
. .\env.ps1
Get-Location
Get-Command python,7z,exiftool,sqlite3,pngcheck,mmls,zsteg
python --version
python $v3 -h
~~~

第一行的“点 + 空格”表示在当前 PowerShell 会话中载入环境脚本。随后显示的当前路径应以 labs 结尾。$v3 是启动器设置的 Vol3 入口，不是内存镜像路径。

如果你现在打开的是 CMD，只用下面这段启动 PowerShell 课堂环境；后续继续在新开的 PowerShell 窗口操作：

~~~cmd root
01_启动课堂终端.cmd
~~~

Windows 工具包提供 BusyBox 版 strings、xxd、grep、dd、base64。它们不保证支持全部 GNU 选项，例如 UTF-16LE 检索不能照抄 GNU strings 的 -e l。Windows 题解中会给出实际可用的替代命令。

## 03 / Kali：准备学习环境

使用自己的 Kali 虚拟机或实体机。Windows 工具包中的 .exe、.cmd 和 Windows Python/Ruby 运行时不能作为 Kali 的原生程序运行。把“Kali 学习资料包”解压后，进入其中的 labs；也可把练习 ZIP 解压到自己选定的 labs 目录。

资料包文件名为 CTF取证基础_Kali学习资料.zip。用文件管理器完整解压后，在解压目录内打开终端，再进入 labs。下面的命令从“含有 labs 的解压目录”开始执行：

~~~bash setup
cd ./labs
pwd
mkdir -p out
~~~

先切换到 Bash。下面前两行不带管理员权限，仅查看当前环境：

~~~bash setup
bash
printf '%s\n' "$BASH_VERSION"
pwd
~~~

检查工具；缺少时再安装。以下是联网的环境准备命令，不属于某道题的分析步骤：

~~~bash setup
sudo apt update
sudo apt install file binutils xxd libimage-exiftool-perl pngcheck sqlite3 sleuthkit 7zip unzip python3 python3-venv python3-pil
command -v file strings xxd exiftool pngcheck sqlite3 mmls fls icat 7z python3
~~~

Kali 的包名与命令名可能不同：安装 libimage-exiftool-perl 后运行 exiftool，安装 binutils 后获得 GNU strings，安装 sleuthkit 后获得 mmls/fls/icat。7zip 包提供 7z；仅安装 standalone 变体时入口可能为 7zz，应按自己的安装确认。

zsteg 是 Ruby 工具。需要使用它时，在 Kali 准备 Ruby 并安装用户级 gem；Python LSB 脚本也能完成本课第 3 题：

~~~bash setup
sudo apt install ruby
gem install --user-install zsteg -v 0.2.14 --no-document
export PATH="$(ruby -r rubygems -e 'puts Gem.user_dir')/bin:$PATH"
zsteg --help
~~~

在新终端使用用户级 zsteg 时，需要再次设置上面的 PATH，或自行把对应目录加入 Shell 配置。Windows 课堂启动器已处理自己的运行时路径，不运行这些 apt/gem 命令。

Vol3 的 Kali 环境准备见内存章节。Kali 命令已按上游和 Kali 文档核对；本次制作环境无法连接可运行的 Kali，因此未声称已在 Kali 上逐条实跑。Windows 随包路线已通过运行验证。

## 04 / 工作目录、路径与变量

本讲后续操作都从 labs 执行。Windows 包里已经有这个目录；Kali 资料包也采用相同布局。out 用来保存生成文件，输入附件保持原样。

~~~powershell
Get-Location
Get-ChildItem
New-Item -ItemType Directory -Force -Path .\out | Out-Null
$img = '.\memory.raw'
~~~

~~~bash
pwd
ls -la
mkdir -p out
img='./memory.raw'
~~~

设置 $img/img 不会创建镜像文件。只有拿到真实 RAM 后，才能把变量改成实际路径并运行镜像分析命令。

| 写法 | Windows PowerShell | Kali Bash |
|---|---|---|
| 当前目录下的路径 | .\01_file\unknown.dat | ./01_file/unknown.dat |
| 赋值 | $img = '.\memory.raw' | img='./memory.raw'，等号两侧无空格 |
| 读取变量 | $img | "$img"；加引号避免空格拆分 |
| 有空格的文件名 | '.\case files\image.raw' | './case files/image.raw' |
| 列目录 | Get-ChildItem -Force | ls -la |
| 查命令入口 | Get-Command python | command -v python3 |
| 判断上条原生命令退出码 | $LASTEXITCODE | $? |

PowerShell 常见别名与 Linux 命令名字相似，参数却不一定相同。例如 PowerShell 的 ls 常指向 Get-ChildItem，而 Bash 的 ls 是外部程序。Windows 反斜杠路径也不能原样复制进 Bash。

## 05 / 读懂命令：输入、选项、管道和输出

以“读取二进制字符串 → 过滤关键词 → 保存文本报告”为例：

~~~powershell
finspect strings .\01_file\unknown.dat --encoding ascii |
  Select-String -Pattern 'Comment|Zmxh' |
  Out-File -Encoding utf8 .\out\hits_windows.txt
~~~

~~~bash
strings -a -t x -n 4 ./01_file/unknown.dat |
  grep -E 'Comment|Zmxh' > out/hits_kali.txt
~~~

输入是 unknown.dat，选项控制处理方式，| 把上一条输出交给下一条，最后一步保存文本。grep/Select-String 的行号属于它们接收的文本，不自动等于原始二进制文件的偏移。

“--help/-h”不是所有工具通用的帮助形式。可分别查看：

~~~powershell
finspect --help
7z -h
exiftool -h
python $v3 windows.dumpfiles -h
~~~

~~~bash
file --help
strings --help
7z -h
exiftool -h
~~~

不要从帮助中任意挑选选项堆叠使用。先说明输入是什么、希望输出什么，再确认该工具选项的准确含义。

## 06 / 二进制基础：字节、十六进制与偏移

1 字节等于 8 位。十六进制用 0～9、a～f 表示数值，每两位十六进制表示一个字节。0x200 是十六进制偏移，换算为十进制是 512。

偏移从 0 开始。文件偏移 16 指第 17 个字节。Python 切片 data[16:20] 取偏移 16、17、18、19 的四字节，不包含 20。

~~~powershell
xxd -g 1 -l 32 .\01_file\unknown.dat
xxd -g 1 -s 0x10 -l 16 .\01_file\unknown.dat
~~~

~~~bash
xxd -g 1 -l 32 ./01_file/unknown.dat
xxd -g 1 -s 0x10 -l 16 ./01_file/unknown.dat
~~~

上面两组都使用 xxd：-g 1 按单字节分组，-l 限制显示长度，-s 跳到指定字节偏移。Windows 使用包内 BusyBox xxd，Kali 使用其原生命令。这些共同选项在两条路线中都适用。

十六进制视图通常分三列：左边是字节偏移，中间是原始字节，右边是可打印字符。右边的点通常表示该字节没有直接显示为可打印 ASCII，不能据此认定原始内容就是“点”。

PNG 签名为 89 50 4e 47 0d 0a 1a 0a。扩展名可随意改，签名和内部结构更接近内容证据；发现签名后仍须检查对应结构，避免把偶然字节当成完整对象。

## 07 / 先保留输入，再验证副本

哈希把任意长度输入映射为固定长度摘要。SHA256 相同可用于核对课堂副本的一致性；哈希不是文件内容的“解码方式”，不能从摘要还原文件。

~~~powershell
New-Item -ItemType Directory -Force -Path .\out\work | Out-Null
Get-FileHash -LiteralPath .\01_file\unknown.dat -Algorithm SHA256
Copy-Item -LiteralPath .\01_file\unknown.dat -Destination .\out\work\unknown.dat
Get-FileHash -LiteralPath .\out\work\unknown.dat -Algorithm SHA256
~~~

~~~bash
mkdir -p out/work
sha256sum ./01_file/unknown.dat
cp -- ./01_file/unknown.dat ./out/work/unknown.dat
sha256sum ./out/work/unknown.dat
~~~

两次摘要应相同。修复、提取、解压会产生新文件，新文件摘要不同是正常现象；记录它对应哪一步输出。输入哈希清单在 labs/SHA256SUMS.txt。

## 08 / file、ExifTool 与字符串：各自回答什么

| 工具 | 适合回答的问题 | 不能直接得出的结论 |
|---|---|---|
| file / finspect type | 文件可能是什么格式 | 单凭命中不能证明整个文件完整 |
| xxd / 文件观察实验台 | 指定偏移到底有哪些字节 | 不能仅凭局部文字决定文件的所有语义 |
| strings / finspect strings | 哪些位置存在连续可读文字 | 命中不自动说明来源、时间或所属进程 |
| ExifTool | 元数据字段及字段组是什么 | 没有元数据不等于没有隐藏信息 |

Windows 用 finspect 识别本课常见签名；它是附源码的教学助手，不是完整 libmagic：

~~~powershell
finspect type .\01_file\unknown.dat
strings -n 4 .\01_file\unknown.dat
finspect strings .\01_file\unknown.dat --encoding ascii
exiftool -a -u -G1 .\01_file\unknown.dat
exiftool -b -Comment .\01_file\unknown.dat
~~~

~~~bash
file ./01_file/unknown.dat
strings -a -t x -n 4 ./01_file/unknown.dat
exiftool -a -u -G1 ./01_file/unknown.dat
exiftool -b -Comment ./01_file/unknown.dat
~~~

GNU strings 的 -a 扫描整个输入，-t x 显示十六进制字节偏移，-n 4 指定最小长度。ExifTool 的 -a 保留同名字段，-u 显示未知字段，-G1 显示字段组，-b 定向输出原始值。先找到字段，再只提取它的值，可以避免把标签名一起送去解码。

## 09 / 编码、加密、哈希与端序

| 概念 | 是否用于隐藏秘密 | 常见例子 | 在取证中的用途 |
|---|---|---|---|
| 编码 | 通常没有秘密密钥 | Base64、Hex、URL 编码 | 把文本或二进制换一种表示 |
| 加密 | 通常依赖密钥/口令 | 加密 ZIP | 没有正确口令不能直接恢复明文 |
| 哈希 | 单向摘要，不是可逆编码 | SHA256 | 副本核对和证据记录 |
| CRC | 结构校验，不是安全哈希 | PNG/ZIP CRC32 | 发现损坏、验证结构假设 |

下面的 Base64 解码不需要口令：

~~~powershell
finspect decode64 ZmxhZ3tkZW1vfQ==
~~~

~~~bash
printf '%s' 'ZmxhZ3tkZW1vfQ==' | base64 -d
printf '\n'
~~~

~~~text
flag{demo}
~~~

端序决定多个字节如何组成整数。00 00 01 00 按大端解释是 256；按小端解释是 65536。PNG 的宽高用大端，FAT16 目录字段多为小端，必须按格式文档解释，不能因为“看起来像一个数”就决定含义。

## 10 / PNG 结构与 CRC：修复为什么需要依据

PNG 从 8 字节签名开始，之后每个块通常由“长度 4 字节 → 类型 4 字节 → 数据 → CRC 4 字节”组成。IHDR 数据长 13 字节，含宽、高、位深、颜色类型等；宽在文件偏移 16～19，高在 20～23。

PNG 块的 CRC32 覆盖“类型 + 数据”，不含块长度。保存的 CRC 与重算值不同说明存在矛盾，但不能单凭矛盾确定是哪一项被改动。

~~~powershell
pngcheck -v .\02_png\broken_width.png
finspect png .\02_png\broken_width.png
~~~

~~~bash
pngcheck -v ./02_png/broken_width.png
python3 ./tools/finspect.py png ./02_png/broken_width.png
~~~

练习样本的错误是故意设置的。你需要读出“哪个块、预期值、计算值”，再决定修复方向。第 2 题已明确只改宽度且原 CRC 保留，因此可以用 CRC 约束枚举候选。若直接替换 CRC，只是让错误的尺寸得到新校验，不能证明恢复了原图。

## 11 / LSB：一个像素位怎样组成文字

RGB 像素有红、绿、蓝三个通道，8 位通道的数值范围为 0～255。最低有效位是最右边一位：120 的最低位为 0，121 的最低位为 1。只改变这一位，颜色差通常很小。

提取之前要固定四个条件：选哪个通道、每个通道取几位、像素遍历顺序、这些位如何组成输出字节。第 3 题约定 R 通道最低位、逐行扫描，每 8 位按高位在前组成字节。

~~~text
取出的位：0 1 1 0 0 1 1 0
按高位在前组成：01100110₂ = 0x66 = ASCII f
~~~

用文件观察实验台选择 R 通道与位平面 0，能观察最低位变化；位平面图不是已解码文字。还需要按题目约定组合字节。

Windows 的 zsteg 启动器自动加 --no-file，关闭外部 Unix file 调用，内置文本扫描与定向提取仍可用。Kali 可以使用其原生 file 配合 zsteg：

~~~powershell
zsteg .\03_lsb\quiet.png
python .\tools\extract_lsb.py .\03_lsb\quiet.png .\out\lsb.bin
~~~

~~~bash
zsteg ./03_lsb/quiet.png
python3 ./tools/extract_lsb.py ./03_lsb/quiet.png ./out/lsb.bin
~~~

zsteg 的 b1,r,lsb,xy 表示取 1 位、红通道、最低有效位、逐行扫描。这里的 lsb 是选择像素位，不能直接等同于把输出字节逆序。

## 12 / ZIP、文件雕刻与口令恢复

7-Zip 的 l 列目录，t 测试解压和 CRC，x 按目录结构提取。先列表，再测试，最后输出到新目录：

~~~powershell
7z l .\04_archive\locked.zip
7z t .\04_archive\locked.zip -ptraining2026
7z x .\04_archive\locked.zip -ptraining2026 "-o.\out\zip_example" -y
~~~

~~~bash
7z l ./04_archive/locked.zip
7z t ./04_archive/locked.zip -ptraining2026
7z x ./04_archive/locked.zip -ptraining2026 -o./out/zip_example -y
~~~

-o 后紧接路径。Windows PowerShell 中将整个“-o路径”用引号包住，尤其是点路径或含空格的路径。这里的口令是公开的教学值，实际解题先从提示构造小字典，再验证解密结果。

ZIP 本地头通常以 PK 03 04 开始，中央目录和结束记录还有各自的签名。同一个 ZIP 可以有多个本地文件头，不能把每个 PK 都当作独立压缩包。

文件雕刻指根据边界把对象字节复制出来。签名命中只是候选；应确定起点、结束边界和完整性。第 4 题属于“固定前缀 + 单个 ZIP 到 EOF”；别把这个特定条件推广到所有文件。

“加密位被错误设置”与“真实加密”不同。清除 ZIP 标志不是解密，只在内容本来就未加密时才可能修正声明；需要同时验证解压和 CRC。第 11、12 个案例会分别练习。

## 13 / 磁盘与 SQLite：先识别结构，再提取

镜像可能以分区表开头，文件系统不一定从 0 开始。mmls 列分区，fls 列文件，icat 按元数据编号导出。-o 在本课 TSK 示例中使用扇区数；扇区大小由镜像/工具报告确认。

本课镜像分区起点是 2048 个 512 字节扇区，换算为字节是 1048576。传给 fls/icat 的 -o 仍应是 2048。元数据编号、起始簇、分区偏移是三个不同概念。

FAT16 删除项首字节常改为 E5，数据簇可能被标记为空闲，但内容未必立即覆盖。这解释了“能恢复”的可能性；簇被复用或文件碎片化时，不保证完整恢复。

SQLite 先看表和字段，再写查询。CLI 点命令不是 SQL：

~~~powershell
sqlite3 -readonly .\06_sqlite\case.db ".tables"
sqlite3 -readonly .\06_sqlite\case.db ".schema artifacts"
sqlite3 -readonly -header -column .\06_sqlite\case.db "SELECT id,name,deleted FROM artifacts;"
~~~

~~~bash
sqlite3 -readonly ./06_sqlite/case.db ".tables"
sqlite3 -readonly ./06_sqlite/case.db ".schema artifacts"
sqlite3 -readonly -header -column ./06_sqlite/case.db "SELECT id,name,deleted FROM artifacts;"
~~~

如果你已在任一系统运行 sqlite3 -readonly 打开库，可在 sqlite3> 交互提示符后输入下面的 SQL；不在系统 Shell 直接执行：

~~~sql
SELECT id,name,note FROM artifacts WHERE deleted=1;
~~~

业务字段 deleted=1 表示应用层软删除，记录仍可被普通 SELECT 读到；它不是物理页残留恢复。实际数据库取证还应保留同一快照的 db、db-wal、db-shm，避免遗漏尚未检查点的内容。

## 14 / 日志：关联键、业务状态与时区

日志行可以提供时间、账号、请求、状态和对象。先看格式，再提出待验证的问题；不能单凭“有一条 200”就断定用户完成了具体业务操作。

第 7 题的 rid 与 request_id 可以关联访问日志和审计日志。export_started 与 download_completed 是不同事件；返回 202 只表示请求已接受，不能当成下载完成。

JSONL 是“一行一个 JSON 对象”。Windows 逐行解析，Kali 使用字段脚本或逐行文本检索：

~~~powershell
Get-Content .\07_logs\audit.jsonl |
  ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object { $_.event -eq 'download_completed' } |
  Format-List *
python .\tools\timeline.py .\07_logs\audit.jsonl
~~~

~~~bash
grep -n 'download_completed' ./07_logs/audit.jsonl
python3 ./tools/timeline.py ./07_logs/audit.jsonl
~~~

时间戳末尾 Z 表示 UTC，+08:00 表示 UTC+8。将 01:18:31Z 转换为 UTC+8 是同一天 09:18:31；也可能发生跨天，必须使用完整日期与带时区的时间计算。

## 15 / 保存输出：文本报告与二进制要分清

PowerShell 的管道能传递对象，Bash 管道通常连接字节流。Windows PowerShell 5.1 的原生命令“>”会经过文本处理；不能据此保存需要逐字节一致的二进制。PowerShell 版本差异也可能影响行为，因此本讲 Windows 路线统一用直接保存字节的助手。

文本报告可以明确写 UTF-8：

~~~powershell
exiftool .\01_file\unknown.dat | Out-File -Encoding utf8 .\out\metadata.txt
~~~

~~~bash
exiftool ./01_file/unknown.dat > out/metadata.txt
~~~

二进制/精确字节导出使用对应路线：

~~~powershell
finspect savebin .\out\recovered.txt -- icat.exe -r -o 2048 .\05_disk\tiny_fat16.dd 4
~~~

~~~bash
icat -r -o 2048 ./05_disk/tiny_fat16.dd 4 > out/recovered.txt
~~~

finspect savebin 的 -- 之后是被执行的原生程序与参数。它直接写 stdout 字节，不做文本解码。不要把二进制先经过 Get-Content、Out-File 或文本管道再保存。

