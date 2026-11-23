# Timeline 0：从异常时间找到隐藏内容

题目来源：学员提供的 **[cylabacademy] Timeline 0 / Misc**。题干要求在磁盘镜像中寻找内容，并用 `academy{}` 包装。以下结果来自对实际上传镜像的本地分析，没有查询网上题解。

镜像：`partition4.img`，489,684,992 字节（467 MiB）。SHA256：

~~~text
8d2fab6ebd3ac75c3065903b05363941eaa4767410397c5a67ed84c6ad85f7ff
~~~

## 先想清楚要找什么

题名 Timeline 提示我们关注时间。拿到镜像仍要先验证格式：它可能是整盘，也可能已经切成一个分区。这里 `fsstat` 验证了起点 **0** 的 Ext4 文件系统；`mmls` 没有分区表输出，不能因此认定文件损坏，也不能照抄练习中的 2048 扇区起点。

目录与字符串可以先做低成本检查。本镜像有 5,918 个目录条目，普通名称没有直接暴露答案；`root/.ash_history` 只有 `poweroff`。全镜像检索 `academy`、`cylab`、`timeline`、`flag.txt` 等没有命中。这些结果让我们转向文件时间，而不是继续盲目增加解压、恢复或挂载操作。

## 在可视化工具台复现

所有镜像分析、导出、文本预览和 Base64 解码均在工作台界面实际运行。时间线汇总是本次发现并补齐的功能，旧版工具台需要更新后再复现。

| 步骤 | 界面操作 | 为什么做 / 应看到什么 |
|---|---|---|
| 1 | 选择自己的 `partition4.img`，进入“文件时间线与异常变更”路线，先运行“验证文件系统与起点” | 留空自动识别起点；本题得到 Ext4、扇区 0。 |
| 2 | 运行“文件时间线 / MACB”，排序选 `oldest`，时间类型选 `all` | 从最早时间找离群记录，不需要预先知道可疑文件名或日期。 |
| 3 | 查看最早的四条记录 | 都指向 `/bin/bcab`，inode **4945**，大小 **41 字节**，UTC 时间 **1985-01-01 17:00:00**。其余文件的有效时间从 2021 年起，差异非常明显。 |
| 4 | 点候选行的“查看元数据”，再运行 | 复核当前镜像的 inode，而非从其他题解照抄编号。`istat` 确认文件已分配、41 字节，数据块为 **155654**。 |
| 5 | 从时间线候选行点“导出此文件”，或手动选择“按元数据编号导出”并填扇区 `0`、编号 `4945` 后运行 | `icat` 读取文件内容。此文件仍已分配，本题不需要删除恢复、PhotoRec 或磁盘挂载。 |
| 6 | 在导出文件中点 `recovered.bin` 的“作为下一步输入”，运行“预览文本与结构化日志” | 看到一行由 Base64 字符组成的短文本，继续验证编码。 |
| 7 | 进入“Base64 解码”，粘贴该行并运行 | 严格解码后得到有意义的文本，内容与题名“时间线离群值”呼应。 |

也可以用结束日期 `1990-01-01` 缩小已发现的异常范围；这是发现线索后的筛选方式，不是拿到陌生镜像时必须猜中的日期。

MACB 中，M 是内容修改、A 是访问、C 是 inode / 元数据变更、B 是创建（文件系统支持时）。**C 不是创建时间。** 时间线按 UTC 展示；这台 Windows 主机上 `istat` 原始输出显示本地时间 `1985-01-02 01:00:00.150000000`，两者相差 8 小时。TSK body 时间为整数秒，纳秒信息需要看 `istat`。

“日期很早”只决定检查优先级，不能直接证明是 flag。这里还通过文件大小、真实导出内容、Base64 严格解码和题意共同验证。不要执行导出的未知文件。

## 导出内容与答案

`/bin/bcab` 原始内容为以下字符串加换行，共 41 字节：

~~~text
NzFtMzExbjNfMHU3MTEzcl9oM3JfNDNhMmU3YWYK
~~~

Base64 解码为 30 字节，其中末尾有一个换行。去掉末尾换行后，按题干要求包装：

~~~text
academy{71m311n3_0u7113r_h3r_43a2e7af}
~~~

这是本地证据推导出的答案；本次没有向赛事平台提交。

## Windows PowerShell：等价命令

先从完整学员包运行 `01_启动课堂终端.cmd`，在 PowerShell 中进入包内 `labs` 目录。下面假设镜像副本放在 `labs/inputs/partition4.img`；通过网页上传时，把 `$caseImage` 改成实际上传目录。输出写入 `labs/out/timeline0`。

~~~powershell
$kitRoot = (Resolve-Path '..').Path
$tsk = Join-Path $kitRoot 'tools\sleuthkit\bin'
$caseImage = (Resolve-Path '.\inputs\partition4.img').Path
New-Item -ItemType Directory -Path '.\out\timeline0' -Force | Out-Null

# 验证裸分区起点，不套用 2048
& "$tsk\fsstat.exe" -o 0 $caseImage

# fls 的 -m 输出 body 格式；按内容修改时间数值排序
& "$tsk\fls.exe" -r -m / -o 0 $caseImage |
    ConvertFrom-Csv -Delimiter '|' -Header md5,path,inode,mode,uid,gid,size,atime,mtime,ctime,btime |
    Where-Object { [long]$_.mtime -ne 0 } |
    Sort-Object { [long]$_.mtime } |
    Select-Object -First 10 path,inode,size,mtime

# 从本次结果取得编号，再复核元数据
& "$tsk\istat.exe" -o 0 $caseImage 4945

# 使用包内 Python 按原始字节保存 icat 输出，兼容 PowerShell 5.1
& "$kitRoot\runtime\python\python.exe" -c "import subprocess,sys; subprocess.run([sys.argv[1],'-r','-o','0',sys.argv[2],'4945'],stdout=open(sys.argv[3],'wb'),check=True)" "$tsk\icat.exe" $caseImage '.\out\timeline0\bcab.bin'

$b64 = [IO.File]::ReadAllText((Resolve-Path '.\out\timeline0\bcab.bin')).Trim()
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)).Trim()
~~~

这里对 `fls` 的管道处理的是文本；保存 `icat` 二进制内容则使用 Python 的 `wb`，避免旧 PowerShell 文本重定向改变原始字节。上述按 `mtime` 排序是本题的简化验证；工作台的 MACB 时间线会同时检查四类时间。

## Kali / Linux Bash：等价命令

在 `labs` 目录运行，先通过课程安装脚本准备 Sleuth Kit。镜像路径按自己的附件位置替换。

~~~bash
mkdir -p out/timeline0
fsstat -o 0 inputs/partition4.img
fls -r -m / -o 0 inputs/partition4.img > out/timeline0/timeline.body
mactime -b out/timeline0/timeline.body -d -z UTC | head -n 15
istat -o 0 inputs/partition4.img 4945
icat -r -o 0 inputs/partition4.img 4945 > out/timeline0/bcab.bin
base64 --decode out/timeline0/bcab.bin
~~~

Kali 命令作为等价复现方法提供；本次实际界面验收在 Windows 完成。

## 本题可以迁移的方法

格式和起点验证 → 目录 / 原始文本初查 → 时间线找离群记录 → 元数据复核 → 定向导出 → 编码验证 → 按题意包装。没有直接关键词不等于没有答案；批量恢复大量系统文件也不等于已经找到题目线索。更换镜像时必须重新取得 inode，不能固定使用本题的 4945。
