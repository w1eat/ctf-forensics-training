# Volatility 社区扩展：凭据、BitLocker 与编辑控件

社区插件用于在已有线索上回答具体问题。先识别系统和进程，再选择插件；帮助加载成功表示依赖就绪，不保证目标镜像含有可恢复数据。本包只对离线镜像运行这些功能。

## 01 / 已安装什么

| 版本 | 插件 / 入口 | 用途与边界 |
|---|---|---|
| Vol2 | mimikatz | Francesco Picasso 的旧系统 WDigest 离线解析；代码支持的 Vista / Win7 布局，不能当作通用 Win10 / Win11 密码恢复器 |
| Vol2 | bitlocker | 扫描加密卷使用过的 FVEK 候选；原作者列出 Vista 到部分 Win10 版本，具体结构仍需验证 |
| Vol2 | editbox | 发行版已内置。读取编辑控件文本、部分撤销内容；依赖 GUI 结构，不能保证所有记事本版本可用 |
| Vol3 | vol_pypykatz.pypykatz | skelsec 的 pypykatz 扩展，依赖 pypykatz 0.6.13；解析离线 LSASS 会话与支持的凭据类型 |
| Vol3 | bitlocker.BitlockerFVEKScan | 社区池扫描与 AES 密钥扩展检查；作者测试目标为 Win10+ x64，候选不等于已解锁卷 |

Vol2 mimikatz 与 Vol3 pypykatz 是不同实现。不能复制 Vol2 的 Python 2 插件到 Vol3，也不要把 mimikatz 改成 windows.mimikatz 猜测运行。原来已有的 hashdump、clipboard、notepad、truecrypt 等标准插件仍然保留。

Windows 随包运行时已准备依赖。Vol2 的 Construct 2.8.22、PyCryptodomex 3.9.9 与 Python 2 标准库兼容文件放在它自己的 extra_deps，不替换 Vol3 的 Python 3 依赖。上游原件、版本锁、许可与兼容改动说明见 tools/memory_plugins 和 licenses/source/volatility-community。

## 02 / 先用界面判断

从 index.html 的“可视化工具台”选择“样本账号与口令线索”路线，先核对系统，再看 LSASS / 加密进程。单项操作在“全部工具”中搜索 pypykatz、mimikatz 或 BitLocker。Vol2 要填写已经由 kdbgscan / pslist 核对的 profile；插件所需 PID 必须来自当前镜像。

选择“Vol3 · pypykatz / BitLocker 社区扩展”后，结果可显示为表格；完整 JSON 和原始输出可下载。选择“Vol2 · mimikatz / BitLocker / Editbox”使用旧版插件。只有 BitLocker 和 Editbox 提供可选文件导出，mimikatz 的内容在文本结果中查看。

### 为什么先检查进程

题目给出加密容器、用户口令或“曾经登录”线索时，应先确认内存中的目标进程、系统版本和镜像完整性。mimikatz / pypykatz 需要可读取的 LSASS 页面及其支持的结构；进程已经结束、关键页缺失、Credential Guard、不同版本结构等都可能导致无结果。不能用空表断言“没有密码”，也不能把 NTLM 哈希当成明文口令。

## 03 / Windows PowerShell：完整工具包

先双击 01_启动课堂终端.cmd，工作目录为 labs。以下命令适用于这个终端；它已经把 bin 目录加入当前 PATH。

~~~powershell ram
vol2 --info
vol2 mimikatz -h
vol2 bitlocker -h
vol3 vol_pypykatz.pypykatz -h
vol3 bitlocker.BitlockerFVEKScan -h
~~~

~~~powershell ram
$img = '.\memory.raw'
vol3 -f $img windows.info
vol3 -f $img windows.pslist
vol3 -f $img vol_pypykatz.pypykatz

# profile 必须换成当前题目核对后的值
$profile = 'Win7SP1x86'
vol2 -f $img --profile=$profile pslist
vol2 -f $img --profile=$profile mimikatz
~~~

vol2.cmd 自动加入额外插件目录。若直接调用独立 EXE，需要显式加入全局 --plugins 参数；先写全局参数，再写插件名。Vol3 的扩展已经放在它的插件搜索目录，vol3 入口可以直接识别。

## 04 / 本机 E:\CTF 的两个工具

本机 Vol2 目录是 E:\CTF\ctf工具箱\数字取证\volatility-master\volatility-master，Vol3 目录是 E:\CTF\ctf工具箱\数字取证\volatility3。分别使用新增的 vol2.cmd、vol3.cmd；保留原来的 vol.exe、vol.py 和已有 plugins 目录。

~~~powershell root
& 'E:\CTF\ctf工具箱\数字取证\volatility-master\volatility-master\vol2.cmd' --info
& 'E:\CTF\ctf工具箱\数字取证\volatility-master\volatility-master\vol2.cmd' mimikatz -h
& 'E:\CTF\ctf工具箱\数字取证\volatility3\vol3.cmd' vol_pypykatz.pypykatz -h
~~~

本机 Vol2 原 plugins/mimikatz.py 不会因为文件已经存在就自动满足依赖。新增启动器加载独立的 extra_plugins / extra_deps。不要用 Python 3 打开 Vol2 脚本；本机原 Python 2 全局环境没有被改造成课程依赖环境。

## 05 / Kali Bash：资料包

在学习资料包根目录准备 Python 3 环境，再启动学习平台。Vol3 扩展源文件附在 tools/volatility3_extra，终端直接调用时使用全局 -p 指定它。

~~~bash root
python3 -m venv .venv
source .venv/bin/activate
python -m pip install volatility3 pypykatz==0.6.13
vol -p ./tools/volatility3_extra vol_pypykatz.pypykatz -h
vol -p ./tools/volatility3_extra -f ./labs/memory.raw vol_pypykatz.pypykatz
~~~

Vol2 Linux 独立版和扩展所需依赖随资料包提供；Linux 原生依赖仍取决于本机兼容环境，不能用 Windows 的 .pyd 文件代替 Linux .so。

~~~bash root
chmod +x ./tools/volatility2/linux/volatility_2.6_lin64_standalone
./tools/volatility2/linux/volatility_2.6_lin64_standalone \
  --plugins=./tools/volatility2/extra_plugins \
  -f ./labs/memory.raw --profile=Win7SP1x86 mimikatz
~~~

Kali 中的 profile 也必须根据本题重新核对。系统安装了其他版本的 vol 时，先核对 vol -h 和 Python 环境，避免调用到另一套 Volatility。

## 06 / BitLocker 与编辑控件怎样继续

### BitLocker：先证明题目确实存在加密卷

先检查磁盘分区与卷头。-FVE-FS-、题目说明、系统配置或关联文件都可以形成加密卷线索；随后从同题 RAM 扫描 FVEK。核对算法、位数、卷与内存的关联，再考虑解锁。FVEK、恢复口令和 TrueCrypt / VeraCrypt master key 不是同一种材料。

~~~powershell ram
$img = '.\memory.raw'
New-Item -ItemType Directory -Force '.\out\bitlocker' | Out-Null
vol3 -o '.\out\bitlocker' -f $img bitlocker.BitlockerFVEKScan --dump
vol2 -f $img --profile=Win7SP1x86 bitlocker
~~~

导出的原始 key 不会自动套入工作台的 AES-CBC 文本解密。磁盘通常涉及扇区、IV、XTS 或 diffuser，必须由支持对应卷格式的工具处理。社区 Vol3 插件的 --dislocker 路径带有作者注明的布局限制，工作台只开放原始候选导出；不把候选直接标记为解锁成功。

### Editbox：有 GUI 线索时定位进程

看到记事本、输入框、未保存文本等线索时，先从 pslist 取得目标 PID，再用控件分析；GUI 页面无法恢复时，改用进程内存导出与 UTF-16LE 字节检索。

~~~powershell ram
# 将 2460 改成当前题目查到的目标 PID
vol2 -f '.\memory.raw' --profile=Win7SP1x86 editbox -p 2460
~~~

## 07 / 已完成的验证与使用边界

安装验证包含插件发现、帮助、依赖导入，以及真实 Win7 教学镜像的离线 mimikatz / pypykatz 运行。不同 Windows 构建仍需以当前镜像测试，空结果和不支持提示都应保留。课程不包含访问当前电脑 LSASS 或导出当前电脑凭据的入口。

上游来源：[Vol2 mimikatz](https://github.com/dfirfpi/hotoloti)、[Vol3 pypykatz 插件](https://github.com/skelsec/pypykatz-volatility3)、[pypykatz](https://github.com/skelsec/pypykatz)、[Vol2 BitLocker](https://github.com/elceef/bitlocker)、[Vol3 BitLocker](https://github.com/lorelyai/volatility3-bitlocker)。Editbox 已随 Volatility 2.6 标准发行版提供。
