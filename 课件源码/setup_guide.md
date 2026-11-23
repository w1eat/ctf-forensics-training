# 第一次使用：环境配置与故障排查

## 01 / Windows 新手只做两步

1. 下载并完整解压“学员工具与练习_Windows64.zip”，进入解压后的“学员工具包_Windows64”文件夹。不要直接在压缩包预览里双击脚本。
2. 双击“00_一键配置并启动.cmd”。等待检查完成，浏览器会打开 index.html。保留启动窗口，网页工具才能继续运行。

适用系统是 Intel / AMD 的 Windows 10/11 x64，并需要可写的本地目录。可以放在自己的文档目录，中文和空格路径均可使用。32 位 Windows、macOS 和 ARM 原生环境需要对应平台工具，不能使用这个 x64 包。

**不需要事先安装 Python 2、Python 3、Ruby、Perl 或 pip。** 包内已有 Python 3、Ruby、ExifTool 的 Perl 依赖，Vol2 独立程序也带有自己的 Python 2 运行时。此入口使用包内程序，不依赖电脑上已有的 Python 版本。

## 02 / 一键入口会做什么

| 项目 | 实际行为 |
|---|---|
| 系统与目录 | 检查 Windows x64、目录可写、完整运行时是否存在 |
| 文件完整性 | 首次校验 SHA256SUMS.txt 中的文件；文件内容不符时停止运行，列出问题 |
| Python 和工具依赖 | 检查 Python 标准库、Pillow、YARA、AES、PDF、Ruby/zsteg、ExifTool、TSK、SQLite、PhotoRec 与两代内存扩展 |
| Python 2 | 使用 Vol2 独立程序，不向全局安装已经停止维护的 Python 2 |
| VC++ 运行库 | 已随包提供 Microsoft 官方 x64 安装器；仅在检测到对应 DLL 错误或明确请求修复时调用，先核对 SHA256 和 Microsoft 数字签名 |
| 本地输出 | 创建 inputs、out 与缓存目录，写入 HTML / JSON 检查报告 |
| 日常启动 | 24 小时内可复用检查结果，仍校验关键文件；完整复查使用“05_环境检查与修复.cmd” |
| 磁盘挂载 | 普通文件分析不安装驱动；需要盘符时再按挂载流程准备 ImDisk 等组件 |

普通学习平台不需要管理员权限。VC++ 系统运行库安装、驱动安装或系统挂载可能出现 Windows 权限提示；取消后会保留原因。脚本不重启电脑、不修改全局 PATH，也不永久修改 PowerShell 执行策略。

## 03 / 三个入口怎样选

| 文件 | 什么时候用 |
|---|---|
| 00_一键配置并启动.cmd | 第一次运行，或者希望重新检查后进入学习平台 |
| 00_启动学习平台.cmd | 日常启动；同样带环境预检，继续支持原启动参数 |
| 05_环境检查与修复.cmd | 工具不能运行、解压不完整、系统组件缺失；检查完成后查看报告 |
| 06_仅基础工具启动.cmd | 暂不使用社区凭据扩展，先做文件、图片、压缩包、数据库和磁盘基础练习 |

检查报告位于 labs/out/setup_runs/本次检查目录；工作区主入口使用练习材料/out/setup_runs。每次报告有独立目录，包含“环境检查.html”“环境检查.json”和工具诊断日志。报告中只记录环境检查，不运行真实内存镜像的凭据解析。

## 04 / pypykatz 等文件被拦截时

取证和安全分析组件可能被防护软件标记，不能只凭工具名断言一定是误报。脚本会检查文件是否缺失；能读取 Windows 防护状态时，还会查找与本工具目录对应的拦截记录。

先打开 Windows 安全中心的“保护历史记录”，核对被拦截的路径、工具版本与授课来源，并对照正式分发的 SHA256。把拦截详情和环境检查报告交给授课人员或安全管理员确认。确认为误报时，可向 [Microsoft 提交样本复核](https://www.microsoft.com/en-us/wdsi/filesubmission)。

**安装脚本不会自动添加防病毒排除项、关闭实时防护、修改安全策略或恢复隔离文件。** 它提供 Windows 安全中心入口和诊断信息。暂时无法使用社区插件时，运行“06_仅基础工具启动.cmd”；页面会明确显示基础模式，社区扩展按钮不能执行。

Windows 的 Internet“受信任站点”和 Defender 文件防护是不同设置。把本地 HTML 当作受信任站点不能补回缺失程序，也不能解决 Python 依赖问题。

## 05 / 常见问题

| 现象 | 先检查什么 | 下一步 |
|---|---|---|
| 提示找不到 Python | 是否只下载了讲义 / Kali 资料包，或只在压缩包内打开了一个脚本 | 换用 Windows 完整包，完整解压后运行 |
| DLL 缺失、0xc0000135 | 包内 DLL 是否解压完整，工具诊断是否指向 VC++ | 运行检查与修复；安装器通过 Microsoft 签名验证后再执行 |
| SHA256 不一致 | 是否改过脚本，下载是否完整，来源是否可信 | 对照来源核验；脚本不覆盖修改过的文件 |
| 无法创建输出文件 | 是否放在只读目录、受管目录或写入受限位置 | 解压到自己可写的本地目录后重试 |
| 某个内存插件没有结果 | 是否有真实镜像、正确 profile / 符号及可读页面 | 这是镜像分析条件；环境检查通过不代表一定可恢复到口令 |
| 页面显示基础模式 | 环境报告中哪些组件缺失或未通过 | 先做可用练习，解决报告中的问题后重新完整启动 |
| 公司电脑禁止脚本或 EXE | 是否受到组织应用控制或脚本策略限制 | 由管理员提供允许的教学环境；安装脚本不绕过组织策略 |

Windows 完整包可离线完成已有组件的检查与启动。Vol3 分析新镜像可能还需要匹配符号；可使用课程提供的离线符号集合，不能把缺符号当成缺 Python。

## 06 / Kali 一键准备

Kali 学员使用 Kali 学习资料包。在根目录打开 Bash，运行：

~~~bash root
bash 00_一键安装_Kali.sh
~~~

脚本通过 apt 安装系统工具，在当前目录 .runtime/kali 创建 Python 3 虚拟环境，并将 zsteg 安装到这个目录。它需要网络和 sudo / 管理员权限，不向系统 Python 执行 pip 安装。准备完后自动启动学习平台；以后运行：

~~~bash root
bash 启动学习平台.sh
~~~

Vol2 使用随资料包提供的 Linux 独立版和对应依赖。Kali 安装流程附有 Bash 语法验证，仍需在实际 Kali 版本上执行验证；本次 Windows 验收不代替 Kali 实机测试。

## 07 / 可选：Windows PowerShell 手动检查

以下命令从 Windows 完整包根目录执行，使用 Windows 自带的 PowerShell，不需要 Python：

~~~powershell root
powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\tools\bootstrap.ps1' -Mode Check -NoLaunch
~~~

明确需要重新安装 VC++ x64 运行库时：

~~~powershell root
powershell.exe -NoProfile -ExecutionPolicy Bypass -File '.\tools\bootstrap.ps1' -Mode Repair -InstallVCRuntime -NoLaunch
~~~

命令中的执行策略参数只作用于这次 PowerShell 进程。脚本会先验证随包安装器的 SHA256 和 Microsoft 数字签名，未通过验证就停止，不会忽略签名错误。
