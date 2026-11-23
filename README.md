# CTF 取证基础专项培训

统一入口：[index.html](index.html)。课程、15 道例题及题解、工具和常见解题流程均从这里进入。

Windows：完整解压“学员工具与练习_Windows64.zip”，双击“00_一键配置并启动.cmd”。适用 Windows 10/11 x64，无需预装 Python 2、Python 3 或 Ruby。保留启动窗口，即可使用可视化工具台。

Kali：解压对应资料包，在 Bash 首次运行“bash 00_一键安装_Kali.sh”，之后运行“bash 启动学习平台.sh”。首次安装依赖需要网络和 sudo。

| 交付文件 | 用途 |
|---|---|
| [学员工具与练习_Windows64.zip](学员工具与练习_Windows64.zip) | Windows 学员完整包 |
| [CTF取证基础_Kali学习资料.zip](CTF取证基础_Kali学习资料.zip) | Kali 学员资料与安装脚本 |
| [讲师课件与逐题题解.zip](讲师课件与逐题题解.zip) | 投影课件、备课题解与维护源码 |
| [Volatility3_Windows离线符号.zip](Volatility3_Windows离线符号.zip) | 可选离线符号，按镜像需要准备 |

启动异常时运行“05_环境检查与修复.cmd”；社区插件不可用时运行“06_仅基础工具启动.cmd”。详见[环境安装与故障排查](环境安装与故障排查.html)。仅阅读资料可以直接打开 index.html。

内存读题练习使用合成输出；真实分析需另备内存镜像及匹配符号。命令框已标注 Windows / Kali。文件校验值见“分发包_SHA256SUMS.txt”。

课件源码、工具包构建和 output 用于课程维护与验收，无需发给学员。
