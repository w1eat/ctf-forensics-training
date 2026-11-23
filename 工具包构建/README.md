# 课程维护源码

学员使用根目录的“学员工具与练习_Windows64.zip”或“CTF取证基础_Kali学习资料.zip”。授课资料与维护源码在“讲师课件与逐题题解.zip”。

- 课件源码：讲义、题解、课堂课件及统一首页的内容和模板。
- 工具包构建：本地服务、分析模块、安装脚本、打包与验收脚本。
- 下载缓存：固定版本的原始安装包、源码与依赖；用于离线重建，不随学员包重复分发。
- output：维护验收记录，不随学员包分发。

在工作区使用包内 Python 运行“工具包构建/package_release.py”可重建并整理交付包；“finalize_delivery.py”负责精简首页下载、重复文档和嵌套分发包。完成后运行“verify_portal_links.py”核对入口链接。

“clean_delivery_workspace.ps1”默认仅预览；加 -Apply 清理已核对的测试副本、编译暂存和重复文档。保留原始上传文件及第三方许可证。

各运行时与工具的版本、来源、SHA256 和许可见学员包内 TOOL_MANIFEST.json、SHA256SUMS.txt、licenses。Kali 安装脚本已做语法检查，尚未实机验证。
