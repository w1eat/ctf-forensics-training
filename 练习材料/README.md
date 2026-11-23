# CTF 取证基础 · 学员练习

从本目录运行课件中的相对路径命令。先保留原件并建立副本。

七组自制题与两份公开题同考点自制复现附件。所有自制数据可离线分析，不连接外部目标。

## 01 · 文件识别与元数据

按课件对应练习页完成，提交 flag 与 3～5 行解题记录。

## 02 · PNG 宽度恢复

按课件对应练习页完成，提交 flag 与 3～5 行解题记录。

## 03 · 红通道 LSB

按课件对应练习页完成，提交 flag 与 3～5 行解题记录。

## 04 · 偏移分离 ZIP

按课件对应练习页完成，提交 flag 与 3～5 行解题记录。

## 05 · FAT16 删除项

按课件对应练习页完成，提交 flag 与 3～5 行解题记录。

## 06 · SQLite 软删除

按课件对应练习页完成，提交 flag 与 3～5 行解题记录。

## 07 · 日志时间线

按课件对应练习页完成，提交 flag 与 3～5 行解题记录。

## 环境与依赖

推荐使用配套“学员工具与练习_Windows64.zip”，完整解压后双击“01_启动课堂终端.cmd”，从 labs 运行命令。
该包内置 Python/Pillow、Volatility 3、7-Zip、ExifTool、SQLite、TSK、pngcheck、zsteg 与 BusyBox 常用命令。
若仅下载本练习 ZIP，则需要自己的工具环境。GNU 命令使用 Linux/WSL，Windows 参数对照见工具包使用指南。
John Jumbo、Autopsy 为可选拓展；小字典 ZIP 和磁盘题分别提供已验证的 Python/7-Zip 与 TSK 路线。
tools 里的 Python 脚本附源码，除 extract_lsb.py 依赖 Pillow 外只使用标准库。

## 补充练习材料

02_png/broken_header.png：已知 PNG 签名损坏；good.png 为对照件。
04_archive/flagged.zip：标志被设为加密，内容实际未加密。
04_archive/locked.zip：真正的教学口令 ZIP，配套 words.txt 为候选字典。
public_examples/*_demo.jpg：来源与原题的区别见 SOURCES.md，不是官方原件。

## 日志格式

access.log 为教学扩展访问日志，rid 对应 audit.jsonl 的 request_id；timestamp 的 Z 表示 UTC。
练习 07 按 flag{IP_HHMMSS} 提交，HHMMSS 取 UTC+8 下载完成时间，不含冒号。

## 输出与验证

脚本输出放在 out/，不要覆盖原件。哈希见 SHA256SUMS.txt，清单不包含自身。
题目校验答案在 HTML 本地完成，适合教学复核，不是竞赛防作弊系统。

## Volatility 3 内存专题

08_memory 提供三道合成输出读题例题、模拟导出片段与命令手册，不是完整 RAM。真实镜像另行提供。
