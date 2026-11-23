# Volatility 3 内存专题 · 教学例题

本目录是三个合成输出读题例题，不含真实 RAM。CSV 是教学摘要，文本和二进制是模拟导出片段。
不要改后缀当成内存镜像，也不能用这些片段代替实际内存解析。

A：从列表找到 PID 3180，再读启动参数，识别编码后还原 flag。
B：关联 PID 2460、memo.txt、虚拟文件对象与模拟导出结果，说明导出步骤。
C：选择记事本进程映射页路线，用 ASCII / UTF-16LE 检索模拟片段。

课件同时给出取得真实镜像后应运行的 Volatility 3 命令；实际读取例题的命令与题解见同目录手册。
从练习材料根目录执行：python ./08_memory/search_excerpt.py ./08_memory/case_c/process_2460_excerpt.bin
该脚本只使用 Python 3 标准库，不解析 RAM、不推断 PID。
