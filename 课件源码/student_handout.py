"""Build the student narrative, paired shell commands, and worked exercises."""
from pathlib import Path
import re
SOURCE=Path(__file__).resolve().parent
ROOT=SOURCE.parent
NAME='CTF取证基础_学员讲义'
KALI={
  1:[r'''sha256sum ./01_file/unknown.dat
file ./01_file/unknown.dat
xxd -g 1 -l 32 ./01_file/unknown.dat
exiftool -a -u -G1 ./01_file/unknown.dat
exiftool -b -Comment ./01_file/unknown.dat
printf '%s' 'ZmxhZ3tmaWxlX3R5cGVfYmVmb3JlX2V4dGVuc2lvbn0=' | base64 -d
printf '\n' '''],
  2:[r'''xxd -g 1 -l 40 ./02_png/broken_width.png
pngcheck -v ./02_png/broken_width.png
python3 ./tools/finspect.py png ./02_png/broken_width.png
python3 ./tools/recover_width.py ./02_png/broken_width.png ./out/fixed_width.png
pngcheck -v ./out/fixed_width.png
exiftool -ImageWidth -ImageHeight -Comment ./out/fixed_width.png'''],
  3:[r'''exiftool -ImageWidth -ImageHeight -ColorType ./03_lsb/quiet.png
python3 ./tools/extract_lsb.py ./03_lsb/quiet.png ./out/lsb.bin
xxd -g 1 -l 64 ./out/lsb.bin
strings -a -n 4 ./out/lsb.bin''',
     r'''zsteg ./03_lsb/quiet.png
zsteg -E b1,r,lsb,xy ./03_lsb/quiet.png > out/zsteg.bin
strings -a -n 4 out/zsteg.bin'''],
  4:[r'''python3 ./tools/finspect.py scan ./04_archive/carrier.bin
xxd -g 1 -s 512 -l 32 ./04_archive/carrier.bin
python3 ./tools/carve.py ./04_archive/carrier.bin ./out/carved.zip --offset 0x200
7z l ./out/carved.zip
7z t ./out/carved.zip
7z x ./out/carved.zip -o./out/carved -y
cat ./out/carved/answer.txt'''],
  5:[r'''mmls ./05_disk/tiny_fat16.dd
fls -r -o 2048 ./05_disk/tiny_fat16.dd
fls -r -d -o 2048 ./05_disk/tiny_fat16.dd
icat -r -o 2048 ./05_disk/tiny_fat16.dd 4 > out/recovered.txt
cat out/recovered.txt
python3 ./tools/read_training_fat.py ./05_disk/tiny_fat16.dd ./out/recovered_by_structure.txt
sha256sum out/recovered.txt out/recovered_by_structure.txt'''],
  6:[r'''file ./06_sqlite/case.db
sqlite3 -readonly ./06_sqlite/case.db ".tables"
sqlite3 -readonly ./06_sqlite/case.db ".schema artifacts"
sqlite3 -readonly ./06_sqlite/case.db "PRAGMA table_info(artifacts);"
sqlite3 -readonly -header -column ./06_sqlite/case.db "SELECT id,name,deleted,note FROM artifacts ORDER BY id;"
sqlite3 -readonly -header -column ./06_sqlite/case.db "SELECT id,name,note FROM artifacts WHERE deleted=1;"
python3 ./tools/query_case.py ./06_sqlite/case.db'''],
  7:[r'''grep -n 'case_notes.zip' ./07_logs/audit.jsonl
grep -n 'download_completed' ./07_logs/audit.jsonl
grep -nE 'r-101|r-102|r-103' ./07_logs/access.log
python3 ./tools/timeline.py ./07_logs/audit.jsonl'''],
  8:[r'''file ./public_examples/garden_demo.jpg
strings -a -n 4 ./public_examples/garden_demo.jpg | grep -n 'flag{'
strings -a -t x -n 8 ./public_examples/garden_demo.jpg
python3 ./tools/finspect.py scan ./public_examples/garden_demo.jpg'''],
  9:[r'''exiftool -a -u -G1 ./public_examples/cat_demo.jpg
exiftool -b -XMP:License ./public_examples/cat_demo.jpg
printf '%s' 'ZmxhZ3ttZXRhZGF0YV90aGVuX2Jhc2U2NH0=' | base64 -d
printf '\n' '''],
  10:[r'''xxd -g 1 -l 40 ./02_png/broken_header.png
xxd -g 1 -l 40 ./02_png/good.png
python3 ./tools/finspect.py patch-png-header ./02_png/broken_header.png ./out/fixed_header.png
pngcheck -v ./out/fixed_header.png
sha256sum ./02_png/good.png ./out/fixed_header.png'''],
  11:[r'''python3 ./tools/zip_flags.py inspect ./04_archive/flagged.zip
python3 ./tools/zip_flags.py clear ./04_archive/flagged.zip ./out/flags_fixed.zip
7z t ./out/flags_fixed.zip
7z x ./out/flags_fixed.zip -o./out/flags_fixed -y
cat ./out/flags_fixed/note.txt'''],
  12:[r'''cat ./04_archive/words.txt
python3 ./tools/finspect.py tryzip ./04_archive/locked.zip ./04_archive/words.txt
7z t ./04_archive/locked.zip -ptraining2026
7z x ./04_archive/locked.zip -ptraining2026 -o./out/unlocked -y
cat ./out/unlocked/note.txt'''],
  13:[r'''cat ./08_memory/case_a/pslist.csv
grep -n '^3180,' ./08_memory/case_a/cmdline.csv
printf '%s' 'ZmxhZ3tyZWFkX3RoZV9jb21tYW5kX2xpbmV9' | base64 -d
printf '\n' ''',
      r'''img='./memory.raw'
sha256sum "$img"
vol -f "$img" windows.info
vol -f "$img" windows.pslist
vol -f "$img" windows.pstree
vol -f "$img" windows.cmdline --pid 3180'''],
  14:[r'''cat ./08_memory/case_b/cmdline.csv
grep -n '^2460,' ./08_memory/case_b/handles.csv
cat ./08_memory/case_b/filescan.txt
cat ./08_memory/case_b/exported_memo.txt''',
      r'''vol -f "$img" windows.cmdline --pid 2460
vol -f "$img" windows.handles --pid 2460
vol -f "$img" windows.filescan
mkdir -p out/files
vol -f "$img" -o out/files windows.dumpfiles --virtaddr 0xffffa10200123070
ls -l out/files'''],
  15:[r'''cat ./08_memory/case_c/pslist.csv
cat ./08_memory/case_c/cmdline.csv
strings -a -t x ./08_memory/case_c/process_2460_excerpt.bin
strings -a -e l -t x ./08_memory/case_c/process_2460_excerpt.bin
python3 ./08_memory/search_excerpt.py ./08_memory/case_c/process_2460_excerpt.bin
xxd -g 1 -s 0x11c -l 64 ./08_memory/case_c/process_2460_excerpt.bin''',
      r'''mkdir -p out/proc
vol -f "$img" -o out/proc windows.memmap --pid 2460 --dump
ls -l out/proc
strings -a -t x out/proc/pid.2460.dmp | grep 'flag{'
strings -a -e l -t x out/proc/pid.2460.dmp | grep 'flag{' '''],
}
STUDENT_REPHRASE={
    '把原理讲清楚':'理解原理与适用条件',
    '必须讲清的边界':'方法的适用条件',
    '提问与排错':'自检与排错',
    '验证与讲解':'验证与复盘',
    '让学员说出“来源字段”和“解码步骤”。':'你需要记录信息的来源字段和解码步骤。',
    '让学员说出':'你需要解释',
    '让学员说明':'你需要说明',
    '让学员对比':'请对比',
    '先让学员解释':'先解释',
    '再解释为何':'再说明为何',
    '口令为公开教学值':'口令为公开练习值',
    '如果工具清单显示已包含 John Jumbo，或在自己的 Linux 环境中已安装，则运行：':
      '下面是 Kali Bash 的 John Jumbo 拓展路线。先安装 Kali 的 john 包，并确认 zip2john 与 john 的入口；Windows 工具包未含 John，不在 PowerShell 执行这段：',
    'Windows 现场优先使用上面的已验证命令；':'Windows 使用上面的 Python/7-Zip 路线；',
    '记事本命令行没有文件路径，提供了模拟的进程映射页片段':'记事本命令行没有文件路径，材料提供了模拟的进程映射页片段',
}

def case_sections():
    text=(SOURCE/'逐题题解.md').read_text(encoding='utf-8-sig')
    matches=list(re.finditer(r'^## (\d{2}) · (.+)$',text,re.M))
    sections=[]
    for m in matches:
        number=int(m[1])
        if number not in KALI:continue
        following=re.search(r'^## ',text[m.end():],re.M)
        end=m.end()+following.start() if following else len(text)
        body=text[m.end():end].strip()
        for original,replacement in STUDENT_REPHRASE.items():body=body.replace(original,replacement)
        body=body.replace('从 labs 运行','从 labs 运行').replace('本题可直接运行的读题命令','本题的材料读取命令')
        count=0
        def pair(block):
            nonlocal count
            original=block[1].strip()
            kali=KALI[number][count].strip();count+=1
            ram=' ram' if ('python $v3 -f $img' in original) else ''
            return ('~~~powershell'+ram+'\n'+original+'\n~~~\n\n'
                    '~~~bash'+ram+'\n'+kali+'\n~~~')
        body=re.sub(r'~~~powershell\n(.*?)\n~~~',pair,body,flags=re.S)
        if count!=len(KALI[number]):raise ValueError(f'Case {number}: {count} Windows blocks, expected {len(KALI[number])}')
        # These are actual shell instructions, not sample outputs.
        if number==4:body=body.replace('~~~text\ndd if=','~~~bash\ndd if=')
        if number==12:
            body=body.replace('~~~text\nzip2john','~~~bash\nzip2john')
            body=body.replace('zip2john 04_archive/locked.zip > out/locked.hash',
                              'sudo apt install john\ncommand -v zip2john john\nzip2john 04_archive/locked.zip > out/locked.hash')
        sections.append((number,'## 案例 '+f'{number:02} · '+m[2]+'\n\n'+body+'\n'))
    if len(sections)!=15:raise ValueError('Expected 15 worked student cases')
    return sections

def foundations():
    return (SOURCE/'student_foundations.md').read_text(encoding='utf-8-sig')

def memory_chapter():
    return (SOURCE/'student_memory.md').read_text(encoding='utf-8-sig')

def memory_notes():
    prefix='''# Volatility 3 内存镜像分析 · 学员讲义\n\n按命令框标签选择 Windows PowerShell 或 Kali Bash，不能混用变量与路径语法。Windows 先从工具包启动课堂终端，默认目录为 labs；Kali 先准备 Python 3 环境并进入资料包的 labs。示例输出只供阅读。\n\n'''
    return prefix+memory_chapter()+'\n\n'+''.join(s for n,s in case_sections() if n>=13)

def build_markdown():
    text=foundations()+'\n'+memory_chapter()
    text+='''\n## 24 / 练习前检查\n\n接下来的代码均从 labs 运行，输出写入 out。Windows 使用课堂终端；Kali 先完成工具安装并进入资料包的 labs。凡标注“真实 RAM”的命令都需要另有真实镜像，不用于 08_memory 的 CSV 或片段。\n\n两套系统的结果应在内容意义上相同，工具版本、终端颜色、列宽和进度信息可能不同。遇到错误，先核对当前目录、输入文件、命令框环境、依赖和选项；不要把换系统当作验证方法。\n\n'''
    text+='\n'.join(s for _,s in case_sections())
    text+='''\n## 25 / 课后自检与记录模板\n\n完成后，尝试不看答案回答：为什么扩展名不足以判定格式？PNG 的 CRC 覆盖哪些字节？LSB 提取必须固定哪些参数？分区扇区与文件偏移有什么区别？cmdline 与命令历史有什么区别？导出文件偏移为什么不等于进程虚拟地址？\n\n记录模板：输入及 SHA256；工作目录与 Shell；工具及版本；完整命令；原始输出；关键字段、对象或偏移；转换方法；验证步骤；结论与未确认范围。\n\n## 26 / 工具、参考资料与验证范围\n\nWindows 工具入口、版本与分发许可见《工具包使用指南》和 TOOL_MANIFEST.json。Kali 的安装命令需要网络，安装后才能按题目离线分析；本资料包不含 Python 3 / Ruby 的 Linux 运行时，额外附有 Vol2 Linux 独立兼容工具。\n\nWindows 随包路线经过实跑；Kali 语法与选项依据下列官方资料核对，本次未在可运行 Kali 上执行。真实 RAM 未随包提供，内存案例的材料读取可本地复现，镜像解析还取决于实际镜像与匹配符号。\n\n- Kali 7zip 包与入口：https://www.kali.org/tools/7zip/\n- Kali ExifTool 包：https://www.kali.org/tools/libimage-exiftool-perl/\n- Kali TSK 包与命令：https://www.kali.org/tools/sleuthkit/\n- Kali John Jumbo：https://www.kali.org/tools/john/\n- zsteg 上游参数：https://github.com/zed-0xff/zsteg\n- Volatility 3 Windows 教程：https://volatility3.readthedocs.io/en/stable/getting-started-windows-tutorial.html\n- SQLite CLI：https://sqlite.org/cli.html\n\n公开题的图片是自制同考点复现，来源与原件区别见 labs/public_examples/SOURCES.md。未把复现 flag 当作官方原题答案。\n'''
    # The handout itself must have no presenter-facing instructions.
    for bad in ('让学员','给学员讲','讲师','建议课堂节奏'):
        if bad in text:raise ValueError('Presenter-oriented language remains: '+bad)
    return text

if __name__=='__main__':
    (ROOT/(NAME+'.md')).write_text(build_markdown(),encoding='utf-8')
    print('Student handout generated:',ROOT/(NAME+'.md'))
