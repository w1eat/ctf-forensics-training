from html import escape as esc

GROUPS = [('方法与命令基础', 'METHOD & SHELL', 15), ('文件分析工具', 'FILE ANALYSIS', 35), ('图片与隐写方法', 'IMAGE & STEGANOGRAPHY', 35), ('压缩包与文件提取', 'ARCHIVE & CARVING', 25), ('磁盘与数据库', 'DISK & DATABASE', 30), ('Vol3 内存镜像', 'VOLATILITY 3', 45), ('日志与时间线', 'LOGS & TIMELINES', 15), ('题型复盘与自测', 'REVIEW & EXAMPLES', 10)]
SLIDES = []

def add(group, title, subtitle, body, notes, kind=""):
    SLIDES.append(dict(group=group, title=title, subtitle=subtitle, body=body, notes=notes, kind=kind))


def code(title, text):
    return f'<div class="codebox"><div class="code-top"><span>{esc(title)}</span><button type="button" data-copy aria-label="复制{esc(title, quote=True)}代码">复制</button></div><pre><code>{esc(text.strip())}</code></pre></div>'


def cols(left, right, kind=""):
    return f'<div class="cols {kind}"><div>{left}</div><div>{right}</div></div>'


def panel(title, text, kind=""):
    return f'<div class="panel {kind}"><h3>{title}</h3>{text}</div>'


def callout(text, kind=""):
    return f'<div class="callout {kind}">{text}</div>'


def table(headers, rows):
    return '<div class="table-wrap"><table><thead><tr>' + ''.join(f'<th>{h}</th>' for h in headers) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join(f'<td>{c}</td>' for c in row) + '</tr>' for row in rows) + '</tbody></table></div>'


def steps(items):
    return '<div class="steps">' + ''.join(f'<div class="step"><span>{i:02}</span><div><h4>{a}</h4><p>{b}</p></div></div>' for i, (a, b) in enumerate(items, 1)) + '</div>'


def ref(title, url):
    return f'<p class="source">参考：<a href="{url}" target="_blank" rel="noopener noreferrer">{title} ↗</a></p>'


def flag_form(number, answer):
    return f'''<form class="flag-form" data-answer="{esc(answer, quote=True)}"><label for="flag-{number}">提交 flag · 仅在本机校验</label><div class="flag-line"><input id="flag-{number}" name="flag" placeholder="flag{{...}}" autocomplete="off" spellcheck="false" aria-describedby="flag-result-{number}"><button class="btn" type="submit">验证答案</button></div><div class="flag-result" id="flag-result-{number}" role="status">先完成分析，再验证结果。</div></form>'''


def hints(first, second):
    return f'<details class="hint-details"><summary>提示 1 · 确定方向</summary><p>{first}</p></details><details class="hint-details"><summary>提示 2 · 缩小范围</summary><p>{second}</p></details>'


def lab_download(minutes):
    return f'<div class="lab-top"><span class="pill gold">HANDS-ON / 教学合成数据</span><span class="lab-time">{minutes} MIN</span></div>'


add(0, 'CTF 取证基础', '', r'''


<div class="hero-grid">
  <div class="hero">
    <p class="hero-kicker">CTF FORENSICS / FOUNDATION COURSE</p>
    <h1>CTF 取证基础<br><span class="accent">从附件到证据。</span></h1>
    <p>读懂工具参数，掌握基础题的解题步骤。<br>用一条可以复现的路径，找到并验证 flag。</p>
    <div class="hero-stats"><div><strong>210<span class="small"> min</span></strong><span>建议培训时长</span></div><div><strong>81</strong><span>页基础课件</span></div><div><strong>07</strong><span>组自制练习 + 2 道公开例题</span></div></div>
    <button class="btn" data-goto="2">开始学习 <span aria-hidden="true">→</span></button>
  </div>
  <div class="hero-visual" aria-label="文件识别教学示意：从 PNG 文件签名发现附件的真实格式">
    <div class="evidence-file"><div class="evidence-top"><span>EVIDENCE / unknown.dat</span><span class="window-dots" aria-hidden="true"><i></i><i></i><i></i></span></div><div class="evidence-body"><div class="hex-labels"><span>OFFSET</span><span>HEX BYTES</span><span>ASCII</span></div><div class="hex-row"><span>0000</span><mark>89 50 4E 47</mark><span>0D 0A 1A 0A</span></div><div class="hex-row"><span>0008</span><span>00 00 00 0D</span><span>49 48 44 52</span></div><div class="hex-row dim"><span>0010</span><span>00 00 01 00</span><span>00 00 00 A0</span></div><div class="hex-row dim"><span>0018</span><span>08 02 00 00</span><span>00 4B 90 F6</span></div><div class="evidence-finding"><div class="finding-icon">✓</div><div><b>发现 PNG 签名</b><small>扩展名提供线索，内容提供证据。</small></div></div></div></div><div class="evidence-stamp">TRAINING EDITION<b>BEGINNER</b></div>
  </div>
</div>

''', '按模块约 210 分钟，可拆成两次授课。公开例题来自 picoCTF，配套七组自制基础题。每个工具都要讲用途、输入、参数、输出与验证。', 'cover')


add(0, '这次培训：基础要讲透，命令要会用', '建议分两次讲授；先讲工具，再用简单例题串起完整过程。', r'''

<div class="cols "><div><h3>四个学习目标</h3><ul class="checklist"><li>看懂字节、偏移、编码、结构与校验。</li><li>会查帮助、读参数、保存输出并验证结果。</li><li>掌握图片、压缩包、磁盘、数据库和内存的基础路线。</li><li>讲清每一道例题的“为什么”和“怎么做”。</li></ul><div class="callout">每个命令框均标注环境。七组自制题随课件下载；两道公开题附平台来源、完整讲解与自制复现附件。</div></div><div><span class="label">MODULES / 含演示与练习</span><div class="agenda-row"><span class="number">00</span><span>方法与命令基础</span><small>15 min</small></div><div class="agenda-row"><span class="number">01</span><span>文件分析工具</span><small>35 min</small></div><div class="agenda-row"><span class="number">02</span><span>图片与隐写方法</span><small>35 min</small></div><div class="agenda-row"><span class="number">03</span><span>压缩包与文件提取</span><small>25 min</small></div><div class="agenda-row"><span class="number">04</span><span>磁盘与数据库</span><small>30 min</small></div><div class="agenda-row"><span class="number">05</span><span>Vol3 内存镜像</span><small>45 min</small></div><div class="agenda-row"><span class="number">06</span><span>日志与时间线</span><small>15 min</small></div><div class="agenda-row"><span class="number">07</span><span>题型复盘与自测</span><small>10 min</small></div></div></div>

''', '总时长 210 分钟，是可裁剪建议。公开例题由讲师演示，自制题由学员练习；磁盘与内存可按环境选讲。', '')


add(0, '拿到附件后的固定流程', '先做成本低、信息量大的检查，再选择专项工具。', r'''


<div class="process"><div><b>01 / PRESERVE</b><h4>保留</h4><p>原件不改动<br>建立工作副本</p></div><div><b>02 / IDENTIFY</b><h4>识别</h4><p>大小、签名<br>类型与结构</p></div><div><b>03 / LOCATE</b><h4>定位</h4><p>元数据、字符串<br>流、行号、偏移</p></div><div><b>04 / EXTRACT</b><h4>提取</h4><p>按格式导出<br>在副本上修复</p></div><div><b>05 / VERIFY</b><h4>验证</h4><p>确认完整性<br>复做并记录</p></div></div>
<div class="cols "><div><div class="panel "><h3>每一步都带着问题</h3><p>为什么判断它是这种格式？<br>线索位于什么位置？<br>导出结果与原始证据如何对应？</p></div></div><div><div class="panel mint"><h3>卡住时回到已知事实</h3><p>确认输入和工具版本；检查偏移、时区、编码与流方向。一次只改变一个分析条件。</p></div></div></div>

''', '请学员口头复述五个动作。强调看到关键字不等于已经证明它就是答案：还要检查上下文、格式和题目要求。', '')


add(0, '先留原件，再做实验', '哈希帮助比较文件内容是否变化；它不能单独证明来源和真实性。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Windows PowerShell · 在 01_file 目录执行</span><button type="button" data-copy aria-label="复制Windows PowerShell · 在 01_file 目录执行代码">复制</button></div><pre><code>New-Item -ItemType Directory -Path .\work
Get-FileHash -LiteralPath .\unknown.dat -Algorithm SHA256
Copy-Item -LiteralPath .\unknown.dat -Destination .\work\unknown.dat
Get-FileHash -LiteralPath .\work\unknown.dat -Algorithm SHA256</code></pre></div></div><div><div class="steps"><div class="step"><span>01</span><div><h4>记下来源与大小</h4><p>记录题目、附件名、获取时间、文件大小与 SHA-256。</p></div></div><div class="step"><span>02</span><div><h4>只在副本上修改</h4><p>重命名、解压、修复、导出结果放在工作目录。</p></div></div><div class="step"><span>03</span><div><h4>保存关键过程</h4><p>记录工具版本、命令、偏移或行号；让另一位学员能够复现。</p></div></div></div></div></div><div class="callout "><strong>改扩展名通常不改变文件字节，哈希也通常不变。</strong>重编码、修改元数据、重新保存图片会改变内容。</div><p class="source">参考：<a href="https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash" target="_blank" rel="noopener noreferrer">Microsoft Learn · Get-FileHash ↗</a></p>

''', '工作目录不存在时执行 New-Item；已经存在可直接使用。将原件与副本的 SHA-256 进行比较。解释内容哈希与文件名、文件系统时间戳是不同维度，避免把哈希称为真实性证明。', '')


add(0, '先分清终端：PowerShell 与 Bash', '相同目的可能有不同命令；“能复制”之前先确认运行环境。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Windows PowerShell</span><button type="button" data-copy aria-label="复制Windows PowerShell代码">复制</button></div><pre><code>Get-Location
Get-ChildItem -Force
Get-Command python
&amp; &#x27;C:\Program Files\7-Zip\7z.exe&#x27; l .\sample.zip</code></pre></div></div><div><div class="codebox"><div class="code-top"><span>Linux Bash</span><button type="button" data-copy aria-label="复制Linux Bash代码">复制</button></div><pre><code>pwd
ls -la
command -v python3
7z l ./sample.zip</code></pre></div><div class="callout ">路径有空格需加引号。PowerShell 调用带引号的可执行文件路径时使用 <code>&amp;</code>；Bash 中直接调用。</div></div></div>

''', '现场展示当前目录。课件中 python 表示已配置的 Python 3；Linux 发行版可能需要使用 python3。不要把 PowerShell 的 & 调用语法照搬到 Bash。', '')


add(0, '读懂一条命令：输入、选项和输出', '理解参数，才能把示例迁移到自己的题目。', r'''

<div class="codebox"><div class="code-top"><span>Linux Bash · 结构拆解</span><button type="button" data-copy aria-label="复制Linux Bash · 结构拆解代码">复制</button></div><pre><code>strings -a -t x -n 6 sample.bin | grep -i flag &gt; hits.txt</code></pre></div><div class="table-wrap"><table><thead><tr><th>片段</th><th>含义</th><th>容易误解的地方</th></tr></thead><tbody><tr><td>strings</td><td>从文件中找可打印序列</td><td>不是完整文件解析器</td></tr><tr><td>-a -t x -n 6</td><td>全文件、十六进制偏移、至少 6 字符</td><td>每个工具的同名字母未必同义</td></tr><tr><td>| grep -i flag</td><td>把文本输出交给下一条命令筛选</td><td>管道不是把文件本身改写</td></tr><tr><td>> hits.txt</td><td>把文本输出写入新文件</td><td>会覆盖同名输出；二进制输出另行处理</td></tr></tbody></table></div><div class="callout ">Python 代码块先保存为 .py，再用 python 文件.py 执行；普通命令先看工具帮助。旧版 PowerShell 的 <code>&gt;</code> 可能重编码原生程序输出；提取二进制优先用工具输出参数或 Python <code>write_bytes()</code>。</div>

''', '解释命令与参数之间的空格、单/双引号和大小写。不要把带偏移的 strings 输出误认为原始文件内容。', '')


add(0, '工具地图：按问题选工具', '本课程使用少量常用工具建立方法，再补充可选工具。', r'''

<div class="table-wrap"><table><thead><tr><th>目的</th><th>工具</th><th>重点掌握</th></tr></thead><tbody><tr><td>识别与查看</td><td>file / 010 Editor / WinHex / xxd</td><td>格式、偏移、字节序</td></tr><tr><td>检索与元数据</td><td>GNU strings / grep / ExifTool</td><td>字符串编码、定位、标签</td></tr><tr><td>图片隐写</td><td>pngcheck / zsteg / StegSolve / steghide</td><td>块结构、CRC、通道与提取参数</td></tr><tr><td>压缩与分离</td><td>7-Zip / binwalk / dd / Python</td><td>目录、密码线索、偏移与边界</td></tr><tr><td>镜像与数据库</td><td>Autopsy / The Sleuth Kit / SQLite</td><td>分区、元数据地址、表结构</td></tr><tr><td>运行与日志痕迹</td><td>Volatility 3 / PowerShell / Python</td><td>版本、插件、时区、关联键</td></tr></tbody></table></div>

''', '最低配置：十六进制查看器、7-Zip、ExifTool、Python 3。Linux/WSL 提供 file、strings、xxd、grep、dd；zsteg 依赖 Ruby，脚本 LSB 提取依赖 Pillow。磁盘和内存工具可选装。', '')


add(0, '读懂十六进制视图的三列', '偏移说明位置，字节说明内容，ASCII 栏帮助阅读。', r'''


<div class="hex-board"><div><span class="offset">00000000</span><mark>89 50 4E 47 0D 0A 1A 0A</mark><span class="ascii">.PNG....</span></div><div><span class="offset">00000008</span>00 00 00 0D 49 48 44 52<span class="ascii">....IHDR</span></div><div class="legend"><span>左 / Offset：从 0 开始的字节位置</span><span>中 / Hex：一个字节用两位表示</span><span>右 / ASCII：不可打印字节常显示为点</span></div></div>
<div class="cols "><div><div class="callout"><strong>0x10 = 十进制 16。</strong><br>不是第 10 个字节；从偏移 0 到 0x0F 共 16 字节。</div></div><div><div class="callout gold"><strong>小测：</strong>偏移 0x08 开始的 <code>00 00 00 0D</code>，在 PNG 大端序字段中表示长度 13。</div></div></div><div class="codebox"><div class="code-top"><span>Windows PowerShell · 查看文件字节</span><button type="button" data-copy aria-label="复制Windows PowerShell · 查看文件字节代码">复制</button></div><pre><code>Format-Hex -LiteralPath .\unknown.dat</code></pre></div>

''', '演示光标移动时偏移如何变化。说明 ASCII 中的点是查看器占位符，并不代表原始字节都是 2E。PNG 块长度字段采用大端序，本课不展开复杂结构体。', '')


add(1, '扩展名会骗人，文件头先发言', 'Magic bytes 是格式线索；仍需结合结构和解析结果确认。', r'''

<div class="table-wrap"><table><thead><tr><th>格式</th><th>常见起始字节（十六进制）</th><th>如何理解</th></tr></thead><tbody><tr><td>PNG</td><td><code>89 50 4E 47 0D 0A 1A 0A</code></td><td>固定 8 字节签名，随后检查 PNG 数据块</td></tr><tr><td>JPEG</td><td><code>FF D8 FF</code></td><td>常见起始特征，还需检查后续标记</td></tr><tr><td>ZIP</td><td><code>50 4B 03 04</code></td><td>常见本地文件头；空 ZIP 等情况不同</td></tr><tr><td>PDF</td><td><code>25 50 44 46 2D</code></td><td>对应可读字符 <code>%PDF-</code></td></tr><tr><td>DOCX / XLSX / PPTX</td><td>常见为 <code>50 4B 03 04</code></td><td>通常是 ZIP 容器，继续看内部目录</td></tr></tbody></table></div><div class="callout ">看到 <code>PK</code>，还不能直接断言“这只是一个普通压缩包”。先列目录，检查 <code>word/</code>、<code>xl/</code>、<code>ppt/</code> 等结构。</div><p class="source">参考：<a href="https://www.w3.org/TR/PNG-Structure.html" target="_blank" rel="noopener noreferrer">W3C · PNG 文件结构 ↗</a></p>

''', '只要求记住 PNG、JPEG、ZIP 三类常见特征。签名可能被伪造、损坏或出现在嵌套内容中，因此要结合解析。不要把所有 ZIP 都描述成以 PK0304 开头。', '')


add(1, 'file：先判断真实类型', '读取内容特征，不依赖文件扩展名。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash</span><button type="button" data-copy aria-label="复制Linux Bash代码">复制</button></div><pre><code>file 01_file/unknown.dat
file -b 01_file/unknown.dat
file --mime-type 01_file/unknown.dat</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>选项</th><th>作用</th></tr></thead><tbody><tr><td>-b</td><td>不显示文件名前缀，便于脚本处理</td></tr><tr><td>--mime-type</td><td>显示候选 MIME 类型</td></tr><tr><td>输出 PNG image data</td><td>提示继续检查 PNG 结构和元数据</td></tr></tbody></table></div><div class="callout ">输出 <code>data</code> 只表示未成功识别，不能直接推断加密。Windows 可用十六进制查看器或 Python 观察签名。</div></div></div>

''', '演示这三个命令的差异。file 的判断来自规则库，损坏的签名或不完整数据会影响结果。', '')


add(1, 'xxd 与 Format-Hex：精确看到某个位置', '重点不是“乱码”，而是偏移、字段长度与原始字节。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash</span><button type="button" data-copy aria-label="复制Linux Bash代码">复制</button></div><pre><code>xxd -g 1 -l 32 01_file/unknown.dat
xxd -g 1 -s 0x10 -l 16 01_file/unknown.dat</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>选项</th><th>作用</th></tr></thead><tbody><tr><td>-g 1</td><td>按 1 字节分组显示</td></tr><tr><td>-l 32</td><td>最多读 32 字节</td></tr><tr><td>-s 0x10</td><td>从十六进制偏移 0x10 开始</td></tr></tbody></table></div><div class="codebox"><div class="code-top"><span>Windows PowerShell</span><button type="button" data-copy aria-label="复制Windows PowerShell代码">复制</button></div><pre><code>Format-Hex -LiteralPath .\01_file\unknown.dat</code></pre></div></div></div>

''', '让学员根据前 32 字节定位 IHDR、宽高。Format-Hex 示例兼容常见 PowerShell，不混入只在部分新版存在的 -Count 等参数。', '')


add(1, 'GNU strings：带位置地检索可读内容', '普通字符串没结果时，再考虑 UTF-16LE、压缩和其他表示。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash · GNU strings</span><button type="button" data-copy aria-label="复制Linux Bash · GNU strings代码">复制</button></div><pre><code>strings -a -t x -n 6 sample.bin
strings -a -e l -t x sample.bin
strings -a sample.bin | grep -i &#x27;flag&#x27;</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>选项</th><th>作用</th></tr></thead><tbody><tr><td>-a</td><td>扫描整个文件</td></tr><tr><td>-n 6</td><td>最小可打印序列长度为 6</td></tr><tr><td>-t x</td><td>输出文件内十六进制偏移</td></tr><tr><td>-e l</td><td>尝试 16 位小端字符序列</td></tr></tbody></table></div><div class="callout ">输出行前的偏移是线索位置；“没找到”不代表不存在。GNU 与 Windows Sysinternals 的 strings 参数不同。</div></div></div><p class="source">参考：<a href="https://sourceware.org/binutils/docs/binutils/strings.html" target="_blank" rel="noopener noreferrer">GNU Binutils · strings ↗</a></p>

''', '用公开例题 garden.jpg 演示第一条和第三条；再展示 UTF-16LE 文本为什么需要 -e l。', '')


add(1, 'grep 与 Select-String：过滤文本、保留行号', '先缩小结果，再回到原文件核对上下文。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash</span><button type="button" data-copy aria-label="复制Linux Bash代码">复制</button></div><pre><code>grep -nEi &#x27;flag|password|secret&#x27; notes.txt
grep -n -A 2 -B 2 &#x27;r-103&#x27; access.log</code></pre></div></div><div><div class="codebox"><div class="code-top"><span>Windows PowerShell</span><button type="button" data-copy aria-label="复制Windows PowerShell代码">复制</button></div><pre><code>Select-String -Path .\notes.txt -Pattern &#x27;flag|password|secret&#x27;
Select-String -Path .\access.log -Pattern &#x27;r-103&#x27; -Context 2,2</code></pre></div><div class="callout "><code>-n</code> 行号，<code>-i</code> 忽略大小写，<code>-E</code> 扩展正则，<code>-A/-B</code> 后/前文。文本行号不等于二进制字节偏移。</div></div></div>

''', '强调 grep 与 Select-String 处理文本；二进制定位用 strings -t x 或十六进制搜索。课件的 notes.txt、sample.bin 属语法示意；配套题的文件路径会明确给出。', '')


add(1, 'ExifTool：从全部标签到一个字段', '先全面查看，再精确提取需要的原始值。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>跨平台 · ExifTool</span><button type="button" data-copy aria-label="复制跨平台 · ExifTool代码">复制</button></div><pre><code>exiftool 01_file/unknown.dat
exiftool -a -u -G1 -s 01_file/unknown.dat
exiftool -b -Comment 01_file/unknown.dat</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>选项</th><th>作用</th></tr></thead><tbody><tr><td>-a / -u</td><td>重复标签 / 未知标签</td></tr><tr><td>-G1 / -s</td><td>标签分组 / 简短名称</td></tr><tr><td>-b -Comment</td><td>仅输出 Comment 的值</td></tr></tbody></table></div><div class="callout ">读取默认不写入文件。带 <code>-标签=值</code> 的命令会修改元数据，课堂分析阶段先不使用。</div></div></div><p class="source">参考：<a href="https://exiftool.org/TagNames/PNG.html" target="_blank" rel="noopener noreferrer">ExifTool · PNG 标签 ↗</a></p>

''', '先看完整输出，定位 Comment；用 -b 精确提取，避免把标签名和冒号一起送入 Base64 解码器。', '')


add(1, 'Python：读字节、找偏移、写新文件', '短脚本既是通用工具，也能解释 GUI 中的操作。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Python 3 · 保存为 inspect_bytes.py</span><button type="button" data-copy aria-label="复制Python 3 · 保存为 inspect_bytes.py代码">复制</button></div><pre><code>from pathlib import Path
data = Path(&quot;01_file/unknown.dat&quot;).read_bytes()
print(len(data))
print(data[:8].hex(&quot; &quot;))
print(data.find(b&quot;Comment&quot;))
# 切片 [起点:终点]，终点不包含
Path(&quot;first32.bin&quot;).write_bytes(data[:32])</code></pre></div></div><div><div class="steps"><div class="step"><span>01</span><div><h4>read_bytes()</h4><p>保持二进制原样读取，不做字符编码转换。</p></div></div><div class="step"><span>02</span><div><h4>find()</h4><p>返回第一个匹配偏移；-1 表示未找到。</p></div></div><div class="step"><span>03</span><div><h4>write_bytes()</h4><p>把字节写到新的输出文件，不重新保存原件。</p></div></div></div></div></div>

''', '解释 Python 切片与偏移从 0 开始。find 是定位候选，解析结构仍需知道长度和边界。', '')


add(1, '编码识别：先说明字节如何表示', 'Base64、Hex、URL 编码是表示转换；仅凭“像乱码”不能判断为加密。', r'''

<div class="cols "><div>
<div class="decode-lab"><label for="decode-input">输入一段编码文本</label><textarea id="decode-input" spellcheck="false">ZmxhZ3toZWxsb19mb3JlbnNpY3N9</textarea><div class="decode-actions"><button class="tool-btn" data-decode="base64">From Base64</button><button class="tool-btn" data-decode="hex">From Hex</button><button class="tool-btn" data-decode="url">URL Decode</button></div><div class="decode-output" id="decode-output" role="status">选择对应的解码方式。</div><div class="decode-actions"><button class="tool-btn" data-encoding-example="ZmxhZ3toZWxsb19mb3JlbnNpY3N9">Base64 示例</button><button class="tool-btn" data-encoding-example="66 6c 61 67 7b 68 65 78 7d">Hex 示例</button><button class="tool-btn" data-encoding-example="flag%7Burl%7D">URL 示例</button></div><p class="small muted">本页在本机解码；演示输出按 UTF-8 文本解释。</p></div>
</div><div><div class="table-wrap"><table><thead><tr><th>线索</th><th>尝试</th><th>注意</th></tr></thead><tbody><tr><td>常见字母、数字、+、/、=</td><td>Base64 解码</td><td>形态仅提供候选；也有 URL-safe 变体</td></tr><tr><td>成对 0–9 / A–F</td><td>Hex 转字节</td><td>先确认是否真的表示十六进制</td></tr><tr><td>%7B、%2F 等</td><td>URL 解码</td><td>确认使用场景，避免盲目多层解码</td></tr></tbody></table></div></div></div><p class="source">参考：<a href="https://docs.python.org/3/library/base64.html" target="_blank" rel="noopener noreferrer">Python · base64 模块 ↗</a></p>

''', '点击三种示例并用对应方式还原。让学员观察文本变为 flag{hello_forensics}。强调解码后的输出也可能是二进制，需要重新识别类型，而不是强制转文字。', '')


add(1, '解码命令：Base64、Hex 与 URL', '示例先处理文本；得到二进制时应保存后重新识别。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Python 3 · 跨平台</span><button type="button" data-copy aria-label="复制Python 3 · 跨平台代码">复制</button></div><pre><code>import base64
from urllib.parse import unquote
print(base64.b64decode(&quot;ZmxhZ3tkZW1vfQ==&quot;).decode())
print(bytes.fromhex(&quot;66 6c 61 67 7b 64 65 6d 6f 7d&quot;).decode())
print(unquote(&quot;flag%7Bdemo%7D&quot;))</code></pre></div></div><div><div class="codebox"><div class="code-top"><span>Linux Bash · Base64</span><button type="button" data-copy aria-label="复制Linux Bash · Base64代码">复制</button></div><pre><code>printf &#x27;%s&#x27; &#x27;ZmxhZ3tkZW1vfQ==&#x27; | base64 -d</code></pre></div><div class="codebox"><div class="code-top"><span>Windows PowerShell</span><button type="button" data-copy aria-label="复制Windows PowerShell代码">复制</button></div><pre><code>[Text.Encoding]::UTF8.GetString(
  [Convert]::FromBase64String(&#x27;ZmxhZ3tkZW1vfQ==&#x27;)
)</code></pre></div><div class="callout ">三段代码的输出均为 <code>flag{demo}</code>。不必对每一串字符连续套所有解码。</div></div></div>

''', '逐个解释字符串与 bytes、UTF-8 decode 的关系；对错误输入说明报错可能来自填充或编码类型。', '')


add(1, '练习 01：文件头、标签与 Base64', '自制基础题 · 把三种工具串成一条路径。', r'''

<div class="lab-top"><span class="pill gold">HANDS-ON / 教学合成数据</span><span class="lab-time">7 MIN</span></div><div class="cols "><div><div class="lab-task"><h3>材料：01_file/unknown.dat</h3><ol><li>记录哈希，识别前 8 字节。</li><li>找到 Comment 并保留原值。</li><li>Base64 解码后提交 flag，写出证据位置。</li></ol><button class="btn secondary" data-download>下载全部学员练习 ↓</button></div><form class="flag-form" data-answer="flag{file_type_before_extension}"><label for="flag-1">提交 flag · 仅在本机校验</label><div class="flag-line"><input id="flag-1" name="flag" placeholder="flag{...}" autocomplete="off" spellcheck="false" aria-describedby="flag-result-1"><button class="btn" type="submit">验证答案</button></div><div class="flag-result" id="flag-result-1" role="status">先完成分析，再验证结果。</div></form></div><div><div class="codebox"><div class="code-top"><span>命令参考 · 从练习材料根目录运行</span><button type="button" data-copy aria-label="复制命令参考 · 从练习材料根目录运行代码">复制</button></div><pre><code>file 01_file/unknown.dat
exiftool -a -G1 -s 01_file/unknown.dat
exiftool -b -Comment 01_file/unknown.dat</code></pre></div><details class="hint-details"><summary>提示 1 · 方向与理由</summary><p>题目先问“真实格式”，因此第一步要验证文件内容，不能由 .dat 猜用途。确认 PNG 后，优先检查格式本来就能保存的文字字段；这比没有线索地枚举隐写参数更直接。只有在 Comment 中实际发现可疑编码值后，才提出“它可能是 Base64”的假设。</p></details><details class="hint-details"><summary>提示 2 · 缩小范围</summary><p>Comment 的值使用 Base64；也可以用本课编码演示解码。</p></details></div></div>

''', '答案 flag{file_type_before_extension}。真实格式为 256×160 RGB PNG，Comment 是 tEXt 字段。用 ExifTool 或十六进制查看均可完成。', '')


add(1, '公开例题 A：Glory of the Garden', 'picoCTF 2019 · 简单字符串检索题 · 讲师演示。', r'''

<div class="cols "><div><div class="panel mint"><h3>题目现象（转述）</h3><p>附件是一张正常显示的花园 JPEG，要求从图片文件中寻找 flag。</p><p>先让学员判断：能看到的画面，是否等于文件中的全部内容？</p></div></div><div><div class="steps"><div class="step"><span>01</span><div><h4>打开图片，仅完成观察</h4><p>画面正常不能排除元数据、尾部文本或其他字节。</p></div></div><div class="step"><span>02</span><div><h4>检查签名与可打印序列</h4><p>先做低成本检查，不直接猜隐写软件。</p></div></div><div class="step"><span>03</span><div><h4>定位命中的原始字节</h4><p>在十六进制视图确认上下文和位置。</p></div></div></div></div></div><p class="source">参考：<a href="https://play.picoctf.org/practice/challenge/44" target="_blank" rel="noopener noreferrer">picoCTF 平台入口 · garden_demo.jpg ↗</a></p>
<div class="callout gold"><strong>离线演示材料为自制复现，非官方原件。</strong>公开原题方法相同；附件、画面、哈希与 flag 不同，详见练习包 SOURCES.md。</div>
''', '公开原题方法讲解，来源为 picoCTF。官方旧附件域名在当前环境无法访问，未声称下载或验证官方原件。课堂改用 public_examples/ 下的自制 *_demo.jpg；A 复现答案 flag{strings_see_more_than_pixels}，B 复现答案 flag{metadata_then_base64}。先让学员判断，再执行页面命令。', '')


add(1, '公开例题 A：从字符串命中到原始字节', '完整讲解：识别 → 检索 → 记录偏移 → 核对。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash · 在 public_examples 目录</span><button type="button" data-copy aria-label="复制Linux Bash · 在 public_examples 目录代码">复制</button></div><pre><code>file garden_demo.jpg
strings -a -t x garden_demo.jpg | grep &#x27;flag{&#x27;
xxd -g 1 garden_demo.jpg | tail -n 12</code></pre></div></div><div><div class="panel mint"><h3>为什么这组命令有效？</h3><p>JPEG 查看器渲染图像；strings 扫描文件字节中的可打印序列。两者观察的对象不同。</p><p>命中后用字节偏移回到原文件，确认文字处于真实图像结束标记之后；仅有 strings 命中还不能说明藏匿位置。-t x 报输入偏移，grep -n 的行号不能代替它。</p><p class="small muted">本地 *_demo.jpg 使用 flag{...}；官方原件使用其实际格式，答案和文件哈希不可混用。</p></div></div></div><p class="source">参考：<a href="https://play.picoctf.org/practice/challenge/44" target="_blank" rel="noopener noreferrer">picoCTF 平台入口 ↗</a></p>
<div class="callout gold"><strong>离线演示材料为自制复现，非官方原件。</strong>公开原题方法相同；附件、画面、哈希与 flag 不同，详见练习包 SOURCES.md。</div>
''', '公开原题方法讲解，来源为 picoCTF。官方旧附件域名在当前环境无法访问，未声称下载或验证官方原件。课堂改用 public_examples/ 下的自制 *_demo.jpg；A 复现答案 flag{strings_see_more_than_pixels}，B 复现答案 flag{metadata_then_base64}。先让学员判断，再执行页面命令。', '')


add(1, '公开例题 B：information', 'picoCTF 2021 · 元数据 + Base64 · 讲师演示。', r'''

<div class="cols "><div><div class="panel mint"><h3>题目现象（转述）</h3><p>附件 cat_demo.jpg 能正常显示，提示关注文件细节。检查元数据时，License 字段出现长串可打印字符。</p></div></div><div><div class="codebox"><div class="code-top"><span>跨平台 · ExifTool</span><button type="button" data-copy aria-label="复制跨平台 · ExifTool代码">复制</button></div><pre><code>exiftool -a -G1 -s cat_demo.jpg
exiftool -b -XMP:License cat_demo.jpg</code></pre></div></div></div><div class="callout ">License 中异常字符形成编码假设；-G1 区分字段组，-b 只输出原值，避免把标签一起解码。成功得到完整 flag 后，仍要保留字段原值，证明答案的来源。</div><p class="source">参考：<a href="https://play.picoctf.org/practice/challenge/186" target="_blank" rel="noopener noreferrer">picoCTF 平台入口 · cat_demo.jpg ↗</a></p>
<div class="callout gold"><strong>离线演示材料为自制复现，非官方原件。</strong>公开原题方法相同；附件、画面、哈希与 flag 不同，详见练习包 SOURCES.md。</div>
''', '公开原题方法讲解，来源为 picoCTF。官方旧附件域名在当前环境无法访问，未声称下载或验证官方原件。课堂改用 public_examples/ 下的自制 *_demo.jpg；A 复现答案 flag{strings_see_more_than_pixels}，B 复现答案 flag{metadata_then_base64}。先让学员判断，再执行页面命令。', '')


add(1, '公开例题 B：提取字段，再解码', '讲清每一段管道的输入和输出，避免连标签名一起解码。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash</span><button type="button" data-copy aria-label="复制Linux Bash代码">复制</button></div><pre><code>exiftool -b -XMP:License cat_demo.jpg | base64 -d</code></pre></div></div><div><div class="codebox"><div class="code-top"><span>Python 3 · 所见字段值的解码</span><button type="button" data-copy aria-label="复制Python 3 · 所见字段值的解码代码">复制</button></div><pre><code>import base64
s = &quot;ZmxhZ3ttZXRhZGF0YV90aGVuX2Jhc2U2NH0=&quot;
print(base64.b64decode(s).decode(&quot;utf-8&quot;))</code></pre></div><div class="callout ">自制复现输出：<code>flag{metadata_then_base64}</code>。原始 License 值也应保留在题解中。</div></div></div><p class="source">参考：<a href="https://play.picoctf.org/practice/challenge/186" target="_blank" rel="noopener noreferrer">picoCTF 平台入口 ↗</a></p>
<div class="callout gold"><strong>离线演示材料为自制复现，非官方原件。</strong>公开原题方法相同；附件、画面、哈希与 flag 不同，详见练习包 SOURCES.md。</div>
''', '公开原题方法讲解，来源为 picoCTF。官方旧附件域名在当前环境无法访问，未声称下载或验证官方原件。课堂改用 public_examples/ 下的自制 *_demo.jpg；A 复现答案 flag{strings_see_more_than_pixels}，B 复现答案 flag{metadata_then_base64}。先让学员判断，再执行页面命令。', '')


add(2, '图片分析，先结构后隐写', '一张图片既有像素，也有承载像素的文件结构。', r'''


<div class="chunk-bar"><div>签名</div><div>IHDR</div><div>tEXt</div><div class="data-chunk">IDAT（压缩图像数据）</div><div>IEND</div><div class="tail-chunk">附加数据？</div></div><div class="chunk-captions"><span>PNG 的结构示意，非固定比例</span><span>规范定义 IEND 为 PNG 数据流结束</span></div>
<div class="cols "><div><div class="steps"><div class="step"><span>01</span><div><h4>正常信息先查完</h4><p>文字标签、尺寸、透明通道、文件大小是否合理？</p></div></div><div class="step"><span>02</span><div><h4>按格式定位边界</h4><p>PNG 块含长度、类型、数据和 CRC；不能只搜索一个 IEND 字符串。</p></div></div><div class="step"><span>03</span><div><h4>异常数据再验证</h4><p>尾部额外字节可能有线索，也可能是其他内容；提取后重新识别。</p></div></div></div></div><div><div class="panel mint"><h3>两个常见误区</h3><ul><li>改了宽高却没处理结构与 CRC，文件仍可能无法解析。</li><li>在数据内部搜到文件签名，就认为一定有可用的完整文件。</li></ul></div></div></div><p class="source">参考：<a href="https://www.w3.org/TR/PNG-Structure.html" target="_blank" rel="noopener noreferrer">W3C · PNG 文件结构 ↗</a></p>

''', '这里只理解结构。不要让初学者机械修改宽高或清除所谓伪加密标志。说明 IEND 应当通过数据块长度逐块解析定位；压缩数据里也可能偶然出现相同字节。', '')


add(2, 'pngcheck：知道哪里损坏，比盲修更重要', '按块查看 PNG，检查长度、顺序和 CRC。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>命令行 · 需先安装 pngcheck</span><button type="button" data-copy aria-label="复制命令行 · 需先安装 pngcheck代码">复制</button></div><pre><code>pngcheck -v 02_png/broken_width.png
pngcheck -v 02_png/good.png</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>观察</th><th>如何判断</th></tr></thead><tbody><tr><td>IHDR 尺寸</td><td>是否与题意和压缩图像数据矛盾</td></tr><tr><td>CRC error</td><td>块数据与保存的校验值不一致</td></tr><tr><td>IDAT 解码报错</td><td>可能是尺寸、压缩流或截断问题</td></tr><tr><td>No errors</td><td>结构检查通过，不代表不存在像素隐写</td></tr></tbody></table></div><div class="callout ">定位到 IHDR 错误后再分析字段。把 CRC 随意改到“通过”不会自动恢复原始像素。</div></div></div><p class="source">参考：<a href="https://github.com/pnggroup/pngcheck" target="_blank" rel="noopener noreferrer">pngcheck 上游 ↗</a></p>

''', 'good.png 是教学对照件，正式练习只要求分析 broken_width.png。先演示报错，再解释 width 字段与 CRC；pngcheck 是可选工具。', '')


add(2, '常见方法 01：恢复已知格式的文件头', '仅当确认签名损坏且其余结构合理时，在副本中修复。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Python 3 · 示例代码</span><button type="button" data-copy aria-label="复制Python 3 · 示例代码代码">复制</button></div><pre><code>from pathlib import Path
p = Path(&quot;broken_header.png&quot;)
data = bytearray(p.read_bytes())
data[:8] = bytes.fromhex(&quot;89 50 4E 47 0D 0A 1A 0A&quot;)
Path(&quot;fixed_header.png&quot;).write_bytes(data)</code></pre></div></div><div><div class="steps"><div class="step"><span>01</span><div><h4>先看损坏范围</h4><p>确认只是头 8 字节错误，后面是合理的 IHDR。</p></div></div><div class="step"><span>02</span><div><h4>写到新文件</h4><p>不覆盖原件；本例文件放在 02_png。</p></div></div><div class="step"><span>03</span><div><h4>重新解析</h4><p>pngcheck -v fixed_header.png，再验证能否正确显示。</p></div></div></div><div class="callout ">改扩展名与改文件头是两种操作。签名修复不等于所有损坏都修好了。</div></div></div>

''', '练习包 02_png/broken_header.png 为已知签名损坏样本；代码在该目录执行。原始块结构与像素保持有效。', '')


add(2, '常见方法 02：用 IHDR 的 CRC 恢复宽度', '适用于“只改宽度、原 CRC 保留”的特定基础题，不是通用修图。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>从练习材料根目录运行 · Python 3</span><button type="button" data-copy aria-label="复制从练习材料根目录运行 · Python 3代码">复制</button></div><pre><code>python tools/recover_width.py 02_png/broken_width.png out/fixed.png
pngcheck -v out/fixed.png</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>位置 / 内容</th><th>含义</th></tr></thead><tbody><tr><td>0x10–0x13</td><td>宽度，4 字节，大端序</td></tr><tr><td>0x14–0x17</td><td>高度，4 字节，大端序</td></tr><tr><td>0x1D–0x20</td><td>IHDR 保存的 CRC-32</td></tr><tr><td>CRC 输入</td><td>类型 IHDR 的 4 字节 + 13 字节块数据</td></tr></tbody></table></div><div class="callout ">脚本只尝试宽度 1～4096，高度和其他字段保持不变；候选匹配后仍需解码验证。</div></div></div>

''', '本样本正确宽度 256、高度 160；错误宽度为 1。脚本读取保存的 CRC，逐一替换宽度计算候选，不去盲改保存的 CRC。它不适用于宽高同时未知或原 CRC 也被改动的所有情况。', '')


add(2, 'LSB：最低有效位的直觉', '改变一个颜色通道的最低位，数值只改变 1；视觉变化可能很小。', r'''

<div class="cols "><div>
<div class="panel white"><span class="label">ONE CHANNEL / 一个通道</span><div class="bit-demo"><div><div class="bit-byte">1001011<mark>0</mark></div><p class="bit-caption">十进制 150 / 最低位 0</p></div></div><div class="bit-demo"><div><div class="bit-byte">1001011<mark>1</mark></div><p class="bit-caption">十进制 151 / 最低位 1</p></div></div></div>
</div><div><h3>把分散的位重新组合</h3><div class="codebox"><div class="code-top"><span>仅演示 8 个比特的拼接</span><button type="button" data-copy aria-label="复制仅演示 8 个比特的拼接代码">复制</button></div><pre><code>0 1 0 0 0 0 0 1
       ↓
01000001₂ = 65₁₀ = ASCII A</code></pre></div><ul><li>从哪些像素、哪些通道读取？</li><li>扫描顺序、位序、起点是什么？</li><li>提取后是文字，还是另一个文件？</li></ul></div></div><div class="callout ">本课只建立 LSB 概念。<strong>先查元数据与文件结构，再根据线索尝试像素分析。</strong>不能把“图片里有 flag”直接等同于 LSB。</div>

''', '用 150 和 151 的二进制变化解释最低位。真实提取还需明确 RGB 通道、位顺序、像素顺序和长度。JPEG 的有损压缩与 PNG 的像素存储不同，不能直接套用同一个提取方法。', '')


add(2, 'zsteg：扫描候选，再按参数提取', '适合 PNG / BMP；结果多时要区分随机命中与有效内容。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash · zsteg（Ruby 工具）</span><button type="button" data-copy aria-label="复制Linux Bash · zsteg（Ruby 工具）代码">复制</button></div><pre><code>zsteg 03_lsb/quiet.png
zsteg -a 03_lsb/quiet.png
zsteg -E &#x27;b1,r,lsb,xy&#x27; 03_lsb/quiet.png &gt; payload.bin
strings -a payload.bin</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>参数片段</th><th>解释</th></tr></thead><tbody><tr><td>b1</td><td>每个通道值取 1 位</td></tr><tr><td>r</td><td>只读取红色通道</td></tr><tr><td>lsb</td><td>最低有效位方案</td></tr><tr><td>xy</td><td>按该像素遍历顺序读取</td></tr></tbody></table></div><div class="callout ">Windows 不便安装 Ruby 时，使用下一页的 Python 提取脚本完成同一基础题。</div></div></div><p class="source">参考：<a href="https://github.com/zed-0xff/zsteg" target="_blank" rel="noopener noreferrer">zsteg 上游用法 ↗</a></p>

''', '提取命令在 Bash 中执行，以保持二进制输出。zsteg 的候选命名应从实际扫描输出复制，不要对所有图片固定使用 b1,r,lsb,xy。', '')


add(2, '用 10 行 Python 理解 LSB 提取', '本例约定：从左上到右下，红通道低位，8 位按高位到低位拼成字节。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Python 3 · 需 Pillow</span><button type="button" data-copy aria-label="复制Python 3 · 需 Pillow代码">复制</button></div><pre><code>from PIL import Image
im = Image.open(&quot;03_lsb/quiet.png&quot;).convert(&quot;RGB&quot;)
bits = [r &amp; 1 for r, g, b in im.getdata()]
out = bytearray()
for i in range(0, len(bits) - 7, 8):
    value = 0
    for bit in bits[i:i+8]:
        value = (value &lt;&lt; 1) | bit
    out.append(value)
print(bytes(out).split(b&quot;\0&quot;, 1)[0].decode())</code></pre></div></div><div><div class="codebox"><div class="code-top"><span>直接运行配套脚本</span><button type="button" data-copy aria-label="复制直接运行配套脚本代码">复制</button></div><pre><code>python tools/extract_lsb.py 03_lsb/quiet.png out/lsb.bin</code></pre></div><div class="callout ">缺少 Pillow 时课前执行 <code>python -m pip install pillow</code>。脚本仅适用于题目约定的 RGB 顺序，不代表所有 LSB 题。</div></div></div>

''', '解释 r & 1 取得最低位，左移累加形成一个字节。脚本依赖 Pillow，但构建课件本身无需第三方库。', '')


add(2, 'StegSolve 与 steghide：别把工具混为一谈', '一个侧重可视化通道观察，一个支持特定载体中的嵌入数据。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>steghide 命令行 · 载体由题目提供</span><button type="button" data-copy aria-label="复制steghide 命令行 · 载体由题目提供代码">复制</button></div><pre><code>steghide info cover.jpg
steghide extract -sf cover.jpg -xf extracted.bin</code></pre></div></div><div><div class="steps"><div class="step"><span>01</span><div><h4>StegSolve</h4><p>打开图片，观察 RGB 位平面、Alpha、反色与通道组合；可用 Data Extract 按线索配置。</p></div></div><div class="step"><span>02</span><div><h4>steghide</h4><p>常用载体为 JPEG、BMP、WAV、AU，提取时可能请求口令。</p></div></div><div class="step"><span>03</span><div><h4>验证提取结果</h4><p>检查输出类型和内容；工具失败不能单独证明没有隐写。</p></div></div></div><div class="callout ">PNG 像素题优先考虑位平面 / zsteg；不要把 steghide 当作适用一切格式的隐写扫描器。</div></div></div>

''', '本页为可选工具流程，不伪造不存在的载体文件。cover.jpg 是语法占位文件名。PNG 的 LSB 与 JPEG 的变换域处理不是同一套直接位操作。', '')


add(2, '练习 02：修复一张尺寸异常的 PNG', '自制基础题 · 使用校验值验证一个明确假设。', r'''

<div class="lab-top"><span class="pill gold">HANDS-ON / 教学合成数据</span><span class="lab-time">7 MIN</span></div><div class="cols "><div><div class="lab-task"><h3>材料：02_png/broken_width.png</h3><ol><li>观察 IHDR 宽度与 CRC 异常。</li><li>运行恢复脚本，记录候选宽度。</li><li>打开修复图片，并读取 Comment 中的 flag。</li></ol><button class="btn secondary" data-download>下载全部学员练习 ↓</button></div><form class="flag-form" data-answer="flag{crc_checks_the_hypothesis}"><label for="flag-2">提交 flag · 仅在本机校验</label><div class="flag-line"><input id="flag-2" name="flag" placeholder="flag{...}" autocomplete="off" spellcheck="false" aria-describedby="flag-result-2"><button class="btn" type="submit">验证答案</button></div><div class="flag-result" id="flag-result-2" role="status">先完成分析，再验证结果。</div></form></div><div><div class="codebox"><div class="code-top"><span>命令参考 · 从练习材料根目录运行</span><button type="button" data-copy aria-label="复制命令参考 · 从练习材料根目录运行代码">复制</button></div><pre><code>python tools/recover_width.py 02_png/broken_width.png out/fixed.png
exiftool out/fixed.png</code></pre></div><details class="hint-details"><summary>提示 1 · 方向与理由</summary><p>本题要修复的是尺寸，不是单纯找到文字。题目给出三个约束：只改宽度、旧 CRC 没改、宽度在 1～4096。它们把问题缩成有限范围的验证：枚举候选宽度，找出哪一个能与原 IHDR 校验值相符，而不是凭画面比例猜一个数。</p></details><details class="hint-details"><summary>提示 2 · 缩小范围</summary><p>正确宽度在 1～4096 之间；脚本应输出唯一候选 256。</p></details></div></div>

''', '正确宽度 256，高度 160。修复后 Comment 为 flag{crc_checks_the_hypothesis}。同时检查解析、尺寸和图像显示，不能只以 CRC 匹配宣布全部恢复。', '')


add(2, '练习 03：红色通道的一位线索', '自制基础题 · 提取参数需要能说清楚。', r'''

<div class="lab-top"><span class="pill gold">HANDS-ON / 教学合成数据</span><span class="lab-time">7 MIN</span></div><div class="cols "><div><div class="lab-task"><h3>材料：03_lsb/quiet.png</h3><ol><li>检查普通字符串与元数据。</li><li>按红通道、最低位、逐行顺序提取。</li><li>解释比特如何组成字节并验证 flag。</li></ol><button class="btn secondary" data-download>下载全部学员练习 ↓</button></div><form class="flag-form" data-answer="flag{one_bit_one_clue}"><label for="flag-3">提交 flag · 仅在本机校验</label><div class="flag-line"><input id="flag-3" name="flag" placeholder="flag{...}" autocomplete="off" spellcheck="false" aria-describedby="flag-result-3"><button class="btn" type="submit">验证答案</button></div><div class="flag-result" id="flag-result-3" role="status">先完成分析，再验证结果。</div></form></div><div><div class="codebox"><div class="code-top"><span>命令参考 · 从练习材料根目录运行</span><button type="button" data-copy aria-label="复制命令参考 · 从练习材料根目录运行代码">复制</button></div><pre><code>zsteg 03_lsb/quiet.png
python tools/extract_lsb.py 03_lsb/quiet.png out/lsb.bin</code></pre></div><details class="hint-details"><summary>提示 1 · 方向与理由</summary><p>题目已经给出了通道、位、扫描顺序和组字节规则，所以下一步是实现并验证这些约定。这里操作的是解码后的像素值，不是把 PNG 压缩文件中的每个字节直接取最低位；两者不是同一层的数据。</p></details><details class="hint-details"><summary>提示 2 · 缩小范围</summary><p>每像素取 R & 1，8 位一组，高位在前，文本以 0 字节结束。</p></details></div></div>

''', '预期 flag{one_bit_one_clue}。提供的 Python 脚本与 zsteg 路线互为替代，学员无需两套环境都配置。', '')


add(3, '7-Zip：列表、测试、解压三步走', '先读目录与属性，不急着展开所有内容。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>跨平台 · 7z 已加入 PATH</span><button type="button" data-copy aria-label="复制跨平台 · 7z 已加入 PATH代码">复制</button></div><pre><code>7z l -slt out/payload.zip
7z t out/payload.zip
7z x out/payload.zip -oout/archive</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>命令 / 选项</th><th>作用</th></tr></thead><tbody><tr><td>l -slt</td><td>详细列出条目及技术属性</td></tr><tr><td>t</td><td>测试条目是否可解压并通过校验</td></tr><tr><td>x</td><td>保留目录结构解压</td></tr><tr><td>-oout/archive</td><td>指定输出目录，-o 与路径相连</td></tr></tbody></table></div><div class="callout ">Windows 的隐藏属性与以点开头的文件名不同；使用详细列表与 <code>Get-ChildItem -Force</code> 检查。</div></div></div>

''', '实际 payload.zip 由 carrier.bin 分离得到；先讲语法，随后练习 4 再运行。不要在错误目录中把同名输出覆盖。', '')


add(3, 'ZIP 结构：为什么会有两个地方写着“加密”？', '本地文件头保存条目信息，中央目录用于索引；二者应相互核对。', r'''

<div class="table-wrap"><table><thead><tr><th>结构</th><th>签名字节</th><th>关注字段</th></tr></thead><tbody><tr><td>本地文件头</td><td><code>50 4B 03 04</code></td><td>通用标志、压缩方法、文件名与数据</td></tr><tr><td>中央目录条目</td><td><code>50 4B 01 02</code></td><td>标志、CRC、尺寸、本地头偏移</td></tr><tr><td>中央目录结束记录</td><td><code>50 4B 05 06</code></td><td>目录位置、条目数、注释</td></tr></tbody></table></div><div class="codebox"><div class="code-top"><span>配套只读检查命令</span><button type="button" data-copy aria-label="复制配套只读检查命令代码">复制</button></div><pre><code>python tools/zip_flags.py inspect 04_archive/flagged.zip</code></pre></div><div class="callout ">通用标志的 bit 0 表示加密。标志异常只是候选原因；真实加密的数据不会因为改掉 bit 0 就变成明文。</div>

''', '本课构造一个“数据未加密但标志被设为加密”的经典 ZIP 对照样本，名称 flagged.zip。脚本只支持单卷、非 ZIP64 的普通 ZIP，不能承诺兼容所有变体。', '')


add(3, '常见方法 03：验证 ZIP 标志伪装', '只针对有证据支持的教学样本，在副本中同步检查两处标志。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Python 3 · 配套脚本</span><button type="button" data-copy aria-label="复制Python 3 · 配套脚本代码">复制</button></div><pre><code>python tools/zip_flags.py inspect 04_archive/flagged.zip
python tools/zip_flags.py clear 04_archive/flagged.zip out/cleared.zip
7z t out/cleared.zip
7z x out/cleared.zip -oout/cleared</code></pre></div></div><div><div class="steps"><div class="step"><span>01</span><div><h4>看数据与标志是否矛盾</h4><p>本样本条目数据实际未加密，仅两处 bit 0 被改动。</p></div></div><div class="step"><span>02</span><div><h4>修复输出到新文件</h4><p>脚本同步处理本地头与中央目录，不覆盖原件。</p></div></div><div class="step"><span>03</span><div><h4>验证解压与 CRC</h4><p>能解压且校验正确，才支持该样本的伪装判断。</p></div></div></div><div class="callout ">如果修改后仍报口令错误或 CRC 错误，回到证据与格式分析，不要继续盲改字节。</div></div></div>

''', 'flagged.zip 内含 note.txt。脚本修改后用 zipfile.testzip 与 7z t 验证。课堂不把此技巧扩展为“万能 ZIP 解密”。', '')


add(3, '真正有密码：先找线索，再做小字典', '仅处理题目附件；口令方法是可选补充，不是取证题的默认起手式。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash · John the Ripper Jumbo</span><button type="button" data-copy aria-label="复制Linux Bash · John the Ripper Jumbo代码">复制</button></div><pre><code>zip2john locked.zip &gt; zip.hash
john --wordlist=words.txt zip.hash
john --show zip.hash</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>输入 / 命令</th><th>作用</th></tr></thead><tbody><tr><td>zip2john</td><td>生成适合 John 的 ZIP 校验描述，不是直接解密</td></tr><tr><td>words.txt</td><td>一行一个候选密码，来源于题目提示</td></tr><tr><td>--wordlist</td><td>用候选集尝试</td></tr><tr><td>--show</td><td>查看已恢复的结果</td></tr></tbody></table></div><div class="callout ">受压缩格式、加密方式和工具构建影响，可能不支持。先检查 <code>zip2john</code> 与 <code>john --help</code>；本页 locked.zip / words.txt 为语法占位。</div></div></div>

''', '不安排漫长暴力破解。强调密码线索可能在注释、隐藏文件、元数据或前一道题里；有密码不等于文件头损坏。', '')


add(3, 'binwalk：从整体文件中找嵌入对象', '输出重点是偏移与候选类型，随后仍需验证提取结果。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash · 查看本机版本帮助</span><button type="button" data-copy aria-label="复制Linux Bash · 查看本机版本帮助代码">复制</button></div><pre><code>binwalk 04_archive/carrier.bin
binwalk --help
# 本机版本与提取依赖支持时
binwalk -e 04_archive/carrier.bin</code></pre></div></div><div><div class="panel mint"><h3>如何读扫描结果</h3><p><strong>DECIMAL / HEXADECIMAL：</strong>同一偏移的两种表示，不是两个不同位置。</p><p><strong>DESCRIPTION：</strong>签名命中的候选格式；随机字节也可能误报。</p><p>练习中的 ZIP 从十进制 512（0x200）开始，持续到文件结尾。</p></div></div></div><p class="source">参考：<a href="https://github.com/ReFirmLabs/binwalk/wiki" target="_blank" rel="noopener noreferrer">Binwalk 上游 Wiki ↗</a></p>

''', 'Binwalk 2 与 3 的实现、选项和提取依赖不同。通用演示采用扫描 + 手动按偏移切片，不依赖自动提取成功。', '')


add(3, '常见方法 04：按偏移分离文件', '本例明确知道 ZIP 从 512 字节开始，并一直延续到文件结尾。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash</span><button type="button" data-copy aria-label="复制Linux Bash代码">复制</button></div><pre><code>dd if=04_archive/carrier.bin of=out/payload.zip bs=1 skip=512 status=none
7z t out/payload.zip</code></pre></div></div><div><div class="codebox"><div class="code-top"><span>Python 3 · 跨平台替代</span><button type="button" data-copy aria-label="复制Python 3 · 跨平台替代代码">复制</button></div><pre><code>from pathlib import Path
data = Path(&quot;04_archive/carrier.bin&quot;).read_bytes()
Path(&quot;out&quot;).mkdir(exist_ok=True)
Path(&quot;out/payload.zip&quot;).write_bytes(data[512:])</code></pre></div><div class="callout "><code>bs=1</code> 表示块长为 1 字节；此时 <code>skip=512</code> 才是跳过 512 字节。若终点已知，用 <code>count=长度</code> 或精确切片。</div></div></div>

''', '两种命令对本教学样本结果应相同。任意文件中的 PK 标记并不证明后面直到结尾全是可用 ZIP；真实题目还要确定边界与结构。', '')


add(3, '练习 04：载体中的 ZIP 文件', '自制基础题 · 找偏移、切片、测试、解压。', r'''

<div class="lab-top"><span class="pill gold">HANDS-ON / 教学合成数据</span><span class="lab-time">7 MIN</span></div><div class="cols "><div><div class="lab-task"><h3>材料：04_archive/carrier.bin</h3><ol><li>用签名扫描或十六进制搜索找 ZIP。</li><li>记录十进制与十六进制偏移。</li><li>分离到新文件，测试后读取 answer.txt。</li></ol><button class="btn secondary" data-download>下载全部学员练习 ↓</button></div><form class="flag-form" data-answer="flag{offsets_make_carving_repeatable}"><label for="flag-4">提交 flag · 仅在本机校验</label><div class="flag-line"><input id="flag-4" name="flag" placeholder="flag{...}" autocomplete="off" spellcheck="false" aria-describedby="flag-result-4"><button class="btn" type="submit">验证答案</button></div><div class="flag-result" id="flag-result-4" role="status">先完成分析，再验证结果。</div></form></div><div><div class="codebox"><div class="code-top"><span>命令参考 · 从练习材料根目录运行</span><button type="button" data-copy aria-label="复制命令参考 · 从练习材料根目录运行代码">复制</button></div><pre><code>python tools/carve.py 04_archive/carrier.bin out/payload.zip --offset 512
7z t out/payload.zip
7z x out/payload.zip -oout/archive</code></pre></div><details class="hint-details"><summary>提示 1 · 方向与理由</summary><p>载体中出现 PK 03 04，说明那里可能有 ZIP 条目，却不能直接说明它是一个独立、完整的压缩包。解题重点是把“签名命中”推进到“有正确边界且能通过 ZIP 解析与 CRC 校验的对象”。</p></details><details class="hint-details"><summary>提示 2 · 缩小范围</summary><p>0x200 等于十进制 512；本样本 ZIP 到文件末尾。</p></details></div></div>

''', '答案 flag{offsets_make_carving_repeatable}。carrier.bin 的前 512 字节是教学前缀，后面是完整 ZIP。out 目录由脚本自动创建。', '')


add(3, '雕刻不是魔法：什么时候会失败？', '已知边界切片、按签名雕刻、文件系统恢复，是三类不同方法。', r'''

<div class="table-wrap"><table><thead><tr><th>方法</th><th>命令入口</th><th>局限</th></tr></thead><tbody><tr><td>已知边界切片</td><td><code>dd ... bs=1 skip=偏移 count=长度</code></td><td>必须确认起点与终点</td></tr><tr><td>签名与格式雕刻</td><td><code>foremost -i sample.img -o carved</code></td><td>依赖规则与连续数据，可能丢失文件名/时间</td></tr><tr><td>文件系统恢复</td><td><code>fls</code> → <code>icat</code></td><td>依赖目录与元数据仍可解释</td></tr></tbody></table></div><div class="callout ">先看文件系统与元数据是否存在，再决定是否雕刻。片段不连续、数据覆盖、TRIM 都可能影响恢复。</div>

''', 'foremost 为可选工具示意；不对所有格式保证恢复。此页把下一模块磁盘恢复与压缩包切片区分开来。', '')


add(4, '磁盘镜像：像看地图一样分层', '先找分区，再找文件系统，最后找目录、文件与数据内容。', r'''


<div class="process"><div><b>DISK IMAGE</b><h4>磁盘镜像</h4><p>整个磁盘的内容<br>可能有多个分区</p></div><div><b>PARTITION</b><h4>分区</h4><p>起始扇区与长度<br>确定文件系统入口</p></div><div><b>FILE SYSTEM</b><h4>文件系统</h4><p>NTFS / FAT / ext 等<br>组织元数据与数据</p></div><div><b>ARTIFACT</b><h4>痕迹</h4><p>目录、文件、回收站<br>应用数据与删除项</p></div></div>
<div class="cols "><div><div class="panel "><h3>删除不等于立即清零</h3><p>目录或元数据可能仍留下痕迹，数据也可能暂时保留。能否恢复取决于覆盖、文件系统、TRIM 等条件。</p></div></div><div><div class="panel mint"><h3>分析时保持只读</h3><p>优先使用镜像分析工具读取工作副本。导出文件写到独立目录，记录来源与元数据地址。</p></div></div></div>

''', '只做概念，不额外下载大型镜像。提醒 .dd/.img 只是常见扩展名，可能是磁盘镜像，也可能是分区镜像；不能固定假设每个镜像都先有分区表。', '')


add(4, 'Autopsy：用图形界面走一遍磁盘流程', '适合课堂展示分区、目录、删除项与文件导出。', r'''

<div class="steps"><div class="step"><span>01</span><div><h4>创建 Case 并添加数据源</h4><p>选择 Disk Image，添加 05_disk/tiny_fat16.dd；在工作副本上分析。</p></div></div><div class="step"><span>02</span><div><h4>查看分区与文件树</h4><p>识别 FAT16 文件系统；先看说明文件，再找题目相关条目。</p></div></div><div class="step"><span>03</span><div><h4>检查删除项与元数据</h4><p>观察删除标记、大小、元数据地址；不要只看文件名。</p></div></div><div class="step"><span>04</span><div><h4>导出并验证</h4><p>对目标条目执行 Extract File(s)，保存到独立目录，核对内容。</p></div></div></div><div class="callout ">界面随版本不同；本质仍是“镜像 → 分区 → 文件系统 → 条目 → 内容”。不需要在原系统挂载为可写。</div>

''', '配套是约 9 MiB 的教学 FAT16 镜像，压缩后很小。Autopsy 可替代命令行完成练习 5，若未安装可先用配套教学解析器演示。', '')


add(4, 'mmls：先找到文件系统从哪里开始', '分区偏移使用扇区计量；不要把字节偏移直接填给 -o。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash · The Sleuth Kit</span><button type="button" data-copy aria-label="复制Linux Bash · The Sleuth Kit代码">复制</button></div><pre><code>mmls 05_disk/tiny_fat16.dd
fsstat -o 2048 05_disk/tiny_fat16.dd</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>教学样本字段</th><th>数值 / 含义</th></tr></thead><tbody><tr><td>分区起始扇区</td><td>2048</td></tr><tr><td>扇区大小</td><td>512 字节</td></tr><tr><td>字节偏移</td><td>2048 × 512 = 1,048,576</td></tr><tr><td>fsstat</td><td>查看该分区的文件系统结构</td></tr></tbody></table></div><div class="callout ">2048 是本样本实际布局。其他镜像应先看实际输出；分区镜像也可能不含分区表。</div></div></div><p class="source">参考：<a href="https://www.sleuthkit.org/sleuthkit/man/mmls.html" target="_blank" rel="noopener noreferrer">The Sleuth Kit · mmls ↗</a></p>

''', '解释 disk image 与 partition image 的区别。fsstat 同样采用 -o 扇区偏移，本样本为 FAT16。', '')


add(4, 'fls：列目录，读懂删除标记与元数据地址', '名字用于识别线索，元数据地址用于后续读取内容。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash · The Sleuth Kit</span><button type="button" data-copy aria-label="复制Linux Bash · The Sleuth Kit代码">复制</button></div><pre><code>fls -r -p -o 2048 05_disk/tiny_fat16.dd
fls -d -o 2048 05_disk/tiny_fat16.dd</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>选项 / 字段</th><th>含义</th></tr></thead><tbody><tr><td>-r / -p</td><td>递归 / 显示完整路径</td></tr><tr><td>-d</td><td>仅列删除项</td></tr><tr><td>*</td><td>TSK 输出中的删除标记</td></tr><tr><td>元数据地址</td><td>后续 icat 的参数，不是文件偏移</td></tr></tbody></table></div><div class="callout ">教学镜像含 README.TXT 与一个删除的 SECRET.TXT 条目。恢复时采用实际 fls 输出的地址。</div></div></div><p class="source">参考：<a href="https://www.sleuthkit.org/sleuthkit/man/fls.html" target="_blank" rel="noopener noreferrer">The Sleuth Kit · fls ↗</a></p>

''', '删除文件名首字节在 FAT 目录中被 E5 代替，因此工具可能显示 _ECRET.TXT 等名称；应结合条目与数据判断。不要保证原文件名首字母可恢复。', '')


add(4, 'icat：根据元数据地址取出内容', '地址来自上一条 fls 输出，不靠猜测。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Linux Bash · 将 META 替换为实际元数据地址</span><button type="button" data-copy aria-label="复制Linux Bash · 将 META 替换为实际元数据地址代码">复制</button></div><pre><code>icat -r -o 2048 05_disk/tiny_fat16.dd META &gt; recovered.txt
file recovered.txt
cat recovered.txt</code></pre></div></div><div><div class="steps"><div class="step"><span>01</span><div><h4>使用相同的分区偏移</h4><p>-o 与 fls 保持一致，否则会读到其他位置。</p></div></div><div class="step"><span>02</span><div><h4>删除项使用 -r 尝试恢复</h4><p>对仍有元数据与数据的条目尝试恢复，不能保证所有删除项成功。</p></div></div><div class="step"><span>03</span><div><h4>验证输出</h4><p>类型、长度、内容与题目线索相符，再记录来源。</p></div></div></div><div class="callout "><code>META</code> 是占位符，必须替换。Windows 旧版 PowerShell 的二进制重定向问题仍然存在。</div></div></div><p class="source">参考：<a href="https://www.sleuthkit.org/sleuthkit/man/icat.html" target="_blank" rel="noopener noreferrer">The Sleuth Kit · icat ↗</a></p>

''', '本例输出是文本；泛化到图片或压缩包时更要避免输出重编码。可用 Autopsy 的文件导出代替。', '')


add(4, '练习 05：从 FAT16 删除项恢复文本', '自制基础题 · 删除的是目录标记，数据仍可能存在。', r'''

<div class="lab-top"><span class="pill gold">HANDS-ON / 教学合成数据</span><span class="lab-time">7 MIN</span></div><div class="cols "><div><div class="lab-task"><h3>材料：05_disk/tiny_fat16.dd</h3><ol><li>确认分区起始扇区。</li><li>定位删除条目，记录元数据地址或目录条目。</li><li>导出文本，解释恢复为何成功。</li></ol><button class="btn secondary" data-download>下载全部学员练习 ↓</button></div><form class="flag-form" data-answer="flag{deleted_entry_is_a_clue}"><label for="flag-5">提交 flag · 仅在本机校验</label><div class="flag-line"><input id="flag-5" name="flag" placeholder="flag{...}" autocomplete="off" spellcheck="false" aria-describedby="flag-result-5"><button class="btn" type="submit">验证答案</button></div><div class="flag-result" id="flag-result-5" role="status">先完成分析，再验证结果。</div></form></div><div><div class="codebox"><div class="code-top"><span>命令参考 · 从练习材料根目录运行</span><button type="button" data-copy aria-label="复制命令参考 · 从练习材料根目录运行代码">复制</button></div><pre><code>mmls 05_disk/tiny_fat16.dd
fls -d -o 2048 05_disk/tiny_fat16.dd
# 没有 TSK 时的本样本教学替代
python tools/read_training_fat.py 05_disk/tiny_fat16.dd out/recovered.txt</code></pre></div><details class="hint-details"><summary>提示 1 · 方向与理由</summary><p>这道题包含两个层次：先找到文件系统位于镜像的哪里，再判断删除项的数据是否仍可恢复。若偏移错了，后面的文件列表和恢复都没有可靠基础；若只看见删除标记，也还不能断言内容一定完整。</p></details><details class="hint-details"><summary>提示 2 · 缩小范围</summary><p>TSK 用 icat -r；替代脚本只解析本课固定布局，不能用于任意镜像。</p></details></div></div>

''', '答案 flag{deleted_entry_is_a_clue}。教学脚本从分区表、BPB 和根目录读取，不是直接全盘搜索 flag；它仅支持本样本的连续单簇 FAT16 文件。', '')


add(4, 'SQLite：先看表，再写查询', '数据库文件中保存的是有结构的记录，不能只当成普通文本。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>SQLite CLI · 只读打开教学库</span><button type="button" data-copy aria-label="复制SQLite CLI · 只读打开教学库代码">复制</button></div><pre><code>sqlite3 -readonly 06_sqlite/case.db &quot;.tables&quot;
sqlite3 -readonly 06_sqlite/case.db &quot;.schema artifacts&quot;
sqlite3 -readonly 06_sqlite/case.db &quot;PRAGMA table_info(artifacts);&quot;</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>命令</th><th>含义</th></tr></thead><tbody><tr><td>.tables</td><td>列出表与视图</td></tr><tr><td>.schema artifacts</td><td>查看建表 SQL 与字段定义</td></tr><tr><td>PRAGMA table_info</td><td>查看列名、类型、主键等</td></tr><tr><td>-readonly</td><td>以只读模式打开已有库</td></tr></tbody></table></div><div class="callout ">点命令由 sqlite3 命令行解释；SQL 语句由数据库引擎执行，不是所有工具都能直接执行 <code>.tables</code>。</div></div></div><p class="source">参考：<a href="https://www.sqlite.org/cli.html" target="_blank" rel="noopener noreferrer">SQLite · CLI ↗</a></p>

''', 'case.db 是简化教学表，不冒充真实浏览器数据库。Windows 可使用 SQLite 命令行或 DB Browser for SQLite。', '')


add(4, 'SQL 基础：选择字段、筛选、排序', '先读字段含义；deleted=1 在本题表示业务软删除。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>SQLite CLI</span><button type="button" data-copy aria-label="复制SQLite CLI代码">复制</button></div><pre><code>sqlite3 -readonly -header -column 06_sqlite/case.db &quot;SELECT id,name,deleted,note FROM artifacts;&quot;
sqlite3 -readonly 06_sqlite/case.db &quot;SELECT note FROM artifacts WHERE deleted=1;&quot;</code></pre></div></div><div><div class="codebox"><div class="code-top"><span>Python 3 · 标准库替代</span><button type="button" data-copy aria-label="复制Python 3 · 标准库替代代码">复制</button></div><pre><code>import sqlite3
con = sqlite3.connect(&quot;file:06_sqlite/case.db?mode=ro&quot;, uri=True)
for row in con.execute(&quot;SELECT id,name,note FROM artifacts WHERE deleted=1&quot;):
    print(row)
con.close()</code></pre></div><div class="callout ">业务软删除只是字段状态，记录仍可查询；它与恢复 SQLite 已删除页或空闲区不是同一件事。</div></div></div>

''', '讲 SELECT、FROM、WHERE、ORDER BY 和 LIMIT 的用途，可追加 SELECT ... ORDER BY id LIMIT 5。不要使用 DELETE、UPDATE 修改证据库。', '')


add(4, '数据库取证：别漏掉 WAL 与时间单位', '真实应用的表结构与存储时间因软件版本而异。', r'''

<div class="cols "><div><div class="panel mint"><h3>主库与附属文件</h3><p>遇到 <code>case.db-wal</code> 与 <code>case.db-shm</code> 时保留同目录文件和原始副本。未合并的事务可能仍在 WAL 中。</p><p>只复制主库，不一定代表采集时完整的可见状态。</p></div></div><div><div class="panel "><h3>先确认时间基准</h3><p>Unix 时间常见单位是秒或毫秒；部分应用采用其他起点和微秒单位。</p><p>先查应用定义，再用已知事件校对，最后统一到带时区时间。</p></div></div></div><div class="codebox"><div class="code-top"><span>Unix 秒时间戳 · SQLite 示例</span><button type="button" data-copy aria-label="复制Unix 秒时间戳 · SQLite 示例代码">复制</button></div><pre><code>SELECT datetime(1792286311, &#x27;unixepoch&#x27;);</code></pre></div><p class="source">参考：<a href="https://www.sqlite.org/wal.html" target="_blank" rel="noopener noreferrer">SQLite · WAL ↗</a></p>

''', '不要保证 WAL 中能恢复所有历史或删除记录；本教学库不依赖 WAL。SQLite datetime(..., unixepoch) 的输出按 UTC 理解，不要把本机 localtime 隐式当作统一取证时区。', '')


add(4, '练习 06：数据库里的软删除线索', '自制基础题 · 先查结构，再按业务字段筛选。', r'''

<div class="lab-top"><span class="pill gold">HANDS-ON / 教学合成数据</span><span class="lab-time">6 MIN</span></div><div class="cols "><div><div class="lab-task"><h3>材料：06_sqlite/case.db</h3><ol><li>识别数据库文件并查看表名。</li><li>解释 artifacts 的字段。</li><li>筛选 deleted=1，提交 note 中的 flag。</li></ol><button class="btn secondary" data-download>下载全部学员练习 ↓</button></div><form class="flag-form" data-answer="flag{query_the_schema_first}"><label for="flag-6">提交 flag · 仅在本机校验</label><div class="flag-line"><input id="flag-6" name="flag" placeholder="flag{...}" autocomplete="off" spellcheck="false" aria-describedby="flag-result-6"><button class="btn" type="submit">验证答案</button></div><div class="flag-result" id="flag-result-6" role="status">先完成分析，再验证结果。</div></form></div><div><div class="codebox"><div class="code-top"><span>命令参考 · 从练习材料根目录运行</span><button type="button" data-copy aria-label="复制命令参考 · 从练习材料根目录运行代码">复制</button></div><pre><code>sqlite3 -readonly 06_sqlite/case.db &quot;.schema artifacts&quot;
sqlite3 -readonly 06_sqlite/case.db &quot;SELECT name,note FROM artifacts WHERE deleted=1;&quot;
# 没有 sqlite3 CLI 时
python tools/query_case.py 06_sqlite/case.db</code></pre></div><details class="hint-details"><summary>提示 1 · 方向与理由</summary><p>界面中“看不见”不等于数据库中“已物理移除”。先检查普通表里是否仍有目标行，是成本较低且可直接验证的假设。只有明确正常表查询不能回答问题，才有理由继续考虑 WAL、空闲页或物理记录恢复。</p></details><details class="hint-details"><summary>提示 2 · 缩小范围</summary><p>读取 artifacts 表中 deleted 等于 1 的 note。</p></details></div></div>

''', '答案 flag{query_the_schema_first}。讲清业务软删除与物理页恢复的不同，避免学员误以为执行 SELECT 就完成了底层数据恢复。', '')


from memory_module import build_memory_slides
SLIDES.extend(build_memory_slides())

add(6, '读日志：先认字段，再讲故事', '不同日志格式不同；先确认格式说明、时区与事件含义。', r'''

<div class="codebox"><div class="code-top"><span>Web 访问日志 · 教学样本节选</span><button type="button" data-copy aria-label="复制Web 访问日志 · 教学样本节选代码">复制</button></div><pre><code>192.0.2.44 - - [18/Oct/2026:09:18:31 +0800]
&quot;GET /exports/42.zip HTTP/1.1&quot; 200 2048
&quot;-&quot; &quot;TrainingBrowser/1.0&quot; rid=r-103</code></pre></div><div class="table-wrap"><table><thead><tr><th>字段</th><th>本例</th><th>能支持的观察</th></tr></thead><tbody><tr><td>地址</td><td>192.0.2.44</td><td>日志记录的客户端地址；代理场景需进一步核对</td></tr><tr><td>时间与时区</td><td>09:18:31 +0800</td><td>明确为 UTC+8 的本地时间</td></tr><tr><td>请求 / 状态 / 字节</td><td>GET、200、2048</td><td>请求路径与返回情况；200 不单独证明业务成功</td></tr><tr><td>关联标识</td><td>rid=r-103</td><td>本样本可与审计日志 request_id 关联</td></tr></tbody></table></div><div class="callout "><strong>IP 地址不自动等于一个人。</strong>业务成功与账号归属应结合审计事件、会话与题目上下文。</div>

''', '指出日志展示为了排版分成多行，原始 access.log 中每个请求占一行。rid 是本教学应用的自定义字段，不是所有服务器都会有。让学员找到状态码和时区。', '')


add(6, '时间线：先统一时区，再关联事件', '同一事件可以有不同的时间写法；保留原值，同时记录统一后的时间。', r'''

<div class="cols "><div>
<div class="tz-switch"><span>显示时间：</span><button data-timezone="local" aria-pressed="true">UTC+8</button><button data-timezone="utc" aria-pressed="false">UTC</button></div>
<div class="timeline"><div class="event"><time data-time-utc="2026-10-18 01:16:10Z" data-time-local="2026-10-18 09:16:10 +08:00">2026-10-18 09:16:10 +08:00</time><strong>登录成功</strong><p>audit.jsonl / login_success / r-101</p></div><div class="event"><time data-time-utc="2026-10-18 01:18:30Z" data-time-local="2026-10-18 09:18:30 +08:00">2026-10-18 09:18:30 +08:00</time><strong>开始导出</strong><p>audit.jsonl / export_started / r-102</p></div><div class="event"><time data-time-utc="2026-10-18 01:18:31Z" data-time-local="2026-10-18 09:18:31 +08:00">2026-10-18 09:18:31 +08:00</time><strong>下载完成</strong><p>audit.jsonl / download_completed / r-103</p></div></div>
</div><div><div class="panel mint"><h3>关联时多找一个锚点</h3><ul><li><code>Z</code> 表示 UTC；本例转换到 UTC+8 时加 8 小时。</li><li>相同 request_id 比“相近时间 + 相同 IP”提供更强关联。</li><li>进一步核对账号、session_id 和文件编号。</li><li>考虑跨日、时钟偏差、日志缺失与重复记录。</li></ul></div></div></div><div class="callout ">日期不可省略：<code>2026-10-18 20:30Z</code> → <code>2026-10-19 04:30 +08:00</code>。</div>

''', '点击 UTC / UTC+8 切换。解释 UTC+8 是本教学案例统一采用的时区；不要对所有历史地区或未带时区的时间盲目加 8。题目没有给时区时应说明假设。', '')


add(6, '日志命令：文本检索 → JSON 解析 → 时间转换', '不要只靠肉眼在几百行里找；让字段与关联键完成筛选。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>Windows PowerShell · 在 07_logs 目录</span><button type="button" data-copy aria-label="复制Windows PowerShell · 在 07_logs 目录代码">复制</button></div><pre><code>Select-String -Path .\access.log -Pattern &#x27;r-103&#x27;
Get-Content .\audit.jsonl | ConvertFrom-Json |
  Where-Object { $_.request_id -eq &#x27;r-103&#x27; } |
  Select-Object timestamp,event,user,client_ip,file_name
[DateTimeOffset]::Parse(&#x27;2026-10-18T01:18:31Z&#x27;).ToOffset(
  [TimeSpan]::FromHours(8)
)</code></pre></div></div><div><div class="table-wrap"><table><thead><tr><th>命令</th><th>作用</th></tr></thead><tbody><tr><td>ConvertFrom-Json</td><td>把 JSON 文本解释为带属性的对象</td></tr><tr><td>Where-Object</td><td>根据关联键筛选</td></tr><tr><td>Select-Object</td><td>只显示需要的字段</td></tr><tr><td>DateTimeOffset</td><td>明确带偏移量地转换时间</td></tr></tbody></table></div><div class="callout ">本题一行一个 JSON 对象，属于 JSONL。普通的多行 JSON 文档可能需要不同读取方式。</div></div></div>

''', '本例命令在 Windows PowerShell 5.1 与现代 PowerShell 的常见对象管道中可用。强调时间转换使用显式偏移，不依赖分析电脑当前时区。', '')


add(6, '练习 07：用请求标识拼出时间线', '自制基础题 · 同一事件在两份日志里有不同表示。', r'''

<div class="lab-top"><span class="pill gold">HANDS-ON / 教学合成数据</span><span class="lab-time">6 MIN</span></div><div class="cols "><div><div class="lab-task"><h3>材料：07_logs/access.log 与 audit.jsonl</h3><ol><li>定位下载请求与下载完成审计事件。</li><li>用 rid / request_id 关联账号、IP、文件名。</li><li>统一到 UTC+8，按 flag{IP_HHMMSS} 提交。</li></ol><button class="btn secondary" data-download>下载全部学员练习 ↓</button></div><form class="flag-form" data-answer="flag{192.0.2.44_091831}"><label for="flag-7">提交 flag · 仅在本机校验</label><div class="flag-line"><input id="flag-7" name="flag" placeholder="flag{...}" autocomplete="off" spellcheck="false" aria-describedby="flag-result-7"><button class="btn" type="submit">验证答案</button></div><div class="flag-result" id="flag-result-7" role="status">先完成分析，再验证结果。</div></form></div><div><div class="codebox"><div class="code-top"><span>命令参考 · 从练习材料根目录运行</span><button type="button" data-copy aria-label="复制命令参考 · 从练习材料根目录运行代码">复制</button></div><pre><code>Select-String -Path .\07_logs\access.log -Pattern &#x27;r-103&#x27;
python tools/timeline.py 07_logs/audit.jsonl</code></pre></div><details class="hint-details"><summary>提示 1 · 方向与理由</summary><p>题目要求的是“哪个账号对哪个文件完成下载、来源 IP 是什么、何时完成”。单个状态码或一条登录记录都回答不完这些问题。先从审计日志找符合账号、文件名和完成事件的记录，再用同一次请求的标识关联访问日志，最后统一时间。</p></details><details class="hint-details"><summary>提示 2 · 缩小范围</summary><p>r-103；UTC 时间 01:18:31Z，转换到 UTC+8 后去掉冒号。</p></details></div></div>

''', 'access.log 第 7 行、audit.jsonl 第 4 行；账号 trainee，文件 case_notes.zip，时间 2026-10-18 09:18:31 +08:00。', '')


add(6, '把结果写成一张证据记录', '记录观察、操作与结论，别人才能独立复现。', r'''

<div class="cols "><div><div class="codebox"><div class="code-top"><span>建议填写的记录模板</span><button type="button" data-copy aria-label="复制建议填写的记录模板代码">复制</button></div><pre><code>题目 / 附件：
原件 SHA-256：
工作副本位置：
工具及版本：
关键命令 / 菜单操作：
定位：偏移 / 标签 / 帧号 / 行号 / PID
观察到的原始值：
转换步骤：编码 / 时区 / 提取方法
结论与 flag：
尚未确认的事项：</code></pre></div></div><div><div class="panel mint"><h3>练习 07 的结论示例</h3><p>审计日志第 4 行记录 trainee 的下载完成事件，请求标识为 r-103；访问日志第 7 行的 rid 与之匹配，记录客户端 192.0.2.44 请求 /exports/42.zip。</p><p>审计记录文件名为 case_notes.zip，事件时间为 2026-10-18T01:18:31Z，即 UTC+8 的 09:18:31。</p></div></div></div><div class="callout "><strong>把观察与推断分开。</strong>两条关联日志能支持本样本中的下载结论；仅凭一个 IP，仍不能识别现实中的操作人员。</div>

''', '让学员把自己的 flag 附上 3 行记录。原件哈希可以从练习 SHA256SUMS.txt 校验，但仍建议独立计算一次。不要把样本中的推断扩展到现实用户身份。', '')


add(7, '基础题型对照：现象决定第一条命令', '把工具组合成方法，而不是记一串无条件执行的命令。', r'''

<div class="table-wrap"><table><thead><tr><th>常见现象</th><th>起手命令</th><th>下一步</th></tr></thead><tbody><tr><td>扩展名可疑</td><td><code>file</code> / <code>xxd -l 32</code></td><td>按真实格式解析</td></tr><tr><td>正常图片但无可见线索</td><td><code>strings -a -t x</code> / <code>exiftool</code></td><td>定位原始字段或字节</td></tr><tr><td>PNG 尺寸异常</td><td><code>pngcheck -v</code></td><td>按已知改动范围恢复并校验</td></tr><tr><td>位平面线索</td><td><code>zsteg</code></td><td>按实际通道和顺序提取</td></tr><tr><td>载体含嵌入文件</td><td><code>binwalk</code> → <code>dd</code></td><td>测试格式与解压校验</td></tr><tr><td>删除文件 / SQLite / 内存</td><td><code>fls</code> / <code>.schema</code> / <code>pslist</code></td><td>依各自结构定位和导出</td></tr></tbody></table></div>

''', '请学员为每一行说出为何选择该命令、它不能证明什么。不要把“常见方法”变成“全部运行一遍”。', '')


add(7, '示例题索引：讲解与上机怎么安排', '公开题讲方法，自制题保证可以直接练。', r'''

<div class="table-wrap"><table><thead><tr><th>类型 / 题目</th><th>考点</th><th>安排</th></tr></thead><tbody><tr><td>公开 A · Glory of the Garden</td><td>strings、偏移、尾部字节</td><td>讲师逐步演示 / 复现附件</td></tr><tr><td>公开 B · information</td><td>XMP License、Base64</td><td>讲师逐步演示 / 复现附件</td></tr><tr><td>自制 01 / 02 / 03</td><td>元数据、PNG 宽度恢复、LSB</td><td>先讲工具，再上机</td></tr><tr><td>自制 04 / 05</td><td>嵌入 ZIP、FAT16 删除项</td><td>分离与恢复对比</td></tr><tr><td>自制 06 / 07</td><td>SQLite 软删除、日志时间线</td><td>结构化字段与证据记录</td></tr></tbody></table></div><div class="callout ">公开例题附平台入口与解题方法；原始服务器不可达时，使用明确标注“自制复现”的同考点附件，不把它当作官方原件。</div>

''', '讲师手册给出每道题的答案、命令和核对点。自制复现附件与公开原件的来源要明确区分。', '')


add(7, '排错：这 6 类错误最常见', '先排除输入、环境和参数错误，再怀疑题目需要复杂技术。', r'''

<div class="table-wrap"><table><thead><tr><th>错误现象</th><th>优先检查</th></tr></thead><tbody><tr><td>找不到命令</td><td>是否安装、PATH、完整路径、PowerShell 调用符 &</td></tr><tr><td>文件或输出损坏</td><td>是否误把二进制当文本、方向/边界是否正确</td></tr><tr><td>PNG 仍打不开</td><td>是否只改 CRC 而没恢复数据或尺寸</td></tr><tr><td>ZIP 仍报错</td><td>是否是真加密、是否只改一处标志、CRC 是否正确</td></tr><tr><td>磁盘/内存输出异常</td><td>分区扇区偏移、Profile/符号、插件与地址类型</td></tr><tr><td>时间或关联对不上</td><td>原始时区、单位、日期、请求标识与时钟偏差</td></tr></tbody></table></div><div class="callout ">一次只改变一个条件，保存原件和失败现象；避免覆盖证据后无法复做。</div>

''', '将学员上机遇到的问题映射到表格，不扩大到未验证的假设。', '')


add(7, '一页命令速查', '标记为 Bash 的二进制重定向不要直接照搬到旧版 PowerShell。', r'''

<div class="table-wrap"><table><thead><tr><th>目标</th><th>常见命令</th></tr></thead><tbody><tr><td>看类型 / 字节</td><td><code>file sample</code> · <code>xxd -g 1 -l 32 sample</code></td></tr><tr><td>找文字 / 标签</td><td><code>strings -a -t x sample</code> · <code>exiftool -a -G1 -s sample</code></td></tr><tr><td>PNG / LSB</td><td><code>pngcheck -v sample.png</code> · <code>zsteg sample.png</code></td></tr><tr><td>列包 / 测试 / 分离</td><td><code>7z l -slt a.zip</code> · <code>7z t a.zip</code> · <code>dd ... bs=1 skip=N</code></td></tr><tr><td>磁盘 / 数据库</td><td><code>mmls → fls → icat</code> · <code>sqlite3 -readonly case.db ".tables"</code></td></tr><tr><td>内存 / 日志</td><td><code>windows.info → windows.pslist</code> · <code>Select-String</code></td></tr></tbody></table></div>

''', '数值参数必须来自实际证据或明确题目约定。配套 tools 目录提供可读 Python 替代方法，帮助没有完整工具环境的学员理解基础。', '')


add(7, '自测 01：工具与提取方法', '说清理由，比记住字母更重要。', r'''

<div class="quiz-grid"><section class="question" data-question="0" data-correct="A" data-explanation="偏移帮助回到原始字节复核。"><span class="q-label">QUESTION 01 / 08</span><h3>字符串结果需要保留哪个信息？</h3><div class="options"><button class="option" data-choice="A" aria-pressed="false"><span>A</span>偏移与原始上下文</button><button class="option" data-choice="B" aria-pressed="false"><span>B</span>只保留一张结果截图</button><button class="option" data-choice="C" aria-pressed="false"><span>C</span>把原文件重新保存</button></div><div class="feedback" role="status" hidden></div></section><section class="question" data-question="1" data-correct="B" data-explanation="校验一致不等于来源真实性或所有内容完整。"><span class="q-label">QUESTION 02 / 08</span><h3>PNG 的 CRC 匹配，能够证明？</h3><div class="options"><button class="option" data-choice="A" aria-pressed="false"><span>A</span>图像一定没有隐写</button><button class="option" data-choice="B" aria-pressed="false"><span>B</span>该块校验一致，仍需解析与内容验证</button><button class="option" data-choice="C" aria-pressed="false"><span>C</span>现实来源一定真实</button></div><div class="feedback" role="status" hidden></div></section><section class="question" data-question="2" data-correct="C" data-explanation="标志修改不能解密真实密文。"><span class="q-label">QUESTION 03 / 08</span><h3>ZIP 改掉加密标志后仍报 CRC 错误，应该？</h3><div class="options"><button class="option" data-choice="A" aria-pressed="false"><span>A</span>继续随意清零</button><button class="option" data-choice="B" aria-pressed="false"><span>B</span>断言密码已破解</button><button class="option" data-choice="C" aria-pressed="false"><span>C</span>回到真实加密、损坏与结构分析</button></div><div class="feedback" role="status" hidden></div></section><section class="question" data-question="3" data-correct="C" data-explanation="避免文字重编码破坏字节。"><span class="q-label">QUESTION 04 / 08</span><h3>跨平台保存提取出的二进制，优先？</h3><div class="options"><button class="option" data-choice="A" aria-pressed="false"><span>A</span>随意使用旧 PowerShell ></button><button class="option" data-choice="B" aria-pressed="false"><span>B</span>用文本编辑器保存</button><button class="option" data-choice="C" aria-pressed="false"><span>C</span>工具原生输出参数或 Python write_bytes</button></div><div class="feedback" role="status" hidden></div></section></div><div class="quiz-score"><span>已作答 <span data-quiz-count>0</span> / 8 · 当前正确 <strong data-quiz-score>0 / 8</strong> · 可修改答案</span><button class="tool-btn" data-reset-quiz>重置自测</button></div>

''', '答案 A、B、C、C。重点讨论校验、标志伪装与二进制输出。', '')


add(7, '自测 02：镜像、数据库与时间', '用参数的含义判断，不靠猜测。', r'''

<div class="quiz-grid"><section class="question" data-question="4" data-correct="A" data-explanation="单位为扇区，还要确认扇区大小。"><span class="q-label">QUESTION 05 / 08</span><h3>TSK 的 -o 2048 表示？</h3><div class="options"><button class="option" data-choice="A" aria-pressed="false"><span>A</span>2048 个扇区的偏移</button><button class="option" data-choice="B" aria-pressed="false"><span>B</span>2048 个字节</button><button class="option" data-choice="C" aria-pressed="false"><span>C</span>元数据地址 2048</button></div><div class="feedback" role="status" hidden></div></section><section class="question" data-question="5" data-correct="B" data-explanation="软删除记录仍在业务表中。"><span class="q-label">QUESTION 06 / 08</span><h3>表里 deleted=1 是什么？</h3><div class="options"><button class="option" data-choice="A" aria-pressed="false"><span>A</span>一定是物理删除页</button><button class="option" data-choice="B" aria-pressed="false"><span>B</span>本教学库的业务软删除字段</button><button class="option" data-choice="C" aria-pressed="false"><span>C</span>无法执行 SELECT 的数据</button></div><div class="feedback" role="status" hidden></div></section><section class="question" data-question="6" data-correct="C" data-explanation="dumpfiles 用于可恢复的文件缓存；进程映射页与可执行映像是不同对象。"><span class="q-label">QUESTION 07 / 08</span><h3>已确认目标 PID 与文件名，导出文件缓存应选择？</h3><div class="options"><button class="option" data-choice="A" aria-pressed="false"><span>A</span>windows.pslist --dump</button><button class="option" data-choice="B" aria-pressed="false"><span>B</span>windows.memmap --dump</button><button class="option" data-choice="C" aria-pressed="false"><span>C</span>windows.dumpfiles --pid … --filter …</button></div><div class="feedback" role="status" hidden></div></section><section class="question" data-question="7" data-correct="A" data-explanation="Z 是 UTC，此例加 8 小时。"><span class="q-label">QUESTION 08 / 08</span><h3>01:18:31Z 转为同日 UTC+8 是？</h3><div class="options"><button class="option" data-choice="A" aria-pressed="false"><span>A</span>09:18:31 +08:00</button><button class="option" data-choice="B" aria-pressed="false"><span>B</span>01:18:31 +08:00</button><button class="option" data-choice="C" aria-pressed="false"><span>C</span>前一天 17:18:31</button></div><div class="feedback" role="status" hidden></div></section></div><div class="quiz-score"><span>已作答 <span data-quiz-count>0</span> / 8 · 当前正确 <strong data-quiz-score>0 / 8</strong> · 可修改答案</span><button class="tool-btn" data-reset-quiz>重置自测</button></div>

''', '答案 A、B、C、A。重点讨论 -o 的单位、软删除与缓存导出对象。', '')


add(7, '参考资料：使用工具自己的文档', '课程核对日期 2026-10-19；工具参数以本机版本帮助为准。', r'''

<ul class="resource-list"><li><a href="https://sourceware.org/binutils/docs/binutils/strings.html" target="_blank" rel="noopener noreferrer">GNU strings ↗</a><small>检索参数、编码与偏移。</small></li><li><a href="https://exiftool.org/" target="_blank" rel="noopener noreferrer">ExifTool ↗</a><small>标签读取与格式参考。</small></li><li><a href="https://github.com/pnggroup/pngcheck" target="_blank" rel="noopener noreferrer">PNG / pngcheck ↗</a><small>PNG 结构与校验工具。</small></li><li><a href="https://github.com/zed-0xff/zsteg" target="_blank" rel="noopener noreferrer">zsteg ↗</a><small>扫描和提取参数。</small></li><li><a href="https://github.com/ReFirmLabs/binwalk/wiki" target="_blank" rel="noopener noreferrer">Binwalk ↗</a><small>版本、扫描与提取。</small></li><li><a href="https://www.sleuthkit.org/sleuthkit/docs.php" target="_blank" rel="noopener noreferrer">The Sleuth Kit ↗</a><small>mmls、fls、icat 文档。</small></li><li><a href="https://www.sqlite.org/cli.html" target="_blank" rel="noopener noreferrer">SQLite ↗</a><small>只读模式、点命令与查询。</small></li><li><a href="https://volatility3.readthedocs.io/en/stable/" target="_blank" rel="noopener noreferrer">Volatility ↗</a><small>插件与符号要求。</small></li></ul><div class="callout ">讲师手册另附公开例题来源、七组自制题的讲解步骤与答案。</div>

''', '外部参考链接需要联网；课件、解码、自测、下载和自制练习可离线使用。', '')


add(7, '从一条命令，到一条证据链', '', r'''

<div class="finish"><div><span class="label">KNOW THE TOOL. EXPLAIN THE EVIDENCE.</span><div class="finish-mark">[✓]</div><h2>会用工具，<br><span class="accent">也会解释结果。</span></h2><p class="finish-sub">识别材料 → 定位线索 → 提取内容 → 复核结论</p></div><div class="end-checks"><h3>带走三样东西</h3><ul class="checklist"><li>工具用途、参数和输出的理解。</li><li>两道公开例题与七组基础练习。</li><li>可复制命令、可复现的解题记录。</li></ul><button class="btn secondary" data-download>下载练习与工具脚本 ↓</button></div></div>

''', '请学员选择一道题，用一分钟讲解“为何选这条命令、输出如何理解、如何验证”。', 'closing')

assert len(SLIDES)==81
