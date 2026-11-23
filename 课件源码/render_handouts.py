"""Render the project's constrained Markdown handouts as offline HTML."""
import html, re
from pathlib import Path

ENVIRONMENTS={
    'powershell':('windows','Windows · PowerShell','复制命令'),
    'cmd':('cmd','Windows · CMD','复制命令'),
    'bash':('kali','Kali Linux · Bash','复制命令'),
    'python':('python','Python 3 源码 · Windows / Kali','复制代码'),
    'sql':('sql','SQLite SQL · sqlite3 交互终端（Windows / Kali）','复制 SQL'),
    'text':('output','示例输出 / 数据 · 不执行','复制文本'),
    'json':('output','JSON 数据 · 不执行','复制文本'),
    'hex':('output','十六进制数据 · 不执行','复制文本'),
    'console':('both','Windows PowerShell / Kali Bash · 同语法命令','复制命令'),
}
CONTEXTS={'root':'从工具包根目录开始','setup':'环境准备 · 选择自己的目录',
          'ram':'从 labs 运行 · 需要另备真实 RAM',
          'source':'保存为源码文件后运行'}

REASONING_STYLE='''.table.reasoning{max-height:none;overflow:visible}.table.reasoning table{table-layout:fixed;font-size:.94em;line-height:1.85}.table.reasoning th{position:static;font-size:inherit}.table.reasoning th:first-child{width:26%}.table.reasoning td{max-width:none;word-break:normal;overflow-wrap:anywhere}@media(max-width:600px){.table.reasoning table,.table.reasoning tbody{display:block;width:100%}.table.reasoning thead{position:absolute;width:1px;height:1px;overflow:hidden;clip-path:inset(50%);white-space:nowrap}.table.reasoning tbody tr{display:block;margin:14px 0;border:1px solid #d3dfd2;border-radius:6px;overflow:hidden;background:#fffffa}.table.reasoning td{display:block;width:100%;padding:11px 14px;border:0}.table.reasoning td:first-child{background:#e5eddb}.table.reasoning td+td{border-top:1px solid #e3e9de}.table.reasoning td::before{content:attr(data-label);display:block;font-size:.85em;font-weight:bold;color:#41643c;margin-bottom:5px}}'''

def command_meta(info):
    parts=info.strip().split();language=parts[0] if parts else 'text'
    if language not in ENVIRONMENTS:raise ValueError('Unlabeled code language: '+language)
    kind,label,copy=ENVIRONMENTS[language]
    scope=next((CONTEXTS[p] for p in parts[1:] if p in CONTEXTS),None)
    if scope is None:
        scope={'python':'在编辑器中保存；不要直接粘贴到 Shell',
               'sql':'先进入 sqlite3；SQL 以分号结束',
               'output':'用于比较与判读，无需输入终端'}.get(kind,'从 labs 运行；先完成对应系统的环境准备')
    return kind,label,copy,scope

def explicit_markdown(markdown):
    """Keep environment labels visible even in Markdown readers hiding fence info."""
    def label(match):
        kind,name,copy,scope=command_meta(match[2])
        return '**运行环境：'+name+'｜'+scope+'**\n\n'+match[0]
    return re.sub(r'^(~~~|`{3})([^\n]*)\n(.*?)^\1[ \t]*$',label,markdown,flags=re.M|re.S)

def inline(text):
    text=html.escape(text)
    text=re.sub(r'\*\*(.+?)\*\*',r'<strong>\1</strong>',text)
    text=re.sub(r'`([^`]+)`',r'<code>\1</code>',text)
    text=re.sub(r'https://[^\s<。；，）]+',lambda m:'<a href="'+m.group()+'" target="_blank" rel="noreferrer">'+m.group()+'</a>',text)
    return text

def render(markdown, title):
    lines=markdown.splitlines(); out=[];toc=[];i=0;counter=0
    while i<len(lines):
        line=lines[i].strip()
        if not line:i+=1;continue
        # The same label is rendered in the code header in HTML.
        if line.startswith('**运行环境：') and line.endswith('**'):i+=1;continue
        if line.startswith(('~~~','\x60\x60\x60')):
            fence=line[:3];language=line[3:];block=[];i+=1
            while i<len(lines) and not lines[i].strip().startswith(fence):
                block.append(lines[i]);i+=1
            kind,label,copy,scope=command_meta(language)
            out.append('<div class="code" data-platform="'+kind+'"><div><span><b>'+html.escape(label)+'</b><small>'+html.escape(scope)+'</small></span><button type="button" class="copy">'+copy+'</button></div><pre><code>'+html.escape('\n'.join(block))+'</code></pre></div>')
            i+=1;continue
        if line.startswith('# '):out.append('<h1>'+inline(line[2:])+'</h1>');i+=1;continue
        if line.startswith('## '):
            counter+=1;name=line[3:];anchor=f's{counter}'
            out.append(f'<h2 id="{anchor}">'+inline(name)+'</h2>')
            toc.append(f'<a href="#{anchor}">'+html.escape(name)+'</a>');i+=1;continue
        if line.startswith('### '):out.append('<h3>'+inline(line[4:])+'</h3>');i+=1;continue
        if line.startswith('|'):
            rows=[]
            while i<len(lines) and lines[i].strip().startswith('|'):
                cells=[x.strip() for x in lines[i].strip().strip('|').split('|')]
                if not all(re.fullmatch(r':?-+:?',x.replace(' ','')) for x in cells):rows.append(cells)
                i+=1
            if rows:
                reasoning=rows[0]==['要回答的问题','选择这一步的理由','看到什么才继续']
                table='<div class="table'+(' reasoning' if reasoning else '')+'"><table><thead><tr>'+''.join('<th>'+inline(c)+'</th>' for c in rows[0])+'</tr></thead><tbody>'
                table+=''.join('<tr>'+''.join('<td'+(' data-label="'+html.escape(rows[0][n],quote=True)+'"' if reasoning else '')+'>'+inline(c)+'</td>' for n,c in enumerate(row))+'</tr>' for row in rows[1:])
                out.append(table+'</tbody></table></div>')
            continue
        if line.startswith('- '):
            items=[]
            while i<len(lines) and lines[i].strip().startswith('- '):
                items.append('<li>'+inline(lines[i].strip()[2:])+'</li>');i+=1
            out.append('<ul>'+''.join(items)+'</ul>');continue
        paragraph=[line];i+=1
        while i<len(lines) and lines[i].strip() and not lines[i].lstrip().startswith(('#','~~~','|','- ','\x60\x60\x60')):
            paragraph.append(lines[i].strip());i+=1
        out.append('<p>'+inline(' '.join(paragraph))+'</p>')
    style="""*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:28px}body{margin:0;background:#f5f6ef;color:#193330;font:16px/1.9 'Microsoft YaHei','PingFang SC',sans-serif}a{color:#286f57;overflow-wrap:anywhere}nav{position:fixed;inset:0 auto 0 0;width:265px;padding:32px 20px;background:#16332e;color:#deeee2;overflow:auto}nav strong{display:block;font-size:20px;margin:0 12px 20px}nav a{display:block;color:#d2e6d8;text-decoration:none;padding:8px 12px;font-size:13px;line-height:1.6;border-bottom:1px solid #ffffff12}nav a:hover{background:#ffffff12;color:white}main{max-width:1240px;margin-left:265px;padding:55px 65px 100px}h1{font-size:36px;line-height:1.4;letter-spacing:-1px;margin:0 0 30px}h2{font-size:27px;line-height:1.5;margin:58px 0 20px;padding-top:20px;border-top:2px solid #b4cbb7}h3{font-size:18px;margin:30px 0 10px}p{margin:12px 0}ul{padding-left:24px}.code{background:#152e2c;color:#e0eee5;border-radius:8px;overflow:hidden;margin:20px 0}.code>div{display:flex;justify-content:space-between;align-items:center;padding:7px 16px;background:#21403a;font-size:12px;color:#accab8}.copy{font:12px inherit;color:#deeee2;background:#ffffff12;border:1px solid #ffffff30;border-radius:4px;padding:4px 10px;cursor:pointer}pre{margin:0;padding:18px;overflow:auto;font:13px/1.85 Consolas,'Cascadia Code',monospace;tab-size:4}.table{overflow:auto;margin:22px 0}table{width:100%;border-collapse:collapse;font-size:14px}th,td{padding:12px 14px;border-bottom:1px solid #d3dfd2;text-align:left;vertical-align:top}th{background:#e1ebdc;font-size:13px}tr:nth-child(even){background:#ffffff70}.meta{font-size:12px;letter-spacing:2px;color:#608269;margin-bottom:18px}.toolbar{position:fixed;right:24px;top:18px;z-index:2}.toolbar button{background:#fff;border:1px solid #c1d3c1;padding:7px 14px;border-radius:5px;color:#204b3e;cursor:pointer}.status{position:fixed;right:24px;bottom:22px;background:#225841;color:white;padding:8px 18px;border-radius:5px;z-index:4}footer{margin-top:60px;border-top:1px solid #bdcfbf;padding-top:18px;font-size:12px;color:#6c8274}@media(max-width:900px){nav{position:relative;width:100%;max-height:230px;padding:20px}main{margin-left:0;padding:35px 20px}h1{font-size:28px}.toolbar{position:absolute;top:20px;right:20px}}@media print{body{background:white;font-size:11pt}nav,.toolbar,.copy,.status{display:none!important}main{margin:0;padding:0;max-width:none}h1{font-size:25pt}h2{page-break-before:always;font-size:20pt}h3{page-break-after:avoid}pre{white-space:pre-wrap;font-size:9pt}.code{color:#132e24;background:#f2f6ef;border:1px solid #bccbbc;break-inside:avoid}.code>div{background:#e1ebdc;color:#264e3d}a{color:inherit}table{font-size:9pt}tr{break-inside:avoid}}@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}"""
    style+='''.code>div{gap:12px}.code>div>span{display:flex;flex-direction:column;min-width:0;line-height:1.6}.code>div b{font-size:12px;letter-spacing:.3px;color:#ecf5e9}.code>div small{font-size:10px;color:#c2d6c5}.copy{flex-shrink:0}.code[data-platform=kali]>div{background:#353d50}.code[data-platform=cmd]>div{background:#49422f}.code[data-platform=output]{background:#e6ece3;color:#23372c;border:1px solid #c2cfbf}.code[data-platform=output]>div{background:#d4dfd0;color:#344d39}.code[data-platform=output]>div b,.code[data-platform=output]>div small{color:#344d39}.code[data-platform=output] .copy{color:#344d39;border-color:#a4b69f;background:#ffffff50}p code,td code{font:90% Consolas,monospace;background:#dce8d9;border-radius:3px;padding:1px 4px}pre{overscroll-behavior-x:contain}.table{max-width:100%}@media print{.code>div b,.code>div small{color:#264e3d}.code[data-platform=kali]>div,.code[data-platform=cmd]>div{background:#e1ebdc}}'''
    style+=REASONING_STYLE
    script="""document.addEventListener('click',async function(e){if(e.target.id==='print'){window.print();return}if(!e.target.classList.contains('copy'))return;const box=e.target.closest('.code'),value=box.querySelector('code').textContent;let done=false;try{await navigator.clipboard.writeText(value);done=true}catch(err){const t=document.createElement('textarea');t.value=value;document.body.appendChild(t);t.select();done=document.execCommand('copy');t.remove()}const s=document.getElementById('status');s.textContent=done?'已复制，请按代码框标注的环境使用':'复制失败，请选中文本手动复制';s.hidden=false;clearTimeout(window.copyTimer);window.copyTimer=setTimeout(()=>s.hidden=true,2200)});"""
    return '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><link rel="icon" href="data:,"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+html.escape(title)+'</title><style>'+style+'</style></head><body><nav aria-label="目录"><a href="index.html" target="_top" style="margin-bottom:14px;color:#fff">← 返回统一学习入口</a><strong>证据实验室</strong>'+''.join(toc)+'</nav><div class="toolbar"><button id="print">打印 / 另存 PDF</button></div><main style="overflow-wrap:anywhere;min-width:0"><div class="meta">FORENSICS CLASSROOM / OFFLINE HANDOUT</div>'+''.join(out)+'<footer>CTF 取证基础专项培训 · 2026.10 · 可离线阅读与复制命令</footer></main><div id="status" class="status" role="status" hidden></div><script>'+script+'</script></body></html>'

if __name__=='__main__':
    root=Path(__file__).resolve().parent.parent
    for name in ('CTF取证基础_学员讲义','Volatility3_内存镜像分析_命令与题解','讲师题解_逐题讲解','工具包使用指南'):
        source=root/(name+'.md')
        if source.exists():(root/(name+'.html')).write_text(render(source.read_text(encoding='utf-8'),name),encoding='utf-8')

