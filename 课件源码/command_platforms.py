"""Explicitly reviewed host-shell labels for every presentation command block."""
import html,re

LABELS={
    'windows':'Windows · PowerShell',
    'cmd':'Windows · CMD',
    'kali':'Kali Linux · Bash',
    'both':'Windows PowerShell / Kali Bash（同命令）',
    'python':'Python 3 源码 · Windows/Kali（编辑器保存后运行）',
    'sql':'SQLite SQL · Windows/Kali 的 sqlite3 交互终端',
    'output':'数据 / 示例输出 · 不执行',
}
GROUPS={
    'windows':('04.1 05.1 08.1 11.2 13.2 17.3 26.1 29.2 31.1 32.1 34.1 35.1 39.1 46.1 50.1 '
               '52.1 53.1 54.1 55.1 56.1 57.1 58.1 59.1 60.1 61.1 62.1 63.2 64.2 65.1 65.2 66.1 66.2 71.1 72.1').split(),
    'kali':('05.2 06.1 10.1 11.1 12.1 13.1 17.2 18.1 20.1 22.1 28.1 30.1 36.1 37.1 38.1 43.1 44.1 45.1 63.1').split(),
    'both':'14.1 21.1 24.1 33.1 47.1 48.1'.split(),
    'python':'15.1 17.1 22.2 25.1 29.1 38.2 48.2 64.3'.split(),
    'sql':['49.1'],
    'output':'27.1 57.2 64.1 69.1 73.1'.split(),
}
ASSIGNMENTS={key:kind for kind,keys in GROUPS.items() for key in keys}
BOX=re.compile(r'<div class="codebox"><div class="code-top"><span>(.*?)</span>(.*?)</div><pre><code>(.*?)</code></pre></div>',re.S)

def annotate_slides(slides):
    result=[];audit=[]
    for slide in slides:
        item=slide.copy();number=0
        # Match by canonical course title, including the separately built memory deck.
        from content import SLIDES
        canonical=next(i for i,s in enumerate(SLIDES,1) if s['title']==slide['title'])
        def replace(match):
            nonlocal number
            number+=1;key=f'{canonical:02}.{number}'
            if key not in ASSIGNMENTS:raise ValueError('Unreviewed code box: '+key)
            kind=ASSIGNMENTS[key];title=html.unescape(match[1]);text=html.unescape(match[3])
            # Correct the reproduction search and JSONL parsing before labeling.
            if key=='20.1':text=text.replace("grep 'picoCTF'","grep -E 'picoCTF|flag'")
            if key=='71.1':text=text.replace('Get-Content .\\audit.jsonl | ConvertFrom-Json |',
                                            'Get-Content .\\audit.jsonl | ForEach-Object { $_ | ConvertFrom-Json } |')
            title=re.sub(r'^(?:Windows PowerShell|PowerShell|Linux Bash|跨平台|Python 3|SQLite CLI)\s*[·｜]?\s*','',title)
            if kind=='output':copy='<small class="code-readonly">仅阅读</small>'
            else:copy=match[2]
            audit.append(dict(slide=canonical,index=number,kind=kind,platform=LABELS[kind],code=text))
            return (f'<div class="codebox" data-platform="{kind}"><div class="code-top"><span>'
                    f'<b class="platform-label platform-{kind}">{html.escape(LABELS[kind])}</b>'
                    f'<em class="code-context">{html.escape(title)}</em></span>{copy}</div>'
                    f'<pre><code>{html.escape(text)}</code></pre></div>')
        item['body']=BOX.sub(replace,item['body'])
        item['subtitle']=item['subtitle'].replace('建议分两次讲授；先讲工具，再用简单例题串起完整过程。','先掌握工具的输入、参数与输出，再按步骤完成基础题。')
        item['body']=item['body'].replace('讲清每一道例题的“为什么”和“怎么做”。','能解释命令为什么有效，并用输出验证结论。')
        if canonical==5:
            item['body']+='<p class="shell-note">Windows 标签指 PowerShell；Kali 标签按 Bash 编写。Kali 终端若使用 Zsh，先执行 <code>bash</code>。完整环境准备与两套命令见《学员讲义》。</p>'
        result.append(item)
    return result,audit
