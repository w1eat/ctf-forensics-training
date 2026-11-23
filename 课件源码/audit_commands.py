"""Inventory the command boxes so platform annotations can be reviewed."""
import html,json,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from content import SLIDES
pattern=re.compile(r'class="codebox".*?<span>(.*?)</span>.*?<pre><code>(.*?)</code>',re.S)
records=[]
for number,slide in enumerate(SLIDES,1):
    for ordinal,match in enumerate(pattern.finditer(slide['body']),1):
        records.append(dict(slide=number,index=ordinal,title=slide['title'],
                            label=html.unescape(match[1]),code=html.unescape(match[2])))
root=Path(__file__).resolve().parent.parent
(root/'output/命令环境审查_原始.json').write_text(json.dumps(records,ensure_ascii=False,indent=2),encoding='utf-8')
for r in records:
    print(f"{r['slide']:02}.{r['index']} {r['title']} | {r['label']} | {r['code']!r}")
