"""Every local link and resource referenced by each distribution must exist."""
from pathlib import Path,PurePosixPath
from html.parser import HTMLParser
from urllib.parse import unquote,urlsplit
import json,zipfile
ROOT=Path(__file__).resolve().parent.parent
class Links(HTMLParser):
    def __init__(self):super().__init__();self.links=[]
    def handle_starttag(self,tag,attrs):
        attrs=dict(attrs)
        if tag=='a' and attrs.get('href'):self.links.append(attrs['href'])

def check(page,exists):
    parser=Links();parser.feed(page);missing=[];count=0
    for href in parser.links:
        if href.startswith(('#','http:','https:','data:','javascript:','blob:')):continue
        name=unquote(urlsplit(href).path)
        if not name:continue
        count+=1
        if not exists(name):missing.append(name)
    start=page.index('<script type="application/json" id="portal-data">')
    data=json.loads(page[start:].split('>',1)[1].split('</script>',1)[0])
    for row in data['resources']:
        count+=1
        if not exists(row['href']):missing.append(row['href'])
    assert not missing,missing
    return dict(local_links=count,resources=len(data['resources']),cases=len(data['cases']),actions=len(data['actions']),missing=missing)

def main():
    result={}
    result['workspace']=check((ROOT/'index.html').read_text(encoding='utf-8'),lambda p:(ROOT/p).is_file())
    for name in ('CTF取证基础_Kali学习资料.zip','讲师课件与逐题题解.zip','学员工具与练习_Windows64.zip'):
        with zipfile.ZipFile(ROOT/name) as z:
            prefix='学员工具包_Windows64/' if name.startswith('学员工具与练习') else ''
            entries=set(z.namelist())
            result[name]=check(z.read(prefix+'index.html').decode('utf-8'),lambda p:prefix+PurePosixPath(p).as_posix() in entries)
            assert z.testzip() is None
    (ROOT/'output/统一索引与分发链接验收.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':main()
