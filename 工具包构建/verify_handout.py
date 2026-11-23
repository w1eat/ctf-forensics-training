"""Validate student wording, environment labels, paired examples and Bash syntax."""
from pathlib import Path
import collections, json, re, subprocess, sys, zipfile
ROOT=Path(__file__).resolve().parent.parent
SOURCE=ROOT/'课件源码'
sys.path.insert(0,str(SOURCE))
from student_handout import NAME
from command_platforms import annotate_slides
from content import SLIDES

def main():
    folder=ROOT/'output/讲义语法检查';folder.mkdir(parents=True,exist_ok=True)
    md=(ROOT/(NAME+'.md')).read_text(encoding='utf-8')
    matches=list(re.finditer(r'^~~~([^\n]*)\n(.*?)^~~~\s*$',md,re.M|re.S))
    commands=[dict(language=m[1].split()[0],info=m[1],code=m[2].rstrip()) for m in matches]
    for bad in ('让学员','讲师','给学员讲','建议课堂节奏'):
        assert bad not in md,bad
    assert len(re.findall(r'^## 案例 \d{2}',md,re.M))==15
    assert md.count('**运行环境：')==len(commands)
    counts=collections.Counter(c['language'] for c in commands)
    bash=Path('E:/soft/Git/bin/bash.exe');assert bash.is_file()
    for n,item in enumerate(commands,1):
        if item['language']!='bash':continue
        path=folder/f'kali_{n:03}.sh';path.write_text(item['code']+'\n',encoding='utf-8',newline='\n')
        result=subprocess.run([str(bash),'-n',str(path)],capture_output=True,text=True,encoding='utf-8')
        assert result.returncode==0,(n,result.stderr)
    (folder/'powershell_blocks.json').write_text(json.dumps([c for c in commands if c['language']=='powershell'],ensure_ascii=False),encoding='utf-8')
    page=(ROOT/(NAME+'.html')).read_text(encoding='utf-8')
    assert page.count('<pre><code>')==page.count('<div class="code" data-platform=')==len(commands)
    assert '复制 SQL' in page and 'Windows · CMD' in page and 'Kali Linux · Bash' in page
    slides,audit=annotate_slides(SLIDES)
    assert sum(s['body'].count('<pre><code>') for s in slides)==len(audit)
    assert len({(a['slide'],a['index']) for a in audit})==len(audit)
    for path in (ROOT/'CTF取证基础_Kali学习资料.zip',ROOT/'CTF取证基础_学员讲义与练习.zip'):
        with zipfile.ZipFile(path) as z:
            assert z.testzip() is None
            assert 'labs/tools/finspect.py' in z.namelist()
            assert NAME+'.html' in z.namelist()
            assert not any(n.endswith(('.exe','.dll','.cmd')) for n in z.namelist())
    summary=dict(student_cases=15,handout_code_blocks=len(commands),languages=dict(counts),
                 slide_code_blocks=len(audit),kali_bash_syntax='pass',kali_actual_execution=False,
                 windows_powershell_syntax='pending',real_ram_provided=False)
    (ROOT/'output/学员讲义验收记录.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(summary,ensure_ascii=False))

if __name__=='__main__':main()
