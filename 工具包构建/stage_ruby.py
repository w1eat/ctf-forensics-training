from pathlib import Path
import json, subprocess, shutil, sys
from prepare_core import ROOT,CACHE,KIT

SEVEN=KIT/'tools/7zip/7z.exe'
DEST=ROOT/'工具包构建/编译暂存/ruby'
DEST.mkdir(parents=True,exist_ok=True)
subprocess.run([str(SEVEN),'x','-y',str(CACHE/'ruby-api.7z'),'-o'+str(DEST)],check=True,stdout=subprocess.DEVNULL)
bindir=next(DEST.rglob('ruby.exe')).parent
rubyroot=bindir.parent
shutil.copytree(rubyroot,KIT/'runtime/ruby',dirs_exist_ok=True)
gems=CACHE/'gems';gems.mkdir(exist_ok=True)
versions={'iostruct':'0.7.0','rainbow':'3.1.1','zpng':'0.4.6','prime':'0.1.4','zsteg':'0.2.14'}
for name,version in versions.items():
    target=gems/(name+'-'+version+'.gem')
    if not target.exists():
        subprocess.run(['curl.exe','-fLsS','--connect-timeout','10','--max-time','90',
                        'https://rubygems.org/downloads/'+target.name,'-o',str(target)],check=True)
    subprocess.run([str(KIT/'runtime/ruby/bin/ruby.exe'),str(KIT/'runtime/ruby/bin/gem'),
                    'install','--local',str(target),'--no-document'],check=True)
source=KIT/'licenses/source'
source.mkdir(parents=True,exist_ok=True)
for f in gems.glob('*.gem'):shutil.copy2(f,source/f.name)
print('Ruby and zsteg staged.')
