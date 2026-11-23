"""Search ASCII/UTF-16LE flags in an excerpt. Does not parse RAM or infer a PID."""
from pathlib import Path
import argparse,re
p=argparse.ArgumentParser(description=__doc__);p.add_argument('input');a=p.parse_args()
data=Path(a.input).read_bytes();found=False
patterns=[('ASCII',rb'flag\{[ -~]{1,100}?\}'),('UTF-16LE',rb'f\x00l\x00a\x00g\x00\{\x00(?:[\x20-\x7e]\x00){1,100}?\}\x00')]
for encoding,pattern in patterns:
    for match in re.finditer(pattern,data):
        found=True;text=match.group().decode('ascii' if encoding=='ASCII' else 'utf-16le')
        print(encoding,'offset-in-input='+hex(match.start()),text)
if not found:print('No matching text in the two supported representations.')
