"""Build upstream pngcheck with static zlib using an existing MinGW compiler."""
from pathlib import Path
import shutil, subprocess, json

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "工具包构建" / "编译暂存"
PNG = BUILD / "pngcheck"
ZLIB = BUILD / "zlib-1.3.1"
DEST = ROOT / "学员工具包_Windows64" / "tools" / "pngcheck"
DEST.mkdir(parents=True, exist_ok=True)
sources = "adler32 compress crc32 deflate gzclose gzlib gzread gzwrite infback inffast inflate inftrees trees uncompr zutil".split()
command = [r"E:\code\MinGW\bin\gcc.exe", "-O2", "-static", "-I", str(ZLIB), str(PNG / "pngcheck.c")]
command += [str(PNG / "third_party" / "wildargs" / "wildargs.c")]
command += [str(ZLIB / (s + ".c")) for s in sources]
command += ["-o", str(DEST / "pngcheck.exe")]
subprocess.run(command, check=True)
shutil.copy2(PNG / "LICENSE", DEST / "LICENSE")
shutil.copy2(PNG / "README.md", DEST / "README.md")
(DEST / "BUILD.json").write_text(json.dumps({"compiler": "MinGW GCC 13.2.0", "pngcheck": "4.0.1", "zlib": "1.3.1", "flags": "-O2 -static", "modifications": "none", "sources": "../../licenses/source/"}, indent=2), encoding="utf-8")
subprocess.run([str(DEST / "pngcheck.exe"), "-h"], check=False)
