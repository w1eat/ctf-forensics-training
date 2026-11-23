"""Stage portable upstream tools and explicit dependencies, without installing globally."""
from pathlib import Path
import shutil, subprocess, tarfile, zipfile

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "工具包构建" / "下载缓存"
KIT = ROOT / "学员工具包_Windows64"
BUILD = ROOT / "工具包构建" / "编译暂存"
OLD7Z = Path(r"E:\CTF\ctf\misc\取证tools\i4Tools8\i4Tools8\x64\files\patchtools\7z-64\7z.exe")

def unzip(src, dest, strip=0):
    with zipfile.ZipFile(src) as z:
        assert z.testzip() is None, src
        for info in z.infolist():
            parts = Path(info.filename).parts[strip:]
            if not parts or info.is_dir():
                continue
            target = dest.joinpath(*parts)
            assert target.resolve().is_relative_to(dest.resolve())
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(info))

def stage():
    KIT.mkdir(exist_ok=True)
    BUILD.mkdir(exist_ok=True)
    unzip(CACHE / "python-3.13.16-embed-amd64.zip", KIT / "runtime" / "python")
    py = KIT / "runtime" / "python"
    (py / "python313._pth").write_text("python313.zip\n.\nLib/site-packages\nimport site\n", encoding="utf-8")
    for wheel in sorted((CACHE / "wheels").glob("*.whl")):
        unzip(wheel, py / "Lib" / "site-packages")
    vol = KIT / "tools" / "volatility3"
    vol.mkdir(parents=True, exist_ok=True)
    # The original package entry point; no result processing or plugin modifications.
    (vol / "vol.py").write_text("from volatility3.cli import main\nif __name__ == '__main__':\n    main()\n", encoding="utf-8")
    vdist = next((py / "Lib" / "site-packages").glob("volatility3-*.dist-info"))
    for item in vdist.rglob("*LICENSE*"):
        if item.is_file():
            shutil.copy2(item, vol / item.name)
    unzip(CACHE / "exiftool-13.59_64.zip", KIT / "tools" / "exiftool", 1)
    exif = KIT / "tools" / "exiftool"
    shutil.copy2(exif / "exiftool(-k).exe", exif / "exiftool.exe")
    unzip(CACHE / "sqlite-tools-win-x64-3540100.zip", KIT / "tools" / "sqlite")
    seven = KIT / "tools" / "7zip"
    subprocess.run([str(OLD7Z), "x", "-y", str(CACHE / "7z2604-sf.exe"), "-o" + str(seven)], check=True, stdout=subprocess.DEVNULL)
    busy = KIT / "tools" / "busybox"
    busy.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CACHE / "busybox64.exe", busy / "busybox.exe")
    unzip(CACHE / "pngcheck-v4.0.1.zip", BUILD / "pngcheck", 1)
    with tarfile.open(CACHE / "zlib-1.3.1.tar.gz") as t:
        t.extractall(BUILD, filter="data")
    print("Staged:", KIT)

if __name__ == "__main__":
    stage()
