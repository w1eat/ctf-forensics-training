"""Download unmodified upstream distributions. No installers are executed."""
from pathlib import Path
import concurrent.futures, hashlib, json, subprocess

BASE = Path(__file__).resolve().parent
CACHE = BASE / "下载缓存"
ITEMS = [
    ("python-3.13.16-embed-amd64.zip", "https://www.python.org/ftp/python/3.13.16/python-3.13.16-embed-amd64.zip"),
    ("7z2604-x64.exe", "https://github.com/ip7z/7zip/releases/download/26.04/7z2604-x64.exe"),
    ("7z2604-src.7z", "https://github.com/ip7z/7zip/releases/download/26.04/7z2604-src.7z"),
    ("exiftool-13.59_64.zip", "https://sourceforge.net/projects/exiftool/files/exiftool-13.59_64.zip/download"),
    ("Image-ExifTool-13.59.tar.gz", "https://exiftool.org/Image-ExifTool-13.59.tar.gz"),
    ("sqlite-tools-win-x64-3540100.zip", "https://sqlite.org/2026/sqlite-tools-win-x64-3540100.zip"),
    ("sleuthkit-4.14.0-win32.zip", "https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.14.0/sleuthkit-4.14.0-win32.zip"),
    ("sleuthkit-4.14.0.tar.gz", "https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.14.0/sleuthkit-4.14.0.tar.gz"),
    ("rubyinstaller-3.3.12-1-x64.7z", "https://github.com/oneclick/rubyinstaller2/releases/download/RubyInstaller-3.3.12-1/rubyinstaller-3.3.12-1-x64.7z"),
    ("pngcheck-v4.0.1.zip", "https://codeload.github.com/pnggroup/pngcheck/zip/refs/tags/v4.0.1"),
    ("zlib-1.3.1.tar.gz", "https://zlib.net/fossils/zlib-1.3.1.tar.gz"),
    ("busybox64.exe", "https://frippery.org/files/busybox/busybox64.exe"),
    ("busybox-home.html", "https://frippery.org/busybox/"),
    ("john-1.9.0-jumbo-1-win64.7z", "https://www.openwall.com/john/k/john-1.9.0-jumbo-1-win64.7z"),
    ("john-1.9.0-jumbo-1.tar.xz", "https://www.openwall.com/john/k/john-1.9.0-jumbo-1.tar.xz"),
    ("autopsy-4.23.1-64bit.msi", "https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.23.1/autopsy-4.23.1-64bit.msi"),
]

def download(item):
    name, url = item
    target = CACHE / name
    if not target.exists():
        partial = target.with_name(name + ".part")
        r = subprocess.run(["curl.exe", "-fL", "-sS", "--retry", "1", "--connect-timeout", "15", "--max-time", "600", url, "-o", str(partial)], capture_output=True)
        if r.returncode:
            return {"file": name, "url": url, "error": r.stderr.decode(errors="replace").strip()}
        partial.replace(target)
    digest = hashlib.file_digest(target.open("rb"), "sha256").hexdigest()
    return {"file": name, "url": url, "bytes": target.stat().st_size, "sha256": digest}

if __name__ == "__main__":
    CACHE.mkdir(parents=True, exist_ok=True)
    records = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        for result in pool.map(download, ITEMS):
            records.append(result)
            print(json.dumps(result, ensure_ascii=False), flush=True)
            (BASE / "downloads.json").write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
