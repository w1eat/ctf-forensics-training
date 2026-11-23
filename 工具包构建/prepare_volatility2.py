"""Stage official Volatility 2.6 standalone builds and their corresponding source.

Downloads are prepared separately. Every build verifies the upstream SHA256 list;
only the executable and original notices are selected from each release archive.
"""
from pathlib import Path
import hashlib, json, shutil, zipfile

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / '工具包构建/下载缓存'
KIT = ROOT / '学员工具包_Windows64'
RELEASE = 'https://downloads.volatilityfoundation.org/releases/2.6/'
ARCHIVES = {
    'volatility_2.6_win64_standalone.zip': 'bb021f3b569bf8ee4a408b2e07b0662699894ff7eecd4473badf0ef0c58f2fce',
    'volatility_2.6_lin64_standalone.zip': 'dc375a0f6909cb93ac17a10e28a0963fcd2decfc3c4291aadb7e5e0cbe28874a',
    'volatility-2.6-source.zip': '5b73050d72bf94870ffce22843f03d4b0b7764011dec29ef1a0a5b1b46cf9295',
}
NOTICES = ('AUTHORS.txt', 'CREDITS.txt', 'LEGAL.txt', 'LICENSE.txt', 'README.txt')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    records = []
    for name, expected in ARCHIVES.items():
        path = CACHE / name
        actual = digest(path)
        if actual != expected:
            raise ValueError('Volatility 2 upstream hash mismatch: ' + name)
        upstream_name = 'volatility-2.6.zip' if name.endswith('source.zip') else name
        records.append(dict(file=name, source=RELEASE + upstream_name, sha256=actual))
    for platform, stem, suffix in (
        ('windows', 'volatility_2.6_win64_standalone', '.exe'),
        ('linux', 'volatility_2.6_lin64_standalone', ''),
    ):
        folder = KIT / 'tools/volatility2' / platform
        folder.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(CACHE / (stem + '.zip')) as archive:
            for name in (*NOTICES, stem + suffix):
                target = folder / name
                target.write_bytes(archive.read(stem + '/' + name))
                if not suffix and name == stem:
                    target.chmod(0o755)
    destination = KIT / 'licenses/source'
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(CACHE / 'volatility-2.6-source.zip', destination / 'volatility-2.6-source.zip')
    shutil.copy2(CACHE / 'volatility-2.6-hashes.txt', KIT / 'tools/volatility2/UPSTREAM_HASHES.txt')
    (KIT / 'tools/volatility2/SOURCES.json').write_text(
        json.dumps(dict(version='2.6', license='GPL-2.0-or-later', archives=records), ensure_ascii=False, indent=2),
        encoding='utf-8',
    )
    print('Volatility 2.6: official Windows / Linux executables and source staged')


if __name__ == '__main__':
    main()
