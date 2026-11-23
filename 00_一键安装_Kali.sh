#!/usr/bin/env bash
set -euo pipefail
platform_root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [[ ! -f "$platform_root/index.html" ]]; then
  printf '%s\n' '请把脚本放在资料包根目录，并先完整解压资料包。'
  exit 20
fi
if ! command -v apt-get >/dev/null 2>&1; then
  printf '%s\n' '此入口用于 Kali / Debian 系环境。Windows 请运行 00_一键配置并启动.cmd。'
  exit 20
fi
if (( EUID != 0 )) && ! command -v sudo >/dev/null 2>&1; then
  printf '%s\n' '需要 sudo 或管理员协助安装系统依赖。'
  exit 20
fi
privileged() { if (( EUID == 0 )); then "$@"; else sudo "$@"; fi; }
printf '%s\n' '将通过系统 apt 与当前目录的 Python 虚拟环境准备依赖；需要网络。'
privileged apt-get update
archive_package=7zip
if ! apt-cache show 7zip >/dev/null 2>&1; then archive_package=p7zip-full; fi
privileged apt-get install -y python3 python3-venv python3-pip ruby ruby-dev build-essential \
  libimage-exiftool-perl "$archive_package" sqlite3 sleuthkit pngcheck binutils coreutils testdisk extundelete
platform_runtime="$platform_root/.runtime/kali"
mkdir -p "$platform_runtime"
if [[ ! -x "$platform_runtime/venv/bin/python" ]]; then python3 -m venv "$platform_runtime/venv"; fi
"$platform_runtime/venv/bin/python" -m pip install \
  volatility3==2.28.2 pypykatz==0.6.13 Pillow pypdf pefile yara-python pycryptodome==4.1.0
gem install zsteg -v 0.2.14 --no-document --install-dir "$platform_runtime/gems"
vol2="$platform_root/tools/volatility2/linux/volatility_2.6_lin64_standalone"
if [[ -f "$vol2" ]]; then chmod +x -- "$vol2"; fi
printf '%s\n' '依赖已准备，正在启动学习平台。Vol2 使用随包独立运行时，无需全局安装 Python 2。'
exec bash "$platform_root/启动学习平台.sh"
