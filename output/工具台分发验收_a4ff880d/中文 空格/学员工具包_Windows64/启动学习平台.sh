#!/usr/bin/env bash
set -euo pipefail
platform_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
platform_python=python3
if [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
  platform_python="$VIRTUAL_ENV/bin/python"
elif [[ -x "$platform_root/.runtime/kali/venv/bin/python" ]]; then
  platform_python="$platform_root/.runtime/kali/venv/bin/python"
elif [[ -x "$HOME/ctf-forensics/.venv/bin/python" ]]; then
  platform_python="$HOME/ctf-forensics/.venv/bin/python"
fi
if [[ -d "$platform_root/.runtime/kali/gems" ]]; then
  export GEM_HOME="$platform_root/.runtime/kali/gems"
  export GEM_PATH="$GEM_HOME"
  export PATH="$GEM_HOME/bin:$(dirname -- "$platform_python"):$PATH"
fi
platform_server="$platform_root/tools/learning_server.py"
if [[ ! -f "$platform_server" ]]; then
  platform_server="$platform_root/工具包构建/learning_server.py"
fi
exec "$platform_python" "$platform_server" --root "$platform_root" "$@"
