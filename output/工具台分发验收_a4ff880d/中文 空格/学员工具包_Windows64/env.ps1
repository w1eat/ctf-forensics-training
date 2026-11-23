$env:CTF_KIT_ROOT = $PSScriptRoot
$paths = @(
    (Join-Path $PSScriptRoot 'bin'),
    (Join-Path $PSScriptRoot 'runtime\python'),
    (Join-Path $PSScriptRoot 'tools\sleuthkit\bin')
)
if (Test-Path (Join-Path $PSScriptRoot 'runtime\ruby\bin\ruby.exe')) {
    $paths += (Join-Path $PSScriptRoot 'runtime\ruby\bin')
    $env:GEM_HOME = Join-Path $PSScriptRoot 'runtime\ruby\lib\ruby\gems\3.3.0'
    $env:GEM_PATH = $env:GEM_HOME
    $env:RUBYOPT = '-EUTF-8'
}
$env:PATH = ($paths -join ';') + ';' + $env:PATH
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:LANG = 'C'
$env:LC_ALL = 'C'
$env:LC_CTYPE = 'C'
$v3 = Join-Path $PSScriptRoot 'tools\volatility3\vol.py'
$img = '.\memory.raw'
Set-Location -LiteralPath (Join-Path $PSScriptRoot 'labs')
New-Item -ItemType Directory -Force -Path '.\out' | Out-Null
Write-Host 'CTF Forensics classroom | Windows x64 | portable tools' -ForegroundColor Green
Write-Host ('Tools: ' + $PSScriptRoot)
Write-Host 'CWD: labs | python / 7z / exiftool / sqlite3 / pngcheck / mmls / fls / icat'
Write-Host 'Helpers: finspect / strings / xxd / grep / dd / base64 / vol3 / vol2'
Write-Host 'Run: python $v3 -h'
Write-Host 'UTF-16LE: finspect strings INPUT --encoding utf16le'
Write-Host 'Commands affect this terminal session only.'
