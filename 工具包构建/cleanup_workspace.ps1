$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent)).TrimEnd('\')
$rootPrefix = $taskRoot + '\'
# Only generated files, obsolete fixtures and failed/duplicate downloads.
$relativeTargets = @(
    '.playwright-mcp',
    'output\分发验证 空格',
    'output\playwright',
    'output\verified',
    'output\讲义语法检查',
    'output\finalize_generator.py',
    'output\rework_course.py',
    'output\upgrade_memory_v3.py',
    'output\verify_course.py',
    'output\verify_memory_v3.py',
    'output\命令环境审查_原始.json',
    'output\讲师题解_手机.png',
    'output\讲师题解_桌面.png',
    'output\学员讲义_命令环境_手机.png',
    'output\学员讲义_命令环境_桌面.png',
    'output\学员讲义_Windows命令框.png',
    'output\主课件_环境标识.png',
    '工具包构建\编译暂存\ruby',
    '工具包构建\下载缓存\john-1.9.0-jumbo-1-win64.7z.part',
    '工具包构建\下载缓存\john-1.9.0-jumbo-1.tar.xz.part',
    '工具包构建\下载缓存\john-win64.zip',
    '工具包构建\下载缓存\sqlite-direct.zip',
    '工具包构建\下载缓存\busybox-source-169694ebd.zip',
    '工具包构建\下载缓存\7zip-download.html',
    '工具包构建\下载缓存\autopsy-release.json',
    '工具包构建\下载缓存\busybox-home.html',
    '工具包构建\下载缓存\exiftool-home.html',
    '工具包构建\下载缓存\iostruct-gem.json',
    '工具包构建\下载缓存\pngcheck-release.json',
    '工具包构建\下载缓存\prime-gem.json',
    '工具包构建\下载缓存\ruby-headers.txt',
    '工具包构建\下载缓存\ruby-release.json',
    '工具包构建\下载缓存\ruby33-release.json',
    '工具包构建\下载缓存\sqlite-download.html',
    '工具包构建\下载缓存\tsk-download.html',
    '工具包构建\下载缓存\tsk-release.json',
    '工具包构建\下载缓存\zpng-gem.json',
    '工具包构建\下载缓存\zsteg-gem.json',
    '工具包构建\下载缓存\zsteg-root.json',
    '练习材料\02_network',
    '练习材料\03_timeline',
    '学员工具包_Windows64\labs\out'
)
$absoluteTargets = @($relativeTargets | ForEach-Object { [IO.Path]::GetFullPath((Join-Path $taskRoot $_)) })
$absoluteTargets += @(Get-ChildItem -LiteralPath $taskRoot -Directory -Filter '__pycache__' -Recurse -Force | ForEach-Object { $_.FullName })
$records = @()
foreach ($candidate in ($absoluteTargets | Select-Object -Unique)) {
    $checkedPath = [IO.Path]::GetFullPath($candidate)
    if (-not $checkedPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Cleanup path outside workspace: $checkedPath"
    }
    if (-not (Test-Path -LiteralPath $checkedPath)) { continue }
    $resolved = (Resolve-Path -LiteralPath $checkedPath).Path
    if (-not $resolved.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Resolved cleanup path outside workspace: $resolved"
    }
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing reparse point: $resolved" }
    if ($item.PSIsContainer) {
        $files = @(Get-ChildItem -LiteralPath $resolved -File -Recurse -Force)
        $bytes = ($files | Measure-Object -Property Length -Sum).Sum
        $fileCount = $files.Count
    } else { $bytes = $item.Length; $fileCount = 1 }
    Remove-Item -LiteralPath $resolved -Recurse -Force
    $records += [pscustomobject]@{path=$resolved.Substring($rootPrefix.Length);files=$fileCount;bytes=[long]$bytes}
}
$null = New-Item -ItemType Directory -Force -Path (Join-Path $taskRoot '学员工具包_Windows64\labs\out')
$total = ($records | Measure-Object -Property bytes -Sum).Sum
$result = [pscustomobject]@{date='2026-10-19';deleted_files=($records | Measure-Object -Property files -Sum).Sum;freed_bytes=[long]$total;targets=$records}
$resultPath = Join-Path $taskRoot 'output\工作区清理记录.json'
[IO.File]::WriteAllText($resultPath, ($result | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
Write-Output ("Removed {0} files; freed {1:N1} MiB" -f $result.deleted_files, ($total / 1MB))
