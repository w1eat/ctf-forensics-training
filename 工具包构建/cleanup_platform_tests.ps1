$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent)).TrimEnd('\')
$prefix = $taskRoot + '\'
$targets = @(
    '.playwright-mcp',
    'output\平台分发验证 空格',
    'output\讲义语法检查',
    '练习材料\out\platform_runs',
    '练习材料\out\平台运行',
    '练习材料\out\platform_args',
    '练习材料\inputs\字符测试',
    '练习材料\inputs\fb18130b9f0f'
) | ForEach-Object { Join-Path $taskRoot $_ }
$inputsDir = Join-Path $taskRoot '练习材料\inputs'
if (Test-Path -LiteralPath $inputsDir) {
    $targets += @(Get-ChildItem -LiteralPath $inputsDir -Directory -Filter '_platform_qa_*' | ForEach-Object { $_.FullName })
    foreach ($dir in Get-ChildItem -LiteralPath $inputsDir -Directory) {
        $files = @(Get-ChildItem -LiteralPath $dir.FullName -File -Recurse)
        if ($files.Count -eq 1 -and $files[0].Name -eq 'uploaded.txt' -and [IO.File]::ReadAllText($files[0].FullName) -eq 'local evidence only') {
            $targets += $dir.FullName
        }
    }
}
$targets += @(Get-ChildItem -LiteralPath $taskRoot -Directory -Recurse -Filter '__pycache__' | ForEach-Object { $_.FullName })
$records = @()
foreach ($candidate in ($targets | Select-Object -Unique)) {
    $full = [IO.Path]::GetFullPath($candidate)
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Outside workspace: $full" }
    if (-not (Test-Path -LiteralPath $full)) { continue }
    $resolved = (Resolve-Path -LiteralPath $full).Path
    if (-not $resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Resolved outside workspace: $resolved" }
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing reparse point: $resolved" }
    $files = @(Get-ChildItem -LiteralPath $resolved -File -Recurse -Force)
    $total = ($files | Measure-Object -Property Length -Sum).Sum
    Remove-Item -LiteralPath $resolved -Recurse -Force
    $records += [pscustomobject]@{path=$resolved.Substring($prefix.Length);files=$files.Count;bytes=[long]$total}
}
$report = [pscustomobject]@{date='2026-10-19';files=($records | Measure-Object -Property files -Sum).Sum;freed_bytes=($records | Measure-Object -Property bytes -Sum).Sum;targets=$records}
$reportPath = Join-Path $taskRoot 'output\学习平台临时文件清理记录.json'
[IO.File]::WriteAllText($reportPath, ($report | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
Write-Output ("Removed {0} generated files; freed {1:N1} MiB" -f $report.files,($report.freed_bytes / 1MB))
