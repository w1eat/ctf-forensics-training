param([switch]$Apply)
$ErrorActionPreference = 'Stop'
$deliveryRoot = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent)).TrimEnd('\')
$deliveryPrefix = $deliveryRoot + '\'
$candidates = [Collections.Generic.List[string]]::new()
foreach ($relative in @('.playwright-mcp', '工具包构建\编译暂存',
    '工具包构建\下载缓存\veracrypt_msi_payload', '工具包构建\下载缓存\veracrypt_legacy_msi_payload',
    'CTF取证基础_学员讲义与练习.zip', 'CTF取证基础_完整培训包.zip')) {
    $candidates.Add((Join-Path $deliveryRoot $relative))
}
foreach ($relative in @('output', '练习材料\out', '学员工具包_Windows64\labs\out')) {
    $parent = Join-Path $deliveryRoot $relative
    if (Test-Path -LiteralPath $parent) {
        foreach ($item in (Get-ChildItem -LiteralPath $parent -Force)) {
            if ($relative -eq 'output' -and -not $item.PSIsContainer -and $item.Extension -eq '.json') { continue }
            $candidates.Add($item.FullName)
        }
    }
}
$inputParent = Join-Path $deliveryRoot '练习材料\inputs'
if (Test-Path -LiteralPath $inputParent) {
    foreach ($item in (Get-ChildItem -LiteralPath $inputParent -Directory -Force)) {
        if ($item.Name -match '^_(casework_qa_|platform_qa_|vol2_ui_)') { $candidates.Add($item.FullName) }
    }
}
foreach ($parent in @($deliveryRoot, (Join-Path $deliveryRoot '学员工具包_Windows64'))) {
    foreach ($item in (Get-ChildItem -LiteralPath $parent -File -Filter '*.md')) {
        if ($item.Name -ne 'README.md' -and (Test-Path -LiteralPath ([IO.Path]::ChangeExtension($item.FullName, '.html')))) {
            $candidates.Add($item.FullName)
        }
    }
}
foreach ($relative in @('课件源码', '工具包构建', '学员工具包_Windows64', '练习材料')) {
    $parent = Join-Path $deliveryRoot $relative
    foreach ($item in (Get-ChildItem -LiteralPath $parent -Directory -Recurse -Force -Filter '__pycache__')) {
        $candidates.Add($item.FullName)
    }
}
# Every recursive target must resolve inside this workspace and contain no junctions.
$verified = @()
foreach ($candidate in ($candidates | Sort-Object -Unique)) {
    $absolute = [IO.Path]::GetFullPath($candidate)
    if (-not $absolute.StartsWith($deliveryPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Target outside workspace: $absolute" }
    if (-not (Test-Path -LiteralPath $absolute)) { continue }
    $resolved = (Resolve-Path -LiteralPath $absolute).ProviderPath
    if (-not $resolved.StartsWith($deliveryPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Resolved target outside workspace: $resolved" }
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing a reparse point: $resolved" }
    if ($item.PSIsContainer) {
        $children = @(Get-ChildItem -LiteralPath $resolved -Recurse -Force)
        if (@($children | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) { throw "Reparse point inside target: $resolved" }
        $files = @($children | Where-Object { -not $_.PSIsContainer })
        $bytes = [long](($files | Measure-Object -Property Length -Sum).Sum)
        $count = $files.Count
    } else { $bytes = $item.Length; $count = 1 }
    $verified += [pscustomobject]@{ path = $resolved; relative = $resolved.Substring($deliveryPrefix.Length); files = $count; logical_bytes = $bytes }
}
$records = @()
foreach ($item in ($verified | Sort-Object { $_.path.Length })) {
    if (@($records | Where-Object { $item.path.StartsWith($_.path + '\', [StringComparison]::OrdinalIgnoreCase) }).Count) { continue }
    if ($Apply) { Remove-Item -LiteralPath $item.path -Recurse -Force }
    $records += $item
}
$result = [pscustomobject]@{
    date = '2026-10-21'; applied = [bool]$Apply; targets = $records.Count
    files = [long](($records | Measure-Object -Property files -Sum).Sum)
    logical_bytes = [long](($records | Measure-Object -Property logical_bytes -Sum).Sum)
    note = 'Logical sizes include hard-linked QA copies; original uploaded inputs are retained.'
    records = @($records | Select-Object relative,files,logical_bytes)
}
if ($Apply) {
    $resultPath = Join-Path $deliveryRoot 'output\交付清理记录.json'
    [IO.File]::WriteAllText($resultPath, ($result | ConvertTo-Json -Depth 5), [Text.UTF8Encoding]::new($false))
}
$result | Select-Object date,applied,targets,files,logical_bytes,note | ConvertTo-Json -Depth 3
