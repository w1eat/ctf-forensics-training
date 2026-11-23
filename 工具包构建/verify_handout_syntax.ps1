$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path $PSScriptRoot -Parent
$blocksPath = Join-Path $taskRoot 'output\讲义语法检查\powershell_blocks.json'
$blocks = Get-Content -LiteralPath $blocksPath -Encoding UTF8 -Raw | ConvertFrom-Json
$checked = 0
foreach ($block in $blocks) {
    $parseTokens = $null
    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($block.code, [ref]$parseTokens, [ref]$parseErrors)
    if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
    $checked++
}
$resultPath = Join-Path $taskRoot 'output\学员讲义验收记录.json'
$result = Get-Content -LiteralPath $resultPath -Encoding UTF8 -Raw | ConvertFrom-Json
$result.windows_powershell_syntax = 'pass'
$result | Add-Member -NotePropertyName windows_powershell_blocks -NotePropertyValue $checked -Force
$json = $result | ConvertTo-Json -Depth 8
[IO.File]::WriteAllText($resultPath, $json, (New-Object Text.UTF8Encoding($false)))
Write-Output "PowerShell syntax: $checked blocks PASS"
