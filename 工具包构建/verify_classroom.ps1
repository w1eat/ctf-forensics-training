param([string]$Kit = (Join-Path (Split-Path $PSScriptRoot -Parent) '学员工具包_Windows64'))
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = [Console]::OutputEncoding
$env:PATH = "$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\WindowsPowerShell\v1.0"
. (Join-Path $Kit 'env.ps1')
$script:checks = @()
function Assert-Text([string]$Text,[string]$Expected) {
    if (-not $Text.Contains($Expected)) { throw "Missing expected text: $Expected ; output: $Text" }
}
function Native([scriptblock]$Command,[int]$ExpectedExit = 0) {
    $saved=$ErrorActionPreference
    try {
        $ErrorActionPreference='Continue'
        $text = (& $Command 2>&1 | Out-String)
        $nativeCode=$LASTEXITCODE
    } finally { $ErrorActionPreference=$saved }
    if ($nativeCode -ne $ExpectedExit) { throw "Native exit $nativeCode; expected $ExpectedExit ; output: $text" }
    return $text
}
function Check([string]$Name,[scriptblock]$Command) {
    try {
        $null = & $Command
        $script:checks += [pscustomobject]@{name=$Name;pass=$true}
        Write-Host "[PASS] $Name"
    } catch {
        $script:checks += [pscustomobject]@{name=$Name;pass=$false;error=$_.Exception.Message}
        Write-Host "[FAIL] $Name : $($_.Exception.Message)"
    }
}
Check '01 PNG identification' { Assert-Text (Native { finspect type .\01_file\unknown.dat }) 'PNG' }
Check '01 Comment and Base64' {
    $raw=Native { exiftool -b -Comment .\01_file\unknown.dat }
    Assert-Text (Native { finspect decode64 $raw.Trim() }) 'flag{file_type_before_extension}'
}
Check '02 damaged IHDR is detected' { Assert-Text (Native { pngcheck -v .\02_png\broken_width.png } 2) 'CRC error in chunk IHDR' }
Check '02 width recovery' { Assert-Text (Native { python .\tools\recover_width.py .\02_png\broken_width.png .\out\qa_width.png }) '[256]' }
Check '02 repaired PNG' { Assert-Text (Native { pngcheck -v .\out\qa_width.png }) 'No errors detected' }
Check '02 metadata' { Assert-Text (Native { exiftool -Comment .\out\qa_width.png }) 'flag{crc_checks_the_hypothesis}' }
Check '03 Python LSB' { Assert-Text (Native { python .\tools\extract_lsb.py .\03_lsb\quiet.png .\out\qa_lsb.bin }) 'flag{one_bit_one_clue}' }
Check '03 zsteg scanner' { Assert-Text (Native { zsteg .\03_lsb\quiet.png }) 'flag{one_bit_one_clue}' }
Check '03 zsteg raw extraction' {
    $zs=Join-Path $env:CTF_KIT_ROOT 'runtime\ruby\bin\zsteg'
    Native { finspect savebin .\out\qa_zsteg.bin -- ruby.exe $zs -E b1,r,lsb,xy .\03_lsb\quiet.png }
    Assert-Text (Native { strings -n 4 .\out\qa_zsteg.bin }) 'flag{one_bit_one_clue}'
}
Check '04 signature offset' { Assert-Text (Native { finspect scan .\04_archive\carrier.bin }) '0x00000200' }
Check '04 carve and CRC' {
    Native { python .\tools\carve.py .\04_archive\carrier.bin .\out\qa_carved.zip --offset 0x200 }
    Assert-Text (Native { 7z t .\out\qa_carved.zip }) 'Everything is Ok'
    Native { 7z x .\out\qa_carved.zip "-o.\out\qa_carved" -y }
    Assert-Text (Get-Content .\out\qa_carved\answer.txt -Raw) 'flag{offsets_make_carving_repeatable}'
}
Check '04 dd byte-for-byte' {
    Native { dd if=04_archive/carrier.bin of=out/qa_dd.zip bs=1 skip=512 }
    if ((Get-FileHash .\out\qa_dd.zip).Hash -ne (Get-FileHash .\out\qa_carved.zip).Hash) {throw 'dd mismatch'}
}
Check '05 mmls partition' { Assert-Text (Native { mmls .\05_disk\tiny_fat16.dd }) '0000002048' }
Check '05 fls deleted metadata number' { Assert-Text (Native { fls -r -d -o 2048 .\05_disk\tiny_fat16.dd }) 'r/r * 4:' }
Check '05 icat byte export' {
    Native { finspect savebin .\out\qa_recovered.txt -- icat.exe -r -o 2048 .\05_disk\tiny_fat16.dd 4 }
    Assert-Text (Get-Content .\out\qa_recovered.txt -Raw) 'flag{deleted_entry_is_a_clue}'
}
Check '05 independent FAT parse' {
    Native { python .\tools\read_training_fat.py .\05_disk\tiny_fat16.dd .\out\qa_fat.txt }
    if ((Get-FileHash .\out\qa_fat.txt).Hash -ne (Get-FileHash .\out\qa_recovered.txt).Hash) {throw 'FAT parse mismatch'}
}
Check '06 SQLite CLI' { Assert-Text (Native { sqlite3 -readonly .\06_sqlite\case.db 'SELECT note FROM artifacts WHERE deleted=1;' }) 'flag{query_the_schema_first}' }
Check '06 SQLite Python' { Assert-Text (Native { python .\tools\query_case.py .\06_sqlite\case.db }) 'flag{query_the_schema_first}' }
Check '07 timeline UTC+8' { Assert-Text (Native { python .\tools\timeline.py .\07_logs\audit.jsonl }) '2026-10-18T09:18:31+08:00 download_completed r-103 trainee 192.0.2.44' }
Check '08 strings and grep' { Assert-Text (Native { strings -n 4 .\public_examples\garden_demo.jpg | grep -n 'flag{' }) 'flag{strings_see_more_than_pixels}' }
Check '09 XMP and Base64' {
    $raw=Native { exiftool -b -XMP:License .\public_examples\cat_demo.jpg }
    Assert-Text (Native { finspect decode64 $raw.Trim() }) 'flag{metadata_then_base64}'
}
Check '10 signature restoration' {
    Native { finspect patch-png-header .\02_png\broken_header.png .\out\qa_header.png }
    Native { pngcheck -v .\out\qa_header.png }
    if ((Get-FileHash .\02_png\good.png).Hash -ne (Get-FileHash .\out\qa_header.png).Hash) {throw 'PNG header restoration mismatch'}
}
Check '11 ZIP flags and CRC' {
    Assert-Text (Native { python .\tools\zip_flags.py clear .\04_archive\flagged.zip .\out\qa_flags.zip }) 'First bad CRC entry: None'
    Assert-Text (Native { 7z t .\out\qa_flags.zip }) 'Everything is Ok'
}
Check '12 tiny wordlist and real decryption' {
    Assert-Text (Native { finspect tryzip .\04_archive\locked.zip .\04_archive\words.txt }) 'Password: training2026'
    Assert-Text (Native { 7z t .\04_archive\locked.zip -ptraining2026 }) 'Everything is Ok'
    Native { 7z x .\04_archive\locked.zip -ptraining2026 "-o.\out\qa_unlocked" -y }
    Assert-Text (Get-Content .\out\qa_unlocked\note.txt -Raw) 'flag{dictionary_from_the_hint}'
}
Check '13 process and command line' {
    $row=Import-Csv .\08_memory\case_a\cmdline.csv | Where-Object {$_.PID -eq '3180'}
    Assert-Text (Native { finspect decode64 (($row.Args -split ' ')[-1]) }) 'flag{read_the_command_line}'
}
Check '14 file object relationship' {
    $row=Import-Csv .\08_memory\case_b\handles.csv | Where-Object {$_.PID -eq '2460'}
    if ($row.VirtualObject -ne '0xffffa10200123070') {throw 'Object address mismatch'}
    Assert-Text (Get-Content .\08_memory\case_b\exported_memo.txt -Raw) 'flag{follow_the_file_object}'
}
Check '15 UTF-16LE flag and offset' {
    Assert-Text (Native { finspect strings .\08_memory\case_c\process_2460_excerpt.bin --encoding utf16le }) 'flag{utf16_is_still_text}'
    Assert-Text (Native { python .\08_memory\search_excerpt.py .\08_memory\case_c\process_2460_excerpt.bin }) '0x11c'
}
foreach ($plugin in @('info','pslist','pstree','psscan','cmdline','cmdscan','consoles','filescan','handles','dumpfiles','memmap')) {
    Check "Vol3 windows.$plugin help" { Assert-Text (Native { python $v3 "windows.$plugin" -h }) 'Volatility 3 Framework 2.28.2' }
}
Check 'Environment selfcheck' { Assert-Text (Native { python ..\tools\check_environment.py }) 'Result: PASS (0 failures)' }
$out=Join-Path (Split-Path $PSScriptRoot -Parent) 'output\工具与题解验收记录.json'
if (-not (Test-Path (Split-Path $out -Parent))) { New-Item -ItemType Directory -Path (Split-Path $out -Parent) | Out-Null }
$script:checks | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $out -Encoding UTF8
$failed=@($script:checks | Where-Object {-not $_.pass})
Write-Host "Total $($script:checks.Count), failed $($failed.Count)"
if ($failed.Count -gt 0) { exit 1 }
