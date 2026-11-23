param([Parameter(Mandatory=$true)][string]$RequestPath)
$ErrorActionPreference = 'Stop'
$request = Get-Content -LiteralPath $RequestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$resultPath = $request.result
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $exe = Join-Path $env:SystemRoot 'System32/WindowsPowerShell/v1.0/powershell.exe'
        $argsList = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -RequestPath "' + $RequestPath + '"'
        $child = Start-Process -FilePath $exe -ArgumentList $argsList -Verb RunAs -WindowStyle Hidden -Wait -PassThru
        if (-not (Test-Path -LiteralPath $resultPath)) { throw 'Operation cancelled or elevated operation did not return a result.' }
        exit $child.ExitCode
    }
    $root = [IO.Path]::GetFullPath($request.labs).TrimEnd('\') + '\'
    $image = if ($request.image) { [IO.Path]::GetFullPath($request.image) } else { '' }
    if ($image -and -not $image.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw 'Image must remain inside the current labs directory.' }
    $letter = ([string]$request.drive).ToUpperInvariant().TrimEnd(':')
    if ($letter -notmatch '^[R-Z]$') { throw 'Choose a drive letter from R to Z.' }
    $registry = $request.registry
    $records = @()
    if (Test-Path -LiteralPath $registry) { $records = @(Get-Content -LiteralPath $registry -Raw -Encoding UTF8 | ConvertFrom-Json) }
    $imdisk = Join-Path $request.kit 'tools/imdisk/cli/amd64/imdisk.exe'
    $vc = Join-Path $request.kit 'tools/veracrypt/VeraCrypt.exe'
    if ($request.method -eq 'truecrypt') { $vc = Join-Path $request.kit 'tools/veracrypt_legacy/VeraCrypt.exe' }
    $drivePath = $letter + ':\'
    if ($request.mode -eq 'install_imdisk') {
        $installer = Join-Path $request.kit 'tools/imdisk/install.exe'
        Start-Process -FilePath $installer -WorkingDirectory (Split-Path $installer) -WindowStyle Hidden -Wait
        $service = Get-Service -Name imdisk -ErrorAction SilentlyContinue
        if (-not $service) { throw 'ImDisk driver installation has not completed.' }
        $result = @{status='driver_installed';drive=$letter}
    } elseif ($request.mode -eq 'unmount') {
        $record = @($records | Where-Object { $_.drive -eq $letter })
        if ($record.Count -ne 1) { throw 'No mount owned by this workspace was found on this drive letter.' }
        $record = $record[0]
        if (Test-Path -LiteralPath $drivePath) {
            $disk = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='" + $letter + ":'")
            if ($record.serial -and $disk.VolumeSerialNumber -ne $record.serial) { throw 'Drive identity changed; refusing to unmount an unrelated drive.' }
        }
        if ($record.method -eq 'windows') {
            $attached = Get-DiskImage -ImagePath $record.image
            if ($attached.Attached) { Dismount-DiskImage -ImagePath $record.image }
        } elseif ($record.method -eq 'imdisk') {
            $query = & $imdisk -l -m ($letter + ':') 2>&1 | Out-String
            if ($query -notlike ('*' + $record.image + '*')) { throw 'ImDisk image path no longer matches the workspace record.' }
            & $imdisk -d -m ($letter + ':') | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'ImDisk refused to unmount. Close open files and retry.' }
        } elseif ($record.method -in @('veracrypt','truecrypt')) {
            $vc = Join-Path $request.kit 'tools/veracrypt/VeraCrypt.exe'
            if ($record.method -eq 'truecrypt') { $vc = Join-Path $request.kit 'tools/veracrypt_legacy/VeraCrypt.exe' }
            & $vc /quit /silent /dismount $letter
            if ($LASTEXITCODE -ne 0) { throw 'VeraCrypt refused to unmount. Close open files and retry.' }
        }
        $records = @($records | Where-Object { $_.drive -ne $letter })
        $result = @{status='unmounted';drive=$letter}
    } elseif ($request.mode -eq 'mount') {
        if (-not (Test-Path -LiteralPath $image -PathType Leaf)) { throw 'Image file is missing.' }
        if (Test-Path -LiteralPath $drivePath) { throw 'The drive letter is already in use.' }
        if (@($records | Where-Object { $_.drive -eq $letter }).Count) { throw 'A workspace mount record already owns this letter. Unmount it first.' }
        if ($request.method -eq 'windows') {
            if ([IO.Path]::GetExtension($image).ToLowerInvariant() -notin @('.iso','.vhd','.vhdx')) { throw 'Native Windows mounting supports ISO/VHD/VHDX. Use ImDisk for raw partitions.' }
            $mounted = Mount-DiskImage -ImagePath $image -Access ReadOnly -PassThru
            $volumes = @($mounted | Get-Volume)
            $actual = @($volumes | Where-Object { $_.DriveLetter })
            if (-not $actual.Count) { Dismount-DiskImage -ImagePath $image; throw 'No native Windows-readable volume obtained. Use the image browser.' }
            $oldLetter = [string]$actual[0].DriveLetter
            if ($oldLetter -ne $letter) {
                $mountvol = Join-Path $env:SystemRoot 'System32/mountvol.exe'
                & $mountvol ($letter + ':\') $actual[0].Path
                if ($LASTEXITCODE -ne 0) { Dismount-DiskImage -ImagePath $image; throw 'Could not assign the requested drive letter.' }
                & $mountvol ($oldLetter + ':\') /D
            }
        } elseif ($request.method -eq 'imdisk') {
            if (-not (Get-Service -Name imdisk -ErrorAction SilentlyContinue)) { throw 'Install the bundled ImDisk driver first.' }
            & $imdisk -a -t file -f $image -b ([string]$request.offset) -o ro -m ($letter + ':') | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'ImDisk mount failed.' }
        } elseif ($request.method -in @('veracrypt','truecrypt')) {
            if (-not (Test-Path -LiteralPath $vc)) { throw 'VeraCrypt runtime is missing.' }
            $vcArgs = @('/quit','/silent','/volume',$image,'/letter',$letter,'/mountoption','readonly','/cache','no','/history','no','/password',[string]$request.password)
            if ($request.method -eq 'truecrypt') { $vcArgs += '/truecrypt' }
            if ($request.keyfile) { $keyfile=[IO.Path]::GetFullPath($request.keyfile);if (-not $keyfile.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) { throw 'Keyfile is outside labs.' };$vcArgs+=@('/keyfile',$keyfile) }
            if ($request.pim) { $vcArgs+=@('/pim',[string]$request.pim) }
            & $vc @vcArgs
            if ($LASTEXITCODE -ne 0) { throw 'VeraCrypt mount failed. Check password, PIM, keyfile and volume format.' }
        } else { throw 'Unsupported mount method.' }
        $disk = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='" + $letter + ":'")
        $record = @{drive=$letter;method=$request.method;image=$image;offset=$request.offset;readonly=$true;serial=$disk.VolumeSerialNumber;created=(Get-Date).ToString('o')}
        $records += $record
        $result = @{status='mounted_readonly';drive=$letter;method=$request.method;image=$image}
    } else { throw 'Unknown mount operation.' }
    ConvertTo-Json -InputObject @($records) -Depth 5 | Set-Content -LiteralPath $registry -Encoding UTF8
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $resultPath -Encoding UTF8
} catch {
    @{status='failed';error=$_.Exception.Message} | ConvertTo-Json | Set-Content -LiteralPath $resultPath -Encoding UTF8
    exit 1
}
