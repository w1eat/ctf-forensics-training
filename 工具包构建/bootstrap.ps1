param(
    [ValidateSet('Setup','Launch','Check','Basic','Repair')][string]$Mode='Setup',
    [string]$WorkspaceRoot='',
    [switch]$NoLaunch,
    [switch]$NoBrowser,
    [switch]$NonInteractive,
    [switch]$NoSystemChanges,
    [switch]$FullVerify,
    [switch]$InstallVCRuntime,
    [int]$Port=0
)
$ErrorActionPreference='Stop'
$env:PSModulePath=(Join-Path $PSHOME 'Modules')+[IO.Path]::PathSeparator+$env:PSModulePath
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$OutputEncoding=[Console]::OutputEncoding
$exitCode=20;$kit='';$labs='';$reportFolder='';$checks=@();$cached=$false
$basic=$Mode -eq 'Basic';$restartNeeded=$false;$cppInstalled=$false
$issues=New-Object 'System.Collections.Generic.List[object]'
$missing=New-Object 'System.Collections.Generic.List[string]'
$modified=New-Object 'System.Collections.Generic.List[string]'
$defender=@{available=$false;matching_detections=0;settings_changed=$false}
function Say([string]$Text) {Write-Host ('[环境配置] '+$Text)}
function Add-Issue([string]$Level,[string]$Text) {$issues.Add(@{level=$Level;text=$Text});Say $Text}
function Read-Json([string]$Path) {Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json}
function File-Sha256([string]$Path) {
    $stream=[IO.File]::OpenRead($Path);$algorithm=[Security.Cryptography.SHA256]::Create()
    try {return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-','').ToLowerInvariant()}
    finally {$stream.Dispose();$algorithm.Dispose()}
}
function Quote-Arg([string]$Text) {
    $escaped=[regex]::Replace($Text,'(\\*)"',{param($m) $m.Groups[1].Value+$m.Groups[1].Value+'\"'})
    return '"'+[regex]::Replace($escaped,'(\\+)$','$1$1')+'"'
}
function Run-Captured([string]$Executable,[string[]]$Arguments,[int]$Timeout=180) {
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$Executable;$info.Arguments=($Arguments | ForEach-Object {Quote-Arg $_}) -join ' '
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.WorkingDirectory=$script:labs
    foreach ($name in @('PYTHONHOME','PYTHONPATH')) {$info.EnvironmentVariables.Remove($name)}
    foreach ($pair in @(@('PYTHONUTF8','1'),@('PYTHONIOENCODING','utf-8'),@('PYTHONNOUSERSITE','1'),@('PYTHONDONTWRITEBYTECODE','1'))) {$info.EnvironmentVariables[$pair[0]]=$pair[1]}
    $info.EnvironmentVariables['PATH']=(Join-Path $env:SystemRoot 'System32')
    $process=New-Object Diagnostics.Process;$process.StartInfo=$info;$null=$process.Start()
    $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while (-not $process.WaitForExit(300)) {if ($timer.Elapsed.TotalSeconds -gt $Timeout) {$process.Kill();throw '环境检查超时；请查看日志后重新运行。'}}
    $process.WaitForExit()
    return @{code=$process.ExitCode;stdout=$stdout.GetAwaiter().GetResult();stderr=$stderr.GetAwaiter().GetResult()}
}
function Install-Cpp {
    if ($NoSystemChanges) {Add-Issue 'warning' '本次仅检查：没有执行 VC++ 安装。';return $false}
    $installer=Join-Path $script:kit 'setup\vendor\VC_redist.x64.exe';$sourceFile=Join-Path $script:kit 'setup\vendor\VC_redist.source.json'
    if (-not (Test-Path -LiteralPath $installer) -or -not (Test-Path -LiteralPath $sourceFile)) {Add-Issue 'warning' '缺少随包 Microsoft VC++ 安装器；请重新取得完整 Windows 工具包。';return $false}
    $source=Read-Json $sourceFile
    if ((File-Sha256 $installer) -ne $source.sha256) {throw 'VC++ 安装器校验失败，已停止执行。'}
    $signature=Get-AuthenticodeSignature -LiteralPath $installer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {throw '无法验证 Microsoft VC++ 数字签名；未执行安装。请联网核对证书或联系授课人员。'}
    Say '将安装 Microsoft 签名的 VC++ x64 运行库；Windows 可能显示权限请求。'
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {$child=Start-Process -FilePath $installer -ArgumentList '/install /quiet /norestart' -PassThru -Wait -WindowStyle Hidden}
    else {$child=Start-Process -FilePath $installer -ArgumentList '/install /quiet /norestart' -Verb RunAs -PassThru -Wait -WindowStyle Hidden}
    if ($child.ExitCode -eq 3010) {$script:restartNeeded=$true}
    if ($child.ExitCode -notin @(0,3010,1638)) {throw ('VC++ 安装器退出码 '+$child.ExitCode+'；安装未完成。')}
    $script:cppInstalled=$true;return $true
}
function Save-Report {
    if (-not $script:reportFolder) {return}
    $status=if ($script:exitCode -eq 0) {'环境已就绪'} elseif ($script:exitCode -eq 10) {'基础工具可运行，部分组件待处理'} else {'需要先处理环境问题'}
    $record=@{schema=1;status=$status;exit_code=$script:exitCode;mode=$Mode;basic_mode=$script:basic;kit=$script:kit;workspace=$WorkspaceRoot;created_utc=[DateTime]::UtcNow.ToString('o');cached=$script:cached;checks=@($script:checks);issues=@($script:issues.ToArray());missing_files=@($script:missing.ToArray());modified_files=@($script:modified.ToArray());defender=$script:defender;vc_runtime_installed=$script:cppInstalled;restart_needed=$script:restartNeeded;system_security_settings_changed=$false}
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $script:reportFolder '环境检查.json') -Encoding UTF8
    $enc={param($v) [Net.WebUtility]::HtmlEncode([string]$v)}
    $issueHtml=(@($script:issues.ToArray()) | ForEach-Object {'<li>'+(& $enc $_.text)+'</li>'}) -join ''
    $rowHtml=(@($script:checks) | ForEach-Object {'<tr><td>'+(& $enc $_.title)+'</td><td>'+(& $enc $_.status)+'</td><td>'+(& $enc $_.detail)+'</td></tr>'}) -join ''
    $missingHtml=(@($script:missing.ToArray()) | Select-Object -First 80 | ForEach-Object {'<li>'+(& $enc $_)+'</li>'}) -join ''
    $security='<p>若 Windows 安全中心有拦截，请查看保护历史记录，核对文件来源和 SHA256，交由授课人员或安全管理员确认。此脚本不会添加防病毒排除项、关闭防护或自动恢复隔离文件。</p><p><a href="windowsdefender:">打开 Windows 安全中心</a> · <a href="https://www.microsoft.com/en-us/wdsi/filesubmission">Microsoft 文件误报提交入口</a></p>'
    $document='<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>环境检查结果</title><style>body{font:15px/1.85 "Microsoft YaHei",sans-serif;background:#f4f5ee;color:#193c33;max-width:1100px;margin:30px auto;padding:0 20px}h1{font-size:26px}table{border-collapse:collapse;width:100%;background:#fff}td,th{padding:10px;border:1px solid #d7dfd1;text-align:left;overflow-wrap:anywhere}th{background:#dce8d4}.note{background:#fff2d8;padding:16px}a{color:#246747}li{overflow-wrap:anywhere}</style><h1>'+(& $enc $status)+'</h1><p>Windows 10/11 x64 · 包内 Python 3 / Ruby / Vol2 独立运行时</p><p>工具目录：'+(& $enc $script:kit)+'</p><ul>'+$issueHtml+'</ul><h2>检查结果</h2><table><tr><th>组件</th><th>状态</th><th>说明</th></tr>'+$rowHtml+'</table><h2>缺失文件（最多显示 80 项）</h2><ul>'+$missingHtml+'</ul><div class="note"><b>文件被拦截或隔离时</b>'+$security+'</div><h2>下一步</h2><p>返回解压目录，双击“00_一键配置并启动.cmd”。若社区组件不可用，可双击“06_仅基础工具启动.cmd”；检查后仍不能运行时，将本目录的 JSON 报告提供给授课人员。</p><p>Python 2 无需全局安装；Vol2 独立程序已带对应运行时。磁盘挂载驱动按课堂需要另行准备，本次没有安装挂载驱动。</p></html>'
    [IO.File]::WriteAllText((Join-Path $script:reportFolder '环境检查.html'),$document,(New-Object Text.UTF8Encoding($false)))
}
try {
    if (-not $WorkspaceRoot) {$WorkspaceRoot=Split-Path $PSScriptRoot -Parent}
    $WorkspaceRoot=[IO.Path]::GetFullPath($WorkspaceRoot).TrimEnd('\')
    if (Test-Path -LiteralPath (Join-Path $WorkspaceRoot 'runtime\python')) {$kit=$WorkspaceRoot}
    elseif (Test-Path -LiteralPath (Join-Path $WorkspaceRoot '学员工具包_Windows64')) {$kit=Join-Path $WorkspaceRoot '学员工具包_Windows64'}
    elseif (Test-Path -LiteralPath (Join-Path (Split-Path $PSScriptRoot -Parent) 'runtime\python')) {$kit=Split-Path $PSScriptRoot -Parent}
    else {throw '没有找到 Windows 完整运行时。请先完整解压“学员工具与练习_Windows64.zip”，不要只运行压缩包预览中的脚本。讲义资料包不含 Windows 运行时。'}
    $kit=[IO.Path]::GetFullPath($kit)
    $labs=if (Test-Path -LiteralPath (Join-Path $WorkspaceRoot 'labs')) {Join-Path $WorkspaceRoot 'labs'} elseif (Test-Path -LiteralPath (Join-Path $WorkspaceRoot '练习材料')) {Join-Path $WorkspaceRoot '练习材料'} else {Join-Path $kit 'labs'}
    $reportFolder=Join-Path $labs ('out\setup_runs\'+[DateTime]::Now.ToString('yyyyMMdd_HHmmss')+'_'+[Guid]::NewGuid().ToString('N').Substring(0,6))
    $null=New-Item -ItemType Directory -Path $reportFolder -Force
    Say ('工具目录：'+$kit)
    if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {throw '本包支持 Intel/AMD 的 Windows 10/11 x64。32 位 Windows、ARM 原生环境请使用对应平台资料。'}
    if ([Environment]::OSVersion.Version.Major -lt 10) {throw '本包需要 Windows 10/11；旧系统无法运行随包 Python 3.13。'}
    foreach ($path in @('out','inputs','out\vol2_cache','out\_setup')) {$null=New-Item -ItemType Directory -Path (Join-Path $labs $path) -Force}
    $manifestPath=Join-Path $kit 'SHA256SUMS.txt'
    if (-not (Test-Path -LiteralPath $manifestPath)) {throw '缺少 SHA256SUMS.txt，请取得并完整解压正式 Windows 工具包。'}
    $manifestHash=File-Sha256 $manifestPath
    $cacheFile=Join-Path $labs 'out\_setup\environment.json'
    $keyFiles=@('runtime/python/python.exe','runtime/python/python313.dll','runtime/python/python313.zip','tools/setup_probe.py','tools/bootstrap.ps1','tools/learning_server.py','tools/volatility3/vol.py','tools/volatility2/windows/volatility_2.6_win64_standalone.exe','tools/volatility2/extra_plugins/mimikatz.py','tools/volatility3_extra/vol_pypykatz.py','runtime/python/Lib/site-packages/pypykatz/pypykatz.py','tools/7zip/7z.exe','tools/exiftool/exiftool.exe','tools/sleuthkit/bin/fls.exe','runtime/ruby/bin/ruby.exe')
    $fingerprint=(@($keyFiles | ForEach-Object {$p=Join-Path $kit $_;if (Test-Path -LiteralPath $p) {$i=Get-Item -LiteralPath $p;$_+'|'+$i.Length+'|'+$i.LastWriteTimeUtc.Ticks} else {$_+'|missing'}}) -join ([Environment]::NewLine))
    $cache=$null
    if (Test-Path -LiteralPath $cacheFile) {try {$cache=Read-Json $cacheFile} catch {$cache=$null}}
    $useCache=$Mode -eq 'Launch' -and -not $FullVerify -and -not $InstallVCRuntime -and $cache -and $cache.base_ready -and $cache.manifest_hash -eq $manifestHash -and $cache.fingerprint -eq $fingerprint -and ([DateTime]::UtcNow-[DateTime]::Parse($cache.created_utc).ToUniversalTime()).TotalHours -lt 24
    $entries=@(Get-Content -LiteralPath $manifestPath -Encoding UTF8 | Where-Object {$_ -match '^[a-fA-F0-9]{64}  '})
    if (-not $entries.Count) {throw '校验清单为空或格式无效，未运行包内工具。'}
    $count=0
    Say $(if ($useCache -or $basic) {'正在校验关键运行文件。'} else {'首次配置：正在逐项校验完整工具包，请稍候。'})
    foreach ($line in $entries) {
        $relative=$line.Substring(66).Replace('/','\')
        if (($useCache -or $basic) -and $keyFiles -notcontains $line.Substring(66)) {continue}
        $path=[IO.Path]::GetFullPath((Join-Path $kit $relative))
        if (-not $path.StartsWith(($kit.TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)) {throw '校验清单包含目录外路径，已停止。'}
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {$missing.Add($line.Substring(66));continue}
        try {$actual=File-Sha256 $path} catch {$missing.Add($line.Substring(66));continue}
        if ($actual -ne $line.Substring(0,64)) {$modified.Add($line.Substring(66))}
        $count++;if ($count % 500 -eq 0) {Say ('已校验 '+$count+' 个文件。')}
    }
    if ($modified.Count) {throw ('有 '+$modified.Count+' 个文件与正式校验值不同，未继续执行；请核对来源与是否自行修改。')}
    if ($missing.Count) {Add-Issue 'warning' ('发现 '+$missing.Count+' 个文件缺失或无法读取；可能是未完整解压、权限问题或防护软件隔离。')}
    $python=Join-Path $kit 'runtime\python\python.exe';$probe=Join-Path $kit 'tools\setup_probe.py'
    foreach ($essential in @($python,$probe,(Join-Path $kit 'tools\learning_server.py'),(Join-Path $kit 'runtime\python\python313.dll'),(Join-Path $kit 'runtime\python\python313.zip'))) {
        if (-not (Test-Path -LiteralPath $essential -PathType Leaf)) {throw ('基础运行文件缺失：'+$essential+'。请核对解压与拦截记录；本脚本不会自动恢复隔离文件。')}
    }
    if ($InstallVCRuntime) {$null=Install-Cpp;$useCache=$false}
    if ($useCache) {$checks=@($cache.checks);$basic=[bool]$cache.basic_mode;$cached=$true;Say '复用 24 小时内的环境检查；关键文件校验通过。';$baseReady=$true;$allReady=[bool]$cache.full_ready}
    else {
        Say '正在用包内运行时检查 Python、Ruby、文件工具与内存扩展。无需系统 Python。'
        $arguments=@($probe,'--kit',$kit,'--labs',$labs,'--output',(Join-Path $reportFolder '运行时检查.json'))
        if ($basic) {$arguments+='--basic'}
        $result=Run-Captured $python $arguments 240
        $result.stdout | Set-Content -LiteralPath (Join-Path $reportFolder '工具检查.log') -Encoding UTF8
        $result.stderr | Set-Content -LiteralPath (Join-Path $reportFolder '工具诊断.log') -Encoding UTF8
        $healthFile=Join-Path $reportFolder '运行时检查.json';$health=$null
        if (Test-Path -LiteralPath $healthFile) {$health=Read-Json $healthFile}
        $needsCpp=($health -and $health.needs_cpp_runtime) -or $result.code -in @(-1073741515,-1073741701,3221225781,3221225595)
        if ($needsCpp -and -not $cppInstalled -and -not $NoSystemChanges) {
            if (Install-Cpp) {$result=Run-Captured $python $arguments 240;if (Test-Path -LiteralPath $healthFile) {$health=Read-Json $healthFile}}
        }
        if (-not $health) {throw ('包内 Python 未能完成检查，退出码 '+$result.code+'。请查看工具诊断.log；不需要另装 Python 2。')}
        $checks=@($health.checks);$baseReady=[bool]$health.base_ready;$allReady=[bool]$health.full_ready -and -not $missing.Count
        if (-not $baseReady) {throw 'Python 或基础学习平台未通过检查；请查看报告中的失败项。'}
        if (-not $allReady -and -not $basic) {$basic=$true;Add-Issue 'warning' '部分组件未就绪，先以基础模式启动；社区扩展暂停使用，报告中列出待处理项。'}
    }
    if ($missing.Count -or -not $allReady) {
        if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {try {$status=Get-MpComputerStatus;$defender.available=$true;$defender.antivirus_enabled=$status.AntivirusEnabled;$defender.real_time_enabled=$status.RealTimeProtectionEnabled} catch {}}
        if (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue) {
            try {
                $relatedDetections=@(Get-MpThreatDetection | Where-Object {($_.Resources -join ([Environment]::NewLine)).IndexOf($kit,[StringComparison]::OrdinalIgnoreCase) -ge 0})
                $defender.matching_detections=$relatedDetections.Count
                if ($relatedDetections.Count) {Add-Issue 'warning' 'Windows 安全中心有与本工具目录相关的拦截记录；请在保护历史记录中核对来源与校验值。'}
            } catch {}
        }
        Add-Issue 'info' '脚本不会添加防病毒排除项、关闭实时防护或恢复隔离文件。可使用基础模式，或把报告交给授课人员核对。'
    }
    $exitCode=if ($allReady -or $Mode -eq 'Basic') {0} else {10}
    $state=@{schema=1;base_ready=$true;full_ready=$allReady;basic_mode=$basic;manifest_hash=$manifestHash;fingerprint=$fingerprint;kit=$kit;created_utc=[DateTime]::UtcNow.ToString('o');checks=$checks;last_report=$reportFolder}
    if ($Mode -ne 'Basic') {$state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $cacheFile -Encoding UTF8}
    Say $(if ($basic) {'基础环境已就绪，社区扩展已暂停。'} else {'运行环境已就绪。'})
} catch {
    Add-Issue 'error' $_.Exception.Message
    if (-not $reportFolder) {try {$reportFolder=Join-Path ([IO.Path]::GetTempPath()) ('CTFForensicsSetup_'+[Guid]::NewGuid().ToString('N'));$null=New-Item -ItemType Directory -Path $reportFolder -Force} catch {}}
    $exitCode=20
}
Save-Report
if ($reportFolder) {Say ('检查报告：'+(Join-Path $reportFolder '环境检查.html'))}
if ($exitCode -ge 20 -or $Mode -eq 'Check' -or $NoLaunch) {
    if (-not $NonInteractive -and -not $NoBrowser -and $reportFolder) {try {Start-Process -FilePath (Join-Path $reportFolder '环境检查.html')} catch {}}
    exit $exitCode
}
if ($basic) {$env:CTF_FORENSICS_MODE='basic'} else {$env:CTF_FORENSICS_MODE='full'}
$server=Join-Path $kit 'tools\learning_server.py';$serverArgs=@($server,'--root',$WorkspaceRoot,'--kit',$kit)
if ($NoBrowser) {$serverArgs+='--no-browser'}
if ($Port -gt 0) {$serverArgs+=@('--port',[string]$Port)}
Say '即将打开学习平台；请保留此窗口，关闭窗口会停止本地工具服务。'
& $python @serverArgs
exit $LASTEXITCODE
