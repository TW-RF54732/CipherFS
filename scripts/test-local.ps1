param(
    [ValidateSet('Auto', 'Shell', 'Cli', 'Core', 'Update', 'WinFsp', 'Fuse', 'All')]
    [string]$Scope = 'Auto',
    [ValidateSet('Fast', 'Runtime', 'Full')]
    [string]$Level = 'Fast',
    [string]$BaseRef,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repo

function Invoke-Step([string[]]$Command) {
    Write-Host ('> ' + ($Command -join ' '))
    if ($DryRun) { return }
    & $Command[0] $Command[1..($Command.Count - 1)]
    if ($LASTEXITCODE -ne 0) { throw "Command failed with exit code $LASTEXITCODE" }
}

function Invoke-GuiStep([string]$Executable, [string[]]$Arguments) {
    Write-Host ('> ' + $Executable + ' ' + ($Arguments -join ' '))
    if ($DryRun) { return }
    $errorFile = Join-Path ([IO.Path]::GetTempPath()) "cipherfs-shell-smoke-$PID.txt"
    Remove-Item -LiteralPath $errorFile -ErrorAction SilentlyContinue
    $env:CIPHERFS_SMOKE_ERROR_FILE = $errorFile
    try {
        $process = Start-Process -FilePath $Executable -ArgumentList $Arguments -PassThru
        if (-not $process.WaitForExit(20000)) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            throw "GUI smoke timed out after 20 seconds (PID $($process.Id))"
        }
        if ($process.ExitCode -ne 0) {
            $detail = if (Test-Path -LiteralPath $errorFile) { (Get-Content -LiteralPath $errorFile) -join "`n" } else { 'No child error report was written.' }
            throw "GUI smoke failed with exit code $($process.ExitCode): $detail"
        }
    } finally {
        Remove-Item Env:CIPHERFS_SMOKE_ERROR_FILE -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $errorFile -ErrorAction SilentlyContinue
    }
}

function Get-ChangedFiles {
    $files = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if (-not $BaseRef) {
        git rev-parse --verify origin/main 2>$null | Out-Null
        $script:BaseRef = if ($LASTEXITCODE -eq 0) { 'origin/main' } else { 'HEAD~1' }
    }
    git merge-base HEAD $BaseRef 2>$null | ForEach-Object {
        git diff --name-only "$_...HEAD" | ForEach-Object { [void]$files.Add($_) }
    }
    git diff --name-only | ForEach-Object { [void]$files.Add($_) }
    git diff --cached --name-only | ForEach-Object { [void]$files.Add($_) }
    git ls-files --others --exclude-standard | ForEach-Object { [void]$files.Add($_) }
    return @($files)
}

function Resolve-Scopes([string[]]$Files) {
    $selected = [System.Collections.Generic.HashSet[string]]::new()
    $code = $false
    foreach ($file in $Files) {
        if ($file -match '^(README|ARCHITECTURE|TESTING|RELEASING|THIRD_PARTY|release_notes/)' -or $file -match '\.md$') { continue }
        $code = $true
        switch -Regex ($file) {
            '^apps/cipherfs-windows-shell/' { [void]$selected.Add('Shell'); break }
            '^apps/cipherfs-cli/' { [void]$selected.Add('Cli'); break }
            '^crates/cipherfs-core/' { [void]$selected.Add('Core'); break }
            '^crates/cipherfs-update/' { [void]$selected.Add('Update'); break }
            '^crates/cipherfs-winfsp/' { [void]$selected.Add('WinFsp'); break }
            '^crates/cipherfs-fuse/' { [void]$selected.Add('Fuse'); break }
            default { [void]$selected.Add('All') }
        }
    }
    if (-not $code) { return @('Docs') }
    return @($selected)
}

$scopes = if ($Scope -eq 'Auto') { Resolve-Scopes (Get-ChangedFiles) } else { @($Scope) }
if ($scopes -contains 'All') { $scopes = @('All') }
Write-Host "Selected scope: $($scopes -join ', '); level: $Level"

Invoke-Step @('cargo', 'fmt', '--all', '--', '--check')
Invoke-Step @('git', 'diff', '--check')
if ($scopes -contains 'Docs') { exit 0 }

$packages = [System.Collections.Generic.HashSet[string]]::new()
foreach ($item in $scopes) {
    switch ($item) {
        'Shell' { [void]$packages.Add('cipherfs-windows-shell') }
        'Cli' { [void]$packages.Add('cipherfs-cli') }
        'Core' {
            @('cipherfs-core', 'cipherfs-cli', 'cipherfs-windows-shell', 'cipherfs-winfsp') |
                ForEach-Object { [void]$packages.Add($_) }
        }
        'Update' { @('cipherfs-update', 'cipherfs-cli', 'cipherfs-windows-shell') | ForEach-Object { [void]$packages.Add($_) } }
        'WinFsp' { @('cipherfs-winfsp', 'cipherfs-cli', 'cipherfs-windows-shell') | ForEach-Object { [void]$packages.Add($_) } }
        'Fuse' { Write-Warning 'FUSE scope is Linux-only; run scripts/test-local.sh on Linux or WSL.' }
        'All' { @('cipherfs-core', 'cipherfs-update', 'cipherfs-cli', 'cipherfs-winfsp', 'cipherfs-windows-shell') | ForEach-Object { [void]$packages.Add($_) } }
    }
}

foreach ($package in $packages) {
    Invoke-Step @('cargo', 'test', '--locked', '-p', $package)
    Invoke-Step @('cargo', 'clippy', '--locked', '-p', $package, '--all-targets', '--', '-D', 'warnings')
}

if ($Level -in @('Runtime', 'Full')) {
    if ($packages -contains 'cipherfs-windows-shell') {
        Invoke-Step @('cargo', 'build', '--locked', '--release', '-p', 'cipherfs-windows-shell')
        Invoke-GuiStep '.\target\release\cipherfs-shell.exe' @('--native-dialog-smoke', 'extract')
        Invoke-GuiStep '.\target\release\cipherfs-shell.exe' @('--native-dialog-smoke', 'pack')
    }
    if ($packages -contains 'cipherfs-winfsp') {
        $installed = Test-Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\WinFsp'
        if ($installed) {
            Invoke-Step @('cargo', 'test', '--locked', '--release', '-p', 'cipherfs-winfsp', 'runtime_mount_reads_files_and_rejects_mutation', '--', '--ignored', '--test-threads=1', '--nocapture')
            Invoke-Step @('cargo', 'test', '--locked', '--release', '-p', 'cipherfs-windows-shell', 'worker_mount_session_auto_drive_and_unmount', '--', '--ignored', '--test-threads=1', '--nocapture')
        } else {
            Write-Warning 'WinFsp runtime is not installed; runtime mount tests were not run.'
        }
    }
}

if ($Level -eq 'Full') {
    Invoke-Step @('cargo', 'check', '--locked', '--workspace', '--all-targets')
    Invoke-Step @('cargo', 'clippy', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings')
    Invoke-Step @('cargo', 'test', '--locked', '--workspace', '--exclude', 'cipherfs-winfsp', '--', '--test-threads=1')
    Invoke-Step @('cargo', 'audit', '--ignore', 'RUSTSEC-2024-0436')
    Invoke-Step @('cargo', 'deny', '--locked', 'check', 'advisories', 'licenses', 'sources')
}
