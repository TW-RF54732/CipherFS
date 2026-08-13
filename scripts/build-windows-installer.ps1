[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [string]$PayloadDirectory,
    [string]$WinFspMsi,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$version = Select-String -Path (Join-Path $repo 'Cargo.toml') -Pattern '^version = "([^"]+)"' |
    Select-Object -First 1 | ForEach-Object { $_.Matches[0].Groups[1].Value }
if (-not $version) { throw 'Unable to read the workspace version from Cargo.toml' }

$semver = [regex]::Match($version, '^(?<major>0|[1-9]\d*)\.(?<minor>0|[1-9]\d*)\.(?<patch>0|[1-9]\d*)(?:-(?<label>alpha|beta|rc)(?:\.(?<number>\d+))?)?$')
if (-not $semver.Success) {
    throw "Unsupported Cargo version for Windows Installer ordering: $version"
}
$major = [int]$semver.Groups['major'].Value
$minor = [int]$semver.Groups['minor'].Value
$patch = [int]$semver.Groups['patch'].Value
$preNumber = if ($semver.Groups['number'].Success) { [int]$semver.Groups['number'].Value } else { 0 }
if ($major -gt 255 -or $minor -gt 255 -or $patch -gt 654 -or $preNumber -gt 19) {
    throw "Cargo version is outside the supported MSI ordering range: $version"
}
$rank = switch ($semver.Groups['label'].Value) {
    'alpha' { 10 + $preNumber }
    'beta' { 30 + $preNumber }
    'rc' { 70 + $preNumber }
    default { 99 }
}
$msiVersion = "$major.$minor.$($patch * 100 + $rank)"

if (-not $PayloadDirectory) {
    $PayloadDirectory = Join-Path $repo 'target\x86_64-pc-windows-msvc\release'
}
if (-not $WinFspMsi) {
    $WinFspMsi = Join-Path $repo 'target\installer-input\winfsp-2.1.25156.msi'
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repo 'target\installer'
}

$payload = (Resolve-Path -LiteralPath $PayloadDirectory).Path
$winfsp = (Resolve-Path -LiteralPath $WinFspMsi).Path
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
foreach ($required in @('cipherfs.exe', 'cipherfs-shell.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $payload $required) -PathType Leaf)) {
        throw "Missing tested Windows payload: $required"
    }
}

$expectedWinFsp = '073A70E00F77423E34BED98B86E600DEF93393BA5822204FAC57A29324DB9F7A'
$actualWinFsp = (Get-FileHash -LiteralPath $winfsp -Algorithm SHA256).Hash
if ($actualWinFsp -ne $expectedWinFsp) {
    throw "WinFsp MSI hash mismatch: $actualWinFsp"
}

$packageOutput = Join-Path $output 'package'
New-Item -ItemType Directory -Force -Path $packageOutput | Out-Null

$packageProject = Join-Path $repo 'installer\windows\package\CipherFS.Package.wixproj'
dotnet build $packageProject --configuration $Configuration --nologo `
    -p:PayloadDir=$payload -p:RepoRoot=$repo -p:MsiVersion=$msiVersion -p:ProductDisplayVersion=$version -p:OutputPath=$packageOutput
if ($LASTEXITCODE -ne 0) { throw 'CipherFS MSI build failed' }
$cipherfsMsi = (Resolve-Path -LiteralPath (Join-Path $packageOutput 'CipherFS.msi')).Path

$bundleOutput = Join-Path $output 'bundle'
New-Item -ItemType Directory -Force -Path $bundleOutput | Out-Null
$bundleProject = Join-Path $repo 'installer\windows\bundle\CipherFS.Bundle.wixproj'
$setupIcon = Join-Path $repo 'assets\windows\cipherfs-app.ico'
dotnet build $bundleProject --configuration $Configuration --nologo `
    -p:CipherFSMsi=$cipherfsMsi -p:WinFspMsi=$winfsp -p:ProductVersion=$version -p:SetupIcon=$setupIcon -p:OutputPath=$bundleOutput
if ($LASTEXITCODE -ne 0) { throw 'CipherFS Setup bundle build failed' }

$final = Join-Path $output 'CipherFS-Setup-x64.exe'
Copy-Item -LiteralPath (Join-Path $bundleOutput 'CipherFS-Setup-x64.exe') -Destination $final -Force
Write-Output $final
