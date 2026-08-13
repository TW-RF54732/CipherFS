$ErrorActionPreference = 'Stop'
$websiteRoot = Split-Path -Parent $PSScriptRoot
$script = Join-Path $PSScriptRoot 'generate-release-data.ps1'
$fixture = Join-Path $websiteRoot 'tests/fixtures/releases.json'
$missingFixture = Join-Path $websiteRoot 'tests/fixtures/releases-without-installer.json'
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("cipherfs-website-tests-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tempRoot | Out-Null

function Assert-Equal($Actual, $Expected, [string]$Message) {
    if ($Actual -ne $Expected) {
        throw "$Message. Expected '$Expected', got '$Actual'."
    }
}

try {
    $env:SOURCE_DATE_EPOCH = '1786660637'
    $output = Join-Path $tempRoot 'release.json'
    & $script -FixturePath $fixture -OutputPath $output
    $data = Get-Content -Raw -LiteralPath $output | ConvertFrom-Json

    Assert-Equal $data.featured.tag 'v3.2.0' 'Newest stable release with an installer must be featured'
    Assert-Equal $data.featured.channel 'stable' 'Featured channel must be stable'
    Assert-Equal $data.installer.download_count 7 'Featured installer count must be preserved'
    Assert-Equal $data.totals.installer_downloads 31 'Installer total must include stable and prerelease assets but exclude drafts'
    Assert-Equal $data.alternatives.windows_portable.name 'cipherfs-windows-portable-x64.zip' 'Portable asset must be selected'
    Assert-Equal $data.verification.checksum_url 'https://github.com/TW-RF54732/CipherFS/releases/download/v3.2.0/cipherfs-windows-x64.sha256' 'Checksum URL must be selected'

    $failedAsExpected = $false
    try {
        & $script -FixturePath $missingFixture -OutputPath (Join-Path $tempRoot 'missing.json') 2>$null
    } catch {
        $failedAsExpected = $_.Exception.Message -like '*No published stable release contains*'
    }
    if (-not $failedAsExpected) { throw 'Missing installer fixture did not fail clearly.' }

    Write-Host 'Release data tests passed.'
} finally {
    Remove-Item Env:SOURCE_DATE_EPOCH -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
