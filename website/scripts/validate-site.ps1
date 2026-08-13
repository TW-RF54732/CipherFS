[CmdletBinding()]
param(
    [string]$WebsiteRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$resolvedRoot = (Resolve-Path -LiteralPath $WebsiteRoot).Path
$repoPrefix = 'https://github.com/TW-RF54732/CipherFS/'

function Assert([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$required = @(
    'index.html',
    'download/index.html',
    '404.html',
    'assets/css/site.css',
    'assets/js/site.js',
    'assets/js/download.js',
    'data/release.json',
    '.nojekyll'
)
foreach ($relative in $required) {
    Assert (Test-Path -LiteralPath (Join-Path $resolvedRoot $relative)) "Missing required website file: $relative"
}

$htmlFiles = Get-ChildItem -LiteralPath $resolvedRoot -Filter '*.html' -File -Recurse
foreach ($htmlFile in $htmlFiles) {
    $html = Get-Content -Raw -LiteralPath $htmlFile.FullName
    Assert ($html -match '<html\s+lang="zh-Hant"') "$($htmlFile.Name) must declare zh-Hant."
    Assert ($html -notmatch '(?i)(github_token|authorization:\s*bearer|ghp_[a-z0-9]+)') "$($htmlFile.Name) may contain a credential."

    foreach ($match in [regex]::Matches($html, '<img\b[^>]*>')) {
        Assert ($match.Value -match '\balt="[^"]*"') "Image in $($htmlFile.FullName) is missing alt text: $($match.Value)"
    }

    foreach ($match in [regex]::Matches($html, '(?:href|src)="([^"#?]+)"')) {
        $target = $match.Groups[1].Value
        if ($target -match '^(https?:|mailto:|data:)') { continue }
        $base = Split-Path -Parent $htmlFile.FullName
        $local = Join-Path $base $target
        if ($target.EndsWith('/')) { $local = Join-Path $local 'index.html' }
        Assert (Test-Path -LiteralPath $local) "Broken local reference in $($htmlFile.FullName): $target"
    }
}

$data = Get-Content -Raw -LiteralPath (Join-Path $resolvedRoot 'data/release.json') | ConvertFrom-Json
Assert (-not [string]::IsNullOrWhiteSpace([string]$data.generated_at)) 'release.json generated_at is missing.'
Assert ($data.featured.tag -and $data.featured.channel -eq 'stable') 'release.json featured stable release is invalid.'
Assert ($data.installer.name -ceq 'CipherFS-Setup-x64.exe') 'release.json installer name is invalid.'
Assert ([long]$data.installer.size_bytes -gt 0) 'release.json installer size is invalid.'
Assert ([long]$data.installer.download_count -ge 0) 'release.json installer download count is invalid.'
Assert ([long]$data.totals.installer_downloads -ge [long]$data.installer.download_count) 'release.json installer total is invalid.'

$urls = @(
    $data.featured.release_url,
    $data.installer.url,
    $data.alternatives.windows_portable.url,
    $data.alternatives.linux_x64.url,
    $data.verification.checksum_url,
    $data.verification.manifest_url,
    $data.verification.minisign_url,
    $data.verification.attestation_url
) | Where-Object { $_ }
foreach ($url in $urls) {
    Assert ($url.StartsWith($repoPrefix, [System.StringComparison]::Ordinal)) "release.json URL is outside the CipherFS repository: $url"
}

Write-Host "Validated $($htmlFiles.Count) HTML pages and release.json."
