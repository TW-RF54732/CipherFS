[CmdletBinding()]
param(
    [string]$Repository = 'TW-RF54732/CipherFS',
    [string]$ApiUrl = 'https://api.github.com',
    [string]$FixturePath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$installerName = 'CipherFS-Setup-x64.exe'
$portableName = 'cipherfs-windows-portable-x64.zip'
$linuxName = 'cipherfs-linux-x64.tar.gz'
$checksumName = 'cipherfs-windows-x64.sha256'
$manifestName = 'cipherfs-windows-setup.manifest'
$minisignName = 'cipherfs-windows-setup.manifest.minisig'
$repoPrefix = "https://github.com/$Repository/"

function Assert-RepositoryUrl([string]$Url, [string]$Label) {
    if ([string]::IsNullOrWhiteSpace($Url) -or -not $Url.StartsWith($repoPrefix, [System.StringComparison]::Ordinal)) {
        throw "$Label URL is outside the expected repository: $Url"
    }
}

function Get-PublicReleases {
    if ($FixturePath) {
        $fixtureReleases = Get-Content -Raw -LiteralPath $FixturePath | ConvertFrom-Json
        foreach ($release in $fixtureReleases) { Write-Output $release }
        return
    }

    $headers = @{
        Accept = 'application/vnd.github+json'
        'X-GitHub-Api-Version' = '2022-11-28'
        'User-Agent' = 'CipherFS-website-release-data'
    }
    if ($env:GITHUB_TOKEN) {
        $headers.Authorization = "Bearer $($env:GITHUB_TOKEN)"
    }

    $all = [System.Collections.Generic.List[object]]::new()
    for ($page = 1; $page -le 10; $page++) {
        $uri = "$ApiUrl/repos/$Repository/releases?per_page=100&page=$page"
        $response = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                $response = @(Invoke-RestMethod -Uri $uri -Headers $headers -Method Get)
                break
            } catch {
                if ($attempt -eq 3) { throw }
                Start-Sleep -Seconds ([Math]::Pow(2, $attempt))
            }
        }
        foreach ($release in $response) { $all.Add($release) }
        if ($response.Count -lt 100) { break }
    }
    foreach ($release in $all) { Write-Output $release }
}

function Find-Asset($Release, [string]$Name) {
    return @($Release.assets | Where-Object { $_.name -ceq $Name }) | Select-Object -First 1
}

$releases = @(Get-PublicReleases | Where-Object { $_.draft -eq $false })
if ($releases.Count -eq 0) {
    throw 'GitHub returned no published releases.'
}

$stableCandidates = @(
    $releases |
        Where-Object { $_.prerelease -eq $false -and (Find-Asset $_ $installerName) } |
        Sort-Object { [DateTimeOffset]$_.published_at } -Descending
)
if ($stableCandidates.Count -eq 0) {
    throw "No published stable release contains $installerName."
}

$featured = $stableCandidates[0]
$installer = Find-Asset $featured $installerName
$portable = Find-Asset $featured $portableName
$linux = Find-Asset $featured $linuxName
$checksum = Find-Asset $featured $checksumName
$manifest = Find-Asset $featured $manifestName
$minisign = Find-Asset $featured $minisignName

$installerTotal = 0L
foreach ($release in $releases) {
    $asset = Find-Asset $release $installerName
    if ($asset) { $installerTotal += [long]$asset.download_count }
}

Assert-RepositoryUrl $featured.html_url 'Release'
Assert-RepositoryUrl $installer.browser_download_url 'Installer'
foreach ($candidate in @($portable, $linux, $checksum, $manifest, $minisign)) {
    if ($candidate) { Assert-RepositoryUrl $candidate.browser_download_url $candidate.name }
}

function Convert-Alternative($Asset) {
    if (-not $Asset) { return $null }
    return [ordered]@{
        name = [string]$Asset.name
        url = [string]$Asset.browser_download_url
        size_bytes = [long]$Asset.size
    }
}

$generatedAt = if ($env:SOURCE_DATE_EPOCH) {
    [DateTimeOffset]::FromUnixTimeSeconds([long]$env:SOURCE_DATE_EPOCH).UtcDateTime.ToString('o')
} else {
    [DateTime]::UtcNow.ToString('o')
}

$payload = [ordered]@{
    generated_at = $generatedAt
    featured = [ordered]@{
        tag = [string]$featured.tag_name
        channel = 'stable'
        published_at = ([DateTimeOffset]$featured.published_at).UtcDateTime.ToString('o')
        release_url = [string]$featured.html_url
    }
    installer = [ordered]@{
        name = [string]$installer.name
        url = [string]$installer.browser_download_url
        size_bytes = [long]$installer.size
        download_count = [long]$installer.download_count
    }
    totals = [ordered]@{
        installer_downloads = $installerTotal
    }
    alternatives = [ordered]@{
        windows_portable = Convert-Alternative $portable
        linux_x64 = Convert-Alternative $linux
    }
    verification = [ordered]@{
        checksum_url = if ($checksum) { [string]$checksum.browser_download_url } else { $null }
        manifest_url = if ($manifest) { [string]$manifest.browser_download_url } else { $null }
        minisign_url = if ($minisign) { [string]$minisign.browser_download_url } else { $null }
        attestation_url = "https://github.com/$Repository/attestations"
    }
}

$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
$json = $payload | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($OutputPath, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
Write-Host "Generated release data for $($featured.tag_name); installer total: $installerTotal"
