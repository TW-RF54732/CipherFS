param(
    [string]$Output = "THIRD_PARTY_DEPENDENCIES.md"
)

$ErrorActionPreference = "Stop"
$metadata = cargo metadata --locked --format-version 1 | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw "cargo metadata failed"
}

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("# Third-party Rust dependencies")
$lines.Add("")
$lines.Add("This file is generated from the locked Cargo dependency graph by")
$lines.Add('`scripts/generate-third-party.ps1`. Regenerate it whenever `Cargo.lock` changes.')
$lines.Add("")
$lines.Add("| Package | License metadata | Exact source |")
$lines.Add("| --- | --- | --- |")

$packages = $metadata.packages |
    Where-Object { $_.source -or $_.name -eq "winfsp-sys" } |
    Sort-Object name, version -Unique
foreach ($package in $packages) {
    $name = $package.name.Replace("|", "\|")
    $version = $package.version
    $license = if ($package.license) { $package.license.Replace("|", "\|") } else { "Not declared" }
    if ($package.source -like "registry+*") {
        $source = "https://crates.io/api/v1/crates/$($package.name)/$version/download"
    } elseif ($package.name -eq "winfsp-sys") {
        $source = "VENDORED_WINFSP.md"
    } else {
        $source = $package.manifest_path
    }
    $lines.Add(('| `{0}` `{1}` | {2} | <{3}> |' -f $name, $version, $license, $source))
}

$utf8 = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllLines((Join-Path (Get-Location) $Output), $lines, $utf8)
