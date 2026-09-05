param(
    [string]$Tag = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$header = Get-Content -LiteralPath (Join-Path $root 'versioning\version.h') -Raw

function Read-VersionPart([string]$name) {
    $match = [regex]::Match($header, "(?m)^#define\s+$name\s+(\d+)\s*$")
    if (-not $match.Success) { throw "Unable to read $name from versioning/version.h" }
    return $match.Groups[1].Value
}

$version = '{0}.{1}.{2}' -f (Read-VersionPart 'VERSION_MAJOR'), (Read-VersionPart 'VERSION_MINOR'), (Read-VersionPart 'VERSION_BUILD')
$wix = Get-Content -LiteralPath (Join-Path $root 'WiXSetup\Config.wxi') -Raw
$wixMatch = [regex]::Match($wix, '<\?define\s+Version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*\?>')
if (-not $wixMatch.Success -or $wixMatch.Groups[1].Value -ne $version) {
    throw "WiXSetup/Config.wxi version must equal $version"
}

$manifest = Get-Content -LiteralPath (Join-Path $root 'vcpkg.json') -Raw | ConvertFrom-Json
if ($manifest.'version-string' -ne $version) { throw "vcpkg.json version-string must equal $version" }
$libfidoManifest = Get-Content -LiteralPath (Join-Path $root 'vcpkg-overlays\libfido2\vcpkg.json') -Raw | ConvertFrom-Json
if ($libfidoManifest.version -ne '1.17.0') { throw 'The libfido2 overlay must remain pinned to version 1.17.0' }
if ($Tag -and $Tag -ne "v$version") { throw "Release tag $Tag does not match source version v$version" }

Write-Output $version
