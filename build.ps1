[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$WixRoot = '',
    [string]$Tag = '',
    [switch]$SkipDependencies,
    [switch]$SkipMsi
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$version = (& (Join-Path $root 'Tests\validate-version.ps1') -Tag $Tag | Select-Object -Last 1).Trim()
& (Join-Path $root 'Tests\security-contract.ps1')

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio vswhere.exe was not found.' }
$msbuild = (& $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1)
$vsInstall = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if (-not $msbuild -or -not (Test-Path -LiteralPath $msbuild)) { throw 'MSBuild was not found.' }
if (-not $vsInstall) { throw 'Visual C++ x64 build tools were not found.' }

$vcpkgRoot = if ($env:VCPKG_ROOT) { $env:VCPKG_ROOT } elseif ($env:VCPKG_INSTALLATION_ROOT) { $env:VCPKG_INSTALLATION_ROOT } else { 'C:\vcpkg' }
$vcpkg = Join-Path $vcpkgRoot 'vcpkg.exe'
if (-not $SkipDependencies) {
    if (-not (Test-Path -LiteralPath $vcpkg)) { throw "vcpkg.exe was not found at $vcpkg" }
    $installedRoot = Join-Path $root 'vcpkg_installed'
    $overlayPorts = Join-Path $root 'vcpkg-overlays'
    & $vcpkg install --triplet x64-windows-static "--x-manifest-root=$root" "--x-install-root=$installedRoot" "--overlay-ports=$overlayPorts"
    if ($LASTEXITCODE -ne 0) { throw 'vcpkg dependency restore failed.' }
}

$installedRoot = Join-Path $root 'vcpkg_installed'
$dependencyLibraryDirectory = if ($Configuration -eq 'Debug') {
    Join-Path $installedRoot 'x64-windows-static\debug\lib'
} else {
    Join-Path $installedRoot 'x64-windows-static\lib'
}
$requiredLibraries = @('fido2_static.lib', 'cbor.lib', 'libcrypto.lib', $(if ($Configuration -eq 'Debug') { 'zsd.lib' } else { 'zs.lib' }))
foreach ($library in $requiredLibraries) {
    $path = Join-Path $dependencyLibraryDirectory $library
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Pinned static dependency output is missing: $path"
    }
}
$nlohmannHeader = Join-Path $installedRoot 'x64-windows-static\include\nlohmann\json.hpp'
if (-not (Test-Path -LiteralPath $nlohmannHeader -PathType Leaf)) {
    throw "Pinned header dependency is missing: $nlohmannHeader"
}
$opensslConfiguration = Join-Path $installedRoot 'x64-windows-static\include\openssl\configuration.h'
if (-not (Test-Path -LiteralPath $opensslConfiguration -PathType Leaf) -or
    (Get-Content -LiteralPath $opensslConfiguration -Raw) -notmatch '#\s*define\s+OPENSSL_NO_SOCK\b') {
    throw 'Pinned OpenSSL was not built with socket support disabled.'
}

$solutionDirectory = $root.TrimEnd('\') + '\'
$common = @(
    '/nologo', '/m', '/verbosity:minimal', '/t:Build',
    "/p:Configuration=$Configuration", '/p:Platform=x64',
    "/p:SolutionDir=$solutionDirectory", "/p:VcpkgRoot=$($vcpkgRoot.TrimEnd('\'))"
)
$projects = @(
    'CppClient\CppClient\CppClient.vcxproj',
    'Tests\FidoVerifierTests.vcxproj',
    'Tests\BrokerProtocolTests.vcxproj',
    'Tests\ManagerUiTests.vcxproj',
    'Tests\CredentialUiTests.vcxproj',
    'CredentialProvider\CredentialProvider.vcxproj',
    'CredentialProviderFilter\CredentialProviderFilter.vcxproj',
    'BrokerService\BrokerService.vcxproj',
    'Manager\Manager.vcxproj'
)
foreach ($project in $projects) {
    & $msbuild (Join-Path $root $project) @common
    if ($LASTEXITCODE -ne 0) { throw "Build failed: $project" }
}

$buildDirectory = Join-Path $root "bin\x64\$Configuration"
& (Join-Path $buildDirectory 'FidoVerifierTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'FidoVerifierTests failed.' }
& (Join-Path $buildDirectory 'BrokerProtocolTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'BrokerProtocolTests failed.' }
& (Join-Path $buildDirectory 'ManagerUiTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'ManagerUiTests failed.' }
& (Join-Path $buildDirectory 'CredentialUiTests.exe')
if ($LASTEXITCODE -ne 0) { throw 'CredentialUiTests failed.' }

$toolset = Get-ChildItem -LiteralPath (Join-Path $vsInstall 'VC\Tools\MSVC') -Directory | Sort-Object Name -Descending | Select-Object -First 1
if (-not $toolset) { throw 'MSVC toolset directory was not found.' }
$dumpbin = Join-Path $toolset.FullName 'bin\Hostx64\x64\dumpbin.exe'

$runtimeBinaries = @(
    'WindowsFidoLogonCredentialProvider.dll',
    'WindowsFidoLogonFilter.dll',
    'WindowsFidoLogonBroker.exe',
    'WindowsFidoLogonManager.exe'
) | ForEach-Object { Join-Path $buildDirectory $_ }

& (Join-Path $root 'Tests\verify-binaries.ps1') -BuildDirectory $buildDirectory -DumpbinPath $dumpbin

if (-not $SkipMsi) {
    if (-not $WixRoot) { $WixRoot = $env:WIX }
    if (-not $WixRoot -or
        -not (Test-Path -LiteralPath (Join-Path $WixRoot 'wix.targets') -PathType Leaf) -or
        -not (Test-Path -LiteralPath (Join-Path $WixRoot 'WixTasks.dll') -PathType Leaf)) {
        throw 'WiX 3.14.1 binaries are required; pass -WixRoot.'
    }
    $wixRootPath = (Resolve-Path -LiteralPath $WixRoot).Path.TrimEnd('\')
    $wixArguments = $common + @(
        '/p:BuildProjectReferences=false',
        "/p:WixTargetsPath=$(Join-Path $wixRootPath 'wix.targets')",
        "/p:WixTasksPath=$(Join-Path $wixRootPath 'WixTasks.dll')",
        "/p:WixInstallPath=$wixRootPath",
        "/p:WixToolPath=$wixRootPath\",
        "/p:WixExtDir=$wixRootPath\"
    )
    & $msbuild (Join-Path $root 'WiXSetup\WiXSetup.wixproj') @wixArguments
    if ($LASTEXITCODE -ne 0) { throw 'MSI build failed.' }

    $msi = Join-Path $root "WiXSetup\bin\x64\$Configuration\WindowsFidoLogonSetup.msi"
    & (Join-Path $root 'Tests\verify-msi.ps1') -MsiPath $msi -WixRoot $WixRoot -BuildDirectory $buildDirectory

    $dist = Join-Path $root 'dist'
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    $releaseName = "WindowsFidoLogon-$version-x64.msi"
    $releaseMsi = Join-Path $dist $releaseName
    Copy-Item -LiteralPath $msi -Destination $releaseMsi -Force
    $hash = (Get-FileHash -LiteralPath $releaseMsi -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $releaseName" | Set-Content -LiteralPath (Join-Path $dist "$releaseName.sha256") -Encoding ascii
    Write-Host "Built $releaseMsi" -ForegroundColor Green
}
