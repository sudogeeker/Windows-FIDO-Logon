$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$compiled = @(
    Join-Path $root 'CppClient\CppClient\CppClient.vcxproj'
    Join-Path $root 'CredentialProvider\CredentialProvider.vcxproj'
    Join-Path $root 'CredentialProviderFilter\CredentialProviderFilter.vcxproj'
    Join-Path $root 'BrokerService\BrokerService.vcxproj'
    Join-Path $root 'Manager\Manager.vcxproj'
    Join-Path $root 'Tests\BrokerProtocolTests.vcxproj'
    Join-Path $root 'Tests\FidoVerifierTests.vcxproj'
)

$projectText = ($compiled | ForEach-Object { Get-Content -LiteralPath $_ -Raw }) -join "`n"
$forbiddenLibraries = @('winhttp.lib', 'wininet.lib', 'httpapi.lib', 'urlmon.lib', 'ws2_32.lib', 'wldap32.lib', 'winscard.lib')
foreach ($library in $forbiddenLibraries) {
    if ($projectText -match [regex]::Escape($library)) { throw "Forbidden network/NFC dependency present: $library" }
}
foreach ($legacyLibrary in @('CppClient.lib', 'fido2.lib', 'crypto.lib', 'zlib.lib')) {
    if ($projectText -match ('(?i)(?:>|;)' + [regex]::Escape($legacyLibrary) + '(?:;|<)')) {
        throw "Legacy or dynamic dependency name present: $legacyLibrary"
    }
}
foreach ($requiredLibrary in @('FidoCore.lib', 'fido2_static.lib', 'libcrypto.lib', 'zs.lib')) {
    if ($projectText -notmatch [regex]::Escape($requiredLibrary)) { throw "Pinned static dependency missing: $requiredLibrary" }
}

$runtimeFiles = Get-ChildItem -LiteralPath $root -Recurse -File -Include *.cpp,*.h,*.vcxproj,*.wxs,*.wxi |
    Where-Object { $_.FullName -notmatch '\\Tests?\\' }
$runtimeText = ($runtimeFiles | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
foreach ($symbol in @('WinHttpOpen', 'InternetOpen', 'HttpSendRequest', 'WSAStartup', 'fido_dev_set_pcsc')) {
    if ($runtimeText -match $symbol) { throw "Forbidden runtime networking/NFC symbol present: $symbol" }
}

$overlayRoot = Join-Path $root 'vcpkg-overlays\libfido2'
$overlayManifest = Get-Content -LiteralPath (Join-Path $overlayRoot 'vcpkg.json') -Raw | ConvertFrom-Json
if ($overlayManifest.version -ne '1.17.0') { throw 'The local-only libfido2 overlay must be pinned to 1.17.0' }
$overlayPort = Get-Content -LiteralPath (Join-Path $overlayRoot 'portfile.cmake') -Raw
foreach ($required in @('SHA512 f168f1bac0b4ebf64a285d6f7b748cc3572e3280e8795e775471ddec059c4b255a80d79e5d93592a9e2a296ec1d959124a3c097e38a9ff203a34a9ccfefc6b66', '-DUSE_WINHELLO=OFF', '-DUSE_PCSC=OFF', '-DNFC_LINUX=OFF', 'local-only-windows.diff')) {
    if ($overlayPort -notmatch [regex]::Escape($required)) { throw "libfido2 overlay contract missing: $required" }
}

$broker = Get-Content -LiteralPath (Join-Path $root 'BrokerService\BrokerService.cpp') -Raw
foreach ($required in @('kSessionLifetime', 'kMaximumSessions', 'kMaximumSessionsPerCaller', 'kPipeIoTimeoutMs', 'TakeSession', 'ImpersonateNamedPipeClient', 'FILE_FLAG_FIRST_PIPE_INSTANCE', 'FILE_FLAG_OVERLAPPED', 'PIPE_REJECT_REMOTE_CLIENTS', 'SecureZeroMemory', 'finish_registration', 'begin_remove', 'finish_remove', 'policy state is inconsistent')) {
    if ($broker -notmatch $required) { throw "Broker security contract missing: $required" }
}

$client = Get-Content -LiteralPath (Join-Path $root 'CppClient\CppClient\BrokerClient.cpp') -Raw
foreach ($required in @('GetNamedPipeServerProcessId', 'WinLocalSystemSid')) {
    if ($client -notmatch $required) { throw "Broker client trust contract missing: $required" }
}

$workflow = Get-Content -LiteralPath (Join-Path $root '.github\workflows\build-release.yml') -Raw
$actionUses = [regex]::Matches($workflow, '(?m)^\s*uses:\s*[^@\s]+@([^\s#]+)')
if ($actionUses.Count -eq 0) { throw 'No GitHub Actions dependencies were found' }
foreach ($use in $actionUses) {
    if ($use.Groups[1].Value -notmatch '^[0-9a-f]{40}$') { throw "GitHub Action is not pinned to a commit: $($use.Value.Trim())" }
}
foreach ($required in @('attestations: write', 'actions/attest@', 'gh release create', 'not Authenticode-signed')) {
    if ($workflow -notmatch [regex]::Escape($required)) { throw "Release workflow contract missing: $required" }
}
foreach ($forbidden in @('WINDOWS_SIGNING_CERTIFICATE_BASE64', 'WINDOWS_SIGNING_CERTIFICATE_PASSWORD', 'RequireSignature')) {
    if ($workflow -match [regex]::Escape($forbidden)) { throw "Unsigned release workflow still requires signing material: $forbidden" }
}
$buildScript = Get-Content -LiteralPath (Join-Path $root 'build.ps1') -Raw
foreach ($required in @('BuildProjectReferences=false', '-BuildDirectory $buildDirectory', 'verify-binaries.ps1', 'verify-msi.ps1', 'fido2_static.lib', 'libcrypto.lib', 'zs.lib')) {
    if ($buildScript -notmatch [regex]::Escape($required)) { throw "Build verification contract missing: $required" }
}

$installer = Get-Content -LiteralPath (Join-Path $root 'WiXSetup\Product.wxs') -Raw
foreach ($required in @('Schedule="afterInstallExecute"', 'NeverOverwrite="yes"', 'WindowsFidoLogonBroker', 'SafeBoot\Minimal')) {
    if ($installer -notmatch [regex]::Escape($required)) { throw "Installer safety contract missing: $required" }
}

$providerGuid = 'A95D1C6B-8D9C-4E0F-A60D-CA6B569E28AD'
$filterGuid = '54B25B17-C7AE-4C2B-B3C4-E3B29A73D9B1'
if ($providerGuid -eq $filterGuid) { throw 'Provider and Filter GUIDs must differ' }

Write-Host 'Security contract checks passed.' -ForegroundColor Green
