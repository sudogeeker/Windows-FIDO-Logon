$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$compiled = @(
    Join-Path $root 'CppClient\CppClient\CppClient.vcxproj'
    Join-Path $root 'CredentialProvider\CredentialProvider.vcxproj'
    Join-Path $root 'CredentialProviderFilter\CredentialProviderFilter.vcxproj'
    Join-Path $root 'BrokerService\BrokerService.vcxproj'
    Join-Path $root 'Manager\Manager.vcxproj'
    Join-Path $root 'Tests\BrokerProtocolTests.vcxproj'
    Join-Path $root 'Tests\ManagerUiTests.vcxproj'
    Join-Path $root 'Tests\CredentialUiTests.vcxproj'
    Join-Path $root 'Tests\FidoVerifierTests.vcxproj'
)

$projectText = ($compiled | ForEach-Object { Get-Content -LiteralPath $_ -Raw }) -join "`n"
$sharedProps = Get-Content -LiteralPath (Join-Path $root 'WindowsFidoLogon.props') -Raw
foreach ($project in $compiled) {
    if ((Get-Content -LiteralPath $project -Raw) -notmatch [regex]::Escape('$(SolutionDir)WindowsFidoLogon.props')) {
        throw "C++ project does not import the shared dependency paths: $project"
    }
}
foreach ($required in @('vcpkg_installed\$(VcpkgTriplet)', 'AdditionalIncludeDirectories', 'AdditionalLibraryDirectories', 'NOMINMAX')) {
    if ($sharedProps -notmatch [regex]::Escape($required)) { throw "Shared C++ build properties missing: $required" }
}
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

$runtimeRoots = @(
    'BrokerService',
    'CppClient',
    'CredentialProvider',
    'CredentialProviderFilter',
    'Manager',
    'RegistryHelpers',
    'Shared',
    'WiXSetup'
) | ForEach-Object { Join-Path $root $_ } | Where-Object { Test-Path -LiteralPath $_ }
$runtimeFiles = Get-ChildItem -LiteralPath $runtimeRoots -Recurse -File -Include *.cpp,*.h,*.vcxproj,*.wxs,*.wxi
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
$localOnlyPatch = Get-Content -LiteralPath (Join-Path $overlayRoot 'local-only-windows.diff') -Raw
foreach ($required in @('#include <windows.h>', '_byteswap_ushort', '_byteswap_ulong')) {
    if ($localOnlyPatch -notmatch [regex]::Escape($required)) { throw "libfido2 Windows compatibility patch missing: $required" }
}

$opensslOverlayRoot = Join-Path $root 'vcpkg-overlays\openssl'
$opensslOverlayManifest = Get-Content -LiteralPath (Join-Path $opensslOverlayRoot 'vcpkg.json') -Raw | ConvertFrom-Json
if ($opensslOverlayManifest.version -ne '3.6.2') { throw 'The local-only OpenSSL overlay must be pinned to 3.6.2' }
$opensslOverlayPort = Get-Content -LiteralPath (Join-Path $opensslOverlayRoot 'portfile.cmake') -Raw
foreach ($required in @('VCPKG_ROOT_DIR', 'no-sock', 'Pinned upstream OpenSSL port layout changed')) {
    if ($opensslOverlayPort -notmatch [regex]::Escape($required)) { throw "OpenSSL local-only overlay contract missing: $required" }
}

$broker = Get-Content -LiteralPath (Join-Path $root 'BrokerService\BrokerService.cpp') -Raw
foreach ($required in @('kSessionLifetime', 'kMaximumSessions', 'kMaximumSessionsPerCaller', 'kPipeIoTimeoutMs', 'TakeSession', 'ImpersonateNamedPipeClient', 'FILE_FLAG_FIRST_PIPE_INSTANCE', 'FILE_FLAG_OVERLAPPED', 'PIPE_REJECT_REMOTE_CLIENTS', 'SecureZeroMemory', 'finish_registration', 'begin_remove', 'remove_with_password', 'finish_remove', 'policy state is inconsistent', 'policy changes are limited to the current user')) {
    if ($broker -notmatch $required) { throw "Broker security contract missing: $required" }
}
if ($runtimeText -match 'WinVerifyTrust|WTHelper|(?i)wintrust\.lib') {
    throw 'Runtime Credential Provider Filter inspection must not perform Authenticode validation.'
}
if ($broker -notmatch 'localfido::IsWindowsGenericFilter') { throw 'Broker must use shared built-in Filter recognition.' }

$filter = Get-Content -LiteralPath (Join-Path $root 'CredentialProviderFilter\CCredentialProviderFilter.cpp') -Raw
foreach ($required in @('allowed[index] = FALSE', 'never restore TRUE')) {
    if ($filter -notmatch [regex]::Escape($required)) { throw "Credential Provider Filter deny-only contract missing: $required" }
}
foreach ($required in @('_filterEnabled && !isOurProvider', '!_filterEnabled && isOurProvider')) {
    if ($filter -notmatch [regex]::Escape($required)) { throw "Credential Provider enablement filter contract missing: $required" }
}
if ($filter -match 'allowed\[index\]\s*=\s*IsEqualGUID') { throw 'Credential Provider Filter must not overwrite shared allow decisions' }

$client = Get-Content -LiteralPath (Join-Path $root 'CppClient\CppClient\BrokerClient.cpp') -Raw
foreach ($required in @('GetNamedPipeServerProcessId', 'WinLocalSystemSid')) {
    if ($client -notmatch $required) { throw "Broker client trust contract missing: $required" }
}
if ($client -notmatch '(?s)SetEnforcement.*?"password".*?ClearJsonSecret\(request, "password"\)') {
    throw 'MFA policy requests must carry and clear the Windows password.'
}
if ($broker -notmatch '(?s)operation == "set_enforcement".*?ExtractPassword\(request\).*?ValidateLocalPassword') {
    throw 'Broker MFA policy changes must validate the current Windows password.'
}
$accounts = Get-Content -LiteralPath (Join-Path $root 'CppClient\CppClient\LocalAccount.cpp') -Raw
foreach ($required in @('SpecialAccounts\\UserList', 'UF_ACCOUNTDISABLE', 'UF_NORMAL_ACCOUNT')) {
    if ($accounts -notmatch [regex]::Escape($required)) { throw "Local account visibility contract missing: $required" }
}
$store = Get-Content -LiteralPath (Join-Path $root 'CppClient\CppClient\LocalCredentialStore.cpp') -Raw
foreach ($required in @('O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FR;;;BA)', 'OWNER_SECURITY_INFORMATION', 'O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;BA)')) {
    if ($store -notmatch [regex]::Escape($required)) { throw "Credential-vault SYSTEM ownership contract missing: $required" }
}
$manager = Get-Content -LiteralPath (Join-Path $root 'Manager\main.cpp') -Raw
foreach ($required in @('BeginDeferWindowPos', 'SWP_NOCOPYBITS', 'RDW_ALLCHILDREN', 'RDW_UPDATENOW')) {
    if ($manager -notmatch [regex]::Escape($required)) { throw "Manager resize-paint contract missing: $required" }
}

$verifier = Get-Content -LiteralPath (Join-Path $root 'CppClient\CppClient\FidoVerifier.cpp') -Raw
foreach ($required in @('fido_assert_set_count(assertionHandle, 1)', 'fido_assert_set_authdata_raw')) {
    if ($verifier -notmatch [regex]::Escape($required)) { throw "libfido2 1.17 assertion API contract missing: $required" }
}
if ($verifier -match '\bfido_assert_set_id\s*\(') { throw 'Non-public libfido2 API fido_assert_set_id must not be used' }

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
foreach ($required in @('BuildProjectReferences=false', '-BuildDirectory $buildDirectory', 'verify-binaries.ps1', 'verify-msi.ps1', 'fido2_static.lib', 'libcrypto.lib', 'zs.lib', 'OPENSSL_NO_SOCK')) {
    if ($buildScript -notmatch [regex]::Escape($required)) { throw "Build verification contract missing: $required" }
}

$installer = Get-Content -LiteralPath (Join-Path $root 'WiXSetup\Product.wxs') -Raw
foreach ($required in @('Schedule="afterInstallExecute"', 'AllowSameVersionUpgrades="yes"', 'NeverOverwrite="yes"', 'ARPPRODUCTICON', 'ARPNOREPAIR', 'WindowsFidoLogonBroker', 'SafeBoot\Minimal', 'MFAFILTERENABLED', 'Secure="yes"', 'MFAFILTERENABLED &lt;&gt; &quot;#1&quot;', 'BlockMfaEnabledMaintenance', 'Before="InstallValidate"', 'PermissionEx Sddl=', 'FirstFailureActionType="restart"', 'ForceDeleteOnUninstall="yes"')) {
    if ($installer -notmatch [regex]::Escape($required)) { throw "Installer safety contract missing: $required" }
}

$providerGuid = 'A95D1C6B-8D9C-4E0F-A60D-CA6B569E28AD'
$filterGuid = '54B25B17-C7AE-4C2B-B3C4-E3B29A73D9B1'
if ($providerGuid -eq $filterGuid) { throw 'Provider and Filter GUIDs must differ' }

Write-Host 'Security contract checks passed.' -ForegroundColor Green
