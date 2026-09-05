param(
    [Parameter(Mandatory = $true)][string]$BuildDirectory,
    [Parameter(Mandatory = $true)][string]$DumpbinPath
)

$ErrorActionPreference = 'Stop'
$targets = @(
    'WindowsFidoLogonCredentialProvider.dll',
    'WindowsFidoLogonFilter.dll',
    'WindowsFidoLogonBroker.exe',
    'WindowsFidoLogonManager.exe'
)
$forbiddenImports = @(
    'winhttp.dll', 'wininet.dll', 'httpapi.dll', 'urlmon.dll', 'ws2_32.dll', 'wintrust.dll',
    'wldap32.dll', 'winscard.dll', 'fido2.dll', 'cbor.dll', 'crypto-*.dll',
    'libcrypto-*.dll', 'zlib*.dll', 'vcruntime*.dll', 'msvcp*.dll'
)

foreach ($name in $targets) {
    $path = Join-Path $BuildDirectory $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing runtime binary: $path" }

    $imports = (& $DumpbinPath /nologo /imports $path 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "dumpbin /imports failed for $name" }
    foreach ($pattern in $forbiddenImports) {
        if ($imports -match ('(?im)^\s*' + [regex]::Escape($pattern).Replace('\*', '.*') + '\s*$')) {
            throw "Forbidden dynamic import in ${name}: $pattern"
        }
    }

    $headers = (& $DumpbinPath /nologo /headers $path 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "dumpbin /headers failed for $name" }
    foreach ($required in @('Dynamic base', 'NX compatible', 'Control Flow Guard')) {
        if ($headers -notmatch [regex]::Escape($required)) { throw "$name is missing PE hardening flag: $required" }
    }

}

Write-Host 'Runtime binary import and hardening checks passed.' -ForegroundColor Green
