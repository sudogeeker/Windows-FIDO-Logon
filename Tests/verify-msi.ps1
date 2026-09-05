param(
    [Parameter(Mandatory = $true)][string]$MsiPath,
    [Parameter(Mandatory = $true)][string]$WixRoot,
    [string]$BuildDirectory = ''
)

$ErrorActionPreference = 'Stop'
$msi = (Resolve-Path -LiteralPath $MsiPath).Path
if ((Get-Item -LiteralPath $msi).Length -lt 1024) { throw 'MSI is unexpectedly small.' }
$dark = Join-Path $WixRoot 'dark.exe'
if (-not (Test-Path -LiteralPath $dark)) { throw "WiX dark.exe was not found at $dark" }
$auditRoot = Join-Path ([IO.Path]::GetTempPath()) ("WindowsFidoLogonMsiAudit-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $auditRoot | Out-Null
try {
    $decompiled = Join-Path $auditRoot 'package.wxs'
    $extracted = Join-Path $auditRoot 'files'
    & $dark -nologo -x $extracted -o $decompiled $msi
    if ($LASTEXITCODE -ne 0) { throw 'WiX could not decompile the generated MSI.' }
    $text = Get-Content -LiteralPath $decompiled -Raw
    foreach ($required in @(
        'Windows FIDO Logon',
        '842EA4D9-6E63-4D18-9217-A4DBD1ED8728',
        'WindowsFidoLogonBroker',
        'A95D1C6B-8D9C-4E0F-A60D-CA6B569E28AD',
        '54B25B17-C7AE-4C2B-B3C4-E3B29A73D9B1',
        'SafeBoot\Minimal',
        'CurrentMajorVersionNumber',
        'WINDOWSMAJORVERSION = "#10"'
    )) {
        if ($text -notmatch [regex]::Escape($required)) { throw "MSI contract is missing: $required" }
    }
    if ($text -match 'VersionNT64\s*&gt;=\s*1000') {
        throw 'MSI contains the invalid Windows 10 version check (VersionNT64 >= 1000).'
    }
    if ($BuildDirectory) {
        [xml]$document = $text
        $fileIds = [ordered]@{
            'WindowsFidoLogonCredentialProvider.dll' = 'CredentialProvider'
            'WindowsFidoLogonFilter.dll' = 'CredentialProviderFilter'
            'WindowsFidoLogonBroker.exe' = 'BrokerExe'
            'WindowsFidoLogonManager.exe' = 'ManagerExe'
        }
        foreach ($name in $fileIds.Keys) {
            $source = Join-Path $BuildDirectory $name
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "MSI comparison source is missing: $source" }
            $matches = @($document.GetElementsByTagName('File') | Where-Object { $_.Id -eq $fileIds[$name] })
            if ($matches.Count -ne 1) { throw "Expected exactly one MSI File row for $name, found $($matches.Count)" }
            $embedded = $matches[0].Source
            if (-not (Test-Path -LiteralPath $embedded -PathType Leaf)) { throw "Extracted MSI payload is missing: $embedded" }
            $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
            $embeddedHash = (Get-FileHash -LiteralPath $embedded -Algorithm SHA256).Hash
            if ($sourceHash -ne $embeddedHash) { throw "MSI embedded binary does not match the tested build: $name" }
        }
    }
}
finally {
    if ($auditRoot.StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $auditRoot)) {
        [IO.Directory]::Delete($auditRoot, $true)
    }
}

Write-Host 'MSI structure and embedded-binary checks passed.' -ForegroundColor Green
