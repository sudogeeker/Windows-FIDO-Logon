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
        'WINDOWSMAJORVERSION = "#10"',
        'MfaFilterEnabledSearch',
        'MFAFILTERENABLED = "#1"',
        'BlockMfaEnabledMaintenance',
        'Before="InstallValidate"',
        'Secure="yes"',
        'ARPNOREPAIR',
        'PermissionEx',
        'O:SYG:SYD:P(A;;FA;;;SY)(A;;FRFX;;;BA)(A;;FRFX;;;BU)',
        'O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FR;;;BA)',
        'ForceDeleteOnUninstall="yes"',
        'FirstFailureActionType="restart"'
    )) {
        if ($text -notmatch [regex]::Escape($required)) { throw "MSI contract is missing: $required" }
    }
    if ($text -match 'VersionNT64\s*&gt;=\s*1000') {
        throw 'MSI contains the invalid Windows 10 version check (VersionNT64 >= 1000).'
    }
    [xml]$document = $text
    $product = @($document.GetElementsByTagName('Product'))[0]
    $upgradeCode = '842EA4D9-6E63-4D18-9217-A4DBD1ED8728'
    if ([guid]$product.UpgradeCode -ne [guid]$upgradeCode) { throw 'MSI product-family UpgradeCode changed.' }
    if ([guid]$product.Id -eq [guid]::Empty) { throw 'MSI has no valid ProductCode.' }
    # dark.exe emits MajorUpgrade but not the Upgrade table rows, so read the
    # compiled MSI database to audit the actual version and sequence contracts.
    $msiInstaller = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    try {
        $database = $msiInstaller.OpenDatabase($msi, 0)
        $upgradeView = $database.OpenView('SELECT `VersionMin`, `VersionMax`, `Attributes`, `ActionProperty` FROM `Upgrade`')
        $upgradeRows = @()
        try {
            $upgradeView.Execute()
            while ($record = $upgradeView.Fetch()) {
                $upgradeRows += [pscustomobject]@{
                    Minimum = $record.StringData(1)
                    Maximum = $record.StringData(2)
                    Attributes = [int]$record.StringData(3)
                    Property = $record.StringData(4)
                }
            }
        }
        finally { $upgradeView.Close() }
        $replacement = @($upgradeRows | Where-Object { $_.Property -eq 'WIX_UPGRADE_DETECTED' })
        if ($replacement.Count -ne 1 -or $replacement[0].Maximum -ne $product.Version -or
            ($replacement[0].Attributes -band 0x200) -eq 0 -or ($replacement[0].Attributes -band 0x2) -ne 0) {
            throw 'MSI must replace older products and equal-version rebuilds in the same family.'
        }
        foreach ($oldVersion in @('1.0.0', '1.0.1', $product.Version)) {
            if ([version]$oldVersion -gt [version]$replacement[0].Maximum -or
                ($replacement[0].Minimum -and [version]$oldVersion -lt [version]$replacement[0].Minimum)) {
                throw "MSI replacement range misses version $oldVersion."
            }
        }
        $downgrade = @($upgradeRows | Where-Object { $_.Property -eq 'WIX_DOWNGRADE_DETECTED' })
        if ($downgrade.Count -ne 1 -or $downgrade[0].Minimum -ne $product.Version -or
            ($downgrade[0].Attributes -band 0x100) -ne 0 -or ($downgrade[0].Attributes -band 0x2) -eq 0) {
            throw 'MSI newer-version detection is invalid.'
        }
        $sequenceView = $database.OpenView('SELECT `Sequence` FROM `InstallExecuteSequence` WHERE `Action` = ''RemoveExistingProducts''')
        try {
            $sequenceView.Execute()
            $removeExisting = @()
            while ($record = $sequenceView.Fetch()) { $removeExisting += [int]$record.StringData(1) }
        }
        finally { $sequenceView.Close() }
        if ($removeExisting.Count -ne 1 -or $removeExisting[0] -ne 6501) {
            throw 'MSI must remove the previous product immediately after InstallExecute.'
        }
    }
    finally {
        if ($database) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($msiInstaller)
    }

    $launchGate = @($document.GetElementsByTagName('Condition') | Where-Object { $_.InnerText -match 'MFAFILTERENABLED' })
    $executeGate = @($document.GetElementsByTagName('Custom') | Where-Object { $_.Action -eq 'BlockMfaEnabledMaintenance' })
    if ($launchGate.Count -ne 1 -or $executeGate.Count -ne 1) { throw 'MSI MFA guards are missing or ambiguous.' }
    # Evaluate the actual compiled conditions without running any installer action.
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $session = $null
    try {
        $session = $installer.OpenPackage($msi, 1)
        $cases = @(
            @{ Installed = ''; REMOVE = ''; UPGRADINGPRODUCTCODE = ''; WIX_UPGRADE_DETECTED = '' },
            @{ Installed = ''; REMOVE = ''; UPGRADINGPRODUCTCODE = ''; WIX_UPGRADE_DETECTED = '{00000000-0000-0000-0000-000000000001}' },
            @{ Installed = '1'; REMOVE = ''; UPGRADINGPRODUCTCODE = ''; WIX_UPGRADE_DETECTED = '' },
            @{ Installed = '1'; REMOVE = 'ALL'; UPGRADINGPRODUCTCODE = ''; WIX_UPGRADE_DETECTED = '' },
            @{ Installed = '1'; REMOVE = 'ALL'; UPGRADINGPRODUCTCODE = '{00000000-0000-0000-0000-000000000002}'; WIX_UPGRADE_DETECTED = '' }
        )
        foreach ($case in $cases) {
            foreach ($property in $case.Keys) { $session.Property($property) = $case[$property] }
            foreach ($uiLevel in @('2', '5')) {
                $session.Property('UILevel') = $uiLevel
                foreach ($mfa in @('', '#0', '#1')) {
                    $session.Property('MFAFILTERENABLED') = $mfa
                    $blocked = $mfa -eq '#1'
                    $allowedResult = [int]$session.EvaluateCondition($launchGate[0].InnerText.Trim())
                    $blockedResult = [int]$session.EvaluateCondition($executeGate[0].InnerText.Trim())
                    if ($allowedResult -ne [int](-not $blocked) -or $blockedResult -ne [int]$blocked) {
                        throw "MSI MFA guard failed: UILevel=$uiLevel, MFA=$mfa, scenario=$($case | ConvertTo-Json -Compress)"
                    }
                }
            }
        }
    }
    finally {
        if ($session) { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($session) }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    }
    if ($BuildDirectory) {
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
