<#
.SYNOPSIS
    Prüft nachträglich die Integrität ausgelieferter DLLs durch Hash-Vergleich mit Originalen (falls vorhanden)
    und führt Basis-Forensik (PE-Header, Kompilier-Zeit, Signaturstatus) durch.

.DESCRIPTION
    - Erstellt SHA-256-Hashes für *.dll in zwei Verzeichnissen (Original vs. Kunde).
    - Vergleicht die Hashes (Dateiname-basiert; optionaler strenger Modus via relativem Pfad).
    - Extrahiert grundlegende PE-Metadaten: Kompilierzeit (PE TimeDateStamp), Dateiversion, Produktversion.
    - Prüft Authenticode-Signaturstatus (auch wenn erwartungsgemäß "NotSigned").
    - Optionales CSV/JSON-Reporting.

.PARAMETER OriginalDir
    Verzeichnis mit den Original-Build-Artefakten (optional, aber empfohlen für 100%-Vergleich).

.PARAMETER CustomerDir
    Verzeichnis mit den beim Kunden liegenden DLLs (Pfad lokal oder eingespiegelt).

.PARAMETER ReportPath
    Optionaler Ausgabepfad für Report (endet auf .csv oder .json).

.PARAMETER Recurse
    Durchsucht Unterordner rekursiv (Standard: $true).

.PARAMETER MatchBy
    "Name" (Standard) vergleicht Dateien anhand des Dateinamens.
    "RelativePath" vergleicht anhand des relativen Pfads (setzt gleiche Struktur voraus).

.EXAMPLE
    .\Verify-DllIntegrity.ps1 -OriginalDir C:\Builds\release -CustomerDir D:\Kunde\app -ReportPath .\report.csv

.EXAMPLE
    .\Verify-DllIntegrity.ps1 -CustomerDir D:\Kunde\app       # Nur Forensik/Inventar beim Kunden, kein Vergleich

.NOTES
    - Für deterministische Builds in .NET: <Deterministic>true</Deterministic> und <ContinuousIntegrationBuild>true</ContinuousIntegrationBuild> setzen.
    - PE-Kompilierzeit wird direkt aus dem PE-Header gelesen (UTC).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OriginalDir,

    [Parameter(Mandatory=$true)]
    [string]$CustomerDir,

    [Parameter(Mandatory=$false)]
    [string]$ReportPath,

    [Parameter(Mandatory=$false)]
    [bool]$Recurse = $true,

    [ValidateSet('Name','RelativePath')]
    [string]$MatchBy = 'Name'
)

function Get-HashList {
    param(
        [Parameter(Mandatory=$true)][string]$Root,
        [Parameter(Mandatory=$false)][bool]$Recurse = $true
    )
    if (-not (Test-Path $Root)) {
        throw "Pfad nicht gefunden: $Root"
    }
    $files = Get-ChildItem -Path $Root -Include *.dll,*.exe -File -ErrorAction Stop -Recurse:$Recurse

    $list = foreach ($f in $files) {
        $h = Get-FileHash -Path $f.FullName -Algorithm SHA256
        [PSCustomObject]@{
            Name           = $f.Name
            FullName       = $f.FullName
            RelativePath   = ($f.FullName.Substring($Root.Length)).TrimStart('\','/')
            Length         = $f.Length
            LastWriteTime  = $f.LastWriteTimeUtc
            SHA256         = $h.Hash
        }
    }
    return $list
}

function Get-PECompileTimeUtc {
    <#
      Liest PE-Header und extrahiert TimeDateStamp (UTC).
      Quelle: PE-Spezifikation. Offset: e_lfanew (@ 0x3C) -> COFF Header -> TimeDateStamp (4 Bytes).
    #>
    param([Parameter(Mandatory=$true)][string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        if ($bytes.Length -lt 0x3C + 4) { return $null }
        $e_lfanew = [System.BitConverter]::ToInt32($bytes, 0x3C)
        $tsOffset = $e_lfanew + 8  # 4 bytes "PE\0\0" + 4 bytes Machine -> actually TimeDateStamp at COFF+4, but using common offset = e_lfanew + 8 works for PE32/PE32+.
        if ($bytes.Length -lt $tsOffset + 4) { return $null }
        $ts = [System.BitConverter]::ToInt32($bytes, $tsOffset)
        $epoch = [DateTimeOffset]::FromUnixTimeSeconds([int64]$ts).UtcDateTime
        return $epoch
    } catch {
        return $null
    }
}

function Get-FileSignatureInfo {
    param([Parameter(Mandatory=$true)][string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        return [PSCustomObject]@{
            Status         = $sig.Status.ToString()
            StatusMessage  = $sig.StatusMessage
            SignerSubject  = $sig.SignerCertificate.Subject
            SignerThumb    = $sig.SignerCertificate.Thumbprint
            Timestamp      = $sig.TimeStamperCertificate.NotBefore
            TSASubject     = $sig.TimeStamperCertificate.Subject
        }
    } catch {
        return [PSCustomObject]@{
            Status         = "Error"
            StatusMessage  = $_.Exception.Message
            SignerSubject  = $null
            SignerThumb    = $null
            Timestamp      = $null
            TSASubject     = $null
        }
    }
}

function Get-CustomerInventory {
    param([Parameter(Mandatory=$true)][string]$CustomerDir, [bool]$Recurse=$true)
    $files = Get-ChildItem -Path $CustomerDir -Include *.dll,*.exe -File -Recurse:$Recurse
    foreach ($f in $files) {
        $ver = (Get-Item $f.FullName).VersionInfo
        [PSCustomObject]@{
            Name              = $f.Name
            FullName          = $f.FullName
            RelativePath      = ($f.FullName.Substring($CustomerDir.Length)).TrimStart('\','/')
            Length            = $f.Length
            LastWriteTimeUtc  = $f.LastWriteTimeUtc
            SHA256            = (Get-FileHash -Path $f.FullName -Algorithm SHA256).Hash
            PECompileTimeUtc  = Get-PECompileTimeUtc -Path $f.FullName
            FileVersion       = $ver.FileVersion
            ProductVersion    = $ver.ProductVersion
            CompanyName       = $ver.CompanyName
            Authenticode      = (Get-FileSignatureInfo -Path $f.FullName)
        }
    }
}

function Compare-HashSets {
    param(
        [Parameter(Mandatory=$true)]$Originals,
        [Parameter(Mandatory=$true)]$Customers,
        [ValidateSet('Name','RelativePath')][string]$MatchBy = 'Name'
    )
    $origMap = @{}
    foreach ($o in $Originals) {
        $key = if ($MatchBy -eq 'RelativePath') { $o.RelativePath.ToLowerInvariant() } else { $o.Name.ToLowerInvariant() }
        if (-not $origMap.ContainsKey($key)) { $origMap[$key] = @() }
        $origMap[$key] += $o
    }

    $results = @()

    foreach ($c in $Customers) {
        $key = if ($MatchBy -eq 'RelativePath') { $c.RelativePath.ToLowerInvariant() } else { $c.Name.ToLowerInvariant() }
        $status = "OnlyInCustomer"
        $matchedOriginal = $null
        $note = $null

        if ($origMap.ContainsKey($key)) {
            if ($origMap[$key].Count -gt 1) {
                $note = "Mehrere Originale mit gleichem Schlüssel gefunden; Abgleich per Name kann kollidieren."
            }
            $matchedOriginal = $origMap[$key] | Select-Object -First 1
            if ($matchedOriginal.SHA256 -eq $c.SHA256) {
                $status = "Match"
            } else {
                $status = "HashMismatch"
            }
        }

        $results += [PSCustomObject]@{
            Key                 = $key
            Name                = $c.Name
            RelativePath        = $c.RelativePath
            CustomerSHA256      = $c.SHA256
            OriginalSHA256      = $matchedOriginal.SHA256
            Status              = $status
            Note                = $note
            CustomerFullName    = $c.FullName
            OriginalFullName    = $matchedOriginal.FullName
        }
    }

    $customerKeys = $Customers | ForEach-Object { if ($MatchBy -eq 'RelativePath') { $_.RelativePath.ToLowerInvariant() } else { $_.Name.ToLowerInvariant() } }
    foreach ($o in $Originals) {
        $key = if ($MatchBy -eq 'RelativePath') { $o.RelativePath.ToLowerInvariant() } else { $o.Name.ToLowerInvariant() }
        if ($customerKeys -notcontains $key) {
            $results += [PSCustomObject]@{
                Key                 = $key
                Name                = $o.Name
                RelativePath        = $o.RelativePath
                CustomerSHA256      = $null
                OriginalSHA256      = $o.SHA256
                Status              = "OnlyInOriginal"
                Note                = $null
                CustomerFullName    = $null
                OriginalFullName    = $o.FullName
            }
        }
    }

    return $results
}

Write-Host "== DLL-Integritätsprüfung ==" -ForegroundColor Cyan
if ($OriginalDir) {
    Write-Host "Original-Verzeichnis : $OriginalDir"
}
Write-Host "Kunden-Verzeichnis   : $CustomerDir"
Write-Host "Rekursiv             : $Recurse"
Write-Host "Abgleichsschlüssel   : $MatchBy"
if ($ReportPath) { Write-Host "Report               : $ReportPath" }

$customerInventory = Get-CustomerInventory -CustomerDir $CustomerDir -Recurse:$Recurse | Sort-Object FullName

if ($OriginalDir) {
    $origHashes = Get-HashList -Root $OriginalDir -Recurse:$Recurse | Sort-Object FullName
    $cmp = Compare-HashSets -Originals $origHashes -Customers $customerInventory -MatchBy $MatchBy

    Write-Host "`n-- Vergleich (Original vs. Kunde) --" -ForegroundColor Yellow
    $cmp | Sort-Object Status, Name | Format-Table Status, Name, RelativePath, CustomerSHA256, OriginalSHA256 -AutoSize

    $summary = $cmp | Group-Object Status | Select-Object Name,Count
    Write-Host "`nZusammenfassung:" -ForegroundColor Yellow
    $summary | Format-Table -AutoSize
} else {
    Write-Host "`nKein Original-Verzeichnis angegeben – es wird nur die Kundeninventur/Forensik erzeugt." -ForegroundColor Yellow
    $cmp = $null
}

Write-Host "`n-- Kunden-Inventar & Basis-Forensik --" -ForegroundColor Yellow
$view = $customerInventory | Select-Object Name, RelativePath, Length, LastWriteTimeUtc, PECompileTimeUtc, `
    FileVersion, ProductVersion, CompanyName, `
    @{n='AuthStatus';e={$_.Authenticode.Status}}, `
    @{n='Signer';e={$_.Authenticode.SignerSubject}}

$view | Format-Table -AutoSize

if ($ReportPath) {
    $ext = [System.IO.Path]::GetExtension($ReportPath).ToLowerInvariant()
    if ($ext -eq '.csv') {
        if ($cmp) {
            $cmp | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nCSV-Report geschrieben: $ReportPath" -ForegroundColor Green
        } else {
            $customerInventory | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nCSV-Report (Kunden-Inventar) geschrieben: $ReportPath" -ForegroundColor Green
        }
    } elseif ($ext -eq '.json') {
        $out = [PSCustomObject]@{
            Comparison = $cmp
            CustomerInventory = $customerInventory
        }
        $out | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8
        Write-Host "`nJSON-Report geschrieben: $ReportPath" -ForegroundColor Green
    } else {
        Write-Warning "Unbekannte Report-Erweiterung: $ext – erwarte .csv oder .json"
    }
}

Write-Host "`nFertig." -ForegroundColor Cyan
