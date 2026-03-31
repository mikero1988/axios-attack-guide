<#
.SYNOPSIS
    Scans for indicators of the axios npm supply chain compromise (March 2026).

.DESCRIPTION
    Checks for compromised axios versions, the phantom plain-crypto-js dependency,
    RAT file artifacts, and active C2 network connections. Generates a report file.

.PARAMETER ScanRoot
    Root directory to scan. Defaults to the current user's home directory.

.EXAMPLE
    .\Scan-Axios.ps1
    .\Scan-Axios.ps1 -ScanRoot "D:\projects"
#>

param(
    [string]$ScanRoot = $env:USERPROFILE
)

$ErrorActionPreference = "SilentlyContinue"

# known indicators
$BadVersions  = @("1.14.1", "0.30.4")
$PhantomDep   = "plain-crypto-js"
$C2IP         = "142.11.206.73"
$C2Domain     = "sfrclak.com"

$Issues  = 0
$Scanned = 0
$ReportFile = "axios-scan-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$ReportLines = [System.Collections.Generic.List[string]]::new()

function Write-Ok   { param($Msg) Write-Host "[+] $Msg" -ForegroundColor Green }
function Write-Warn { param($Msg) Write-Host "[!] $Msg" -ForegroundColor Red }
function Write-Info { param($Msg) Write-Host "[-] $Msg" -ForegroundColor Cyan }

function Add-Report { param($Line) $ReportLines.Add($Line) }

# ═══════════════════════════════════════════════════════
Write-Host ""
Write-Host ([char]0x2554 + ("=" * 50) + [char]0x2557) -ForegroundColor White
Write-Host ([char]0x2551 + "       axios supply chain compromise scanner      " + [char]0x2551) -ForegroundColor White
Write-Host ([char]0x255A + ("=" * 50) + [char]0x255D) -ForegroundColor White
Write-Host ""

$timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")
Write-Info "scan root: $ScanRoot"
Write-Info "report: $ReportFile"
Write-Info "date: $timestamp"
Write-Host ""

Add-Report "axios compromise scan - $timestamp"
Add-Report "scan root: $ScanRoot"
Add-Report "---"

# ── phase 1: find axios installations ──
Write-Host "-- phase 1: scanning for axios installations --" -ForegroundColor White
Write-Host ""

$axiosFound = $false

# walk the filesystem looking for node_modules/axios/package.json
$axiosPackages = Get-ChildItem -Path $ScanRoot -Recurse -Depth 8 -Filter "package.json" -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Directory.Name -eq "axios" -and $_.Directory.Parent.Name -eq "node_modules" }

foreach ($pkg in $axiosPackages) {
    try {
        $json = Get-Content $pkg.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($json.name -ne "axios" -or -not $json.version) { continue }

        $Scanned++
        $axiosFound = $true
        $ver = $json.version

        if ($BadVersions -contains $ver) {
            Write-Warn "COMPROMISED  axios@$ver  <- $($pkg.Directory.FullName)"
            Add-Report "COMPROMISED: axios@$ver at $($pkg.Directory.FullName)"
            $Issues++
        } else {
            Write-Ok "ok  axios@$ver  <- $($pkg.Directory.FullName)"
        }
    } catch { }
}

# global npm check
try {
    $npmOut = & npm ls -g axios --depth=0 2>$null | Out-String
    if ($npmOut -match 'axios@(\d+\.\d+\.\d+)') {
        $gver = $Matches[1]
        $Scanned++
        $axiosFound = $true
        if ($BadVersions -contains $gver) {
            Write-Warn "COMPROMISED  axios@$gver  (global npm)"
            Add-Report "COMPROMISED: axios@$gver (global)"
            $Issues++
        } else {
            Write-Ok "ok  axios@$gver  (global npm)"
        }
    }
} catch { }

if (-not $axiosFound) {
    Write-Info "no axios installations found under $ScanRoot"
}
Write-Host ""

# ── phase 2: lockfile check ──
Write-Host "-- phase 2: checking lockfiles for $PhantomDep --" -ForegroundColor White
Write-Host ""

$lockHit = $false

$lockfiles = Get-ChildItem -Path $ScanRoot -Recurse -Depth 6 -Include "package-lock.json","yarn.lock","pnpm-lock.yaml" -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notlike "*node_modules*" }

foreach ($lf in $lockfiles) {
    $match = Select-String -Path $lf.FullName -Pattern $PhantomDep -ErrorAction SilentlyContinue
    if ($match) {
        Write-Warn "phantom dep found in $($lf.FullName)"
        Add-Report "PHANTOM DEP: $PhantomDep in $($lf.FullName)"
        $Issues++
        $lockHit = $true
    }
}

if (-not $lockHit) {
    Write-Ok "no lockfiles reference $PhantomDep"
}
Write-Host ""

# ── phase 3: git history forensics ──
Write-Host "-- phase 3: searching git history for past exposure --" -ForegroundColor White
Write-Host ""

$gitHit = $false

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd) {
    $gitDirs = Get-ChildItem -Path $ScanRoot -Recurse -Depth 6 -Directory -Filter ".git" -Force -ErrorAction SilentlyContinue

    foreach ($gd in $gitDirs) {
        $repoRoot = $gd.Parent.FullName
        try {
            $logOutput = & git -C $repoRoot log --all -p -- package-lock.json yarn.lock pnpm-lock.yaml 2>$null | Out-String
            if ($logOutput -match "plain-crypto-js|`"axios`": `"1\.14\.1`"|`"axios`": `"0\.30\.4`"|axios@1\.14\.1|axios@0\.30\.4") {
                Write-Warn "exposure found in repo: $repoRoot"
                Add-Report "GIT HISTORY: compromise traces in $repoRoot"
                $Issues++
                $gitHit = $true
            }
        } catch { }
    }
} else {
    Write-Info "git not available, skipping history scan"
}

if (-not $gitHit) {
    Write-Ok "no compromise traces in git history"
}
Write-Host ""

# ── phase 4: RAT artifacts ──
Write-Host "-- phase 4: checking for RAT file artifacts --" -ForegroundColor White
Write-Host ""

$ratHit = $false

$RatPaths = @(
    @{ Path = "$env:PROGRAMDATA\wt.exe";   Desc = "RAT payload (copied powershell.exe)" },
    @{ Path = "$env:TEMP\6202033.vbs";     Desc = "VBScript launcher" },
    @{ Path = "$env:TEMP\6202033.ps1";     Desc = "PowerShell launcher" }
)

foreach ($entry in $RatPaths) {
    if (Test-Path $entry.Path) {
        Write-Warn "RAT artifact: $($entry.Path) — $($entry.Desc)"
        $fi = Get-Item $entry.Path
        Add-Report "RAT ARTIFACT: $($entry.Path) (size=$($fi.Length), modified=$($fi.LastWriteTimeUtc))"
        $Issues++
        $ratHit = $true
    } else {
        Write-Ok "clean: $($entry.Path)"
    }
}

# also look for the phantom package directory itself
$phantomDirs = Get-ChildItem -Path $ScanRoot -Recurse -Depth 8 -Directory -Filter $PhantomDep -ErrorAction SilentlyContinue |
    Where-Object { $_.Parent.Name -eq "node_modules" }

foreach ($pd in $phantomDirs) {
    Write-Warn "phantom package on disk: $($pd.FullName)"
    Add-Report "PHANTOM PACKAGE DIR: $($pd.FullName)"
    $Issues++
    $ratHit = $true
}

if (-not $ratHit) {
    Write-Ok "no RAT artifacts or phantom package directories found"
}
Write-Host ""

# ── phase 5: network check ──
Write-Host "-- phase 5: checking for C2 network activity --" -ForegroundColor White
Write-Host ""

$netHit = $false

try {
    $conns = Get-NetTCPConnection -RemoteAddress $C2IP -ErrorAction SilentlyContinue
    if ($conns) {
        foreach ($c in $conns) {
            Write-Warn "active C2 connection! PID=$($c.OwningProcess) State=$($c.State) Port=$($c.RemotePort)"
            Add-Report "C2 CONNECTION: PID=$($c.OwningProcess) State=$($c.State) $($C2IP):$($c.RemotePort)"
            $Issues++
            $netHit = $true
        }
    }
} catch {
    # fall back to netstat parsing
    try {
        $ns = netstat -an | Select-String $C2IP
        if ($ns) {
            foreach ($line in $ns) {
                Write-Warn "active C2 connection: $line"
                Add-Report "C2 CONNECTION: $line"
                $Issues++
                $netHit = $true
            }
        }
    } catch { }
}

# dns check
try {
    $dns = Resolve-DnsName $C2Domain -ErrorAction SilentlyContinue
    if ($dns) {
        Write-Info "note: $C2Domain still resolves — consider blocking at DNS level"
    }
} catch { }

if (-not $netHit) {
    Write-Ok "no active C2 connections"
}
Write-Host ""

# ── phase 6: system log scan ──
Write-Host "-- phase 6: searching system logs for C2 domain queries --" -ForegroundColor White
Write-Host ""

$logHit = $false

# Windows DNS client cache
try {
    $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -like "*$C2Domain*" }
    if ($dnsCache) {
        Write-Warn "C2 domain found in DNS client cache!"
        foreach ($entry in $dnsCache) {
            Write-Info "  $($entry.Entry) → $($entry.Data)"
        }
        Add-Report "DNS LOG: $C2Domain found in DNS client cache"
        $Issues++
        $logHit = $true
    }
} catch { }

# Windows event logs — DNS and Sysmon if available
try {
    $dnsEvents = Get-WinEvent -LogName "Microsoft-Windows-DNS-Client/Operational" -MaxEvents 5000 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like "*$C2Domain*" }
    if ($dnsEvents) {
        Write-Warn "C2 domain found in DNS client event log! ($($dnsEvents.Count) entries)"
        Add-Report "DNS LOG: $C2Domain found in DNS Client event log ($($dnsEvents.Count) entries)"
        $Issues++
        $logHit = $true
    }
} catch { }

try {
    $sysmonEvents = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10000 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -like "*$C2Domain*" -or $_.Message -like "*$C2IP*" }
    if ($sysmonEvents) {
        Write-Warn "C2 indicators found in Sysmon log! ($($sysmonEvents.Count) entries)"
        Add-Report "DNS LOG: C2 indicators in Sysmon log ($($sysmonEvents.Count) entries)"
        $Issues++
        $logHit = $true
    }
} catch { }

if (-not $logHit) {
    Write-Ok "no C2 domain queries found in system logs"
}
Write-Host ""

# ── summary ──
Write-Host ("=" * 52) -ForegroundColor White

if ($Issues -gt 0) {
    Write-Warn "SCAN COMPLETE - $Issues issue(s) found across $Scanned axios installation(s)"
    Write-Host ""
    Write-Warn "you should:"
    Write-Host "  1. disconnect from the network immediately"
    Write-Host "  2. block sfrclak.com / 142.11.206.73 at your firewall"
    Write-Host "  3. rotate every credential accessible from this machine"
    Write-Host "  4. downgrade axios to 1.14.0 / 0.30.3"
    Write-Host "  5. delete node_modules\plain-crypto-js everywhere"
    Write-Host "  6. audit your CI/CD for builds that used the bad versions"
    Write-Host "  7. seriously consider a clean OS reinstall"
    Add-Report "---"
    Add-Report "RESULT: $Issues issue(s) found - action required"
} else {
    Write-Ok "SCAN COMPLETE - no indicators of compromise found"
    Add-Report "---"
    Add-Report "RESULT: clean"
}

# write report
$ReportLines | Out-File -FilePath $ReportFile -Encoding utf8
Write-Host ""
Write-Info "full report saved to $ReportFile"
Write-Host ""
