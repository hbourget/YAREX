# YAREX - YARA scans made easy
#
# Usage: .\yarex.ps1 [--extract] [--help]

# Parse command-line arguments
$autoExtract = $false
$autoUpdate  = $false
$showHelp    = $false
$badArg      = $false
foreach ($a in $args) {
    switch ($a) {
        "--extract" { $autoExtract = $true }
        "--auto-update" { $autoUpdate = $true }
        "--help"    { $showHelp = $true }
        "-h"        { $showHelp = $true }
        default {
            Write-Host "Error: unknown argument: $a" -ForegroundColor Red
            $showHelp = $true
            $badArg = $true
        }
    }
}

if ($showHelp) {
    Write-Host @"
YAREX - YARA scans made easy

Usage: .\yarex.ps1 [OPTIONS]

Options:
  --extract      Extract flagged files at the end of the scan without prompting.
  --auto-update  Update the rules without asking (rule sets 1-4).
  -h, --help   Show this help and exit.

The script is interactive and will prompt for the scan name, rule set,
locations, file size limit and exclusions.
"@
    if ($badArg) { exit 2 }
    exit 0
}

# Always operate relative to the script's own directory, not the caller's cwd.
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
Set-Location -LiteralPath $scriptDir
# Set-Location only changes PowerShell's location. .NET (StreamWriter, File) and
# native exes (yara) resolve relative paths against the PROCESS directory, which
# is C:\WINDOWS\system32 in an elevated shell. Align them.
[Environment]::CurrentDirectory = $scriptDir
try {
    [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch { }

# Windows PowerShell 5.1 does not negotiate TLS 1.2 by default, which makes
# every request to GitHub fail on stock installations.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    # Newer PowerShell versions manage this themselves.
}

$runDir       = Join-Path $scriptDir "runtime\run"
$includedFile = "$runDir\included"
$excludedFile = "$runDir\excluded"
$diffFile     = "$runDir\diff"
$matchesFile  = "$runDir\matches"

function Display-AsciiArt {
@"
    .-"^`\                                        /`^"-.
  .'   ___\                                      /___   `.
 /    /.---.                                    .---.\    \
|    //     '-.  ___________________________ .-'     \\    |
|   ;|         \/--------------------------//         |;   |
\   ||       |\_)          YAREX          (_/|       ||   /
 \  | \  . \ ;  |   YARA scans made easy   || ; / .  / |  /
  '\_\ \\ \ \ \ |                          ||/ / / // /_/'
        \\ \ \ \|       Release 1.0        |/ / / //
         `'-\_\_\                          /_/_/-'`
                '--------------------------'
"@
}

function Log-Message {
    param([string]$message, [string]$color = "Gray")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $message" -ForegroundColor $color
}

# Read one answer. Aborts on EOF rather than falling back to defaults, so a
# non-interactive invocation can never silently start scanning everything.
function Prompt-Line {
    param([string]$text)
    try {
        $value = Read-Host $text
    } catch {
        Write-Host ""
        Log-Message "Input stream closed - YAREX needs an interactive terminal. Aborting." "Red"
        exit 1
    }
    if ($null -eq $value) {
        Write-Host ""
        Log-Message "Input stream closed - YAREX needs an interactive terminal. Aborting." "Red"
        exit 1
    }
    return $value
}

function Prepare-Directories {
    $dirs = @(".\runtime\rules", ".\runtime\inames", ".\runtime\bin", $runDir,
              ".\results\csv", ".\results\logs", ".\results\extracts")
    foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
            Write-Host "Created directory: $d"
        }
    }
}

# Locate the YARA binary: bundled first, then PATH.
function Resolve-YaraExe {
    $bundled = ".\runtime\bin\yara64.exe"
    if (Test-Path -LiteralPath $bundled -PathType Leaf) {
        return (Resolve-Path -LiteralPath $bundled).Path
    }
    $onPath = Get-Command "yara64.exe" -ErrorAction SilentlyContinue
    if (-not $onPath) { $onPath = Get-Command "yara.exe" -ErrorAction SilentlyContinue }
    if (-not $onPath) { $onPath = Get-Command "yara" -ErrorAction SilentlyContinue }
    if ($onPath) { return $onPath.Source }
    return $null
}

function Check-InternetConnectivity {
    try {
        Invoke-WebRequest -Uri "https://api.github.com" -UseBasicParsing -TimeoutSec 8 | Out-Null
        return $true
    } catch {
        Log-Message "No internet connection. Proceeding without updating rules." "Red"
        return $false
    }
}

# Update YARA rules from the yara-forge GitHub releases.
# Only the archive matching the selected rule set is downloaded.
function Update-YaraRules {
    param([string]$RuleSet)

    Log-Message "Updating YARA rules ($RuleSet) from GitHub..."

    $tempDir = Join-Path $env:TEMP ([System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        try {
            $releaseJson = Invoke-WebRequest -Uri "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest" -UseBasicParsing -TimeoutSec 30
            $releaseInfo = $releaseJson.Content | ConvertFrom-Json
        } catch {
            Log-Message "Failed to retrieve the latest release information. $_" "Red"
            return $false
        }

        $downloadUrls = $releaseInfo.assets |
            Where-Object { $_.browser_download_url -like "*.zip" } |
            Select-Object -ExpandProperty browser_download_url
        if (!$downloadUrls) {
            Log-Message "Failed to retrieve the latest release URLs." "Red"
            return $false
        }

        # Fetch only the requested set; fall back to everything if naming changed.
        $wanted = $downloadUrls | Where-Object { $_ -like "*-$RuleSet.zip" }
        if (!$wanted) {
            Log-Message "Could not identify the '$RuleSet' archive; downloading all rule archives." "Yellow"
            $wanted = $downloadUrls
        }

        foreach ($url in $wanted) {
            $filename    = Split-Path $url -Leaf
            $destination = Join-Path $tempDir $filename

            try {
                Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing
                Expand-Archive -LiteralPath $destination -DestinationPath $tempDir -Force -ErrorAction Stop
            } catch {
                Log-Message "Failed to download or extract $filename. Error: $_" "Yellow"
                continue
            }
        }

        $moved   = 0
        $yarFiles = Get-ChildItem -LiteralPath $tempDir -Recurse -Filter "*.yar" -ErrorAction SilentlyContinue
        foreach ($f in $yarFiles) {
            switch ($f.Name) {
                { $_ -in @("yara-rules-core.yar", "yara-rules-extended.yar", "yara-rules-full.yar") } {
                    Move-Item -LiteralPath $f.FullName -Destination ".\runtime\rules\$($f.Name)" -Force
                    $moved++
                }
                default {
                    Log-Message "Unknown or unexpected rule file: $($f.Name). Skipping."
                }
            }
        }

        if ($moved -eq 0) {
            Log-Message "No rule files were updated." "Red"
            return $false
        }

        Log-Message "YARA rules updated successfully ($moved file(s))." "Green"
        return $true
    } finally {
        # Always clean up the staging area, including on Ctrl-C.
        if (Test-Path -LiteralPath $tempDir) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# Optional extra rules: a curated subset of Yara-Rules/rules (GPL-2.0, upstream
# inactive since 2022). Only Windows-relevant malware / maldoc / exploit-kit /
# CVE / webshell folders are used. Packer, anti-debug, capability and crypto
# folders are left out on purpose: they flag a large share of clean Windows
# binaries. Every file is validated with the local yara binary, so rules that
# need other includes or newer syntax are skipped instead of breaking the scan.
function Update-CommunityRules {
    param([string]$YaraExe)

    $target = Join-Path $scriptDir "runtime\rules\yara-rules-community.yar"
    if (Test-Path -LiteralPath $target -PathType Leaf) {
        $age = (Get-Date) - (Get-Item -LiteralPath $target).LastWriteTime
        if ($age.TotalDays -lt 30) {
            Log-Message "Community rules are $([int]$age.TotalDays) day(s) old; keeping them (upstream rarely changes)."
            return $true
        }
    }

    Log-Message "Updating community rules (Yara-Rules) from GitHub..."
    $tempDir = Join-Path $env:TEMP ([System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null

    try {
        $zip = Join-Path $tempDir "rules.zip"
        try {
            Invoke-WebRequest -Uri "https://codeload.github.com/Yara-Rules/rules/zip/refs/heads/master" -OutFile $zip -UseBasicParsing -TimeoutSec 180
            Expand-Archive -LiteralPath $zip -DestinationPath $tempDir -Force -ErrorAction Stop
        } catch {
            Log-Message "Failed to download community rules. $_" "Red"
            return $false
        }

        $root = Get-ChildItem -LiteralPath $tempDir -Directory | Select-Object -First 1
        if (-not $root) { Log-Message "Community rules archive was empty." "Red"; return $false }

        $probe = Join-Path $tempDir "probe.txt"
        $outF  = Join-Path $tempDir "probe.out"
        $errF  = Join-Path $tempDir "probe.err"
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($probe, "probe", $utf8NoBom)

        $seen    = New-Object System.Collections.Generic.HashSet[string]
        $parts   = New-Object System.Collections.Generic.List[string]
        $kept    = 0
        $skipped = 0

        foreach ($d in @("malware", "maldocs", "exploit_kits", "cve_rules", "webshells")) {
            $dp = Join-Path $root.FullName $d
            if (-not (Test-Path -LiteralPath $dp)) { continue }
            $files = Get-ChildItem -LiteralPath $dp -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Extension -in @(".yar", ".yara") -and $_.Name -notlike "*index*" } |
                Sort-Object FullName
            foreach ($f in $files) {
                $text = [System.IO.File]::ReadAllText($f.FullName)
                if ($text -match '(?m)^\s*include\s+"') { $skipped++; continue }

                $names = @([regex]::Matches($text, '(?m)^\s*(?:(?:private|global)\s+)*rule\s+(\w+)') | ForEach-Object { $_.Groups[1].Value })
                if ($names.Count -eq 0) { $skipped++; continue }
                $dup = $false
                foreach ($n in $names) { if ($seen.Contains($n)) { $dup = $true; break } }
                if ($dup) { $skipped++; continue }

                foreach ($x in @($outF, $errF)) { if (Test-Path -LiteralPath $x) { Remove-Item -LiteralPath $x -Force } }
                try {
                    $pr = Start-Process -FilePath $YaraExe -ArgumentList ('-w "{0}" "{1}"' -f $f.FullName, $probe) `
                              -NoNewWindow -Wait -PassThru -RedirectStandardOutput $outF -RedirectStandardError $errF
                    $pr.WaitForExit()
                    $okFile = ($pr.ExitCode -eq 0)
                } catch { $okFile = $false }

                if ($okFile) {
                    foreach ($n in $names) { [void]$seen.Add($n) }
                    $parts.Add($text)
                    $kept++
                } else {
                    $skipped++
                }
            }
        }

        if ($kept -eq 0) {
            Log-Message "No usable community rule files were found." "Red"
            return $false
        }

        # Validate the merged file as a whole before replacing the old one.
        $merged = Join-Path $tempDir "yara-rules-community.yar"
        [System.IO.File]::WriteAllText($merged, ($parts -join "`r`n"), $utf8NoBom)
        foreach ($x in @($outF, $errF)) { if (Test-Path -LiteralPath $x) { Remove-Item -LiteralPath $x -Force } }
        $pr = Start-Process -FilePath $YaraExe -ArgumentList ('-w "{0}" "{1}"' -f $merged, $probe) `
                  -NoNewWindow -Wait -PassThru -RedirectStandardOutput $outF -RedirectStandardError $errF
        $pr.WaitForExit()
        if ($pr.ExitCode -ne 0) {
            Log-Message "Merged community rules failed to compile; keeping previous version if any." "Red"
            return $false
        }

        Move-Item -LiteralPath $merged -Destination $target -Force
        Log-Message "Community rules updated: $kept file(s) / $($seen.Count) rule(s) kept, $skipped skipped." "Green"
        return $true
    } finally {
        if (Test-Path -LiteralPath $tempDir) {
            Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Prompt-CaseName {
    $caseName = Prompt-Line "Enter scan name (no spaces; e.g., case123)"
    # Keep the name usable as a path component.
    $caseName = ($caseName -replace '[^A-Za-z0-9._-]', '_')
    if ([string]::IsNullOrWhiteSpace($caseName)) {
        $caseName = "default_case"
    }
    return $caseName
}

function Prompt-RecommendedDirectories {
    Write-Host "`nRecommended directories to scan:"
    $recommendedDirs = @(
        "C:\Windows\System32",
        "C:\Users",
        "C:\ProgramData",
        "C:\Program Files",
        "C:\Program Files (x86)"
    )
    $recommendedDirs | ForEach-Object { Write-Host "  - $_" }
    Write-Host ""

    $userChoice = Prompt-Line "Press Enter to use this list or type 'custom' to specify your own"
    $toScan = New-Object System.Collections.ArrayList

    if ([string]::IsNullOrWhiteSpace($userChoice)) {
        # Silently drop entries that do not exist on this system.
        foreach ($d in $recommendedDirs) {
            if (Test-Path -LiteralPath $d -PathType Container) { [void]$toScan.Add($d) }
        }
        Write-Host "Using recommended directories present on this system:"
        $toScan | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "Please enter the directories to scan, one per line."
        Write-Host "Press Enter on a blank line to finish."
        while ($true) {
            $dir = Prompt-Line "Directory"
            if ([string]::IsNullOrWhiteSpace($dir)) {
                break
            } elseif (Test-Path -LiteralPath $dir -PathType Container) {
                [void]$toScan.Add((Resolve-Path -LiteralPath $dir).Path)
                Write-Host "Added: $dir"
            } else {
                Write-Host "Invalid directory: $dir"
            }
        }
        if ($toScan.Count -eq 0) {
            if (Test-Path -LiteralPath "C:\Users" -PathType Container) {
                [void]$toScan.Add("C:\Users")
                Write-Host "No directories entered. Defaulting to C:\Users."
            }
        }
    }

    if ($toScan.Count -eq 0) {
        Log-Message "No valid directories to scan." "Red"
        exit 1
    }
    # Emitted exactly once: a bare `$toScan` here as well would return the
    # list twice and scan every location a second time.
    return $toScan
}

function Select-Exclusions {
    Write-Host ""
    Write-Host "Choose which exclusions to apply (default: all):"
    Write-Host "1. Archives"
    Write-Host "2. Audio"
    Write-Host "3. Databases"
    Write-Host "4. Images"
    Write-Host "5. Video"
    Write-Host "6. Virtual Machines"
    Write-Host "7. All (default)"
    Write-Host "8. None (no exclusions)"
    $exclusionChoices = Prompt-Line "Enter choices (comma-separated, e.g., 1,2,3)"

    if ([string]::IsNullOrWhiteSpace($exclusionChoices)) {
        $exclusionChoices = "7"
    }

    $all = @(".\runtime\inames\archives.inm", ".\runtime\inames\audio.inm",
             ".\runtime\inames\databases.inm", ".\runtime\inames\images.inm",
             ".\runtime\inames\video.inm", ".\runtime\inames\vm.inm")

    $choiceArray    = $exclusionChoices -split "," | ForEach-Object { $_.Trim() }
    $exclusionFiles = New-Object System.Collections.ArrayList

    foreach ($choice in $choiceArray) {
        switch ($choice) {
            "1" { [void]$exclusionFiles.Add(".\runtime\inames\archives.inm") }
            "2" { [void]$exclusionFiles.Add(".\runtime\inames\audio.inm") }
            "3" { [void]$exclusionFiles.Add(".\runtime\inames\databases.inm") }
            "4" { [void]$exclusionFiles.Add(".\runtime\inames\images.inm") }
            "5" { [void]$exclusionFiles.Add(".\runtime\inames\video.inm") }
            "6" { [void]$exclusionFiles.Add(".\runtime\inames\vm.inm") }
            "7" { $exclusionFiles.Clear(); $all | ForEach-Object { [void]$exclusionFiles.Add($_) } }
            "8" { $exclusionFiles.Clear() }
            default { Write-Host "Invalid choice: $choice. Skipping." }
        }
    }
    $unique = New-Object System.Collections.Generic.List[string]
    foreach ($e in $exclusionFiles) {
        if (-not $unique.Contains($e)) { [void]$unique.Add($e) }
    }
    return ,$unique.ToArray()
}

function Select-MaxFileSize {
    $defaultMaxSize = 750000000L
    Write-Host ""
    Write-Host "Enter the maximum file size to scan (in bytes)."
    Write-Host "Default: $defaultMaxSize (750 MB)."
    while ($true) {
        $answer = Prompt-Line "Value"
        if ([string]::IsNullOrWhiteSpace($answer)) {
            return $defaultMaxSize
        }
        # Accept 750,000,000 and 750 000 000 as well.
        $answer = $answer -replace '[ ,_]', ''
        [long]$parsed = 0
        # [long], not [int]: a 3 GB limit overflows Int32 and crashes the script.
        if ([long]::TryParse($answer, [ref]$parsed) -and $parsed -gt 0) {
            return $parsed
        }
        Write-Host "Please enter a positive whole number of bytes."
    }
}

function Select-YaraRuleSet {
    Write-Host ""
    Write-Host "Choose YARA rule set:"
    Write-Host "1. Core"
    Write-Host "2. Extended (default)"
    Write-Host "3. Full"
    Write-Host "4. Full + community extras (curated Yara-Rules subset: slower, more false positives)"
    $ruleChoice = Prompt-Line "Enter choice (1/2/3/4)"

    switch ($ruleChoice) {
        "1" { return "core" }
        "3" { return "full" }
        "4" { return "fullplus" }
        default { return "extended" }
    }
}

# Write a list of lines as BOM-less UTF-8, one per line.
# Out-File is not used: on Windows PowerShell 5.1 it defaults to UTF-16 and
# truncates long lines, both of which corrupt the list yara reads.
function Write-Lines {
    param([string]$Path, [System.Collections.Generic.IEnumerable[string]]$Lines, [System.Text.Encoding]$Encoding)
    $full = if ([System.IO.Path]::IsPathRooted($Path)) { $Path } else { Join-Path (Get-Location).Path $Path }
    if (-not $Encoding) { $Encoding = New-Object System.Text.UTF8Encoding($false) }
    [System.IO.File]::WriteAllLines($full, $Lines, $Encoding)
}

# yara64.exe on Windows does not read --scan-list files in a fixed encoding
# (the bundled 4.5.2 build expects UTF-16; a UTF-8 list is parsed as ONE giant
# bogus path -> "could not open file" and an instant, empty "clean" scan).
# Probe which encoding this binary actually understands, using a throwaway
# rule and target file, before the real scan.
function Get-ScanListEncoding {
    param([string]$YaraExe)
    $dir = Join-Path $runDir "selftest"
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    $target = Join-Path $dir "target.txt"
    $rule   = Join-Path $dir "selftest.yar"
    $list   = Join-Path $dir "list.txt"
    $out    = Join-Path $dir "out.txt"
    $err    = Join-Path $dir "err.txt"
    [System.IO.File]::WriteAllText($target, "YAREXSELFTEST", $utf8NoBom)
    [System.IO.File]::WriteAllText($rule, 'rule yarex_selftest { strings: $a = "YAREXSELFTEST" condition: $a }', $utf8NoBom)

    $candidates = @(
        (New-Object System.Text.UnicodeEncoding($false, $true)),   # UTF-16LE + BOM
        (New-Object System.Text.UnicodeEncoding($false, $false)),  # UTF-16LE, no BOM
        $utf8NoBom,
        [System.Text.Encoding]::Default                             # ANSI
    )
    $found = $null
    foreach ($enc in $candidates) {
        [System.IO.File]::WriteAllLines($list, [string[]]@($target), $enc)
        foreach ($f in @($out, $err)) { if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force } }
        try {
            $argStr = '"{0}" -N --scan-list "{1}"' -f $rule, $list
            $pr = Start-Process -FilePath $YaraExe -ArgumentList $argStr -NoNewWindow -Wait -PassThru `
                      -RedirectStandardOutput $out -RedirectStandardError $err
            $pr.WaitForExit()
        } catch { continue }
        if ((Test-Path -LiteralPath $out) -and ([System.IO.File]::ReadAllText($out) -match 'yarex_selftest')) {
            $found = $enc
            break
        }
    }
    Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
    return $found
}

# Quote a CSV field per RFC 4180 and neutralize spreadsheet formula injection.
function Format-CsvField {
    param([string]$Value)
    if ($null -eq $Value) { $Value = "" }
    if ($Value -match '^[=+@\-]' -or $Value -match "^[`t`r]") {
        $Value = "'" + $Value
    }
    return '"' + ($Value -replace '"', '""') + '"'
}

$script:ScanOk = $true

function Scan-AllDirectories {
    param(
        [string[]]$ScanLocations,
        [string[]]$ExclusionFiles,
        [long]$MaxSize,
        [string]$RuleFile,
        [string]$ExtraRuleFile,
        [string]$YaraExe,
        [string]$ErrorFile,
        [string]$CsvOutput
    )

    if (-not (Test-Path -LiteralPath $runDir)) {
        New-Item -ItemType Directory -Path $runDir -Force | Out-Null
    }
    foreach ($f in @($includedFile, $excludedFile, $diffFile, $matchesFile)) {
        if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
    }

    $listEncoding = Get-ScanListEncoding -YaraExe $YaraExe
    if (-not $listEncoding) {
        Log-Message "YARA self-test failed: this yara binary could not scan a one-file list. Aborting." "Red"
        Log-Message "Replace runtime\bin\yara64.exe with an official build (VirusTotal/yara releases) and retry." "Red"
        $script:ScanOk = $false
        return
    }

    $scriptDirPrefix = (Get-Location).Path.TrimEnd('\') + '\'

    # Included set: deduplicated so overlapping scan roots cannot list a file
    # twice, and size-limited here because yara's --skip-larger is ignored
    # when it reads a --scan-list.
    $includedSet = New-Object System.Collections.Generic.HashSet[string]
    $ruleNames   = @("yara-rules-core.yar", "yara-rules-extended.yar", "yara-rules-full.yar",
                     "yara-rules-core.compiled", "yara-rules-extended.compiled", "yara-rules-full.compiled")

    foreach ($scanPath in $ScanLocations) {
        Log-Message "Gathering file list from $scanPath ..."
        $gciErrors = @()
        # -Force is required: without it hidden and system files are silently
        # skipped, which is exactly where malware tends to sit.
        Get-ChildItem -LiteralPath $scanPath -Recurse -File -Force -ErrorAction SilentlyContinue -ErrorVariable +gciErrors |
            ForEach-Object {
                if ($_.Length -lt $MaxSize -and
                    $ruleNames -notcontains $_.Name -and
                    -not $_.FullName.StartsWith($scriptDirPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    [void]$includedSet.Add($_.FullName)
                }
            }
        if ($gciErrors.Count -gt 0) {
            Add-Content -LiteralPath $ErrorFile -Value ($gciErrors | ForEach-Object { "enumeration: $_" })
        }
    }

    Log-Message "Applying exclusions ..."

    # Exclusions as a HashSet. The previous array-based `-notcontains` was
    # O(included x excluded) and dominated the runtime on real scans.
    $patterns = New-Object System.Collections.Generic.List[string]
    foreach ($sourceFile in $ExclusionFiles) {
        if (Test-Path -LiteralPath $sourceFile) {
            foreach ($p in (Get-Content -LiteralPath $sourceFile -ErrorAction SilentlyContinue)) {
                # .inm files hold find(1) syntax: -iname "*.zip" -o \
                foreach ($m in [regex]::Matches($p, '-iname\s+"([^"]+)"')) {
                    $patterns.Add($m.Groups[1].Value)
                }
            }
        } else {
            Log-Message "Exclusion file not found, ignoring: $sourceFile" "Yellow"
        }
    }

    $excludedSet = New-Object System.Collections.Generic.HashSet[string]
    if ($patterns.Count -gt 0) {
        foreach ($f in $includedSet) {
            # Match the base name, which is what find -iname does.
            $name = [System.IO.Path]::GetFileName($f)
            foreach ($pat in $patterns) {
                if ($name -like $pat) { [void]$excludedSet.Add($f); break }
            }
        }
    }

    $finalList = New-Object System.Collections.Generic.List[string]
    foreach ($f in $includedSet) {
        if (-not $excludedSet.Contains($f)) { $finalList.Add($f) }
    }

    Write-Lines -Path $includedFile -Lines ([string[]]$includedSet)
    Write-Lines -Path $excludedFile -Lines ([string[]]$excludedSet)
    Write-Lines -Path $diffFile     -Lines $finalList -Encoding $listEncoding

    Log-Message "Finished building included and excluded lists."

    Write-Host "`n############################################`n"
    Write-Host "Files found within the size limit: $($includedSet.Count)"
    Write-Host "Excluded by file type: $($excludedSet.Count)"
    Write-Host ""
    Write-Host "Files to be scanned : $($finalList.Count)"
    Write-Host "`n############################################`n"

    if ($finalList.Count -eq 0) {
        Log-Message "Nothing to scan. Review your locations, size limit and exclusions." "Yellow"
        $script:ScanOk = $false
        return
    }

    Log-Message "Running YARA scan..."

    $yaraArgs = New-Object System.Collections.Generic.List[string]
    # YARA defaults to 8 worker threads; raise it on larger machines.
    $cores = [Environment]::ProcessorCount
    if ($cores -gt 8) { $yaraArgs.Add("-p"); $yaraArgs.Add("$cores") }
    if ($RuleFile -like "*.compiled") { $yaraArgs.Add("-C") } else { $yaraArgs.Add("-w") }
    if ($ExtraRuleFile) {
        # Separate namespaces so identically named rules in the two sets cannot
        # clash. Relative paths avoid any ambiguity with drive-letter colons;
        # the working directory is the script directory.
        $yaraArgs.Add("forge:.\runtime\rules\" + (Split-Path -Leaf $RuleFile))
        $yaraArgs.Add("community:.\runtime\rules\" + (Split-Path -Leaf $ExtraRuleFile))
    } else {
        $yaraArgs.Add($RuleFile)
    }
    $yaraArgs.Add("-N")
    $yaraArgs.Add("--scan-list")
    $yaraArgs.Add((Resolve-Path -LiteralPath $diffFile).Path)
    # Pass a plain array: native-command argument unrolling is only reliable
    # for arrays across Windows PowerShell 5.1 and PowerShell 7.
    $yaraArgv = $yaraArgs.ToArray()

    $seen       = New-Object System.Collections.Generic.HashSet[string]
    $utf8NoBom  = New-Object System.Text.UTF8Encoding($false)
    $csvWriter  = New-Object System.IO.StreamWriter($CsvOutput, $false, $utf8NoBom)
    $matchWriter = New-Object System.IO.StreamWriter($matchesFile, $false, $utf8NoBom)
    $csvWriter.AutoFlush   = $true
    $matchWriter.AutoFlush = $true
    $csvWriter.WriteLine("Rule,File,SHA256")
    $matchCount = 0

    $yaraOut = Join-Path $runDir "yara_stdout"
    $yaraErr = Join-Path $runDir "yara_stderr"
    foreach ($f in @($yaraOut, $yaraErr)) {
        if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
    }
    # Start-Process joins arguments verbatim, so quote anything with spaces.
    $quotedArgs = ($yaraArgv | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '
    $yaraExit = -1

    try {
        try {
            $proc = Start-Process -FilePath $YaraExe -ArgumentList $quotedArgs -NoNewWindow -Wait -PassThru `
                        -RedirectStandardOutput $yaraOut -RedirectStandardError $yaraErr
            $proc.WaitForExit()
            $yaraExit = [int]$proc.ExitCode
        } catch {
            Log-Message "Failed to launch YARA: $_" "Red"
            Add-Content -LiteralPath $ErrorFile -Value "launch: $_"
        }

        if (Test-Path -LiteralPath $yaraErr) {
            $errText = [System.IO.File]::ReadAllText($yaraErr)
            if ($errText.Length -gt 0) { [System.IO.File]::AppendAllText($ErrorFile, $errText) }
        }

        if (Test-Path -LiteralPath $yaraOut) {
            foreach ($line in [System.IO.File]::ReadLines($yaraOut, [System.Text.Encoding]::UTF8)) {
                if ($line -notmatch "^(\S+)\s+(.*)$") { continue }

                $ruleName = $Matches[1]
                $filePath = $Matches[2]

                if (Test-Path -LiteralPath $filePath -PathType Leaf) {
                    try {
                        $fileHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $filePath -ErrorAction Stop).Hash
                    } catch {
                        $fileHash = "HASH_ERROR"
                    }
                } else {
                    $fileHash = "FILE_NOT_FOUND"
                }

                $key = "$ruleName`0$filePath"
                if ($seen.Add($key)) {
                    $csvWriter.WriteLine("$(Format-CsvField $ruleName),$(Format-CsvField $filePath),$(Format-CsvField $fileHash)")
                    $matchWriter.Write("$ruleName`0$filePath`0$fileHash`0")
                    $matchCount++
                }
            }
        }
    } finally {
        $csvWriter.Dispose()
        $matchWriter.Dispose()
    }

    Write-Host ""
    $fatal = $false
    if ($yaraExit -ne 0) {
        $errLines = @()
        if (Test-Path -LiteralPath $ErrorFile) { $errLines = @(Get-Content -LiteralPath $ErrorFile -ErrorAction SilentlyContinue) }
        # Locked/denied files (pagefile, NTUSER.DAT, ...) make yara exit non-zero
        # but are not a failed scan. Anything else (rule syntax, launch) is fatal.
        $other = @($errLines | Where-Object { $_ -and $_ -notmatch 'could not open file|^enumeration:' })
        $ruleHit = @($errLines | Where-Object { $_ -like "*yara-rules-*" })
        $openErr = @($errLines | Where-Object { $_ -match 'could not open file' })
        # Fatal: launch failure, rule/compile errors, or most of the list unreadable.
        $bogus = @($errLines | Where-Object { $_.Length -gt 1000 })   # a whole list parsed as one path
        $fatal = ($yaraExit -lt 0) -or ($other.Count -gt 0) -or ($ruleHit.Count -gt 0) -or ($bogus.Count -gt 0) -or ($openErr.Count -gt ($finalList.Count / 2))
    }
    if ($fatal) {
        $script:ScanOk = $false
        Write-Host "`n############################################`n" -ForegroundColor Red
        Log-Message "YARA exited with status $yaraExit - the scan is INCOMPLETE." "Red"
        Log-Message "Do not read these results as a clean scan." "Red"
        Log-Message "Details: $ErrorFile" "Red"
        Write-Host "`n############################################`n" -ForegroundColor Red
        return
    }

    if ((Test-Path -LiteralPath $ErrorFile) -and (Get-Item -LiteralPath $ErrorFile).Length -gt 0) {
        $n = @(Get-Content -LiteralPath $ErrorFile -ErrorAction SilentlyContinue).Count
        Log-Message "YARA exit code $yaraExit; $n error line(s) logged to $ErrorFile" "Yellow"
        Get-Content -LiteralPath $ErrorFile -TotalCount 3 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
    }

    Write-Host "`n############################################`n" -ForegroundColor Green
    Log-Message "Scan completed. $matchCount match(es)." "Green"
    Log-Message "Results saved in $CsvOutput" "Green"
    Write-Host "`n############################################`n" -ForegroundColor Green
}

function Extract-FlaggedFiles {
    param(
        [string]$ExtractsDir
    )

    Write-Host ""
    if (-not (Test-Path -LiteralPath $matchesFile) -or (Get-Item -LiteralPath $matchesFile).Length -eq 0) {
        Log-Message "No flagged files to extract."
        return
    }

    Log-Message "Extracting flagged files to $ExtractsDir"
    if (-not (Test-Path -LiteralPath $ExtractsDir)) {
        New-Item -ItemType Directory -Path $ExtractsDir -Force | Out-Null
    }

    # Records are NUL-delimited, so commas or quotes in paths are handled.
    $raw    = [System.IO.File]::ReadAllText((Resolve-Path -LiteralPath $matchesFile).Path, [System.Text.Encoding]::UTF8)
    $fields = $raw -split "`0"
    $copied  = 0
    $skipped = 0

    for ($i = 0; ($i + 2) -lt $fields.Count; $i += 3) {
        $ruleName = $fields[$i]
        $filePath = $fields[$i + 1]
        $fileHash = $fields[$i + 2]
        if ([string]::IsNullOrEmpty($filePath)) { continue }

        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
            Log-Message "File not found: $filePath (skipping)" "Red"
            $skipped++
            continue
        }

        $sourceDir = [System.IO.Path]::GetDirectoryName($filePath)
        $relDir = ($sourceDir -replace '^[A-Za-z]:', '') -replace '^[\\/]+', ''
        if ([string]::IsNullOrEmpty($relDir)) { $relDir = "." }

        $targetDir = Join-Path $ExtractsDir $relDir
        if (-not (Test-Path -LiteralPath $targetDir)) {
            New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
        }

        try {
            # -LiteralPath: paths containing [ or ] are otherwise treated as
            # wildcards and silently fail to copy.
            Copy-Item -LiteralPath $filePath -Destination $targetDir -Force -ErrorAction Stop
        } catch {
            Log-Message "Copy failed: $filePath ($_)" "Red"
            $skipped++
            continue
        }

        # Confirm the evidence copy matches what was recorded during the scan.
        $destFile = Join-Path $targetDir ([System.IO.Path]::GetFileName($filePath))
        if ($fileHash -and $fileHash -ne "HASH_ERROR" -and $fileHash -ne "FILE_NOT_FOUND") {
            try {
                $newHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $destFile -ErrorAction Stop).Hash
                if ($newHash -ne $fileHash) {
                    Log-Message "Hash mismatch after copy: $filePath (file changed on disk since the scan)" "Yellow"
                }
            } catch { }
        }

        Log-Message "Extracted: $filePath (SHA-256: $fileHash)" "Green"
        $copied++
    }

    Write-Host "`n############################################`n" -ForegroundColor Green
    Log-Message "Extraction complete. $copied copied, $skipped skipped." "Green"
    Log-Message "Suspected files in $ExtractsDir" "Green"
    Write-Host "`n############################################`n" -ForegroundColor Green
}

# Main exec
Clear-Host
Display-AsciiArt

Prepare-Directories

$yaraExe = Resolve-YaraExe
if (-not $yaraExe) {
    Log-Message "YARA binary not found." "Red"
    Log-Message "Expected .\runtime\bin\yara64.exe, or yara.exe available on PATH." "Red"
    exit 1
}

$caseName = Prompt-CaseName

$randomNumbers = Get-Random -Minimum 0 -Maximum 10000
$randomNumbers = "{0:D4}" -f $randomNumbers
$dateStamp     = (Get-Date).ToString("yyyy-MM-dd")

$csvOutput   = Join-Path $scriptDir "results\csv\$($caseName)_scan_${dateStamp}_$randomNumbers.csv"
$errorFile   = Join-Path $scriptDir "results\logs\$($caseName)_scan_errors_${dateStamp}_$randomNumbers.log"
$extractsDir = Join-Path $scriptDir "results\extracts\$caseName"
New-Item -ItemType File -Path $errorFile -Force | Out-Null

# The rule set is chosen first so the update only downloads what is needed.
$ruleSet  = Select-YaraRuleSet
$useCommunity = $false
if ($ruleSet -eq "fullplus") { $ruleSet = "full"; $useCommunity = $true }
$ruleFile = Join-Path $scriptDir "runtime\rules\yara-rules-$ruleSet.yar"

if (Check-InternetConnectivity) {
    if ($autoUpdate) {
        $updateChoice = "y"
    } else {
        $updateChoice = Prompt-Line "Would you like to update YARA rules now? (y/n)"
    }
    if ($updateChoice -match "^(Y|y|)$") {
        Update-YaraRules -RuleSet $ruleSet | Out-Null
        if ($useCommunity) { Update-CommunityRules -YaraExe $yaraExe | Out-Null }
    } else {
        Log-Message "Skipping YARA rules update at user request."
    }
} else {
    Log-Message "Skipping YARA rules update (no internet)."
}

if (-not (Test-Path -LiteralPath $ruleFile -PathType Leaf)) {
    Write-Host ""
    Log-Message "Rule file not found: $ruleFile" "Red"
    Log-Message "Run YAREX again and accept the rules update, or place the file there manually." "Red"
    exit 1
}

$communityFile = Join-Path $scriptDir "runtime\rules\yara-rules-community.yar"
if ($useCommunity -and -not (Test-Path -LiteralPath $communityFile -PathType Leaf)) {
    Log-Message "Community rules are not available; continuing with the Full set only." "Yellow"
    $useCommunity = $false
}
$extraRule = ""
if ($useCommunity) { $extraRule = $communityFile }

$toScan         = Prompt-RecommendedDirectories
$maxSize        = Select-MaxFileSize
$exclusionFiles = Select-Exclusions

Scan-AllDirectories -ScanLocations $toScan `
                    -ExclusionFiles $exclusionFiles `
                    -MaxSize $maxSize `
                    -RuleFile $ruleFile `
                    -ExtraRuleFile $extraRule `
                    -YaraExe $yaraExe `
                    -ErrorFile $errorFile `
                    -CsvOutput $csvOutput

if (-not $script:ScanOk) {
    exit 1
}

if ($autoExtract) {
    Extract-FlaggedFiles -ExtractsDir $extractsDir
} else {
    $extractChoice = Prompt-Line "Would you like to extract flagged files? (y/n)"
    if ($extractChoice -match "^(Y|y|)$") {
        Extract-FlaggedFiles -ExtractsDir $extractsDir
    } else {
        Log-Message "Not extracting files."
    }
}

exit 0
