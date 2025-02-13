# Parse command-line arguments for --extract
$autoExtract = $false
if ($args -contains "--extract") {
    $autoExtract = $true
}

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
    param([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $message"
}

function Check-InternetConnectivity {
    try {
        Invoke-WebRequest -Uri "https://www.github.com" -UseBasicParsing -TimeoutSec 10 | Out-Null
        return $true
    } catch {
        Log-Message "No internet connection. Proceeding without updating rules."
        return $false
    }
}

function Update-YaraRules {
    Log-Message "Updating YARA rules from GitHub..."

    $tempDir = Join-Path $env:TEMP ([System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir | Out-Null

    try {
        $releaseJson = Invoke-WebRequest -Uri "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest" -UseBasicParsing
        $releaseInfo = $releaseJson.Content | ConvertFrom-Json
    } catch {
        Log-Message "Failed to retrieve the latest release information."
        Remove-Item $tempDir -Recurse -Force
        return
    }

    $downloadUrls = $releaseInfo.assets | Where-Object { $_.browser_download_url -like "*.zip" } | Select-Object -ExpandProperty browser_download_url
    if (!$downloadUrls) {
        Log-Message "Failed to retrieve the latest release URLs."
        Remove-Item $tempDir -Recurse -Force
        return
    }

    foreach ($url in $downloadUrls) {
        $filename    = Split-Path $url -Leaf
        $destination = Join-Path $tempDir $filename

        try {
            Invoke-WebRequest -Uri $url -OutFile $destination -UseBasicParsing
            Expand-Archive -Path $destination -DestinationPath $tempDir -ErrorAction Stop
        } catch {
            Log-Message "Failed to download or extract $filename. Error: $_"
            continue
        }
    }

    $yarFiles = Get-ChildItem -Path $tempDir -Recurse -Filter "*.yar"
    foreach ($f in $yarFiles) {
        switch ($f.Name) {
            "yara-rules-core.yar" {
                Move-Item -LiteralPath $f.FullName ".\runtime\rules\yara-rules-core.yar" -Force
            }
            "yara-rules-extended.yar" {
                Move-Item -LiteralPath $f.FullName ".\runtime\rules\yara-rules-extended.yar" -Force
            }
            "yara-rules-full.yar" {
                Move-Item -LiteralPath $f.FullName ".\runtime\rules\yara-rules-full.yar" -Force
            }
            default {
                Log-Message "Unknown or unexpected rule file: $($f.Name). Skipping."
            }
        }
    }

    Log-Message "YARA rules updated successfully."
    Remove-Item $tempDir -Recurse -Force
}

function Prompt-CaseName {
    $caseName = Read-Host "Enter scan name (no spaces; e.g., case123)"
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

    $userChoice = Read-Host "Press Enter to use this list or type 'custom' to specify your own"
    $toScan = New-Object System.Collections.ArrayList
    if ([string]::IsNullOrWhiteSpace($userChoice)) {
        $recommendedDirs | ForEach-Object { [void]$toScan.Add($_) }
        Write-Host "Using recommended directories:"
        $toScan
        return $toScan
    } else {
        Write-Host "Please enter the directories to scan, one per line."
        Write-Host "Press Enter on a blank line to finish."
        while ($true) {
            $dir = Read-Host "Directory"
            if ([string]::IsNullOrWhiteSpace($dir)) {
                break
            } elseif (Test-Path $dir -PathType Container) {
                [void]$toScan.Add($dir)
                Write-Host "Added: $dir"
            } else {
                Write-Host "Invalid directory: $dir"
            }
        }
        if ($toScan.Count -eq 0) {
            [void]$toScan.Add("C:\Users")
            Write-Host "No directories entered. Defaulting to C:\Users."
        }
        return $toScan
    }
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
    $exclusionChoices = Read-Host "Enter choices (comma-separated, e.g., 1,2,3)"

    if ([string]::IsNullOrWhiteSpace($exclusionChoices)) {
        $exclusionChoices = "7"
    }

    $choiceArray   = $exclusionChoices -split "," | ForEach-Object { $_.Trim() }
    $exclusionFiles = New-Object System.Collections.ArrayList

    foreach ($choice in $choiceArray) {
        switch ($choice) {
            1 { [void]$exclusionFiles.Add(".\runtime\inames\archives.inm") }
            2 { [void]$exclusionFiles.Add(".\runtime\inames\audio.inm") }
            3 { [void]$exclusionFiles.Add(".\runtime\inames\databases.inm") }
            4 { [void]$exclusionFiles.Add(".\runtime\inames\images.inm") }
            5 { [void]$exclusionFiles.Add(".\runtime\inames\video.inm") }
            6 { [void]$exclusionFiles.Add(".\runtime\inames\vm.inm") }
            7 {
                $exclusionFiles = New-Object System.Collections.ArrayList
                [void]$exclusionFiles.Add(".\runtime\inames\archives.inm")
                [void]$exclusionFiles.Add(".\runtime\inames\audio.inm")
                [void]$exclusionFiles.Add(".\runtime\inames\databases.inm")
                [void]$exclusionFiles.Add(".\runtime\inames\images.inm")
                [void]$exclusionFiles.Add(".\runtime\inames\video.inm")
                [void]$exclusionFiles.Add(".\runtime\inames\vm.inm")
            }
            8 {
                $exclusionFiles.Clear()
            }
            default {
                Write-Host "Invalid choice: $choice. Skipping."
            }
        }
    }
    return $exclusionFiles
}

function Select-MaxFileSize {
    $defaultMaxSize = 750000000
    Write-Host ""
    Write-Host "Enter the maximum file size to scan (in bytes)."
    Write-Host "Default: $defaultMaxSize (750 MB)."
    $input = Read-Host "Value"
    if ([string]::IsNullOrWhiteSpace($input)) {
        return $defaultMaxSize
    } else {
        return ([int]$input)
    }
}

function Select-YaraRuleSet {
    Write-Host ""
    Write-Host "Choose YARA rule set:"
    Write-Host "1. Core"
    Write-Host "2. Extended (default)"
    Write-Host "3. Full"
    $ruleChoice = Read-Host "Enter choice (1/2/3)"

    switch ($ruleChoice) {
        "1" { return ".\runtime\rules\yara-rules-core.yar" }
        "3" { return ".\runtime\rules\yara-rules-full.yar" }
        default { return ".\runtime\rules\yara-rules-extended.yar" }
    }
}

function Scan-AllDirectories {
    param(
        [string[]]$ScanLocations,
        [string[]]$ExclusionFiles,
        [int]$MaxSize,
        [string]$RuleFile,
        [string]$ErrorFile,
        [string]$CsvOutput
    )

    # Ensure the run directory exists and clear old files
    if (-not (Test-Path ".\runtime\run")) {
        New-Item -ItemType Directory -Path ".\runtime\run" | Out-Null
    }
    $includedFile = ".\runtime\run\included"
    $excludedFile = ".\runtime\run\excluded"
    $diffFile     = ".\runtime\run\diff"

    foreach ($f in @($includedFile, $excludedFile, $diffFile)) {
        if (Test-Path $f) {
            Remove-Item $f -Force
        }
        New-Item $f -ItemType File | Out-Null
    }

    # Capture the directory where the script is running (to be excluded)
    $scriptDir = (Get-Location).Path

    $includedFilesSet = New-Object System.Collections.Generic.HashSet[string]

    foreach ($scanPath in $ScanLocations) {
        Log-Message "Gathering file list from $scanPath ..."
        $files = Get-ChildItem -Path $scanPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -notin @("yara-rules-core.yar","yara-rules-extended.yar","yara-rules-full.yar")
            } |
            Select-Object -ExpandProperty FullName

        # Exclude files that reside in the current (script) directory.
        $files = $files | Where-Object { $_ -notlike "$scriptDir\*" }

        foreach ($file in $files) {
            [void]$includedFilesSet.Add($file)
        }
    }

    $includedFilesSet | Out-File -FilePath $includedFile

    Log-Message "Finished building included list."

    $includeList = Get-Content $includedFile
    $excludeList = @()

    foreach ($sourceFile in $ExclusionFiles) {
        if (Test-Path $sourceFile) {
            $patterns = Get-Content $sourceFile -ErrorAction SilentlyContinue
            foreach ($p in $patterns) {
                if ($p -match '-iname\s+"([^"]+)"') {
                    $pattern = $Matches[1]
                    $excludeMatches = $includeList | Where-Object { $_ -like $pattern }
                    $excludeList += $excludeMatches
                }
            }
        }
    }
    $excludeList | Out-File $excludedFile
    Log-Message "Finished building excluded list."

    $finalList = $includeList | Where-Object { $excludeList -notcontains $_ }
    $finalList | Out-File $diffFile

    $includedCount = $includeList.Count
    $excludedCount = $excludeList.Count
    $finalCount    = $finalList.Count
    Write-Host "`n############################################`n"
    Write-Host ""
    Write-Host "Total included files: $includedCount"
    Write-Host "Total excluded files: $excludedCount"
    Write-Host ""
    Write-Host "Files to be scanned : $finalCount"
    Write-Host ""
    Write-Host "`n############################################`n"
    Write-Host ""

    Log-Message "Running YARA scan..."

    $yaraArgs = @(
        "-w",
        $RuleFile,
        "-N",
        "--skip-larger=$MaxSize",
        "--scan-list",
        $diffFile
    )
    $yaraOutput = & ".\runtime\bin\yara64.exe" $yaraArgs 2> $ErrorFile

    $csvTempOutput = @()
    foreach ($line in $yaraOutput) {
        if ($line -match "^(\S+)\s+(.*)$") {
            $ruleName = $Matches[1]
            $filePath = $Matches[2]
        }
        if (Test-Path $filePath -PathType Leaf) {
            try {
                $hashObj  = Get-FileHash -Algorithm SHA256 -LiteralPath $filePath -ErrorAction Stop
                $fileHash = $hashObj.Hash
            } catch {
                $fileHash = "HASH_ERROR"
            }
        } else {
            $fileHash = "FILE_NOT_FOUND"
        }
        $csvTempOutput += "$ruleName,$filePath,$fileHash"
    }

    $uniqueOutput = $csvTempOutput | Sort-Object -Unique
    "Rule,File,SHA256" | Out-File -Encoding UTF8 -FilePath $CsvOutput
    $uniqueOutput | Out-File -Append -FilePath $CsvOutput -Encoding UTF8

    Write-Host "`n############################################`n"
    Write-Host ""
    Log-Message "Scan completed. Results saved in $CsvOutput"
    Write-Host ""
    Write-Host "`n############################################`n"
}

function Extract-FlaggedFiles {
    param(
        [string]$CsvResults,
        [string]$ExtractsDir
    )
    Log-Message "Extracting flagged files to $ExtractsDir"
    if (-not (Test-Path $ExtractsDir)) {
        New-Item -ItemType Directory -Path $ExtractsDir | Out-Null
    }

    $lines = Get-Content $CsvResults
    foreach ($line in $lines) {
        if ($line -match "^(Rule,File,SHA256)$") {
            continue
        }
        $columns = $line -split ","
        if ($columns.Count -lt 3) { continue }

        $ruleName = $columns[0]
        $filePath = $columns[1]
        $fileHash = $columns[2]

        if (Test-Path $filePath -PathType Leaf) {
            $sourceDir = [System.IO.Path]::GetDirectoryName($filePath)
            $relDir = ($sourceDir -replace '^[A-Za-z]:', '') -replace '^[\\/]+',''
            if ([string]::IsNullOrEmpty($relDir)) { $relDir = "." }

            $targetDir = Join-Path $ExtractsDir $relDir
            if (-not (Test-Path $targetDir)) {
                New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            }

            Copy-Item -Path $filePath -Destination $targetDir -Force
            Log-Message "Extracted: $filePath (SHA-256: $fileHash)"
        }
        else {
            Log-Message "File not found: $filePath (skipping)"
        }
    }

    Write-Host "`n############################################`n"
    Write-Host ""
    Log-Message "Extraction complete. Suspected files in $ExtractsDir"
    Write-Host ""
    Write-Host "`n############################################`n"
}

Clear-Host
Display-AsciiArt

$caseName = Prompt-CaseName

if (-not (Test-Path ".\results\csv"))      { New-Item -ItemType Directory -Path ".\results\csv"      | Out-Null }
if (-not (Test-Path ".\results\logs"))     { New-Item -ItemType Directory -Path ".\results\logs"     | Out-Null }
if (-not (Test-Path ".\results\extracts")) { New-Item -ItemType Directory -Path ".\results\extracts" | Out-Null }

$randomNumbers = Get-Random -Minimum 0 -Maximum 10000
$randomNumbers = "{0:D4}" -f $randomNumbers
$dateStamp     = (Get-Date).ToString("yyyy-MM-dd")

$csvOutput  = ".\results\csv\$($caseName)_scan_${dateStamp}_$randomNumbers.csv"
$errorFile  = ".\results\logs\$($caseName)_scan_errors_${dateStamp}_$randomNumbers.log"
$extractsDir = ".\results\extracts\$caseName"

if (Check-InternetConnectivity) {
    $updateChoice = Read-Host "Would you like to update YARA rules now? (y/n)"
    if ($updateChoice -match "^(Y|y|)$") {
        Update-YaraRules
    } else {
        Log-Message "Skipping YARA rules update at user request."
    }
} else {
    Log-Message "Skipping YARA rules update (no internet)."
}

$toScan         = Prompt-RecommendedDirectories
$maxSize        = Select-MaxFileSize
$ruleFile       = Select-YaraRuleSet
$exclusionFiles = Select-Exclusions

Scan-AllDirectories -ScanLocations $toScan `
                    -ExclusionFiles $exclusionFiles `
                    -MaxSize $maxSize `
                    -RuleFile $ruleFile `
                    -ErrorFile $errorFile `
                    -CsvOutput $csvOutput

if ($autoExtract) {
    Extract-FlaggedFiles -CsvResults $csvOutput -ExtractsDir $extractsDir
} else {
    $updateChoice = Read-Host "Would you like to extract flagged files? (y/n)"
    if ($updateChoice -match "^(Y|y|)$") {
        Extract-FlaggedFiles -CsvResults $csvOutput -ExtractsDir $extractsDir
    } else {
        Log-Message "Not extracting files."
    }
}
