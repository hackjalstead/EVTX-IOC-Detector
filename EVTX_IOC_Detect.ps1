
# Currently used for automation and identifying IOCs/timeframes/areas to go hunt further.
# Add in patterns from researching TA TTP repos or IOCs seen from current project. Can also change params to pull specific event IDs. 
# Future, may add sigma rule parsing instead of static, if so, need to rewrite pattern definitions, add converter from Sigma to PS and check/pull latest rules every run. Would be good to build rule bank to be current/specific to observed TAs.

# To run - .\EVTX_IOC_Detect.ps1 -path "\Path\to\EVTX\folder\"

param (
    [Parameter(Mandatory = $true)]
    [string]$path
)

$LogFile = "IOC_Detections_$(Get-Date -Format 'yyyy-MM-ddTHHmmssZ').log" # producing timestamped log of results from console

# Regex and String IOC patterns below
#add more patterns as necessary to the job you're working on

$RegexPatterns = @(
    "\\\\(?:[0-9]{1,3}\.){3}[0-9]{1,3}\\ADMIN\$\\\w{7}\.exe", #Service File Name Catch All
    #"Service Name:\s+[a-zA-Z0-9]{7}\b", #Service Name with 7 char regex, may produce duplicate entries with above
    #"HostApplication=powershell\s+-nop\s+-exec\s+bypass\s+-EncodedCommand",
    "%COMSPEC%\s+/b\s+/c\s+start\s+/b\s+/min\s+powershell\s+-nop\s+-w\s+hidden",
    "\\\\\.\\pipe\\[a-zA-Z0-9_-]{3,20}"
#Other named pipes seen in the wild --------
    #'MSSE-[0-9a-f]{3}-server',
    #'status_[0-9a-f]{2}',
    #'postex_ssh_[0-9a-f]{4}',
    #'msagent_[0-9a-f]{2}',
    #'postex_[0-9a-f]{4}',
    #'mojo\.5688\.8052\.183894939787088877[0-9a-f]{2}',
    #'mojo\.5688\.8052\.35780273329370473[0-9a-f]{2}',
    #'wkssvc[0-9a-f]{2}',
    #'ntsvcs[0-9a-f]{2}',
    #'DserNamePipe[0-9a-f]{2}',
    #'SearchTextHarvester[0-9a-f]{2}',
    #'ntsvcs',
    #'scerpc',
    #'mypipe-f[0-9a-f]{2}',
    #'mypipe-h[0-9a-f]{2}',
    #'windows\.update\.manager[0-9a-f]{2}',
    #'windows\.update\.manager[0-9a-f]{3}',
    #'ntsvcs_[0-9a-f]{2}',
    #'scerpc_[0-9a-f]{2}',
    #'scerpc[0-9a-f]{2}',
    #'ntsvcs[0-9a-f]{2}'
)

$StringPatterns = @(
    #"JABz", #may produce duplicate entries with regex queries above
    #"SQBFAFgA",
    "IEX" #might have a tendency to pull FP depending on env.
    #add more string patterns here specific to the job you're working on, mimikatz examples below -
    #"privilege::debug"
    #"sekurlsa::"
)

$CompiledRegex = @()
foreach ($pattern in $RegexPatterns) {
    $CompiledRegex += [PSCustomObject]@{
        PatternText = $pattern
        RegexObject = [regex]::new($pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    }
}

function Search-EvtxForIOCs {
    param (
        [string]$EvtxFile,
        [array]$RegexPatterns,
        [array]$StringPatterns
    )
    Write-Host "`nAnalyzing: $EvtxFile" -ForegroundColor Cyan

    try {
        $events = Get-WinEvent -Path $EvtxFile -ErrorAction Stop
        foreach ($event in $events) { # loop for regex patterns
            $message = $event.Message
            foreach ($p in $RegexPatterns) {
                if ($p.RegexObject.IsMatch($message)) {
                    Write-Host "`nIOC Found in ${EvtxFile}:" -ForegroundColor Red -NoNewline
                    Write-Host "`nEvent ID: " -NoNewline
                    Write-Host "$($event.Id)" -ForegroundColor Cyan
                    Write-Host "Time Stamp: " -NoNewline
                    Write-Host "$($event.TimeCreated)" -ForegroundColor Cyan
                    Write-Host "Matched Pattern (Regex): " -NoNewline
                    Write-Host "$($p.PatternText)" -ForegroundColor Cyan
                    Write-Host "Message:" 
                    Write-Host "$message" -ForegroundColor Cyan

                    Add-Content -Path $LogFile -Value @"
`n`n======================================================== IOC DETECTION ========================================================
File: ${EvtxFile}
Event ID: $($event.Id)
Time Stamp: $($event.TimeCreated)
Matched Pattern (Regex): $($p.PatternText)
Message:
$message
"@ 
                }
            }
            foreach ($s in $StringPatterns) { # Loop for string patterns
                if ($message -like "*$s*") {
                    Write-Host "`nIOC Found in ${EvtxFile}:" -ForegroundColor Red -NoNewline
                    Write-Host "`nEvent ID: " -NoNewline
                    Write-Host "$($event.Id)" -ForegroundColor Cyan
                    Write-Host "Time Stamp: " -NoNewline
                    Write-Host "$($event.TimeCreated)" -ForegroundColor Cyan
                    Write-Host "Matched Pattern (String): " -NoNewline
                    Write-Host "$s" -ForegroundColor Cyan
                    Write-Host "Message:" 
                    Write-Host "$message" -ForegroundColor Cyan

                    Add-Content -Path $LogFile -Value @"
`n`n======================================================== IOC DETECTION ========================================================
File: ${EvtxFile}
Event ID: $($event.Id)
Time Stamp: $($event.TimeCreated)
Matched Pattern (String): $s
Message:
$message
"@ 
                }
            }
        }
    }
    catch {
        Write-Warning "Failed to parse ${EvtxFile}: $_"
    }
}
    $evtxFiles = Get-ChildItem -Path $path -Filter *.evtx -Recurse | Where-Object { # comment out all text from | if you wanna search all EVTX or add more individually as needed
    $_.BaseName -in @(
        "System",
        "Windows PowerShell",
        "Microsoft-Windows-PowerShell%4Operational"
        # to add other EVTX here, add a comma to the line above
    )
}
foreach ($file in $evtxFiles) {
    Search-EvtxForIOCs -EvtxFile $file.FullName -RegexPatterns $CompiledRegex -StringPatterns $StringPatterns
}