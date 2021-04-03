$ServiceName = "Sysmon"

function Get-SectionText {
    param($configContent,$ruleName,$ruleType)

    # print the lines associated with a rule
    $pattern = "\s+-\s+$($rulename)\s+onmatch:\s+($($ruletype))"
    $inRuleSection = $false
    $SectionText = @()
    foreach ($line in $content) {
        
        if ($line -match "\s+-\s+\S+\s+onmatch:") {
            if ($line -match $pattern) {
                $inRuleSection = $true
            } else {
                $inRuleSection = $false
            }
        }

        if ($inRuleSection) { $SectionText += $line }
    }

    return $SectionText
}

# check whether process is running as admin
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-host "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."
    exit
}

$Service = Get-WmiObject -Class Win32_Service -Filter "name='$($ServiceName)'"

if (-not($service)) {
    Write-host "$($ServceName) service not found.  Is the service installed? Exiting."
    exit
}

if (-not(Test-Path -Path $service.Pathname)) {
    write-host "$($service.Pathname) file not found. Is sysmon installed? Exiting."
    exit
}

$BinaryVersion = ((Get-ChildItem -Path $service.PathName).VersionInfo).FileVersion
write-host "Binary file version is $($BinaryVersion)."

# get sysmon schema object
write-host "Exporting current schema..."
$TemporaryFile = New-TemporaryFile
$process = Start-Process -FilePath $service.Pathname -ArgumentList "-s" -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput $TemporaryFile.FullName
$schema = [xml](Get-Content -Path $TemporaryFile.FullName)
$TemporaryFile | Remove-Item -Force


# get sysmon config into object
write-host "Exporting current config..."
$TemporaryFile = New-TemporaryFile
$process = Start-Process -FilePath $service.Pathname -ArgumentList "-c" -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput $TemporaryFile.FullName
$content = Get-Content -Path $TemporaryFile.FullName
$TemporaryFile | Remove-Item -Force

# get sysmon config schema version
$capture = $content | Select-String -Pattern "configuration \(version ([^\)]+)\):"
if (-not($capture)) {
    write-host "Rule configuration version not found. Exiting."
    exit
}
$SchmaVersion = $capture.Matches.captures[0].groups[1].Value
write-host "Configuration schema version is $($SchmaVersion)"

# get the config file name
$capture = $content | select-string -pattern "^\s+- Config file:\s+(.*)"
if (-not($capture)) {
    write-host "xml configuration file not found. this is fine"
    $ConfigFileName = "unknown"
} else {
    $ConfigFileName = $capture.Matches.captures[0].groups[1].Value
}


# iterate events in schema which support rules
$Records = @()
$lastRuleName = ""
foreach ($event in $Schema.manifest.events.event | ?{$_.rulename} | ?{$_.rulename -match ".*"}) {

    $rulename = $event.rulename

    if ($rulename -eq $lastRuleName) {
        # skip duplicate rule        
    } else {

        # get section text for rule name and type
        $SectionTextIncludes = Get-SectionText -configContent $content -ruleName $rulename -ruleType "include"
        $SectionTextExcludes = Get-SectionText -configContent $content -ruleName $rulename -ruleType "exclude"

        # determine if the input is enabled at all
        $Enabled = $false
        if ($SectionTextExcludes -or $SectionTextIncludes.Count -gt 1) { $Enabled = $true }

        # determine if compound or legacy rules in use
        $IncludeCompoundRules = $false
        $ExcludeCompoundRules = $false

        $CompoundRuleCountInclude = ($SectionTextIncludes | Select-String -pattern "^\s+Compound Rule").count
        $CompoundRuleCountExclude = ($SectionTextExcludes | Select-String -pattern "^\s+Compound Rule").count

        $TotalRuleCountInclude = ($SectionTextIncludes | Select-String -pattern "\s+filter:\s+").count
        $TotalRuleCountExclude = ($SectionTextExcludes | Select-String -pattern "\s+filter:\s+").count

        $record = @{
            rulename = $rulename
            Id = [int]$event.value
            enabled = $Enabled
            BinaryVersion = $BinaryVersion
            SchemaVersion = $SchmaVersion
            TotalRuleCountInclude = $TotalRuleCountInclude
            TotalRuleCountExclude = $TotalRuleCountExclude
            CompoundRuleCountInclude = $CompoundRuleCountInclude
            CompoundRuleCountExclude = $CompoundRuleCountExclude        
        }

        $Records += New-Object -TypeName PSObject -Property $Record

        
    }   
    
    $lastRuleName = $rulename     

}

# todo -- dedup shared event types like wmi, registry, and pipe
$Records | select BinaryVersion, SchemaVersion, Id, rulename, enabled, TotalRuleCountInclude, TotalRuleCountExclude, CompoundRuleCountInclude, CompoundRuleCountExclude | Sort-Object ID | Out-GridView -Title "Tier 1 Triage Context for $($ConfigFileName)"