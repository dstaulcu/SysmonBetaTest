<#
TODO:
- move dependency checks up front
- find alternative to notmyfault64 for SYSMON_DRIVER_LOAD
- find alternative to PowerSploit Invoke-DllInjection for SYSMON_IMAGE_LOAD
- find alternative to PowerSploit Invoke-NinjaCopy for SYSMON_RAWACCESS_READ (https://devblogs.microsoft.com/scripting/use-powershell-to-interact-with-the-windows-api-part-1/)
- expand checks to confirm that all fields have values and do not introduce whitespaces
- expand checks to confirm that there are no collisions in schema of paramter names
- expand checks to confirm reliabilty under heavy loads (low memory, low cpu, high network/disk i/o.)
#>

<#
$DebugPreference = "Continue"           # Debug Mode
$DebugPreference = "SilentlyContinue"   # Normal Mode
#>

$TestCount = 1
$SysinternalsSuitePath = "C:\Users\david\Downloads\SysinternalsSuite"

# creates Sysmon config with all inputs except specified type
function make-sysmon-config ($sysmonPath, $name) 
{

    Write-Debug "creating sysmon config"

    # Get sysmon schema into xml
    $sysmonSchemaPrint = & $sysmonPath -s 2> $null | Select-String -Pattern "<"
    $sysmonSchemaPrintXml = [xml]$sysmonSchemaPrint

    # spit out a new template file
    $events = $sysmonSchemaPrintXml.manifest.events.event | Where-Object {$_.name -notmatch "(SYSMON_ERROR|SYSMON_SERVICE_STATE_CHANGE|SYSMON_SERVICE_CONFIGURATION_CHANGE)"}

    $xmlConfig = @()
    $xmlConfig += "<Sysmon schemaversion=`"$($sysmonSchemaPrintXml.manifest.schemaversion)`">"
#    if ($sysmonSchemaPrintXml.manifest.binaryversion -gt 9.20) { $xmlConfig += "`t<DnsLookup>False</DnsLookup>" }
    $xmlConfig += "`t<EventFiltering>"


    foreach ($event in $events) {

        $printConfig = $true
        # print the section hearder listing ID (value), Description (template), and config file section id (rulename)
        $xmlConfig += ""
        $xmlConfig += "`t`t<!--SYSMON EVENT ID $($event.value) : $($event.template) [$($event.rulename)]-->"

        # print the section hearder data elements of event
        $items = ""
        foreach ($item in $event.data | Select Name) {
            if ($items -eq "") {
                $items = "$($item.name)"
            } else {
                $items += ", $($item.name)"
            }        
        }
        $xmlConfig += "`t`t<!--DATA: $($items)-->"

        #
        if ($event.value -match "12|13|17|19|20") { $printConfig = $false}

        if ($name -match "SYSMON_REG_KEY|SYSMON_REG_SETVALUE" -and $event) {
            $name = "SYSMON_REG_NAME"
        }

        if ($name -match "SYSMON_CREATE_NAMEDPIPE|SYSMON_CONNECT_NAMEDPIPE" -and $event) {
            $name = "SYSMON_CONNECT_NAMEDPIPE"
        }

        if ($name -match "SYSMON_WMI_FILTER|SYSMON_WMI_CONSUMER|SYSMON_WMI_BINDING" -and $event) {
            $name = "SYSMON_WMI_BINDING"
        }

        $matchtype = "include"
        if ($event.name -ieq $name) { 
            Write-Debug "setting $($event.name) match level to exclude"
            $matchtype = "exclude" 
        }
        

        if ($printConfig -eq $true) {
            $xmlConfig += ""
            $xmlConfig += "`t`t<RuleGroup name=`"`" groupRelation=`"or`">"
            $xmlConfig += "`t`t`t<$($event.rulename) onmatch=`"$($matchtype)`">"
            $xmlConfig += "`t`t`t</$($event.rulename)>"
            $xmlConfig += "`t`t</RuleGroup>"
        }
    }
    $xmlConfig += ""
    $xmlConfig += "`t</EventFiltering>"
    $xmlConfig += ""
    $xmlConfig += "</Sysmon>"

    $ConfigFile = "$($env:TEMP)\$($name).xml"
    if (Test-Path -Path $ConfigFile) { Remove-Item -Path $ConfigFile -Force }
    write-debug "writing config to file: $($configfile)"
    Set-Content -Path $ConfigFile -Value $xmlConfig

    return $ConfigFile

}

# instlls sysmon
function install-sysmon ($sysmonPath)
{

    Write-Debug "uninstalling sysmon"
    Start-Process -FilePath $sysmonPath -ArgumentList @("-u","force") -NoNewWindow
    Start-Sleep -Seconds 2

    Write-Debug "installing sysmon"
    Start-Process -FilePath $sysmonPath -ArgumentList @("-i","-accepteula") -NoNewWindow
    Start-Sleep -Seconds 2

}

# stops sysmon, clears log file, merges new config, starts-sysmon
function reset-sysmon ($sysmonPath, $configpath)
{

    Write-Debug "configuring sysmon"
    Start-Process -FilePath $sysmonPath -ArgumentList @("-c",$configpath) -NoNewWindow
    Start-Sleep -Seconds 2

    Write-Debug "clearing sysmon logfile"
    (New-Object System.Diagnostics.Eventing.Reader.EventLogSession).ClearLog("Microsoft-Windows-Sysmon/Operational")

}

# gets event logs of specified type
function get-eventlog ($logname, $id) 
{
    $events = Get-WInEvent -log $logname
    # Parse out the event message data            
    ForEach ($Event in $Events) {            
        # Convert the event to XML            
        $eventXML = [xml]$Event.ToXml()            
        # Iterate through each one of the XML message properties            
        For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {            
            # Append these as object properties            
            Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name  $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'            
        }            
    }       
    return $Events
}

# Establish path to Sysmon
$sysmonPath = "$($env:windir)\sysmon.exe"
if (!(Test-Path -Path $sysmonPath)) {
    write-host "Sysmon.exe not present in $($sysmonPath). Exiting."
    exit
} 

# Make sure .NET 2.0 is present
if ((get-WindowsOptionalFeature -FeatureName "NetFX3" -Online).State -ne "Enabled") {
    Enable-WindowsOptionalFeature -Online -FeatureName "NetFX3" -All
}

#Disable AV
if ((Get-MpPreference).DisableRealtimeMonitoring -eq $false) {
    Read-Host -Prompt "Please disable A/V and press ENTER to continue.."
}

# Ensure PowerSploit is present
$ModulePath = "C:\Windows\system32\WindowsPowerShell\v1.0\Modules\PowerSploit"

$url = "https://github.com/PowerShellMafia/PowerSploit/archive/master.zip"
$download = "$($env:temp)\master.zip"
if (Test-Path -Path $download) { Remove-Item -Path $download -Force -Recurse }
write-host "-downloading latest project from $($url)."
$Response = Invoke-WebRequest -Uri $url -OutFile $download

# extract the compressed content (if local copy older than 20 hours)
write-host "-extracting archive."
$extracted = "$($env:temp)\extracted"
if (Test-Path -Path $extracted) { Remove-Item -Path $extracted -Force -Recurse }
Expand-Archive -LiteralPath $download -DestinationPath $extracted -Force

# copy the module
Rename-Item -Path "$($extracted)\PowerSploit-master" -NewName "PowerSploit"
Copy-Item -Path "$($extracted)\PowerSploit" -Destination $ModulePath -Recurse -Force

# remove any marks of the web/streams
Get-ChildItem -path $ModulePath -Recurse | Unblock-File

################################################################################
# SYSMON_CREATE_PROCESS: EventCode=1 RuleName=ProcessCreate
################################################################################
$TestName = "SYSMON_CREATE_PROCESS"
$EventID = 1
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    
    ###########################################################################
    # Payload:
    $Process = start-process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
    $FilterItems += $Process.Id
    Stop-Process -Id $Process.Id -ErrorAction stop            
    ###########################################################################
}
Write-Progress -Activity "Conducting $($testname) test" -Completed

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$FilterItemsExpression = $FilterItems -join "|"
$matchingEvents = $events | ?{$_.ProcessId -match "^$($FilterItemsExpression)$"}
if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_FILE_TIME: EventCode=2 RuleName=FileCreateTime
################################################################################
$TestName = "SYSMON_FILE_TIME"
$EventID = 2
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    
    ###########################################################################
    # Payload:
    $TemporaryFile = New-TemporaryFile
    (Get-Item -path $TemporaryFile.FullName).CreationTime=("08 March 2016 18:00:00")
    $FilterItems += [regex]::escape($TemporaryFile.FullName)
    Remove-Item -Path $TemporaryFile.FullName
    ###########################################################################
}
Write-Progress -Activity "Conducting $($testname) test" -Completed

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$FilterItemsExpression = $FilterItems -join "|"
$matchingEvents = $events | ?{$_.TargetFileName -match $($FilterItemsExpression)}
if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_NETWORK_CONNECT: EventCode=3 RuleName=NetworkConnect
################################################################################
$TestName = "SYSMON_NETWORK_CONNECT"
$EventID = 3
write-host "Conducting `"$($TestName)`" test..."

# do a warm up run
$warmup = Test-NetConnection -ComputerName "www.google.com"

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    
    ###########################################################################
    # Payload:
    $blah = Invoke-WebRequest -Uri "www.google.com" -DisableKeepAlive
    ###########################################################################
}
Write-Progress -Activity "Conducting $($testname) test" -Completed

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$matchingEvents = $events | ?{$_.SourceIP -eq $warmup.SourceAddress.IPv4Address -and $_.destinationIP -eq $warmup.RemoteAddress.IPAddressToString}
if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


###############################################################################
# SYSMON_SERVICE_STATE_CHANGE: EventCode=4
###############################################################################
$TestName = "SYSMON_SERVICE_STATE_CHANGE"
$EventID = 4
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    
    ###########################################################################
    # Payload:
    Get-Service sysmon | Restart-Service
    ###########################################################################
}
Write-Progress -Activity "Conducting $($testname) test" -Completed

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$matchingEvents = $events | ?{$_.State -eq "started"}
if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_PROCESS_TERMINATE: EventCode=5 RuleName=ProcessTerminate
################################################################################
$TestName = "SYSMON_PROCESS_TERMINATE"
$EventID = 5
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete     
    ###########################################################################
    # Payload:
    $Process = start-process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
    $FilterItems += $Process.Id
    Stop-Process -Id $Process.Id -ErrorAction stop           
    ###########################################################################
}
Write-Progress -Activity "Conducting $($testname) test" -Completed

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$FilterItemsExpression = $FilterItems -join "|"
$matchingEvents = $events | ?{$_.ProcessId -match "^$($FilterItemsExpression)$"}

if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_DRIVER_LOAD: EventCode=6 RuleName=DriverLoad
################################################################################
$TestName = "SYSMON_DRIVER_LOAD"
$EventID = 6
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    
    ###########################################################################
    # Payload:
    $ProcessPath = "$($SysinternalsSuitePath)\notmyfault64.exe"
    $Process = start-process -FilePath $ProcessPath -ArgumentList @("/AcceptEula") -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 1
    Stop-Process -Id $Process.Id -ErrorAction stop -Force  
    Get-Service myfault | Stop-Service
    ###########################################################################

}
Write-Progress -Activity "Conducting $($testname) test" -Completed   

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$FilterItemsExpression = "myfault"
$matchingEvents = $events | ?{$_.ImageLoaded -match "$($FilterItemsExpression)"}

if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_IMAGE_LOAD: EventCode=7 RuleName=ImageLoad
################################################################################
$TestName = "SYSMON_IMAGE_LOAD"
$EventID = 7
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath


$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    

    ###########################################################################
    # Payload:
    $ProcessPath = "c:\windows\notepad.exe"
    $Process = start-process -FilePath $ProcessPath -WindowStyle Hidden -PassThru
    $FilterItems += $Process.Id
    Stop-Process -Id $Process.Id -ErrorAction stop 
    ###########################################################################
}
Write-Progress -Activity "Conducting $($testname) test" -Completed

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$FilterItemsExpression = $FilterItems -join "|"
$matchingEvents = $events | ?{$_.ProcessId -match "^$($FilterItemsExpression)$"}

if ($matchingEvents) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_CREATE_REMOTE_THREAD: EventCode=8 RuleName=CreateRemoteThread
################################################################################
# The CreateRemoteThread event detects when a process creates a thread in 
# another process. This technique is used by malware to inject code and hide 
# in other processes. The event indicates the source and target process. It 
# gives information on the code that will be run in the new thread: 
# StartAddress, StartModule and StartFunction. Note that StartModule and 
# StartFunction fields are inferred, they might be empty if the starting 
# address is outside loaded modules or known exported functions.
################################################################################
$TestName = "SYSMON_CREATE_REMOTE_THREAD"
$EventID = 8
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    

    ###########################################################################
    # Payload:

    $ScriptPath = "C:\Users\David\Downloads\SYSMON_CREATE_REMOTE_THREAD.ps1"
    $dll = "C:\Windows\System32\advapi32.dll"
    $ProcessPath = "c:\windows\notepad.exe"

    #Disable AV
    if ((Get-MpPreference).DisableRealtimeMonitoring -eq $false) {
        Read-Host -Prompt "Please disable A/V and press ENTER to continue.."
    }

    #Set PowerShell ExecutionPolicy is top allow execution of PowerSploit
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force

    $Process = start-process -FilePath $ProcessPath -WindowStyle Hidden -PassThru
    Start-Process -FilePath "Powershell.exe" -ArgumentList @("-version 2.0","-file $($ScriptPath)","-processid $($process.id)","-dll $($dll)") -Wait -WindowStyle Hidden
    $FilterItems += $Process.id
    Stop-Process -Id $process.id -Force
    ###########################################################################
}
Write-Progress -Activity "Conducting $($testname) test" -Completed         

#Enable AV
Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Basic

#Reset PowerShell Execution Policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$FilterItemsExpression = $FilterItems -join "|"
$matchingEvents = $events | ?{$_.TargetProcessId -match "^$($FilterItemsExpression)$"}

if ($matchingEvents) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_RAWACCESS_READ: EventCode=9 RuleName=RawAccessRead
################################################################################
# The RawAccessRead event detects when a process conducts reading operations 
# from the drive using the \\.\ denotation. This technique is often used by 
# malware for data exfiltration of files that are locked for reading, as well 
# as to avoid file access auditing tools. The event indicates the source 
# process and target device.
# https://devblogs.microsoft.com/scripting/use-powershell-to-interact-with-the-windows-api-part-1/
###############################################################################
$TestName = "SYSMON_RAWACCESS_READ"
$EventID = 9
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    

    ###########################################################################
    # Payload:

    # build the script to call
    $ScriptPath = "$($env:temp)\$($TestName).ps1"
    if (Test-Path -Path $ScriptPath) { Remove-Item -Path $ScriptPath -Force }
    $Content = @()
    $Content += "Import-Module PowerSploit -Force"
    $Content += "Invoke-NinjaCopy -Path `"$($env:windir)\system32\calc.exe`" -LocalDestination `"$($env:temp)\calc.exe`""
    Set-Content -Path $ScriptPath -Value $Content

    #Disable AV
    if ((Get-MpPreference).DisableRealtimeMonitoring -eq $false) {
        Read-Host -Prompt "Please disable A/V and press ENTER to continue.."
    }

    #Set PowerShell ExecutionPolicy is top allow execution of PowerSploit
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force

    $Process = Start-Process -FilePath "Powershell.exe" -ArgumentList @("-version 2.0","-file $($ScriptPath)") -Wait -WindowStyle Hidden -PassThru
    $FilterItems += $Process.id
    ###########################################################################
}
Write-Progress -Activity "Conducting $($testname) test" -Completed         

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$FilterItemsExpression = $FilterItems -join "|"
$matchingEvents = $events | ?{$_.ProcessId -match "^$($FilterItemsExpression)$"}

if ($matchingEvents) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_FILE_CREATE: EventCode=11 RuleName=FileCreate
################################################################################
# File create operations are logged when a file is created or overwritten. 
# This event is useful for monitoring autostart locations, like the Startup 
# folder, as well as temporary and download directories, which are common 
# places malware drops during initial infection.
###############################################################################
$TestName = "SYSMON_FILE_CREATE"
$EventID = 11
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    

    ###########################################################################
    # Payload:
    $TemporaryFile = New-TemporaryFile
    $FilterItems += [regex]::escape($TemporaryFile.FullName)
    Remove-Item $TemporaryFile -Force
    ###########################################################################

}
Write-Progress -Activity "Conducting $($testname) test" -Completed         

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$FilterItemsExpression = $FilterItems -join "|"
$matchingEvents = $events | ?{$_.ProcessId -eq $PID -and $_.TargetFilename -match $FilterItemsExpression}

if ($matchingEvents) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_REG_KEY: EventCode=12 RuleName=RegistryEvent (Object create and delete)
################################################################################
$TestName = "SYSMON_REG_KEY"
$EventID = 12
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()

for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    

    ###########################################################################
    # Payload:
    New-Item -Path HKLM:\Software\DeleteMe | Out-Null
    remove-item -Path HKLM:\Software\DeleteMe | Out-Null
    ###########################################################################
}
Write-Progress -Activity "Conducting $($testname) test" -Completed         

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$matchingEvents = $events | ?{$_.ProcessId -eq $PID -and $_.TargetObject -match "Software_DeleteMe" -and $_.EventType -eq "CreateKey"}

if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_REG_SETVALUE: EventCode=13 RuleName=RegistryEvent (Value Set)
################################################################################
$TestName = "SYSMON_REG_SETVALUE"
$EventID = 13
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()

for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    

    ###########################################################################
    # Payload:
    New-Item -Path HKLM:\Software\DeleteMe  | out-null
    New-ItemProperty -Path HKLM:\Software\DeleteMe -Name Test -PropertyType String -Value "Hello World!" | out-null
    remove-item -Path HKLM:\Software\DeleteMe | out-null
    ###########################################################################

}
Write-Progress -Activity "Conducting $($testname) test" -Completed         

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$matchingEvents = $events | ?{$_.ProcessId -eq $PID -and $_.TargetObject -match "Software_DeleteMe" -and $_.EventType -eq "SetValue"}

if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_REG_NAME: EventCode=14 RuleName=RegistryEvent (Key and Value Rename)
################################################################################
$TestName = "SYSMON_REG_NAME"
$EventID = 14
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()

for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    

    ###########################################################################
    # Payload:
    New-Item -Path HKLM:\Software\DeleteMe  | Out-Null
    Rename-Item -Path HKLM:\Software\DeleteMe  -NewName "DeleteMe-v2" | Out-Null
    remove-item -Path HKLM:\Software\DeleteMe-v2 | Out-Null 
    ###########################################################################

}
Write-Progress -Activity "Conducting $($testname) test" -Completed         

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$matchingEvents = $events | ?{$_.ProcessId -eq $PID -and $_.TargetObject -match "Software_DeleteMe"} 

if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_FILE_CREATE_STREAM_HASH: EventCode=15 RuleName=FileCreateStreamHash
################################################################################
$TestName = "SYSMON_FILE_CREATE_STREAM_HASH"
$EventID = 15
write-host "Conducting "$($TestName)" test..."


$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)

    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    

    ###########################################################################
    # Payload:
    $TempFile = New-TemporaryFile
    $StreamName = "StreamMessage"
    $StreamText = "Hello World"
    write-host "$(Get-date) - Creating stream `"$($StreamName)`" with stream text `"$($StreamText)`" in file `"$($TempFile.FullName)`"."
    Set-Content -Path $TempFile.FullName -Stream $StreamName -Value $StreamText
    $TempFile | Remove-Item -Force
    $FilterItems += [regex]::escape($TempFile.FullName)
    ###########################################################################
}
$FilterItemsExpression = $FilterItems -join "|"
Write-Progress -Activity "Conducting $($testname) test" -Completed

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$matchingEvents = $events | ?{$_.ProcessId -eq $PID -and $_.TargetFilename -match "$($FilterItemsExpression):" -and $_.Hash -ne "Unknown"} 


if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_CREATE_NAMEDPIPE: EventCode=17 RuleName=PipeEvent
# https://stackoverflow.com/questions/24096969/powershell-named-pipe-no-connection
################################################################################
$TestName = "SYSMON_CREATE_NAMEDPIPE"
$EventID = 17
write-host "Conducting "$($TestName)" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    

    ###########################################################################
    # Payload:
    # create a named pipe
    $pipeName = "testpipe$($i)"  
    $pipe = new-object System.IO.Pipes.NamedPipeServerStream $pipeName,'Out'
    $pipe.Dispose()
    $FilterItems += [regex]::escape("\$($pipeName)")
    ###########################################################################

}
Write-Progress -Activity "Conducting $($testname) test" -Completed
$FilterItemsExpression = $FilterItems -join "|"

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$matchingEvents = $events | ?{$_.ProcessId -eq $PID -and $_.PipeName -match $FilterItemsExpression} 


if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_CONNECT_NAMEDPIPE: EventCode=18 RuleName=PipeEvent
################################################################################
$TestName = "SYSMON_CONNECT_NAMEDPIPE"
$EventID = 18
write-host "Conducting "$($TestName)" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    

    ###########################################################################
    # Payload:
    # build the script to run the pipe server
    $ScriptPath = "$($env:temp)\$($TestName).ps1"
    if (Test-Path -Path $ScriptPath) { Remove-Item -Path $ScriptPath -Force }
    $Content = @()
    $Content += "`$pipe = new-object System.IO.Pipes.NamedPipeServerStream 'testpipe','Out'"
    $Content += "`$pipe.WaitForConnection()"
    $Content += "`$sw = new-object System.IO.StreamWriter `$pipe"
    $Content += "`$sw.AutoFlush = `$true"
    $Content += "`$sw.WriteLine(`"Server pid is `$pid`")"
    $Content += "`$sw.Dispose()"
    $Content += "`$pipe.Dispose()"
    Set-Content -Path $ScriptPath -Value $Content
    $Process = Start-Process -FilePath "Powershell.exe" -ArgumentList @("-file $($ScriptPath)") -PassThru -WindowStyle Hidden

    # create a named pipe
    $pipe = new-object System.IO.Pipes.NamedPipeClientStream '.','testpipe','In'
    $pipe.Connect()
    $sr = new-object System.IO.StreamReader $pipe
    while (($data = $sr.ReadLine()) -ne $null) { "Received: $data" }
    $sr.Dispose()
    $pipe.Dispose()

    $FilterItems += $PID
    ###########################################################################

}
Write-Progress -Activity "Conducting $($testname) test" -Completed
$FilterItemsExpression = $FilterItems -join "|"

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -id $EventID -logname "Microsoft-Windows-Sysmon/Operational"
$matchingEvents = $events | ?{$_.Id -eq $EventID -and $_.ProcessId -match $FilterItemsExpression -and $_.PipeName -eq '\testpipe'} 

if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_WMI_FILTER: EventCode=19 RuleName=WmiEvent
# SYSMON_WMI_CONSUMER: EventCode=20 RuleName=WmiEvent
# SYSMON_WMI_BINDING: EventCode=21 RuleName=WmiEvent
################################################################################
$TestName = "SYSMON_WMI_CONSUMER"
$EventIDs = "^(19|20|21)$"

write-host "Conducting WmiEvent test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    

    ###########################################################################
    # Payload:
    $command = 'powershell.exe -Command {write-host "hello world!"}'

    $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{
           EventNamespace = 'root/cimv2'
           Name = "TestFilter"
           Query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process' AND Name='calc.exe'"
           QueryLanguage = 'WQL'
    }

    $Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{
           Name = "TestConsumer"
           CommandLineTemplate = $Command
    }

    $Binding = Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{
           Filter = $Filter
           Consumer = $Consumer
    }

    #Cleanup
    Get-WmiObject __EventFilter  -namespace root\subscription  | ?{$_.Name -eq "TestFilter"} | Remove-WmiObject
    Get-WmiObject CommandLineEventConsumer  -Namespace root\subscription  | ?{$_.Name -eq "TestConsumer"} | Remove-WmiObject
    Get-WmiObject __FilterToConsumerBinding   -Namespace root\subscription  | ?{$_.filter -match "TestFilter"} | Remove-WmiObject
    ###########################################################################

}
Write-Progress -Activity "Conducting $($testname) test" -Completed

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -logname "Microsoft-Windows-Sysmon/Operational"
$matchingEvents = $events | ?{$_.ID -match $EventIDs -and $_.Operation -eq "Created"}
# -and $_.ProcessId -eq $PID}
if ($matchingEvents.count -eq $TestCount*3) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}


################################################################################
# SYSMON_DNS_QUERY: EventCode=22 RuleName=DnsQuery
################################################################################
$TestName = "SYSMON_DNS_QUERY"
$EventID = 22
write-host "Conducting "$($TestName)" test..."


$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    

    ###########################################################################
    # Payload:
    Resolve-DnsName -Name "www.google.com" | Out-Null
    ###########################################################################

}
Write-Progress -Activity "Conducting $($testname) test" -Completed

# review the events
Start-Sleep -Seconds 5
$Events = get-eventlog -logname "Microsoft-Windows-Sysmon/Operational"
$matchingEvents = $events | ?{$_.ID -eq $EventID -and $_.Processid -eq $PID}
# -and $_.ProcessId -eq $PID}
if ($matchingEvents.count -eq $TestCount) {
    write-host "Test passed"
} else {
    write-host "Test failed"
}

