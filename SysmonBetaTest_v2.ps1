<#
$DebugPreference = "Continue"           # Debug Mode
$DebugPreference = "SilentlyContinue"   # Normal Mode
#>

# creates Sysmon config with all inputs disabled except specified type
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
    $xmlConfig += "`t<DnsLookup>False</DnsLookup>"
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

# stops sysmon, clears log file, merges new config, starts-sysmon
function reset-sysmon ($sysmonPath, $configpath)
{

    Write-Debug "uninstalling sysmon"
    Start-Process -FilePath $sysmonPath -ArgumentList @("-u","force") -NoNewWindow
    Start-Sleep -Seconds 1

    Write-Debug "installing sysmon"
    Start-Process -FilePath $sysmonPath -ArgumentList @("-i","-accepteula") -NoNewWindow
    Start-Sleep -Seconds 1

    Write-Debug "configuring sysmon"
    Start-Process -FilePath $sysmonPath -ArgumentList @("-c",$configpath) -NoNewWindow
    Start-Sleep -Seconds 1

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

<#

###############################################################################
# SYSMON_CREATE_PROCESS (EventID 1)
###############################################################################
$EventID = 1
$TestName = "SYSMON_CREATE_PROCESS"
$TestCount = 5
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    
    $Process = start-process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
    $FilterItems += $Process.Id
    Stop-Process -Id $Process.Id -ErrorAction stop            
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


###############################################################################
# SYSMON_FILE_TIME (EventID 2)
###############################################################################
$EventID = 2
$TestName = "SYSMON_FILE_TIME"
$TestCount = 5
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    
    $TemporaryFile = New-TemporaryFile
    (Get-Item -path $TemporaryFile.FullName).CreationTime=("08 March 2016 18:00:00")
    $FilterItems += [regex]::escape($TemporaryFile.FullName)
    Remove-Item -Path $TemporaryFile.FullName
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


###############################################################################
# SYSMON_NETWORK_CONNECT (EventID 3)
###############################################################################
$EventID = 3
$TestName = "SYSMON_NETWORK_CONNECT"
$TestCount = 5
write-host "Conducting `"$($TestName)`" test..."

# do a warm up run
$warmup = Test-NetConnection -ComputerName "www.google.com"

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    
    $blah = Invoke-WebRequest -Uri "www.google.com" -DisableKeepAlive
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
# SYSMON_SERVICE_STATE_CHANGE (EventID 4)
###############################################################################
$EventID = 4
$TestName = "SYSMON_SERVICE_STATE_CHANGE"
$TestCount = 5
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    
    Get-Service sysmon | Restart-Service
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


###############################################################################
# SYSMON_PROCESS_TERMINATE (EventID 5)
###############################################################################
$EventID = 5
$TestName = "SYSMON_PROCESS_TERMINATE"
$TestCount = 5
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete     
    $Process = start-process -FilePath "notepad.exe" -WindowStyle Hidden -PassThru
    $FilterItems += $Process.Id
    Stop-Process -Id $Process.Id -ErrorAction stop           
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


###############################################################################
# SYSMON_DRIVER_LOAD (EventID 5)
###############################################################################
$EventID = 6
$TestName = "SYSMON_DRIVER_LOAD"
$TestCount = 5
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$ProcessPath = "C:\Users\david\Downloads\Archive\SysinternalsSuite\notmyfault.exe"
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    
    $Process = start-process -FilePath $ProcessPath -ArgumentList @("/AcceptEula") -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 1
    Stop-Process -Id $Process.Id -ErrorAction stop -Force  
    Get-Service myfault | Stop-Service
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


###############################################################################
# SYSMON_IMAGE_LOAD (EventID 7)
###############################################################################
$EventID = 7
$TestName = "SYSMON_IMAGE_LOAD"
$TestCount = 5
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$ProcessPath = "c:\windows\notepad.exe"
$FilterItems = @()
for ($i = 1; $i -le $TestCount; $i++)
{ 
    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    
    $Process = start-process -FilePath $ProcessPath -WindowStyle Hidden -PassThru
    $FilterItems += $Process.Id
    Stop-Process -Id $Process.Id -ErrorAction stop 
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


# test table for events
<#
name                                value
----                                -----
[done]SYSMON_CREATE_PROCESS               1    
[done]SYSMON_FILE_TIME                    2    
[done]SYSMON_NETWORK_CONNECT              3    
[done]SYSMON_SERVICE_STATE_CHANGE         4    
[done]SYSMON_PROCESS_TERMINATE            5    
[done]SYSMON_DRIVER_LOAD                  6    
[done]SYSMON_IMAGE_LOAD                   7    
[todo]SYSMON_CREATE_REMOTE_THREAD         8    
[todo]SYSMON_RAWACCESS_READ               9    
[todo]SYSMON_ACCESS_PROCESS               10   
[todo]SYSMON_FILE_CREATE                  11   
[todo]SYSMON_REG_KEY                      12   
[todo]SYSMON_REG_SETVALUE                 13   
[todo]SYSMON_REG_NAME                     14   
[todo]SYSMON_FILE_CREATE_STREAM_HASH      15   
[todo]SYSMON_SERVICE_CONFIGURATION_CHANGE 16   
[todo]SYSMON_CREATE_NAMEDPIPE             17   
[todo]SYSMON_CONNECT_NAMEDPIPE            18   
[todo]SYSMON_WMI_FILTER                   19   
[todo]SYSMON_WMI_CONSUMER                 20   
[todo]SYSMON_WMI_BINDING                  21   
[todo]SYSMON_DNS_QUERY                    22   
[todo]SYSMON_FILE_DELETE                  23   

#>

#>

###############################################################################
# SYSMON_CREATE_REMOTE_THREAD (EventID 8)
# https://clymb3r.wordpress.com/2013/05/26/implementing-remote-loadlibrary-and-remote-getprocaddress-using-powershell-and-assembly/
###############################################################################
$EventID = 9
$TestName = "SYSMON_CREATE_REMOTE_THREAD"
$TestCount = 5
write-host "Conducting `"$($TestName)`" test..."

$configpath = make-sysmon-config -name $TestName -sysmonPath $sysmonPath
reset-sysmon -sysmonPath $sysmonpath -configpath $configpath

$FilterItems = @()
$ScriptPath = "C:\Users\David\Downloads\SYSMON_CREATE_REMOTE_THREAD.ps1"
$dll = "C:\Windows\System32\advapi32.dll"
$ProcessPath = "c:\windows\notepad.exe"

#Disable AV
Set-MpPreference -DisableRealtimeMonitoring $true -MAPSReporting Disabled

#Ensure PowerSploit is present
$ModulePath = "C:\Windows\system32\WindowsPowerShell\v1.0\Modules\PowerSploit"
if (!(Test-Path -Path $ModulePath)) {

    $url = "https://github.com/PowerShellMafia/PowerSploit/archive/master.zip"
    $download = "$($env:temp)\master.zip"
    if (Test-Path -Path $download) { Remove-Item -Path $download -Force -Recurse }
    write-host "-downloading latest project from $($url)."
    $Response = Invoke-WebRequest -Uri $url -OutFile $download

    # extract the compressed content (if local copy older than 20 hours)
    write-host "-extracting dataset archive."
    $extracted = "$($env:temp)\extracted"
    if (Test-Path -Path $extracted) { Remove-Item -Path $extracted -Force -Recurse }
    Expand-Archive -LiteralPath $download -DestinationPath $extracted -Force

    # copy the module
    Rename-Item -Path "$($extracted)\PowerSploit-master" -NewName "PowerSploit"
    Copy-Item -Path "$($extracted)\PowerSploit" -Destination $ModulePath -Recurse -Force

    # remove any marks of the web/streams
    Get-ChildItem -path $ModulePath -Recurse | Unblock-File
}

#Set PowerShell ExecutionPolicy is top allow execution of PowerSploit
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force

for ($i = 1; $i -le $TestCount; $i++)
{ 

    $pctComplete = [math]::round(($i / $TestCount)*100)
    Write-Progress -Activity "Conducting $($testname) test" -Status "$($pctComplete)% complete" -PercentComplete $pctComplete    
    $Process = start-process -FilePath $ProcessPath -WindowStyle Hidden -PassThru
    Start-Process -FilePath "Powershell.exe" -ArgumentList @("-version 2.0","-file $($ScriptPath)","-processid $($process.id)","-dll $($dll)") -Wait -WindowStyle Hidden
    $FilterItems += $Process.id
    Stop-Process -Id $process.id -Force
}
Write-Progress -Activity "Conducting $($testname) test" -Completed         

#Enable AV
Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Basic

#Reset PowerShell Execution Policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

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
