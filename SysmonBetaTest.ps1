# stop the sysmon service
stop-Service sysmon

# clear the event log
(New-Object System.Diagnostics.Eventing.Reader.EventLogSession).ClearLog("Microsoft-Windows-Sysmon/Operational")

Start-Process -FilePath "c:\windows\sysmon.exe" -ArgumentList "-c D:\sysmonconfig-test-noreverselookup.xml"

Start-Service sysmon

# wait 60 seconds for some network connections to occur
Start-Sleep -Seconds 60


# review the events
$events = Get-WInEvent -log "Microsoft-Windows-Sysmon/Operational"

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

# select the network connection events from content of log
$NetEvents = $Events | Where-Object {$_.id -eq "3"}

foreach ($item in $NetEvents) {

    # dynamically derive the reverse lookup type of concern based on whether the network connection was initated locally or remotely
    $reverse = ""

    if ($item.initiated -eq "false") { 
        $arpa = $item.sourceip -split "\."
    } else {
        $arpa = $item.DestinationIp -split "\."
    }

    $reverse = "$($arpa[3]).$($arpa[2]).$($arpa[1]).$($arpa[0])"   

    Add-Member -InputObject $item -MemberType NoteProperty -Force -Name  Reverse -Value $reverse


    # find nearest DNSQuery event referencing reverse lookup of concern and intiated by sysmon
    $EventsDetected = @()
    [array]$EventsDetected = $Events | ?{$_.id -eq "22" -and $_.QueryName -match $reverse -and $_.image -match "sysmon.exe" -and $_.RecordId -ge $item.RecordId} | Sort-Object -Property RecordID | Select-Object -First 1 -Property RecordID, UtcTime, Id, Image, QueryName, QueryResults, QueryStatus

    # if a match is found print details of the network connection and dns query events
    if ($EventsDetected.Count -eq 1) {

        write-host ""
        write-host "*******************************************************"
        write-host "Network connection with sysmon reverse lookup detected."
        write-host ""
        write-host "Network Connection:"
        $item | select RecordID, UTCTime, ID, Image, Initiated, Reverse, SourceIP, DestinationIP, SourceHostname, DestinationHostname
        write-host ""
        Write-Host "Sysmon Reverse Lookup:"
        $EventsDetected | select RecordID, UTCTime, ID, Image, QueryName, QueryResults, QueryStatus

    }

    $RecordIDDiff = $EventsDetected.recordid -$item.RecordId
    write-host "The count of events between Network Connection and DNSQuery was $($RecordIDDiff)."


}

