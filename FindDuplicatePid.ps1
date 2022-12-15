<#
& auditpol /clear
& auditpol /set /category:"Detailed Tracking" /success:enable
#>

$PollingFrequencySeconds = 5
$EventlogLookbackMilliseconds = $PollingFrequencySeconds * 1000 * 3
$LastRecordId = 0

$xmlfilter = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4688) and TimeCreated[timediff(@SystemTime) &lt;= &&&PollingFrequencySeconds&&& ]]]</Select>
  </Query>
</QueryList>
"@

<#
$VerbosePreference = 'SilentlyContinue'
$VerbosePreference = 'Continue'
#>



$xmlfilter = $xmlfilter -replace '&&&PollingFrequencySeconds&&&',$($PollingFrequencySeconds*1000*2)

$Records = New-Object System.Collections.ArrayList


while ($true)
{

    $LookbackTime = (get-date).AddMilliseconds($EventlogLookbackMilliseconds * -1)
    write-verbose "$(get-date) - Checking for new events since $($LookbackTime) - [$($EventlogLookbackMilliseconds) ms ago]."
    $NewEvents = Get-WinEvent -LogName "Security"  -FilterXPath $xmlfilter -ErrorAction SilentlyContinue | Sort-Object -Property RecordID 

    if ($NewEvents) {

        $NewEventCounter = 0

        foreach ($Event in $NewEvents) {

            $eventXML = [xml]$Event.ToXml()            

            For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {            
                Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name  $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'            
            } 

            if ($Event.RecordId -gt $LastRecordId) {

                $NewEventCounter++

                $NewProcessIdString = [convert]::tostring($event.NewPRocessId,10)

                write-host "$(get-date) - Found RecordID $($Event.RecordId) with TimeCreated $($Event.TimeCreated) where PID was $($NewProcessIdString) and new process name was $($Event.NewProcessName)." -ForegroundColor Green

                $Record = [ordered]@{
                    TimeCreated = $Event.TimeCreated
                    RecordID = $Event.RecordId
                    NewProcessName = $Event.NewProcessName
                    NewProcessID = $NewProcessIdString
                    User = $Event.UserId
                }

                $Records.Add([PSCustomObject]$Record) | Out-Null

                $LastRecordId = $Event.RecordId

            }
           
        }

        # summartize the recordset we have accumulated

        write-verbose "$(get-date) - Found $($NewEventCounter) new processes in last polling interval!  There are $($records.count) process creation events in records cache."

        $Groups = $Records | Group-Object -Property NewProcessID | ?{$_.count -gt 1}

        if ($Groups.count -gt 0) {
            write-host "$(get-date) - Found a process id that exists more than once in records cache. Exiting"
            $Groups[0].Group
            break }

    } else {
        write-verbose "$(get-date) - No new events were found in lookback period."
    }

    write-verbose "$(get-date) - Sleeping for $($PollingFrequencySeconds) seconds..."
    Start-Sleep -Seconds $PollingFrequencySeconds
} 
