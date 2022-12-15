<#
note:  this must run as local admin

# clear existing audit policies - this could fire a notable to security teams if endpoiont is corporately managed
& auditpol /clear   

# enable detailed tracking success auditing to ensure windows security log will receive process creation events
& auditpol /set /category:"Detailed Tracking" /success:enable   
#>

$PollingFrequencySeconds = 5
$EventlogLookbackMilliseconds = $PollingFrequencySeconds * 1000 * 3
$LastRecordId = 0

# define xmlfilter to be interpreted by get-wineventlog inside of a here-string
$xmlfilter = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4688) and TimeCreated[timediff(@SystemTime) &lt;= &&&EventlogLookbackMilliseconds&&& ]]]</Select>
  </Query>
</QueryList>
"@

<#
$VerbosePreference = 'SilentlyContinue'    # write-verbose statements hidden
$VerbosePreference = 'Continue'            # write-verbose statements displayed
#>


# update substring in xml block used to filter get-wineventlog results. 
$xmlfilter = $xmlfilter -replace '&&&EventlogLookbackMilliseconds&&&',$($EventlogLookbackMilliseconds)

# initialize object to hold items relating to events
$Records = New-Object System.Collections.ArrayList

while ($true)
{

    $LookbackTime = (get-date).AddMilliseconds($EventlogLookbackMilliseconds * -1)
    write-verbose "$(get-date) - Checking for new events since $($LookbackTime) - [$($EventlogLookbackMilliseconds) ms ago]."
    
    # query the windows security eventlog applying the xmlfilter we constructed previously. sort results on recordid
    $NewEvents = Get-WinEvent -LogName "Security"  -FilterXPath $xmlfilter -ErrorAction SilentlyContinue | Sort-Object -Property RecordID 

    if ($NewEvents) {

        $NewEventCounter = 0

        foreach ($Event in $NewEvents) {

            # extract additional fields from xml portion of event message and add them as additional properties in newevents collection members.
            $eventXML = [xml]$Event.ToXml()            

            For ($i=0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {            
                Add-Member -InputObject $Event -MemberType NoteProperty -Force -Name  $eventXML.Event.EventData.Data[$i].name -Value $eventXML.Event.EventData.Data[$i].'#text'            
            } 

            # when we query the event log we look a little bit past the time of the last event we observed.  Only process events since last eventlog recordid we observed
            if ($Event.RecordId -gt $LastRecordId) {

                $NewEventCounter++

                # eventid 4688 in windows eventlog stores process id as hex, convert
                $NewProcessIdString = [convert]::tostring($event.NewPRocessId,10)

                write-verbose "$(get-date) - Found RecordID $($Event.RecordId) with TimeCreated $($Event.TimeCreated) where PID was $($NewProcessIdString) and new process name was $($Event.NewProcessName)."

                # Add items we care about to a dictionary
                $Record = [ordered]@{
                    TimeCreated = $Event.TimeCreated
                    RecordID = $Event.RecordId
                    NewProcessName = $Event.NewProcessName
                    NewProcessID = $NewProcessIdString
                    User = $Event.UserId
                }

                # Add dictionary item to collection
                $Records.Add([PSCustomObject]$Record) | Out-Null

                $LastRecordId = $Event.RecordId

            }
           
        }

        # summarize impact of changes we have observed
        write-host "$(get-date) - Found $($NewEventCounter) new processes in last polling interval.  There are $($records.count) process creation events in records cache."

        # group the observed events on new processid.  Returns Name, Count, and SubGroup members.
        $Groups = $Records | Group-Object -Property NewProcessID | ?{$_.count -gt 1}
        
        # if there are any groups with more than 1 member break and print members of first group instance.
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
