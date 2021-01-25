
<#
$DebugPreference = "Continue"           # Debug Mode
$DebugPreference = "SilentlyContinue"   # Normal Mode
#>

$TestDurationTotalSeconds = 120
$SysinternalsSuitePath = "$($env:userprofile)\Downloads\SysinternalsSuite"
$ProgramDataPath = "C:\ProgramData\SysmonBetaTest"
if (!(test-path -path $ProgramDataPath)) { New-Item -Path $ProgramDataPath -ItemType Directory | out-null }
$LogFile = "C:\ProgramData\SysmonBetaTest\activity.log"

function PoolMonSnap {
    $poshPoolmon = "$($env:userprofile)\Downloads\poolmon-powershell.ps1"
    if (Test-Path -Path $poshPoolmon) {
        $pool = & $poshPoolmon
        $pool | Out-File -Encoding ascii -FilePath "$($ProgramDataPath)\poolsnap.log"
    }
}

# merges new config, starts-sysmon
function reset-sysmon ($sysmonPath, $configpath)
{
    Write-Debug "configuring sysmon"
    $stdout = & $sysmonPath -c -- 2> $null
    Start-Sleep -Seconds 1
    $stdout = & $sysmonPath -c $configpath 2> $null
    Start-Sleep -Seconds 1
    PoolMonSnap
}

function format-splunktime {
    param (
        [parameter(Mandatory=$false)][datetime]$inputDate=(Get-Date)
    )

    $inputDateString = $inputDate.ToString('MM-dd-yyyy HH:mm:ss.fff zzzz')
    $inputDateParts = $inputDateString -split " "
    $inputDateZone = $inputDateParts[2] -replace ":",""
    $outputDateString  = "$($inputDateParts[0]) $($inputDateParts[1]) $($inputDateZone)"
    return $outputDateString
}

# Establish path to Sysmon
$sysmonPath = "$($env:windir)\sysmon.exe"
if (!(Test-Path -Path $sysmonPath)) {
    write-host "Sysmon.exe not present in $($sysmonPath). Exiting."
    exit
} 

PoolMonSnap

$TestConfigs = @("SYSMON_FILE_DELETE_Archive_ExcludeNothing.xml","SYSMON_FILE_DELETE_Archive_IncludeQuietFolder.xml","SYSMON_FILE_DELETE_Archive_IncludeNothing.xml")

$TestInstances = 4
# do TestInstances number of tests
for ($i = 1; $i -le $TestInstances; $i++)
{ 
    # Do test for each config
    foreach ($TestName in $TestConfigs) {

        ################################################################################
        # SYSMON_FILE_DELETE: EventCode=23 RuleName=FileDelete
        ################################################################################
        $ConfigPath = "C:\Users\admin\downloads\$($TestName)"

		$stdout = & $sysmonPath -c -- 2> $null
		Start-Sleep -Seconds 1
		$stdout = & $sysmonPath -c $configpath 2> $null
		Start-Sleep -Seconds 1

        $Message = "$(format-splunktime) TestName=`"$($TestName)`" TestDurationTotalSeconds=`"$($TestDurationTotalSeconds)`" TestStatus=`"Begin`""	
		$Message | Out-File -Encoding ascii -FilePath $LogFile -Append		
        write-host $Message


        $TestStart = (get-date) ; $TestCount = 0
        do
        {
            $TestCount++
            ###########################################################################
            # Payload:
            $TemporaryFile = New-TemporaryFile
            Add-Content -Value "Hello World!" -Path $TemporaryFile.FullName
            Remove-Item -Path $TemporaryFile.FullName -Force
            ###########################################################################
    
        } until ((New-TimeSpan -Start $TestStart).TotalSeconds -ge $TestDurationTotalSeconds)

		PoolMonSnap
		
        $Message = "$(format-splunktime) TestName=`"$($TestName)`" TestDurationTotalSeconds=`"$($TestDurationTotalSeconds)`" TestStatus=`"End`" TestCount=`"$($TestCount)`""	
		$Message | Out-File -Encoding ascii -FilePath $LogFile -Append		
        write-host $Message
        Start-Sleep -Seconds 5

    }
   
}

