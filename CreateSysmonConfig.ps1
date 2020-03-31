# Get sysmon schema into xml
$sysmonSchemaPrint = & sysmon.exe -s
$sysmonSchemaPrintXml = [xml]$sysmonSchemaPrint

# spit out a new template file
$events = $sysmonSchemaPrintXml.manifest.events.event | Where-Object {$_.name -notmatch "(SYSMON_ERROR|SYSMON_SERVICE_STATE_CHANGE|SYSMON_SERVICE_CONFIGURATION_CHANGE)"}


$xmlConfig = @()

$xmlConfig += "<Sysmon schemaversion=`"$($sysmonSchemaPrintXml.manifest.schemaversion)`">"
$xmlConfig += ""
$xmlConfig += "`t<DnsLookup>False</DnsLookup>"
$xmlConfig += ""
$xmlConfig += "`t<EventFiltering>"

foreach ($event in $events) {
    $printConfig = $true
    $xmlConfig += ""
    # print the section hearder listing ID (value), Description (template), and config file section id (rulename)
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

    if ($printConfig -eq $true) {
        $xmlConfig += ""
        $xmlConfig += "`t`t<RuleGroup name=`"$($event.rulename)_RG_001`" groupRelation=`"or`">"
        $xmlConfig += "`t`t`t<$($event.rulename) onmatch=`"include`">"
        $xmlConfig += "`t`t`t</$($event.rulename)>"
        $xmlConfig += "`t`t</RuleGroup>"
    }
}
$xmlConfig += ""
$xmlConfig += "`t</EventFiltering>"
$xmlConfig += ""
$xmlConfig += "</Sysmon>"



$xmlConfig | clip
