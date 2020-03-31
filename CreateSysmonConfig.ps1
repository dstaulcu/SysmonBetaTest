# Get sysmon schema into xml
$sysmonSchemaPrint = & sysmon.exe -s
$sysmonSchemaPrintXml = [xml]$sysmonSchemaPrint

# get sysmon events defined in schema except those known to not allow rules processing
$events = $sysmonSchemaPrintXml.manifest.events.event | Where-Object {$_.name -notmatch "(SYSMON_ERROR|SYSMON_SERVICE_STATE_CHANGE|SYSMON_SERVICE_CONFIGURATION_CHANGE)"}

# initialize an array of lines
$xmlConfig = @()

# printer header rows
$xmlConfig += "<Sysmon schemaversion=`"$($sysmonSchemaPrintXml.manifest.schemaversion)`">"
$xmlConfig += ""

# todo:  add placeholders for other configs like HashingAlgorithm, etc.
$xmlConfig += "`t<DnsLookup>False</DnsLookup>"
$xmlConfig += ""

# print xml comments and sample rule for each event which is responsive to rules engine
$xmlConfig += "`t<EventFiltering>"
foreach ($event in $events) {
    $xmlConfig += ""
    
    # assume we want to print the rule group by default
    $printConfig = $true
    
    # print the section hearder listing ID (value), Description (template), and config file section id (rulename)
    $xmlConfig += "`t`t<!--SYSMON EVENT ID $($event.value) : $($event.template) [$($event.rulename)]-->"

    # gather the various fields for event id and print them within xml comment 
    $items = ""
    foreach ($item in $event.data | Select Name) {
        if ($items -eq "") {
            $items = "$($item.name)"
        } else {
            $items += ", $($item.name)"
        }        
    }
    $xmlConfig += "`t`t<!--DATA: $($items)-->"

    # for event codes, skip print of sample rule group
    if ($event.value -match "12|13|17|19|20") { $printConfig = $false}

    if ($printConfig -eq $true) {
        $xmlConfig += ""
        $xmlConfig += "`t`t<RuleGroup name=`"$($event.rulename)_RG_001`" groupRelation=`"or`">"
        $xmlConfig += "`t`t`t<$($event.rulename) onmatch=`"include`">"
        $xmlConfig += "`t`t`t</$($event.rulename)>"
        $xmlConfig += "`t`t</RuleGroup>"
    }
}

# close out the xml
$xmlConfig += ""
$xmlConfig += "`t</EventFiltering>"
$xmlConfig += ""
$xmlConfig += "</Sysmon>"

# throw the xml config into clipboard
$xmlConfig | clip
