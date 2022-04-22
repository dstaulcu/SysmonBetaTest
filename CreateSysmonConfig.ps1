$sysmonPath = "$($env:windir)\sysmon.exe"
if (!(Test-Path -Path $sysmonPath)) {
    write-host "Sysmon.exe not present in $($sysmonPath). Exiting."
    exit
} 

# Get sysmon schema into xml
$sysmonSchemaPrint = & $sysmonPath -s 2> $null | Select-String -Pattern "<"
$sysmonSchemaPrintXml = [xml]$sysmonSchemaPrint

# Stop if version is less than 4.22
if ($sysmonSchemaPrintXml.manifest.schemaversion -lt 4.22) {
    write-host "Sysmon.exe binary does not support schema version 4.22 or higher. Exiting."
    exit    
}

# spit out a new template file
$events = $sysmonSchemaPrintXml.manifest.events.event | Where-Object {$_.name -notmatch "(SYSMON_ERROR|SYSMON_SERVICE_STATE_CHANGE|SYSMON_SERVICE_CONFIGURATION_CHANGE)"}


$xmlConfig = @()
$xmlConfig += "<!--"
$xmlConfig += "  FILTERING: Filter conditions available for use are: $($sysmonSchemaPrintXml.manifest.configuration.filters.'#text')"
$xmlConfig += "  "
$xmlConfig += "  COMPOUND RULE GROUP EXAMPLE:"
$xmlConfig += "  <Rule groupRelation=`"and`" name=`"`">"
$xmlConfig += "     <ID condition=`"contains`">SomeValue</ID>"
$xmlConfig += "     <Description condition=`"contains`">SomeValue</Description>"
$xmlConfig += "  </Rule>"
$xmlConfig += "-->"
$xmlConfig += ""
$xmlConfig += "<Sysmon schemaversion=`"$($sysmonSchemaPrintXml.manifest.schemaversion)`">"
$xmlConfig += ""
if ($sysmonSchemaPrintXml.manifest.configuration.options.option.name -match "HashAlgorithms") { $xmlConfig += "`t<HashAlgorithms>*</HashAlgorithms>" }
if ($sysmonSchemaPrintXml.manifest.configuration.options.option.name -match "DnsLookup") { $xmlConfig += "`t<DnsLookup>False</DnsLookup>" }
if ($sysmonSchemaPrintXml.manifest.configuration.options.option.name -match "CheckRevocation") { $xmlConfig += "`t<CheckRevocation>False</CheckRevocation>" }
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
    if ($event.value -notmatch "^(255|4|16|12|13|16|17|19|20)$") {
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


write-host "sample sysmon config file added to clipboard!"
$xmlConfig | clip
