$outlook = "C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE"
if (-not(Test-Path -Path $outlook)) {
    write-host "missing path to file - $($outlook)."
    return
}

$toAddresses = @("security@microsoft.com")
$ccAddresses = @("hoppergb@microsoft.com")
$subject = "Background check for Hopper, Grace B."

$body = @"
(U) Please provide background check results for: Hopper, Grace B.
(U//FOUO) DOB - 12/09/1906
(U//FOUO) SSN - 867-42-5309
"@


if ($toAddresses) {
    $composition = "$($toAddresses -join ";")"
}

if ($ccAddresses) {
    $composition += "?cc=$($ccAddresses -join ";")" 
 }

 if ($subject) {     
    $composition += "&subject=$($subject)" 
}

if ($body) { 
    $composition += "&body=$($body)" 
}

& $outlook /c ipm.note /m $($composition)

