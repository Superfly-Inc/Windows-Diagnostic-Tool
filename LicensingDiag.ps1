Param(
        [Parameter(Position=1)]
        [switch]$Show = $false
        )

$OutputFile = Join-Path $env:USERPROFILE -ChildPath "\Desktop\LicensingDiag.txt"

$RunCmd =  Join-Path $env:SystemRoot -ChildPath "\system32\licensingdiag.exe -q"

$Date = Get-Date -UFormat "_%Y-%m-%d_"

$CabFile = $env:TEMP + "\" + $env:computername + $Date  + "diag.cab"

$Extracted = Join-Path $env:TEMP -ChildPath "\Extracted"

if (Test-Path($Extracted)) { Remove-Item $Extracted -Recurse -Force }
if (Test-Path($CabFile)) { Remove-Item $CabFile -Recurse -Force }
if (Test-Path($OutputFile)) { Remove-Item $OutputFile -Recurse -Force }

function MaskKey($PKey){

if ($Show -ne $true){

    $KeyArray = $PKey.Split('-')

    for ($x = 0; $x -lt $KeyArray.Count-1; $x++) {

       $KeyArray[$x] = "***** -"
      }
    return [string] $KeyArray
    }
else {
    return [string] $PKey
    }
}

function Get-WindowsKey ($encoded) {
$HexString = [Convert]::FromBase64String($encoded) | Format-Hex | Select-Object -Expand Bytes | ForEach-Object { '0x{0:x2}' -f $_ }

[string[]] $digitalProductId = $HexString[52..66]

New-Variable -Name base24 -Value 'BCDFGHJKMPQRTVWXY2346789' -Option Const
New-Variable -Name cryptedStringLength -Value 24 -Option Const
New-Variable -Name decryptionLength -Value 14 -Option Const
New-Variable -Name decryptedKey -Value ([System.String]::Empty)

$containsN = ($digitalProductId[$decryptionLength] -shr 3) -bAnd 1
$digitalProductId[$decryptionLength] = [System.Byte]($digitalProductId[$decryptionLength] -bAnd 0xF7)
for ($i = $cryptedStringLength; $i -ge 0; $i--)
{
$digitMapIndex = 0
for ($j = $decryptionLength; $j -ge 0; $j--)
{
$digitMapIndex = [System.Int16]($digitMapIndex -shl 8 -bXor $digitalProductId[$j])
$digitalProductId[$j] = [System.Byte][System.Math]::Floor($digitMapIndex / $base24.Length)
$digitMapIndex = [System.Int16]($digitMapIndex % $base24.Length)
}
$decryptedKey = $decryptedKey.Insert(0, $base24[$digitMapIndex])
}
if ([System.Boolean]$containsN)
{
$firstCharIndex = 0
for ($index = 0; $index -lt $cryptedStringLength; $index++)
{
if ($decryptedKey[0] -ne $base24[$index]) {continue}
$firstCharIndex = $index
break
}
$keyWithN = $decryptedKey
$keyWithN = $keyWithN.Remove(0, 1)
$keyWithN = $keyWithN.Substring(0, $firstCharIndex) + 'N' + $keyWithN.Remove(0, $firstCharIndex)
$decryptedKey = $keyWithN;
}
$returnValue = $decryptedKey
for ($t = 20; $t -ge 5; $t -= 5)
{
$returnValue = $returnValue.Insert($t, '-')
}
Return $returnValue
}

Invoke-Expression -Command $RunCmd | Out-Null

# create folder and extract cab file
New-Item $Extracted -Type directory | Out-Null

Invoke-Expression -Command ('expand -F:* $CabFile $Extracted') | Out-Null

#We now have 2 sub-dir's CLIP and SPP in $Extracted folder
[xml] $xmlSPPData = Get-Content (Join-Path $Extracted -ChildPath "\SPP\SppDiagReport.xml")

$OAKey = $xmlSPPData.DiagReport.LicensingData.OA3ProductKey

$xmlSPPData.DiagReport.LicensingData.OA3ProductKey = MaskKey($OAKey)

[xml] $xmlServerProps = $xmlSPPData.DiagReport.GenuineAuthz.ServerProps.Replace($OAKey,(MaskKey($OAKey)))

    foreach ($node in $xmlServerProps.genuineAuthorization.genuineProperties)
    {   
       $ServerProps = "`r`n" +  $node.InnerText
    }
   
    $xmlSPPData.DiagReport.GenuineAuthz.ServerProps = $ServerProps.Replace(';',"`r`n" )


#Create ArrayLists to store info from each folder
$CLIPInfo = New-Object System.Collections.ArrayList
$SPPInfo =  New-Object System.Collections.ArrayList

#Format XML 
$SPPInfo.Add('--------- Licensing Data ---------')

foreach ($nodes in $xmlSPPData.DiagReport.ChildNodes)
{
    foreach ($node in $nodes.ChildNodes )
    {   
        $SPPInfo.Add($node.Name + ": " + $node.InnerText)
    }
}

#Add H/W data
[xml] $xmlCLIP = Get-Content (Join-Path $Extracted -ChildPath "\CLIP\HardwareData.xml")
    
$CLIPInfo.Add(" `r`n" + "--------- Hardware Data ---------")

foreach ($nodes in $xmlCLIP.HardwareID.ChildNodes)
{   
    foreach ($node in $nodes)
    {
         $CLIPInfo.Add( "+" + $node.LocalName + ': ' + $node.path)

        foreach ($element in $node.ChildNodes)
        {
            if ($element.name.Contains('OSProductPfn')) {$OSProductPfn = $element.InnerText}
            if ($element.name.Contains('BackupProductKeyDefault')) { $element.InnerText = MaskKey($element.InnerText)}
            if ($element.name.Contains('LastBiosKey')) { $element.InnerText = MaskKey($element.InnerText)}
            if($Show -eq $true){
            if ($element.name -eq 'DigitalProductId') { $element.InnerText = Get-WindowsKey ($element.InnerText)}
            if ($node.LocalName -ccontains'LegacyHWID') {$element.InnerText =[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($element.InnerText)) -replace '[\W]', " "}
            if ($node.LocalName -ccontains 'SMBIOS') {$element.InnerText =[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($element.InnerText)) -replace '[\W]', " "   }
            }
            
            $CLIPInfo.Add("  " + $element.name + ": " + $element.InnerText)
        }
    }
}
#Add Event log data
$SPPInfo.Add(" `r`n" + "--------- SPP Event log data ---------")

$XPathSPP = "*[System[Provider[@Name='Microsoft-Windows-Security-SPP'] and (Level=2)]]"

#TO DO: 
#$XPathTask = "*[System[Provider[@Name='Microsoft-Windows-Security-SPP'] and EventID=1061]]"

$SPPEvents = Get-WinEvent -Path (Join-Path $Extracted -ChildPath '\SPP\SppDiagEvents.evtx') -FilterXPath $XPathSPP -ErrorAction Ignore

if ($SPPEvents.Count -ne 0) 
{
 foreach  ($SPPevent in $SPPEvents)
 {
    $SPPInfo.Add($SPPevent.Message)
 }
}
else 
{
 $SPPInfo.Add("No SPP event log errors found!")
}

$CLIPInfo.Add(" `r`n" + "--------- Clip Event log data ---------")

$XPathClip = "*[System[(EventID=116)]]" #These are only installed licences

$ClipEvents = Get-WinEvent -Path (Join-Path $Extracted -ChildPath '\CLIP\Client-Licensing.evtx') -FilterXPath $XPathClip -Oldest -ErrorAction Ignore

if ($ClipEvents.Count -ne 0) 
{
    foreach  ($ClipEvent in $ClipEvents)
    {
        if ($ClipEvent.Message.Contains("Microsoft.Windows.48"))
        {
            $CLIPInfo.Add($ClipEvent.Message) 
            $CLIPInfo.Add("Digital License acquired: " + $ClipEvent.TimeCreated.ToLongDateString())
        }
    }
}
else 
{
 $CLIPInfo.Add("No Digital License entries found!")
}

#Create the Output File with all gathered info
Set-Content -Path $OutputFile -Value $SPPInfo 
Add-Content -Path $OutputFile -Value $CLIPInfo

#Clean up
Remove-Item $CabFile -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:TEMP "\*.etl") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $Extracted -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item ($env:TEMP + "\WindowsPolicyData.xml") -Force -ErrorAction SilentlyContinue

Invoke-Expression $OutputFile

