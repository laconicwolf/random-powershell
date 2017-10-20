function Get-RecentDocs {

    $RecentDocs = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete"
    $RecentDocs.PSObject.Properties | ForEach-Object {
        $value = $_.Value
        $decoded_value = ([System.Text.Encoding]::Unicode.GetString($value)) 
        $decoded_value -replace '[^\u0020-\u007E]+', ''  
    }
}
Get-RecentDocs