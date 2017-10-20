# Retrieve-ShareList.ps1
# Takes a list of servers as input, enumerates shares via net view,
# and writes to a new file.

$infile = 'LDAP_computers.txt'
$outfile =  'share_names.txt'
$server_index = 1

$servers = Get-Content $infile
foreach($server in $servers) {
    Write-Host(($server_index -as [string]) + " of " + ($servers.Count -as [string]))
    $net_output = net view $server 2>$null
    if($net_output -eq $null) {
        Write-Host("No shares found on server: $server")
        $server_index ++
		Continue
    }
    if($net_output.GetValue(0) -match 'Shared Resources at') {
        $share_index = 7..($net_output.GetUpperBound(0) -2)
        foreach($i in $share_index) {
            $shares = $net_output.GetValue($i)
            if($shares.Contains("Disk") -eq 'true') {
                $pos = $shares.IndexOf("Disk")
                $share_name = $shares.Substring(0,$pos).Trim()
            }
            $share_path = '\\' + $server + '\' + $share_name
            Write-Host $share_path -ForegroundColor "Green"
            $share_path | Add-Content $outfile        
        }
    }    
    
    $server_index ++
}
