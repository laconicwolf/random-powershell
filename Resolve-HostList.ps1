# Resolve-HostList.ps1
# Takes a list of server names as input, attempts to resolve,
# and writes IP addresses to the screen and to a new file.

$infile = "LDAP_computers.txt"
$outfile = "host_ips.csv"

$hostlist = Get-Content $infile

$output = 
foreach ($hostname in $hostlist){
    Try {
        $addr = [System.Net.Dns]::GetHostByName($hostname)
    } 
    Catch [Exception] {
        Write-Host("Could not resolve: $hostname") -ForegroundColor Red
        Continue
    }
     
    Write-Host($addr.HostName, $addr.AddressList)
    Write-Output($addr.HostName, $addr.AddressList)
    $addr.HostName + ',' + $addr.AddressList | Add-Content $outfile
}

Write-Host("Results are written to $outfile") -ForegroundColor Green