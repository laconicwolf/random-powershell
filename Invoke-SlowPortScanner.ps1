# Invoke-SlowPortScanner.ps1
# Takes a file of IP addresses and a file of ports to be scanned as parameters.
# Pings the hosts to see if they are up and writes alive hosts to alive_hosts.txt.
# If hosts are alive it attempts a to connect via TCP on the ports specificied,
# in the port file, and writes the open ports to a file.

function Invoke-SlowPortScanner {
    
    [CmdletBinding()]
    param(
    [Parameter()]
    $IpAddressFile,

    [Parameter()]
    $PortFile
    )

    $upfile = "alive_hosts.txt"
    $open_ports_file = "scan_results.txt"
    $ip_list = Get-Content($IpAddressFile)
    $port_list = Get-Content($PortFile)

    foreach($ip in $ip_list) {
        if(Test-Connection -BufferSize 32 -Count 1 -Quiet -ComputerName $ip -ErrorAction SilentlyContinue) {
            Write-Host("$ip is up")
            $ip | Add-Content $upfile
            foreach($port in $port_list) {
                try {
                    $socket = New-Object System.Net.Sockets.TcpClient($ip, $port)
                }
                Catch [Exception] {
                    Continue
                }
                if($socket.Connected) {
                    Write-Host("$ip is listening on port $port") -ForegroundColor Green
                    "$ip : $port" | Add-Content $open_ports_file
                    $socket.Close()
                }
            }
        }
        else {
            Write-Host("$ip did not respond to ping...") -ForegroundColor Gray
        }
    }
}