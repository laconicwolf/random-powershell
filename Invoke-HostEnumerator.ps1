<#
.SYNOPSIS
Runs a number of commands to enumerate a system. The output is designed to allow it to be used with the Export-Csv Cmdlet so you can analyze the output of multiple systems.

Author: Jake Miller (credit to Beau Bullock's Invoke-HostRecon for the idea and many of the commands.)
Warning: Code is provided as is and the author take no responsibility for anything bad that happens if you execute this code. Use at your own risk.

.DESCRIPTION
Runs a number of commands to enumerate a system. The output is designed to allow it to be used with the Export-CSV Cmdlet so you can analyze the output of multiple systems

.EXAMPLE
PS > Invoke-HostEnumerator | Export-Csv test.csv -NoTypeInformation -Append

[*] Getting Domain Name...

MyDomain.local

[*] Getting Hostname...

MyBox

[*] Getting IP Address Info...

.EXAMPLE
PS > Invoke-Command -FilePath .\Invoke-HostEnumerator.ps1 | Export-Csv host_details.csv -NoTypeInformation -Append
#> 

function Invoke-HostEnumerator {

    Write-Host "`n[*] Getting Domain Name...`n" -ForegroundColor Cyan
    $domain = $env:USERDOMAIN
    Write-Host $domain

    Write-Host "`n[*] Getting Hostname...`n" -ForegroundColor Cyan
    $hostname = $env:COMPUTERNAME
    Write-Host $hostname

    Write-Host "`n[*] Getting IP Address Info...`n" -ForegroundColor Cyan
    $ipinfo = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True'| Select-Object IPAddress,Description | Format-Table -Wrap | Out-String
    Write-Host $ipinfo

    Write-Host "`n[*] Enumerating Local Users...`n" -ForegroundColor Cyan
    $locals = (Get-WmiObject -Class Win32_UserAccount -Filter  "LocalAccount='True'").Name
    Write-Host $locals

    Write-Host "`n[*] Enumerating Local Administrators...`n" -ForegroundColor Cyan
    $admingroup = get-wmiobject win32_group -Filter “LocalAccount=True AND SID='S-1-5-32-544'"
    $query=”GroupComponent = `”Win32_Group.Domain='” + $admingroup.Domain + “‘,NAME='” + $admingroup.Name + “‘`””
    $admincomponents = (Get-WmiObject win32groupuser -Filter $query).PartComponent
    foreach($admincomponent in $admincomponents) {
        $localadmins += @($admincomponent.split('=')[2].split('"')[1])
    }
    Write-Host $localadmins

    Write-Host "`n[*] Enumerating Shares...`n" -ForegroundColor Cyan
    $shares = @()
    $shares = Get-WmiObject -Class Win32_Share | Format-Table -Wrap | Out-String
    Write-Host $shares

    Write-Host "`n[*] Determining Active Network Connections...`n" -ForegroundColor Cyan
    $TCPProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()            
    $Connections = $TCPProperties.GetActiveTcpConnections()            
    $objarray = @()
    foreach($Connection in $Connections) {            
        if($Connection.LocalEndPoint.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }            
            $OutputObj = New-Object -TypeName PSobject            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $Connection.LocalEndPoint.Address            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "LocalPort" -Value $Connection.LocalEndPoint.Port            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "RemoteAddress" -Value $Connection.RemoteEndPoint.Address            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "RemotePort" -Value $Connection.RemoteEndPoint.Port            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "State" -Value $Connection.State            
            $OutputObj | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType            
            $objarray += $OutputObj
        }
        $activeconnections = $objarray | Format-Table -Wrap | Out-String
    Write-Host $activeconnections

    Write-Host "`n[*] Determining Active TCP Listeners...`n" -ForegroundColor Cyan      
    $ListenConnections = $TCPProperties.GetActiveTcpListeners()            
    $objarraylisten = @()
    foreach($Connection in $ListenConnections) {            
        if($Connection.address.AddressFamily -eq "InterNetwork" ) { $IPType = "IPv4" } else { $IPType = "IPv6" }                 
            $OutputObjListen = New-Object -TypeName PSobject            
            $OutputObjListen | Add-Member -MemberType NoteProperty -Name "LocalAddress" -Value $connection.Address            
            $OutputObjListen | Add-Member -MemberType NoteProperty -Name "ListeningPort" -Value $Connection.Port            
            $OutputObjListen | Add-Member -MemberType NoteProperty -Name "IPV4Or6" -Value $IPType            
            $objarraylisten += $OutputObjListen 
        }
        $listeners = $objarraylisten | Format-Table -Wrap | Out-String
    Write-Host $listeners

    Write-Host "`n[*] Gathering the Contents of the DNS Cache...`n" -ForegroundColor Cyan  
    try {
        $dnscache = Get-WmiObject -query "Select * from MSFT_DNSClientCache" -Namespace "root\standardcimv2" -ErrorAction stop | Select-Object Entry,Name,Data | Format-Table -Wrap | Out-String
        Write-Host $dnscache
    }
    catch {
        $dnscache = "Unable to retrieve the DNS cache content"
        Write-Host $dnscache
    }

    Write-Host "`n[*] Gathering List of Scheduled Tasks...`n" -ForegroundColor Cyan
    $schedule = new-object -com("Schedule.Service")
    $schedule.connect() 
    $tasks = $schedule.getfolder("\").gettasks(0) | Select-Object Name | Format-Table -Wrap | Out-String
    If ($tasks.count -eq 0) {
        $tasks =  "Task scheduler appears to be empty"
        Write-Host $tasks
    }
    Else {
        $tasks
    }

    Write-Host "`n[*] Determining whether a Proxy is in use...`n" -ForegroundColor Cyan
    $proxyenabled = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyEnable
    $proxyserver = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyServer
    If ($proxyenabled -eq 1) {
        $proxy = "A system proxy appears to be enabled."
    }
    Elseif($proxyenabled -eq 0) {
        $proxy = "There does not appear to be a system proxy enabled."
    }
    Write-Host $proxy

    Write-Host "`n[*] Checking if AV is installed...`n" -ForegroundColor Cyan
    $AV = Get-WmiObject -Namespace "root\SecurityCenter2" -Query "SELECT * FROM AntiVirusProduct" 
    If ($AV -ne "") {
        $AV_name = $AV.displayName
    }
    If ($AV -eq "") {
        $AV_name = "No AV detected."
    }
    Write-Host $AV_name

    Write-Host "`n[*] Obtaining local firewall status...`n" -ForegroundColor Cyan
    $firewallstatus = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$env:COMPUTERNAME).OpenSubKey("System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile").GetValue("EnableFirewall")
    If($firewallstatus -eq 1) {
        $firewall =  "The local firewall appears to be enabled."
    }
    If($firewallstatus -ne 1) {
        $firewall = "The local firewall appears to be disabled."
    }
    Write-Host $firewall

    Write-Host "`n[*] Checking for Local Admin Password Solution (LAPS)...`n" -ForegroundColor Cyan
    try {
        $lapsfile = Get-ChildItem 'C:\Program Files\LAPS\CSE\Admpwd.dll' -ErrorAction Stop
        if ($lapsfile) {
            $laps = "The LAPS DLL (Admpwd.dll) was found. Local Admin password randomization may be in use."
            }
        }
    catch {
        $laps = "The LAPS DLL was not found."
        }
    Write-Host $laps

    Write-Host "`n[*] Enumerating Processes...`n" -ForegroundColor Cyan
    $processes = Get-Process | Select-Object ProcessName, Id, Description, Path
    Write-Host $processes

    $properties = @{
        Processes = @($processes | Out-String).Trim()
        LAPS = @($laps | Out-String).Trim()
        FirewallStatus = @($firewall | Out-String).Trim()
        SharedDrives = @($shares | Out-String).Trim()
        AntiVirus = @($AV_name | Out-String).Trim()
        Proxy = @($proxy | Out-String).Trim()
        ScheduledTasks = @($tasks | Out-String).Trim()
        DNSCache = @($dnscache | Out-String).Trim()
        ActiveNetworkListeners = @($listeners | Out-String).Trim()
        ActiveNetworkConnections = @($activeconnections | Out-String).Trim()
        LocalAdmins = @($localadmins | Out-String).Trim()
        LocalUsers = @($locals | Out-String).Trim()
        Domain = @($domain | Out-String).Trim()
        Hostname = @($hostname | Out-String).Trim()
        IPAddressInfo = @($ipinfo | Out-String).Trim()
    }

    $csv_obj = New-Object PSObject -Property $properties

    return $csv_obj

}