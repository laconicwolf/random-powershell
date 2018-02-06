Function _Get-RandomAgent {
    <#
    .DESCRIPTION
        Helper function that returns a random user-agent.
    #>

    $num = Get-Random -Minimum 1 -Maximum 5
    if($num -eq 1) {
        $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
    } 
    elseif($num -eq 2) {
        $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox
    }
    elseif($num -eq 3) {
        $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::InternetExplorer
    }
    elseif($num -eq 4) {
        $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::Opera
    }
    elseif($num -eq 5) {
        $ua = [Microsoft.PowerShell.Commands.PSUserAgent]::Safari
    }
    return $ua
}

Function Get-SiteInformation {
    <#
    .DESCRIPTION
        Reads a text file of URLs (one per line) and uses Invoke-WebRequests to 
        attempt to visit the each URL. Returns information regarding any
        redirect, the site Title (if <title> tags are present), and Server type
        (if the server header is present). 
         
    .PARAMETER UrlFile
        Mandatory. The file path to the text file containing URLs, one per line.

    .PARAMETER Proxy
        Optional. Send requests through a specified proxy. 
        Example: -Proxy http://127.0.0.1:8080
    
    .PARAMETER CSV
        Optional. Write the output to a CSV file. Will append if the filepath 
        specified already exists.
        
    .PARAMETER RandomAgent
        Optional. Change the User-Agent each request.
        
    .PARAMETER Info
        Optional. Increase output verbosity. 

    .EXAMPLE
        PS C:\> Get-SiteInformation -UrlFile urls.txt -CSV results.csv
        
        Title       URL                        Server   RedirectURL            
        -----       ---                        ------   -----------            
        LAN         192.168.0.1                         http://192.168.0.1     
        LAN         https://192.168.0.1/                                       
        LaconicWolf http://www.laconicwolf.net AmazonS3 http://laconicwolf.net/
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        $UrlFile,
    
        [Parameter(Mandatory = $false)]
        $Proxy,
    
        [Parameter(Mandatory = $false)]
        $CSV,
        
        [Parameter(Mandatory = $false)]
        [switch]
        $RandomAgent,

        [Parameter(Mandatory = $false)]
        [switch]
        $Info
    )

# ignore HTTPS certificate warnings
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

    # add error checking for file
    $URLs = Get-Content $UrlFile
    
    # initializes an empty array to store data
    $Data = @()
    foreach ($URL in $URLs) {

        # initializes an empty array to store data for each indivual site
        $SiteData = @()

        # sets a user-agent
        if ($RandomAgent) {
            $UserAgent = _Get-RandomAgent
        }
        else{
            $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox
        }

        if ($Info) {Write-Host "`n[*] Checking $URL"}

        if ($Proxy) {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method Get -Proxy $Proxy
            }
            Catch {
                if ($Info) {"[-] Unable to connect to $URL"}
                continue
            }
        }
        else {
            Try {
                $Response = Invoke-WebRequest -Uri $URL -UserAgent $UserAgent -Method Get
            }
            Catch {
                if ($Info) {"[-] Unable to connect to $URL"}
                continue
            }
        }

        if ($Response.BaseResponse.ResponseUri.OriginalString -ne $URL) {
            $RedirectedUrl = $Response.BaseResponse.ResponseUri.OriginalString
        }
        else {
            $RedirectedUrl = ""
        }

        if ($Response.ParsedHtml.title) {
            $Title = $Response.ParsedHtml.title
        }
        else {
            $Title = ""
        } 

        if ($Response.Headers.ContainsKey('Server')) {
            $Server = $Response.Headers.Server
        }
        else {
            $Server = ""
        }

        $SiteData += New-Object -TypeName PSObject -Property @{
                                        "URL" = $URL
                                        "RedirectURL" = $RedirectedUrl
                                        "Title" = $Title
                                        "Server" = $Server
                                        }
        if ($Info) {$SiteData | Format-Table}
        $Data += $SiteData
    }

    $Data

    if ($CSV) {
        "url,redir,title,server,notes" | Out-File -FilePath $CSV -Append -Encoding utf8
        foreach($item in $SiteData) {
            $item.URL + "," + $item.RedirectURL + "," + $item.Title + "," + $item.Server | Out-File -FilePath $CSV -Append -Encoding utf8
        }
    }
}