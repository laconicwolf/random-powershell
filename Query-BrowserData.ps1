Import-Module PSSQLite
Import-Module ESENT

Function Query-ChromeData {

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $false)]
        $UserName = $env:USERNAME,

        [Parameter(Mandatory = $false)]
        $Search = '',

        [Parameter(Mandatory = $false)]
        [switch]
        $URLs

    )

    $Database = "C:\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"
    $data = @()

    if (-not (Test-Path -Path $Database)){
        Write-Verbose "[*] Could not find the Chrome History SQLite database for username: $UserName"
        return
    }

    if ($URLs -and $Search -ne '') {
        Invoke-SqliteQuery -DataSource $Database -Query "SELECT url FROM urls WHERE url LIKE '%$Search%'" | ForEach-Object {
            if ($_ -eq $null) {
                continue
            }
            if ($_.url.startswith('http') -and $_.url -match $Search) {
                $Key = $_
                $urlData = New-Object -TypeName PSObject -Property @{
                    User = $UserName
                    Browser = 'Chrome'
                    DataType = 'History'
                    Data = $_.url
                    }
                $data += $urlData
            }
        }
    }

    if ($URLs -and -not $Search) {
        Invoke-SqliteQuery -DataSource $Database -Query "SELECT url FROM urls" | ForEach-Object {
            if ($_ -eq $null) {
                continue
            }
            if ($_.url.startswith('http')) {
                $Key = $_
                $urlData = New-Object -TypeName PSObject -Property @{
                    User = $UserName
                    Browser = 'Chrome'
                    DataType = 'History'
                    Data = $_.url
                    }
                $data += $urlData
            }
        }
    }
    return $data
}

Function Query-FirefoxData {

    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $false)]
        $UserName = $env:USERNAME,

        [Parameter(Mandatory = $false)]
        $Search = '',

        [Parameter(Mandatory = $false)]
        [switch]
        $URLs

    )

    $Database = "C:\Users\$UserName\AppData\Roaming\mozilla\firefox\Profiles\*.default\places.sqlite"
    $Database = (Get-ChildItem -Path $Database).DirectoryName
    $Database = $Database + "\places.sqlite"
    $data = @()

    if (-not (Test-Path -Path $Database)){
        Write-Verbose "[*] Could not find the Firefox SQLite database for username: $UserName"
        return
    }

    if ($URLs -and $Search -ne '') {
        Invoke-SqliteQuery -DataSource $Database -Query "SELECT url FROM moz_places WHERE url LIKE '%$Search%'" | ForEach-Object {
            if ($_ -eq $null) {
                continue
            }
            if ($_.url.startswith('http') -and $_.url -match $Search) {
                $Key = $_
                $urlData = New-Object -TypeName PSObject -Property @{
                    User = $UserName
                    Browser = 'Firefox'
                    DataType = 'History'
                    Data = $_.url
                    }
                $data += $urlData
            }
        }
    }

    if ($URLs -and -not $Search) {
        Invoke-SqliteQuery -DataSource $Database -Query "SELECT url FROM moz_places" | ForEach-Object {
            if ($_ -eq $null) {
                continue
            }
            if ($_.url.startswith('http')) {
                $Key = $_
                $urlData = New-Object -TypeName PSObject -Property @{
                    User = $UserName
                    Browser = 'Firefox'
                    DataType = 'History'
                    Data = $_.url
                    }
                $data += $urlData
            }
        }
    }
    return $data
}

Function Query-InternetExplorerData {
    
    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $false)]
        $UserName = $env:USERNAME,

        [Parameter(Mandatory = $false)]
        $Search = '',

        [Parameter(Mandatory = $false)]
        [switch]
        $URLs

    )

    $Database = "C:\Users\$UserName\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat"
    if (-not (Test-Path -Path $Database)){
        Write-Verbose "[*] Could not find the Internet Explorer ESE database for username: $UserName"
        return
    }

    $DB = Get-ESEDatabase -Path $Database -LogPrefix "V01" -ProcessesToStop @("dllhost","taskhostw") -Force
    $data = @()

    if ($URLs -and $Search -ne '') {
        $DB.Rows.url | ForEach-Object {
            if ($_ -eq $null) {
                continue
            }
            if ($_.startswith('http') -and $_ -match $Search) {
                $Key = $_
                $urlData = New-Object -TypeName PSObject -Property @{
                    User = $UserName
                    Browser = 'IE'
                    DataType = 'History'
                    Data = $_
                    }
                $data += $urlData
            }
        }
    }

    if ($URLs -and -not $Search) {
        $DB.Rows.url | ForEach-Object {
            if ($_ -eq $null) {
                continue
            }
            if ($_.startswith('http')) {
                $Key = $_
                $urlData = New-Object -TypeName PSObject -Property @{
                    User = $UserName
                    Browser = 'IE'
                    DataType = 'History'
                    Data = $_
                    }
                $data += $urlData
            }
        }
    }
    return $data
}

Function Get-AllBrowserHistory {
    
    [CmdletBinding()]
    Param(

        [Parameter(Mandatory = $false)]
        $UserName = $env:USERNAME,

        [Parameter(Mandatory = $false)]
        $Search = '',

        [Parameter(Mandatory = $false)]
        [switch]
        $All

    )
    if ($Search -eq "") {
        Query-ChromeData -URLs
        Query-FirefoxData -URLs 
        Query-InternetExplorerData -URLs 
    }
    if ($Search -ne "") {
        Query-ChromeData -URLs -Search $Search
        Query-FirefoxData -URLs -Search $Search
        Query-InternetExplorerData -URLs -Search $Search
    }
}