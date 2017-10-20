function Get-RecentItems {
    
    [cmdletbinding()]
    Param()

    foreach($user in (Get-ChildItem "$env:SystemDrive\Users")) {
        $recentpath = "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Recent\"
        $recentdocs = Get-childItem $recentpath
        foreach($doc in $recentdocs){
            $filepath = $recentpath + $doc
            $sh = New-Object -ComObject WScript.Shell 
            $target = $sh.CreateShortcut($filepath).TargetPath
            $target
        }
    }
}
