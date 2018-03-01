Function Start-AutoRuns {
    
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath = "C:\QT\bin\autorunsc.exe"
    )

    Start-Process -FilePath $FilePath -ArgumentList "-a * -c -h" -RedirectStandardOutput autoruns.csv -WindowStyle Hidden
    Start-Sleep -Seconds 1
    Stop-Process -Name autorunsc

}


Function Edit-AutorunsCsv {

    param(

        [Parameter(Mandatory=$true)]
        [string]$InputCsvFilename,

        [Parameter(Mandatory=$true)]
        [string]$OutputCsvFilename
    )

    $reader = [System.IO.File]::OpenText($InputCsvFilename)
    $writer = New-Object System.IO.StreamWriter $OutputCsvFilename
    $counter = 1
    $targetHost = [system.environment]::MachineName
    for(;;) {
        $line = $reader.ReadLine()
        if ($null -eq $line) {
            break
        }
        $data = $line.Split(",")
        if ($counter -eq 1) {
            $writer.WriteLine('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17}', 
                              'Hostname',$data[0],$data[1],$data[2],$data[3],$data[4],$data[5],$data[6],$data[7],$data[8],$data[9],$data[10],$data[11],$data[12],$data[13],$data[14],$data[15],$data[16])
        }
        else {
            $writer.WriteLine('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14},{15},{16},{17}', 
                              $targetHost,$data[0],$data[1],$data[2],$data[3],$data[4],$data[5],$data[6],$data[7],$data[8],$data[9],$data[10],$data[11],$data[12],$data[13],$data[14],$data[15],$data[16])
        }
        $counter += 1
    }
    $reader.Close()
    $writer.Close()
}


Start-AutoRuns -FilePath C:\QT\bin\autorunsc.exe
Edit-AutorunsCsv -InputCsvFilename C:\QT\bin\autoruns.csv -OutputCsvFilename C:\QT\bin\autoruns_with_hostname1.csv