$EntryArray=@()
$MRUList = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatCache\' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AppCompatCache
$MemoryStream = New-Object System.IO.MemoryStream(,$MRUList)
$BinReader = New-Object System.IO.BinaryReader $MemoryStream
$UnicodeEncoding = New-Object System.Text.UnicodeEncoding
$ASCIIEncoding = New-Object System.Text.ASCIIEncoding
# The first 4 bytes of the AppCompatCache is a Header.  Lets parse that and use it to determine which format the cache is in.
$Header = ([System.BitConverter]::ToString($BinReader.ReadBytes(4))) -replace "-",""