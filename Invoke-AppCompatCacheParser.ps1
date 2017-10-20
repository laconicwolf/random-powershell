#Lifted from https://github.com/davidhowell-tx/PS-WindowsForensics/blob/master/AppCompatCache/Invoke-AppCompatCacheParser.ps1

# Initialize Array to store our data
$EntryArray=@()
$AppCompatCache = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\AppCompatCache\' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty AppCompatCache
$MemoryStream = New-Object System.IO.MemoryStream(,$AppCompatCache)
$BinReader = New-Object System.IO.BinaryReader $MemoryStream
$UnicodeEncoding = New-Object System.Text.UnicodeEncoding
$ASCIIEncoding = New-Object System.Text.ASCIIEncoding
# The first 4 bytes of the AppCompatCache is a Header.  Lets parse that and use it to determine which format the cache is in.
$Header = ([System.BitConverter]::ToString($BinReader.ReadBytes(4))) -replace "-",""
# BADC0FEE in Little Endian Hex - Windows 7 / Windows 2008 R2

# Number of Entries at Offset 4, Length of 4 bytes
$NumberOfEntries = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
# Move BinReader to the Offset 128 where the Entries begin
$MemoryStream.Position=128
# Get some baseline info about the 1st entry to determine if we're on 32-bit or 64-bit OS
$Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
$MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
$Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
# Move Binary Reader back to the start of the entries
$MemoryStream.Position=128

for ($i=0; $i -lt $NumberOfEntries; $i++) {
    # Parse the metadata for the entry and add to a custom object
	$TempObject = "" | Select-Object -Property Name, Length, MaxLength, Padding, Offset0, Offset1, Time, Flag0, Flag1
	$TempObject.Length = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
	$TempObject.MaxLength = [System.BitConverter]::ToUInt16($BinReader.ReadBytes(2),0)
	$TempObject.Padding = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
	$TempObject.Offset0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
	$TempObject.Offset1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
	# calculate the modified date/time in this QWORD
	$TempObject.Time = [DateTime]::FromFileTime([System.BitConverter]::ToUInt64($BinReader.ReadBytes(8),0)).ToString("G")
	$TempObject.Flag0 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
	$TempObject.Flag1 = [System.BitConverter]::ToUInt32($BinReader.ReadBytes(4),0)
	# Use the Offset and the Length to read the File Name
	$TempObject.Name = ($UnicodeEncoding.GetString($AppCompatCache[$TempObject.Offset0..($TempObject.Offset0+$TempObject.Length-1)])) -replace "\\\?\?\\",""
	# Seek past the 16 Null Bytes at the end of the entry header
	# This is Blob Size and Blob Offset according to: https://dl.mandiant.com/EE/library/Whitepaper_ShimCacheParser.pdf
	$Nothing = $BinReader.ReadBytes(16)
	$EntryArray += $TempObject
}
$EntryArray | Format-Table -AutoSize -Property Name, Time, Flag0, Flag1