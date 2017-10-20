function Get-HeXor($hexdata1, $hexdata2) {
    <#takes two equal-length buffers and 
    produces their XOR combination#>

    # Breaks hexdata into hexidecimal chunks (1c, 01, 11, etc.)
    $hexarray1 = $hexdata1 -split '(..)' | ? { $_ }
    $hexarray2 = $hexdata2 -split '(..)' | ? { $_ }

    # Converts each hex array character to byte array
    $dec1 = @()
    foreach($hexchar1 in $hexarray1) {
        $dec1 += @([int][Convert]::ToInt16($hexchar1, 16))   
    }

    $dec2 = @()
    foreach($hexchar2 in $hexarray2) {
        $dec2 += @([int][Convert]::ToInt16($hexchar2, 16))  
    }

    # Loops thru each byte array, performs the XOR, and returns the XOR'd hex
    $hexxor = @()
    for($i=0; $i -lt $dec1.count ; $i++)
    {
        $xor = $dec1[$i] -bxor $dec2[$i]
        $hexxor += @([convert]::tostring($xor,16))
    }
    $hexxor -join ''
}
Get-HeXor '1c0111001f010100061a024b53535009181c' '686974207468652062756c6c277320657965'