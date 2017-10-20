$hexdata = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

# Breaks hexdata into hexidecimal chunks (49, 27, 6d, etc.)
$hexarray = $hexdata -split '(..)' | ? { $_ }

# Intializes an empty array to store the ascii message, loops through the hex array and converts to ascii
$ascii_message = @()
foreach($hexchar in $hexarray) {
    $ascii_message += @([char][Convert]::ToInt16($hexchar, 16))
}
$decoded = $ascii_message -join ''
$decoded

# Takes the ascii and converts to a byte array
$bytestring =  [System.Text.Encoding]::UTF8.GetBytes($decoded)

# Converts the byte array to base64
$base64string = [System.Convert]::ToBase64String($bytestring)
$base64string