
function Invoke-RepeatingKeyXor($plaintext, $key) {
    <#Implements the repeating key XOR encryption#>
    $ciphertext = ''
    $bytearray = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $i = 0

    foreach($byte in $bytearray) {
        $xor = ($byte -bxor $key[$i])
        $xor =  [convert]::tostring($xor,16)
        $ciphertext += $xor

        # Cycle i to point to the next byte of the key
        $i = $i + 1 
        if($i -eq $key.length) {
            $i = 0
        }
    }
    return $ciphertext
}

$message = "Burning 'em, if you ain't quick and nimble`nI go crazy when I hear a cymbal"
$key = 'ICE'
$cipher = Invoke-RepeatingKeyXor $message $key
$cipher