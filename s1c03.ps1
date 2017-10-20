function Convert-HexStringToByteArray
{
################################################################
#.Synopsis
# Convert a string of hex data into a System.Byte[] array. An
# array is always returned, even if it contains only one byte.
#.Parameter String
# A string containing hex data in any of a variety of formats,
# including strings like the following, with or without extra
# tabs, spaces, quotes or other non-hex characters:
# 0x41,0x42,0x43,0x44
# \x41\x42\x43\x44
# 41-42-43-44
# 41424344
# The string can be piped into the function too.
################################################################
[CmdletBinding()]
Param ( [Parameter(Mandatory = $True, ValueFromPipeline = $True)] [String] $String )
 
#Clean out whitespaces and any other non-hex crud.
$String = $String.ToLower() -replace '[^a-f0-9\\,x\-\:]',"
 
#Try to put into canonical colon-delimited format.
$String = $String -replace '0x|\x|\-|,',':'
 
#Remove beginning and ending colons, and other detritus.
$String = $String -replace '^:+|:+$|x|\',"
 
#Maybe there's nothing left over to convert...
if ($String.Length -eq 0) { ,@() ; return }
 
#Split string with or without colon delimiters.
if ($String.Length -eq 1)
{ ,@([System.Convert]::ToByte($String,16)) }
elseif (($String.Length % 2 -eq 0) -and ($String.IndexOf(":") -eq -1))
{ ,@($String -split '([a-f0-9]{2})' | foreach-object { if ($_) {[System.Convert]::ToByte($_,16)}}) }
elseif ($String.IndexOf(":") -ne -1)
{ ,@($String -split ':+' | foreach-object {[System.Convert]::ToByte($_,16)}) }
else
{ ,@() }
#The strange ",@(...)" syntax is needed to force the output into an
#array even if there is only one element in the output (or none).
}

# http://www.data-compression.com/english.html
$CHARACTER_FREQ = @{
    'a'= 0.0651738; 'b'= 0.0124248; 'c'= 0.0217339; 'd'= 0.0349835; 'e'= 0.1041442; 'f'= 0.0197881; 'g'= 0.0158610;
    'h'= 0.0492888; 'i'= 0.0558094; 'j'= 0.0009033; 'k'= 0.0050529; 'l'= 0.0331490; 'm'= 0.0202124; 'n'= 0.0564513;
    'o'= 0.0596302; 'p'= 0.0137645; 'q'= 0.0008606; 'r'= 0.0497563; 's'= 0.0515760; 't'= 0.0729357; 'u'= 0.0225134;
    'v'= 0.0082903; 'w'= 0.0171272; 'x'= 0.0013692; 'y'= 0.0145984; 'z'= 0.0007836; ' '= 0.1918182
}

function Get-EnglishScore($input_bytes) {
    <#Returns a score which is the sum of the probabilities
    in how each letter of the input data appears in the 
    English language. Uses the above probabilities.#>

    # Converting string to character array to loop thru each character
    $input_bytes = [char[]]$input_bytes

    $score = 0

    foreach($byte in $input_bytes) {
        
        # Coverting each character to string so it can be looked up in hash table
        $byte = [string]$byte
        $score += $CHARACTER_FREQ.Get_Item($byte)
    }
    return $score
}
function Get-SingleCharXor($input_bytes, $key_value) {
    <#XORs every byte of the input with the given
    key_value and returns the result.#>

    $hexoutput = @()

    foreach($char in $input_bytes) {
        $output = ($char -bxor $key_value)

        # Convert bytes back to ascii
        $ascii += @([char][Convert]::ToInt16($output, 10))
    }
    
    $ascii_output = $ascii -join ''
    return $ascii_output
}

function Get-SingleCharXorBruteForce($ciphertext) {
    <#Tries every possible byte for the single-char key, 
    decrypts the ciphertext with that byte and computes 
    the english score for each plaintext. The plaintext 
    with the highest score is likely to be the one decrypted 
    with the correct value of key.#>
    $candidates = @()

    foreach($key_candidate in 1..256){
        $plaintext_candidate = Get-SingleCharXor $ciphertext $key_candidate
        $candidate_score = Get-EnglishScore($plaintext_candidate)

        $result = @{
            'key' = $key_candidate;
            'score' = $candidate_score;
            'plaintext' = $plaintext_candidate
        }

        $candidates += $result
    }
    return $candidates
}

$ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736" | Convert-HexStringToByteArray #https://cyber-defense.sans.org/blog/2010/02/11/powershell-byte-array-hex-convert/

$possible_solutions = Get-SingleCharXorBruteForce($ciphertext)

$high_score = $possible_solutions.score | Sort-Object -Descending | Select-Object -First 1

foreach($item in $possible_solutions){
    if($item.score -eq $high_score) {
        Write-Output $item
    }
}
