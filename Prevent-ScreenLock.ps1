# Prevent-ScreenLock.ps1
# Simulates user interaction through sendkeys.
# Mostly adapted from https://dmitrysotnikov.wordpress.com/2009/06/29/prevent-desktop-lock-or-screensaver-with-powershell/
# Open up notepad and click into it and sendkeys will write the remaining time the script will run in minutes.

$runtime_minutes = 1..480
$input_sender = New-Object -ComObject "Wscript.Shell"

foreach($minute in $runtime_minutes) {
    Start-Sleep -Seconds 60
    $time_remaining = ($runtime_minutes[-1] - ($minute))
    $input_sender.sendkeys($time_remaining.ToString() + "`n")
}