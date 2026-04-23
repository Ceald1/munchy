Get-WinEvent -FilterHashTable @{
    LogName = 'Security'
    ID = 4662
} | Where-Object {
    $_.Message -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or 
    $_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
} | Select-Object TimeCreated, @{
    Name = 'User'; Expression = {$_.Properties[5].Value}
}, @{
    Name = 'Object'; Expression = {$_.Properties[8].Value}
} | Format-Table -AutoSize

