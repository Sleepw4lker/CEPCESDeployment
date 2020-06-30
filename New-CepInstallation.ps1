$Script:BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# Loading all Libary Scripts we depend on
Get-ChildItem -Path "$Script:BaseDirectory\lib" -Filter *.ps1 | ForEach-Object {
    . ($_.FullName)
}

New-CepDeployment `
    -SSLCertificate (Get-ChildItem -Path Cert:\LocalMachine\my\56CC9EEDFB282E91F2BC4C89D843677ED1D8E278) `
    -FriendlyName "ADCS Labor CEP" `
    -Alias "cep.adcslabor.de" `
    -ServiceGMSA "INTRA\gmsa_CEP$" `
    -AuthenticationType Username,Kerberos,Certificate `
    -Keybasedrenewal