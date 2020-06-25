Remove-WindowsFeature ADCS-Enroll-Web-Pol
Remove-WindowsFeature ADCS-Enroll-Web-Svc
Remove-WindowsFeature Web-Server
Remove-WindowsFeature RSAT-AD-PowerShell

Write-Warning -Message "Enrollment Server URLs for CES must be deleted manually!"
Write-Warning -Message "Rebooting in 15 Seconds, press Crtl-C to abort."

Start-Sleep -Seconds 15

Restart-Computer