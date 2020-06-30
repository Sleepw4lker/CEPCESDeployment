Function Disable-IISKernelModeAuthentication {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Location = "Default Web Site"
    )

    begin {
        Import-Module WebAdministration
    }

    process {

        Write-Verbose "Disabling Kernel Mode Authentication for $Location"

        Try {
            Set-WebConfigurationProperty `
                -PSPath 'MACHINE/WEBROOT/APPHOST' `
                -Location $Location `
                -Filter "system.webServer/security/authentication/windowsAuthentication" `
                -Name "useKernelMode" `
                -Value "False"
                
        }
        Catch {
            Write-Warning -Message "Unable to disable Kernel Mode Authentication for $Location"
        }

    }

    end {}

}