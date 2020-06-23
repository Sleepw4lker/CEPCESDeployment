Function Disable-IISKernelModeAuthentication {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Location = "Default Web Site"
    )

    begin {
        #Import-Module WebAdministration
    }

    process {

        $Filter = "/system.webServer/security/authentication/windowsAuthentication"
        $Name = "useKernelMode"

        Write-Verbose "Disabling Kernel Mode Authentication for $Location"

        Try {
            Set-WebConfigurationProperty `
                -Filter $Filter `
                -Name $Name `
                -Value "False" `
                -PSPath IIS: `
                -Location $Location
        }
        Catch {
            Write-Verbose -Message "Unable to disable Kernel Mode Authentication for $Location"
        }

    }

    end {}

}