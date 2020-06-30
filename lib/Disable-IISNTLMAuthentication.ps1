Function Disable-IISNTLMAuthentication {

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

        Write-Verbose "Disabling NTLM Authentication for $Location"

        Try {

            Remove-WebConfigurationProperty `
                -PSPath 'MACHINE/WEBROOT/APPHOST' `
                -Location $Location `
                -Filter "system.webServer/security/authentication/windowsAuthentication/providers" `
                -Name "." `
                -AtElement @{value='Negotiate'}

            Add-WebConfigurationProperty `
                -PSPath 'MACHINE/WEBROOT/APPHOST' `
                -Location $Location `
                -Filter "system.webServer/security/authentication/windowsAuthentication/providers" `
                -Name "." `
                -Value @{value='Negotiate:Kerberos'}

        }
        Catch {
            Write-Warning -Message "Unable to disable NTLM Authentication for $Location"
        }

    }

    end {}

}