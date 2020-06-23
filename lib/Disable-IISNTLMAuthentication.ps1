Function Disable-IISNTLMAuthentication {

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

        Write-Verbose "Disabling NTLM Authentication for $Location"

        Try {
            Add-WebConfigurationProperty `
                -PSPath 'MACHINE/WEBROOT/APPHOST' `
                -Location $Location `
                -Filter "system.webServer/security/authentication/windowsAuthentication/providers" `
                -Name "." `
                -Value @{value='Negotiate:Kerberos'}
            
            Remove-WebConfigurationProperty `
                -PSPath 'MACHINE/WEBROOT/APPHOST' `
                -LÖocation $Location `
                -Filter "system.webServer/security/authentication/windowsAuthentication/providers" `
                -Name "." `
                -AtElement @{value='Negotiate'}
        }
        Catch {
            Write-Verbose -Message "Unable to disable NTLM Authentication for $Location"
        }

    }

    end {}

}