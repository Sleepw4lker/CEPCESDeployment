Function Set-IISFriendlyName {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Location = "Default Web Site",

        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [String]
        $FriendlyName
    )

    begin {
        #Import-Module WebAdministration
    }

    process {

        Write-Verbose "Setting IIS Friendly Name for $Location to $FriendlyName"

        Try {
            Set-WebConfigurationProperty `
                -PSPath "MACHINE/WEBROOT/APPHOST/$Location" `
                -Filter "appSettings/add[@key='FriendlyName']" `
                -Name "value" `
                -Value $FriendlyName `
                -ErrorAction SilentlyContinue
        }
        Catch {
            Write-Verbose -Message "Unable to set IIS Friendly Name for $Location to $FriendlyName"
        }

    }

    end {}

}