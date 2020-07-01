Function Set-IISURI {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Location = "Default Web Site",

        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [String]
        $URI
    )

    begin {
        Import-Module WebAdministration
    }

    process {

        Write-Verbose "Setting IIS URI for $Location to $URI"

        Try {
            Set-WebConfigurationProperty `
                -PSPath "MACHINE/WEBROOT/APPHOST/$Location" `
                -Filter "appSettings/add[@key='URI']" `
                -Name "value" `
                -Value $URI `
                -ErrorAction SilentlyContinue
        }
        Catch {
            Write-Verbose -Message "Unable to set IIS URI for $Location to $URI"
        }

    }

    end {}

}