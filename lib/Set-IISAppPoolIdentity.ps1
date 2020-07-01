Function Set-IISAppPoolIdentity {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateScript({Test-Path IIS:\AppPools\$($_)})]
        [String]
        $Name,
    
        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [String]
        $UserName,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Password
    )

    begin {
        Import-Module WebAdministration
    }

    process {

        Write-Verbose -Message "Setting $Name Application Pool Identity to $UserName"
        
        # IdentityType = 3 Specifies that the application pool runs under a custom identity, 
        # which is configured by using the userName and password attributes.
        # https://docs.microsoft.com/en-us/iis/configuration/system.applicationhost/applicationpools/add/processmodel

        $Arguments = @{
            Path = "IIS:\AppPools\$($Name)"
            name = "processModel"
        }

        If ($Password) {
            $Arguments.Add("value", @{userName="$($UserName)";password="$($Password)";identitytype=3})
        }
        Else {
            $Arguments.Add("value", @{userName="$($UserName)";identitytype=3})
        }

        Try {
            Set-ItemProperty @Arguments
        } 
        Catch {
            Write-Error -Message "Unable to set $Name Application Pool Identity to $UserName"
        }

    }

    end {}

}