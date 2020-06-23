Function New-CepDeployment {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [X509Certificate]
        $SSLCertificate,

        [Parameter(Mandatory=$False)]
        [String]
        $Alias,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullorEmpty()]
        [String]
        $FriendlyName = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName,

        [ValidateSet("UserName","Kerberos","Certificate")]
        [Parameter(Mandatory=$False)]
        [String[]]
        $AuthenticationType = "Kerberos",

        [Switch]
        $KeybasedRenewal,

        [ValidateScript({$_.Contains("\")})]
        [Parameter(
            ParameterSetName="UseDomainAccount",
            Mandatory=$False
        )]
        [String]
        $ServiceAccount,

        [Parameter(
            ParameterSetName="UseDomainAccount",
            Mandatory=$True
        )]
        [ValidateNotNullorEmpty()]
        [String]
        $Password,

        [ValidateScript({$_.Contains("\")})]
        [Parameter(
            ParameterSetName="UseGMSA",
            Mandatory=$False
        )]
        [String]
        $ServiceGMSA
    )

    begin {

        # Abort if not Admin
        If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error `
                -Message "You must be local Administrator and execute with Elevation!"
            return
        }

        # Install all necessary Windows Features
        Add-WindowsFeature RSAT-AD-PowerShell
        Add-WindowsFeature Web-Server -IncludeManagementTools
        Add-WindowsFeature ADCS-Enroll-Web-Pol

        Import-Module ActiveDirectory
        Import-Module WebAdministration

        # Test for Enterprise Administrator Permissions
        $ForestRootDomain = $(Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain)
        $DomainSid = $ForestRootDomain.DomainSID
        $EnterpriseAdminsGroup = "$($DomainSid)-519"
        $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $GroupMemberships = $CurrentUser.Groups.Value

        If (-not ($GroupMemberships -contains $EnterpriseAdminsGroup)) {
            Write-Error `
                -Message "You must be Enterprise Administrator for the CEP Installation!"
            return
        }

        $ServerName = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
        $ServerShortName = $env:COMPUTERNAME

        If ($Alias) {
            $ServicePrincipalNames = @("HTTP/$Alias")
            $FriendlyName = $Alias
        }
        Else {
            $ServicePrincipalNames = @("HTTP/$ServerName","HTTP/$ServerShortName")
            $FriendlyName = $ServerName
        }

    }

    process {
        # Deploy the CEP Roles
        $AuthenticationType | ForEach-Object -Process {

            Write-Verbose -Message "Installing CEP with $_ Authentication"

            $Arguments = @{
                SSLCertThumbprint = $SSLCertificate.Thumbprint
                AuthenticationType = $_
                Force = $True
            }

            # Install the CEP Services
            Install-AdcsEnrollmentPolicyWebService @Arguments

            If (($_ -ne "Kerberos") -and $KeybasedRenewal.IsPresent) {
                Install-AdcsEnrollmentPolicyWebService @Arguments -KeyBasedRenewal
            }

        }

        If ($ServiceAccount -or $ServiceGMSA) {

            If ($ServiceGMSA) {

                If (-not $ServiceGMSA.Endswith("$")) {
                    $ServiceGMSA += "$"
                }

                $DomainName = $ServiceGMSA.Split("\")[0]
                $UserName = $ServiceGMSA.Split("\")[1]

            }
            ElseIf ($ServiceAccount) {

                $DomainName = $ServiceAccount.Split("\")[0]
                $UserName = $ServiceAccount.Split("\")[1]

            }
                
            $DC = Get-ADDomainController `
                -DomainName $DomainName `
                -Discover `
                -NextClosestSite

            If ($ServiceGMSA) {

                $ADUserObject = Get-ADServiceAccount `
                    -Identity $UserName `
                    -Server $DC.HostName[0]

                # Install the Group Managed Service Account on the Machine
                $ADUserObject | Install-ADServiceAccount
            
            }
            ElseIf ($ServiceAccount) {

                $ADUserObject = Get-ADUser`
                    -Identity $UserName `
                    -Server $DC.HostName[0]

            }

            Add-LocalGroupMember `
                -Group IIS_IUSRS `
                -Member "$DomainName\$UserName" `
                -ErrorAction SilentlyContinue

            $ADUserObject | Set-ADObject `
                -Add @{"serviceprincipalname"=$ServicePrincipalNames}

            $Arguments = @{
                Name = "WSEnrollmentPolicyServer"
                UserName = "$DomainName\$UserName"
            }

            If ($Password) {
                $Arguments.Add("Password", $Password)
            }

            Set-IISAppPoolIdentity @Arguments

        }

        If ($AuthenticationType -contains "UserName") {

            Set-IISFriendlyName `
                -Location "Default Web Site/ADPolicyProvider_CEP_UsernamePassword" `
                -FriendlyName "$FriendlyName (UserName)"

            If ($KeyBasedRenewal.IsPresent) {
                Set-IISFriendlyName `
                    -Location "Default Web Site/KeyBasedRenewal_ADPolicyProvider_CEP_UsernamePassword" `
                    -FriendlyName "$FriendlyName (UserName, Key based Renewal)" 
            }

        }

        If ($AuthenticationType -contains "Certificate") {
            
            Set-IISFriendlyName `
                -Location "Default Web Site/ADPolicyProvider_CEP_Certificate" `
                -FriendlyName "$FriendlyName (Certificate)"

            If ($KeyBasedRenewal.IsPresent) {
                Set-IISFriendlyName `
                    -Location "Default Web Site/KeyBasedRenewal_ADPolicyProvider_CEP_Certificate" `
                    -FriendlyName "$FriendlyName (Certificate, Key based Renewal)" 
            }

        }

        If ($AuthenticationType -contains "Kerberos") {

            Set-IISFriendlyName `
                -Location "Default Web Site/ADPolicyProvider_CEP_Kerberos" `
                -FriendlyName "$FriendlyName (Kerberos)"

            If ($ServiceAccount -or $ServiceGMSA) {

                Disable-IISKernelModeAuthentication `
                    -Location "Default Web Site/ADPolicyProvider_CEP_Kerberos"
    
                Disable-IISNTLMAuthentication `
                    -Location "Default Web Site/ADPolicyProvider_CEP_Kerberos"

            }

        }

    }

    end {}
}