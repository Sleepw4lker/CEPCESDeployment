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

    }

    process {

        # Abort if not Admin
        If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error `
                -Message "You must be local Administrator and execute with Elevation!"
            return
        }

        # Install all necessary Windows Features
        $RestartRequired = $False
        "RSAT-AD-PowerShell","Web-Server","ADCS-Enroll-Web-Pol" | ForEach-Object -Process {

            If ((Get-WindowsFeature $_).Installed -ne $True) {
                $InstallResult = Install-WindowsFeature $_ -IncludeManagementTools
                If ($InstallResult.restartneeded -ne 'no') {
                    $RestartRequired = $True
                }
            }
        }

        If ($RestartRequired -eq $True) {
            Write-Warning -Message "Rebooting in 15 Seconds, press Crtl-C to abort."
            Write-Warning -Message "Repeat Installation after Reboot"
            Start-Sleep -Seconds 15
            Restart-Computer
            return
        }

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
        }
        Else {
            $ServicePrincipalNames = @("HTTP/$ServerName","HTTP/$ServerShortName")
        }

        # Deploy the CEP Roles
        $AuthenticationType | ForEach-Object -Process {

            Write-Verbose -Message "Installing CEP with $_ Authentication"

            $Arguments = @{
                SSLCertThumbprint = $SSLCertificate.Thumbprint
                AuthenticationType = $_
                Force = $True
            }

            If (($_ -ne "Kerberos") -and $KeybasedRenewal.IsPresent) {
                $Arguments.Add("KeyBasedRenewal", $True)
            }

            # Install the CEP Services
            Install-AdcsEnrollmentPolicyWebService @Arguments

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

                # Test if we can retrieve gMSA Password (if used)
                $Haystack = (Get-ADServiceAccount `
                    -Identity $UserName `
                    -Server $DC.HostName[0] `
                    -Property PrincipalsAllowedToRetrieveManagedPassword).PrincipalsAllowedToRetrieveManagedPassword

                $Needle = (Get-ADComputer `
                    -Identity $env:computername `
                    -Server $DC.HostName[0]).distinguishedname

                If (-not ($Haystack -contains $Needle)) {
                    Write-Error `
                        -Message "We are not permitted to retrieve the Password for $Username!"
                    return
                }

                # Install the Group Managed Service Account on the Machine
                $ADUserObject | Install-ADServiceAccount
            
            }
            ElseIf ($ServiceAccount) {

                $ADUserObject = Get-ADUser `
                    -Identity $UserName `
                    -Server $DC.HostName[0]

            }

            Add-LocalGroupMember `
                -Group IIS_IUSRS `
                -Member "$DomainName\$UserName" `
                -ErrorAction SilentlyContinue

            $ADUserObject | Set-ADObject `
                -Replace @{"serviceprincipalname"=$ServicePrincipalNames}

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

        If ($Alias) {

            $AuthenticationType | ForEach-Object -Process {

                Write-Verbose -Message "Configuring Enrollment URI for $_ Authentication"

                Switch ($_) {

                    "Kerberos"      { $Node = "ADPolicyProvider_CEP_Kerberos" }
                    "Username"      { $Node = "ADPolicyProvider_CEP_UsernamePassword" }
                    "Certificate"   { $Node = "ADPolicyProvider_CEP_Certificate" }

                }

                Try {

                    Set-IISURI  `
                        -Location "Default Web Site/$Node" `
                        -URI "https://$Alias/$Node/service.svc/CEP"

                }
                Catch {
                    #
                }

            }
        }

        # Apply Configuration
        Restart-Service w3svc

    }

    end {
        
    }
}