Function New-CesDeployment {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [X509Certificate]
        $SSLCertificate,

        [Parameter(Mandatory=$False)]
        [String]
        $Alias,

        [ValidateScript({$_.Contains("\")})]
        [Parameter(Mandatory=$True)]
        [String]
        $ConfigString,

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
        "RSAT-AD-PowerShell","Web-Server","ADCS-Enroll-Web-Svc" | ForEach-Object -Process {

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

        $CaServerName = $ConfigString.Split("\")[0]
        $CaName = $ConfigString.Split("\")[1]

        # Deploy the CES Roles
        $AuthenticationType | ForEach-Object -Process {

            Write-Verbose -Message "Installing CES with $_ Authentication"

            $Arguments = @{
                CAConfig = $ConfigString
                SSLCertThumbprint = $SSLCertificate.Thumbprint
                AuthenticationType = $_
                Force = $True
            }

            If (($_ -eq "Certificate") -and $KeybasedRenewal.IsPresent) {
                $Arguments.Add("RenewalOnly", $True)
                $Arguments.Add("AllowKeyBasedRenewal", $True)
            }
            
            Install-AdcsEnrollmentWebService @Arguments

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

            # Configure Delegation Settings for CES
            $AllowedToDelegateTo = @(
                "rpcss/$CaServerName",
                "HOST/$CaServerName"
            )

            $ADUserObject | Set-ADObject `
                -Add @{"msDS-AllowedToDelegateTo"=$AllowedToDelegateTo}

            $Arguments = @{
                Name = "WSEnrollmentServer"
                UserName = "$DomainName\$UserName"
            }

            If ($Password) {
                $Arguments.Add("Password", $Password)
            }

            Set-IISAppPoolIdentity @Arguments

        }

        If ($AuthenticationType -contains "Kerberos") {

            If ($ServiceAccount -or $ServiceGMSA) {

                Disable-IISKernelModeAuthentication `
                    -Location "Default Web Site/$($CaName)_CES_Kerberos"
    
                Disable-IISNTLMAuthentication `
                    -Location "Default Web Site/$($CaName)_CES_Kerberos"

            }

        }

        # Configure Enrollment URLs

        If ($Alias) {

            $AuthenticationType | ForEach-Object -Process {

                Write-Verbose -Message "Configuring Enrollment Url for $_ Authentication"

                Try {

                    Switch ($_) {

                        "Kerberos" {
                            certutil -config "$($CaServerName)\$($CaName)" -enrollmentserverurl "https://$($ServerName)/$($CaName.Replace(" ", "%20"))_CES_Kerberos/service.svc/CES" delete
                            certutil -config "$($CaServerName)\$($CaName)" -enrollmentserverurl "https://$($ServerShortName)/$($CaName.Replace(" ", "%20"))_CES_Kerberos/service.svc/CES" delete
                            certutil -config "$($CaServerName)\$($CaName)" -enrollmentserverurl "https://$($Alias)/$($CaName.Replace(" ", "%20"))_CES_Kerberos/service.svc/CES" Kerberos 1

                        }

                        "Username" {

                            certutil -config "$($CaServerName)\$($CaName)" -enrollmentserverurl "https://$($ServerName)/$($CaName.Replace(" ", "%20"))_CES_Kerberos/service.svc/CES" delete
                            certutil -config "$($CaServerName)\$($CaName)" -enrollmentserverurl "https://$($ServerShortName)/$($CaName.Replace(" ", "%20"))_CES_Kerberos/service.svc/CES" delete
                            certutil -config "$($CaServerName)\$($CaName)" -enrollmentserverurl "https://$($Alias)/$($CaName.Replace(" ", "%20"))_CES_UsernamePassword/service.svc/CES" UserName 1

                        }

                        "Certificate" {
                            
                            certutil -config "$($CaServerName)\$($CaName)" -enrollmentserverurl "https://$($ServerName)/$($CaName.Replace(" ", "%20"))_CES_Kerberos/service.svc/CES" delete
                            certutil -config "$($CaServerName)\$($CaName)" -enrollmentserverurl "https://$($ServerShortName)/$($CaName.Replace(" ", "%20"))_CES_Kerberos/service.svc/CES" delete

                            If ($KeybasedRenewal.IsPresent) {
                                certutil -config "$($CaServerName)\$($CaName)" -enrollmentserverurl "https://$($Alias)/$($CaName.Replace(" ", "%20"))_CES_Certificate/service.svc/CES" ClientCertificate 1 AllowRenewalsOnly,AllowKeyBasedRenewal
                            }
                            Else {
                                certutil -config "$($CaServerName)\$($CaName)" -enrollmentserverurl "https://$($Alias)/$($CaName.Replace(" ", "%20"))_CES_Certificate/service.svc/CES" ClientCertificate 1
                            }

                        }

                    }
                }
                Catch {
                    #
                }

            }

        }

        Restart-Service w3svc

    }

    end {
        
    }

}