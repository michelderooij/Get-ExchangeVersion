<#
    .SYNOPSIS
    Retrieves Exchange server version information using registry for rollup info
    Outputs objects which can be post-processed or filtered.
       
    Michel de Rooij
    michel@eightwone.com
    http://eightwone.com
	
    THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE 
    RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.
	
    Version 2.0, March 6th 2024
	
	.DESCRIPTION
	Retrieves Exchange server version information using registry for rollup info
	Outputs objects which can be post-processed or filtered.

	.LINK
	http://eightwone.com

	Revision History
	---------------------------------------------------------------------
	1.0  Initial release
	1.1  Added support for Exchange Server 2013
         Renamed script to Get-ExchangeVersions.p1
    1.2  Added connectivity test
         Fixed patchless Exchange 2010 output issue
	1.3  Added Exchange 2016 support
    1.31 Fixed layout bug for 4-digit build no.
    1.32 Added EMS check
         Renamed to Get-ExchangeVersion
    1.33 Added Exchange Server 2019 support
    1.40 Added ComputerName parameter
         Default operation mode is against local host
         Made pipeline friendly
         Small optimizations
    2.00 Added Site in output
         Added EMS-less operating mode (uses AD)

	.EXAMPLE
	Get-ExchangeVersion.ps1

    .EXAMPLE
    Get-ExchangeVersion.ps1 -Name EX1
#>
#Requires -Version 3.0
Param(
    [parameter( Position= 0, Mandatory= $false, ValueFromPipelineByPropertyName= $true)] 
    [alias('Name')]
    [string[]]$ComputerName
)

Begin {
    # Script doesn't works for these roles and only for indicated versions (as reported by Exchange, not AD)
    $NonValidRoles= ( 'ProvisionedServer', 'Edge')
    $ValidVersions= 8, 14, 15
    #MBX=2,CAS=4,UM=16,HT=32,Edge=64 multirole servers:CAS/HT=36,CAS/MBX/HT=38,CAS/UM=20,E2k13 MBX=54,E2K13 CAS=16385,E2k13 CAS/MBX=16439
    $ValidMsExchCurrentServerRole= 2,4,16,20,32,36,38,54,64,16385,16439

    Function getExchVersion {
        Param(
            $Server
        )
		switch ( $Server.AdminDisplayVersion.Major) {
			8 {
				$prodguid= "461C2B4266EDEF444B864AD6D9E5B613"
				break
			}
			14 {
				$prodguid= "AE1D439464EB1B8488741FFA028E291C"
				break
			}
			15 {
				switch( $Server.AdminDisplayVersion.Minor) {
					0 {
						$prodguid= "AE1D439464EB1B8488741FFA028E291C"
						break
					}
					1 {
						$prodguid= "442189DC8B9EA5040962A6BED9EC1F1F"
						break
					}
					2 {
						$prodguid= "442189DC8B9EA5040962A6BED9EC1F1F"
						break
					}
					default {
						Write-Error ('Unknown minor version: {0}' -f $Server.AdminDisplayVersion)
						return $null
					}
				}
			}
			default {
				Write-Error ('Unknown major version: {0}' -f $Server.AdminDisplayVersion)
				return $null
			}
		}
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey( 'LocalMachine', $Server)
		$MainKey= 'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\{0}\' -f $prodguid

		$displayVersion= $reg.OpenSubKey( ('{0}\InstallProperties' -f $MainKey)).GetValue( 'DisplayVersion')
		$maxMajor= [regex]::match( $displayVersion, '^\d{1,4}\.\d{1,4}').value
		$maxMinor= [regex]::match( $displayVersion, '\d{1,4}\.\d{1,4}$').value
		$updates= $reg.OpenSubKey( ('{0}\Patches' -f $MainKey)).GetSubKeyNames()
		If( $Updates) {
			ForEach ($updatekey in $updates) {
				$update= $reg.OpenSubKey( ('{0}\Patches\{1}' -f $MainKey, $updatekey)).GetValue( 'DisplayName')
				$fullversion= [regex]::match( $update, '[0-9\.]*$').value
				$major= [regex]::match( $fullversion, '^\d{1,3}\.\d{1,3}').value
				$minor= [regex]::match( $fullversion, '\d{1,3}\.\d{1,3}$').value
				If ($major -gt $maxMajor -or $major -ge $maxMajor -and $minor -gt $maxMinor) {
					$maxMajor= $major
					$maxMinor= $minor
				}
			}
		}
		return ('{0}.{1}' -f $maxMajor, $maxMinor)
    }

    $ExchangeLessMode= $False
    If( -not( Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue)) {
        If( -not( Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
            Throw 'Exchange Management Shell not loaded and Active Directory module not available.'
        }
        Else {
            Write-Warning ('Using Active Directory information, will only report CU level')
            $ExchangeLessMode= $True
        }
    }
}
Process {
    If($null -eq $ComputerName) {
        If( $ExchangeLessMode) {
            $ComputerName= Get-ADObject -Filter "objectCategory -eq 'msExchExchangeServer'" -SearchBase (Get-ADRootDSE).ConfigurationNamingContext
        }
        Else {
            $ComputerName= Get-ExchangeServer -Identity $ENV:COMPUTERNAME
        }
    }
    $ComputerName | ForEach-Object {

        If( 'Microsoft.Exchange.Data.Directory.Management.ExchangeServer' -eq $_.getType().FullName) {
            $ThisServer= $_
        }
        Else {
            If( $ExchangeLessMode) {
                # Retrieve object with necessary properties
                $ThisServer= $_ | Get-ADObject -Properties *
            }
            Else {
                $ThisServer= Get-ExchangeServer -Identity $_
            }
        }

        $outObj= New-Object Object

        If( $ExchangeLessMode) {
            $outObj | Add-Member -MemberType NoteProperty Server -Value $ThisServer.CN
        }
        Else {
            $outObj | Add-Member -MemberType NoteProperty Server -Value $ThisServer.Name
        }

        # Only try remote reg access when not using EMS or when using EMS and it's not Edge server role
        $bValid= $False
        If( $ExchangeLessMode) {
            If( $ThisServer.MsExchCurrentServerRoles -in $ValidMsExchCurrentServerRole) {
                Write-Warning ('Script does not work on Exchange server {0} with msExchCurrentServerRoles #{1}' -f $outobj.Server, $ThisServer.MsExchCurrentServerRoles)
            }
        }
        Else {
            If ($ValidVersions -contains $ThisServer.AdminDisplayVersion.Major) {
                If( $NonValidRoles.Contains( $ThisServer.ServerRole)) {
                    Write-Warning ('Script does not work on Exchange server {0} with roles {1}' -f $outobj.Server, ($NonValidRoles -join ','))
                }
                Else {
                    $bValid= $True
                }

            }
            Else {
                Write-Warning ('Script does not work on Exchange server {0} with version {1}' -f $outobj.Server, $ThisServer.AdminDisplayVersion.Major)
            }
	    }

        $bOnline= Test-Connection -ComputerName $outobj.Server -Count 1 -ErrorAction SilentlyContinue

        If( $ExchangeLessMode) {
            $outObj | Add-Member -MemberType NoteProperty -Name Site -Value (($ThisServer.msExchServerSite -split ',')[0] -split '=')[1]
        }
        Else {
            $outObj | Add-Member -MemberType NoteProperty -Name Site -Value ($ThisServer.Site -split '/')[-1]
        }

        If( $bValid -and $bOnline) {
            $outObj | Add-Member -MemberType NoteProperty -Name Accessible -Value $true
            If( $ExchangeLessMode) {
            }
            Else {
                $exVer= getExchVersion -Server $ThisServer 
                $outObj | Add-Member -MemberType NoteProperty -Name ExchangeVersion -Value $exVer
            }
        }
        Else {
            $outObj | Add-Member -MemberType NoteProperty Accessible $false
            $outObj | Add-Member -MemberType NoteProperty ExchangeVersion "N/A"
        }

        If( $ExchangeLessMode) {
            $outObj | Add-Member -MemberType NoteProperty -Name AdminVersion -Value $ThisServer.serialNumber[0]
        }
        Else {
            $outObj | Add-Member -MemberType NoteProperty -Name AdminVersion -Value $ThisServer.AdminDisplayVersion
        }

        $outObj
    }
}
End {

}
