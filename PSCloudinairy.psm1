function Install-CloudinairySDK {
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Version = '1.4.1',

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('net40', 'netstandard1.3', 'netcore')]
		[string]$DotNetVersion = 'net40'
	)

	$ErrorActionPreference = 'Stop'

	$libraryFilePath = "$PSScriptRoot\CloudinairyDotNet\lib\$DotNetVersion\CloudinaryDotNet.dll"
	if (-not (Test-Path -Path $libraryFilePath -PathType Leaf)) {
		$url = "https://www.nuget.org/api/v2/package/CloudinaryDotNet/$Version"
		$zipPath = "$env:TEMP\CloudinairySDK.zip"
		Invoke-WebRequest -Uri $url -OutFile $zipPath

		$installPath = Join-Path -Path $PSScriptRoot -ChildPath 'CloudinairyDotNet'
		Expand-Archive -Path $zipPath -DestinationPath $installPath
	} else {
		Write-Verbose -Message 'Cloudinairy .NET SDK already exists. No need to download.'
	}
	Add-Type -Path $libraryFilePath
}

function Get-PSCloudinairyApiAuthInfo {
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$RegistryKeyPath = 'HKCU:\Software\PSCloudinairy'
	)
	
	$ErrorActionPreference = 'Stop'

	function decrypt([string]$TextToDecrypt) {
		$secure = ConvertTo-SecureString $TextToDecrypt
		$hook = New-Object system.Management.Automation.PSCredential("test", $secure)
		$plain = $hook.GetNetworkCredential().Password
		return $plain
	}

	try {
		if (-not (Test-Path -Path $RegistryKeyPath)) {
			Write-Warning 'No PSCloudinairy API info found in registry'
		} else {
			$keys = (Get-Item -Path $RegistryKeyPath).Property
			$ht = @{}
			foreach ($key in $keys) {
				$ht[$key] = decrypt (Get-ItemProperty -Path $RegistryKeyPath).$key
			}
			[pscustomobject]$ht
		}
	} catch {
		Write-Error $_.Exception.Message
	}
}

function Save-PSCloudinairyApiAuthInfo {
	[CmdletBinding()]
	param (
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$CloudName,

		[Parameter()]
		[string]$ApiKey,

		[Parameter()]
		[string]$ApiSecret,
	
		[Parameter()]
		[string]$RegistryKeyPath = "HKCU:\Software\PSCloudinairy"
	)

	begin {
		function encrypt([string]$TextToEncrypt) {
			$secure = ConvertTo-SecureString $TextToEncrypt -AsPlainText -Force
			$encrypted = $secure | ConvertFrom-SecureString
			return $encrypted
		}
	}
	
	process {
		if (-not (Test-Path -Path $RegistryKeyPath)) {
			New-Item -Path ($RegistryKeyPath | Split-Path -Parent) -Name ($RegistryKeyPath | Split-Path -Leaf) | Out-Null
		}
		
		$values = $PSBoundParameters.GetEnumerator().where({ $_.Key -ne 'RegistryKeyPath' -and $_.Value}) | Select-Object -ExpandProperty Key
		
		foreach ($val in $values) {
			Write-Verbose "Creating $RegistryKeyPath\$val"
			New-ItemProperty $RegistryKeyPath -Name $val -Value $(encrypt $((Get-Variable $val).Value)) -Force | Out-Null
		}
	}
}