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

function Get-CloudinairyApiAuthInfo {
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

function Save-CloudinairyApiAuthInfo {
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

function Connect-Cloudinairy {
	[OutputType('null')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory, ValueFromPipelineByPropertyName)]
		[ValidateNotNullOrEmpty()]
		[string]$CloudName,

		[Parameter(Mandatory, ValueFromPipelineByPropertyName)]
		[ValidateNotNullOrEmpty()]
		[string]$ApiKey,

		[Parameter(Mandatory, ValueFromPipelineByPropertyName)]
		[ValidateNotNullOrEmpty()]
		[string]$ApiSecret
	)

	$ErrorActionPreference = 'Stop'

	$cloudinairyAccount = New-Object -Type 'CloudinaryDotNet.Account' -ArgumentList $apiInfo.CloudName, $apiInfo.ApiKey, $apiInfo.ApiSecret
	$script:cloudinairy = New-Object -Type 'CloudinaryDotNet.Cloudinary' -ArgumentList $cloudinairyAccount
}

function Get-CloudinairyResource {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$PublicId
	)

	$ErrorActionPreference = 'Stop'

	$getResult = $cloudinairy.GetResource($PublicId)
	switch ($getResult.StatusCode) {
		'OK' {
			$getResult
			break
		}
		'NotFound' {
			Write-Verbose -Message "The public ID [$($PublicId)] was not found."
			break
		}
		default {
			throw "Unrecognized status code: [$_]"
		}
	}
}

function Send-CloudinairyResource {
	[OutputType('void')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$PublicId,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
		[string]$FilePath,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[switch]$Overwrite
	)

	begin {

		$ErrorActionPreference = 'Stop'

		function Get-FileType {
			param($Path)
			$shell  = New-Object -ComObject Shell.Application
			$folderPath = $Path | Split-Path -Parent
			$folder = $objShell.namespace($folderPath)
			$file = $folder.items() | Where-Object { $_.Path -eq $Path }
			$folder.getDetailsOf($file, 9)
		}
	}

	process {
		
		if ($Overwrite.IsPresent) {
			$ow = 'true'
		} else {
			$ow = 'false'
		}

		$args = @(
			(New-Object -Type 'CloudinaryDotNet.FileDescription' -ArgumentList $FilePath)
			$PublicId
			# $ow
			# 'http://PSCloudinairyDummyUrl'
		)

		switch ((Get-FileType -Path $FilePath)) {
			'Image' {
				$uploadParams = New-Object -Type 'CloudinaryDotNet.Actions.ImageUploadParams' -ArgumentList $args
				break
			}
			'Video' {
				$uploadParams = New-Object -Type 'CloudinaryDotNet.VideoUploadParams' -ArgumentList $args
				break
			}
			default {
				throw "File type not allowed: [$_]"
			}
		}
	
		$cloudinairy.Upload($uploadParams)
	}
}