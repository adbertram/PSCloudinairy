function Get-CloudinairyApiAuthInfo {
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ApiKey,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ApiSecret,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$CloudName,

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
		$CloudinairyApiInfo = @{}
		
		'ApiKey', 'ApiSecret', 'CloudName' | ForEach-Object {
			if ($PSBoundParameters.ContainsKey($_)) {
				$CloudinairyApiInfo.$_ = (Get-Variable -Name $_).Value
			}
		}

		if ($CloudinairyApiInfo.Keys.Count -ne 3) {
			if (Get-Variable -Name CloudinairyApiInfo -Scope Script -ErrorAction 'Ignore') {
				$script:CloudinairyApiInfo
			} elseif (-not (Test-Path -Path $RegistryKeyPath)) {
				throw "No Cloudinairy API info found in registry!"
			} elseif (-not ($keyValues = Get-ItemProperty -Path $RegistryKeyPath)) {
				throw 'Cloudinairy API info not found in registry!'
			} else {
				'ApiKey', 'ApiSecret', 'CloudName' | ForEach-Object {
					$decryptedVal = decrypt $keyValues.$_
					$CloudinairyApiInfo.$_ = $decryptedVal
				}
				$script:CloudinairyApiInfo = [pscustomobject]$CloudinairyApiInfo
				$script:CloudinairyApiInfo
			}
			
		} else {
			$script:CloudinairyApiInfo = [pscustomobject]$CloudinairyApiInfo
			$script:CloudinairyApiInfo
		}
	} catch {
		$PSCmdlet.ThrowTerminatingError($_)
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

function Invoke-CloudinairyApiCall {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$HttpMethod,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$UrlParameters,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[hashtable]$QueryParameters,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[hashtable]$Payload,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ApiVersion = 'v1_1'
	)

	$ErrorActionPreference = 'Stop'

	function Get-StringHash([String] $String, $HashName = "MD5") {
		$StringBuilder = New-Object System.Text.StringBuilder
		[System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{
			[Void]$StringBuilder.Append($_.ToString("x2"))
		}
		$StringBuilder.ToString()
	}

	$apiInfo = Get-CloudinairyApiAuthInfo

	$invRestParams = @{
		Method = $HttpMethod
		Uri    = "https://api.cloudinary.com/$ApiVersion/$($apiInfo.CloudName)/$UrlParameters"
	}

	$queryParams = @{
		'max_results' = 500
	}
	if ($PSBoundParameters.ContainsKey('QueryParameters')) {
		$invRestParams.Body = $queryParams + $QueryParameters
	}

	if ($HttpMethod -eq 'POST') {
		throw 'POST method currently not supported.'
		# $unixTime = [int][double]::Parse((Get-Date -UFormat %s))
		# $signatureBase = ''

		# $paramsToSign = @{ timestamp = $unixTime }
		# if ($PSBoundParameters.ContainsKey('Parameters')) {
		# 	$paramsToSign += $Parameters
		# }
	
		# $paramsToSign.GetEnumerator() | sort Name | foreach { 
		# 	$signatureBase += [System.Uri]::EscapeDataString("$($_.Key)=$($_.Value)&") 
		# }
		# $signatureBase = $signatureBase.TrimEnd('%26')
		# $signature = Get-StringHash -String $signatureBase -HashName 'SHA1'

		# $invRestParams.Body = @{
		# 	api_key   = $apiInfo.ApiKey
		# 	timestamp = '{0}{1}' -f $unixTime, $apiInfo.ApiSecret
		# 	signature = $signature
		# }
		if ($PSBoundParameters.ContainsKey('Payload')) {
			$invRestParams.Body = $Payload
		}
	} else {
		$secret = ConvertTo-SecureString $apiInfo.ApiSecret -AsPlainText -Force
		$invRestParams.Credential = New-Object System.Management.Automation.PSCredential ($apiInfo.ApiKey, $secret)
	}
	Invoke-RestMethod @invRestParams
}

function Get-CloudinairyResource {
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('image', 'raw', 'video')]
		[string]$ResourceType,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$PublicId
	)

	$ErrorActionPreference = 'Stop'

	$invParams = @{
		HttpMethod    = 'GET'
		UrlParameters = "resources/search"
	}

	$expressionParts = @()
	if ($PSBoundParameters.ContainsKey('ResourceType')) {
		$expressionParts += @("resource_type:$ResourceType")	
	}
	
	if ($PSBoundParameters.ContainsKey('PublicId')) {
		$expressionParts += @("public_id:$PublicId")
	}

	if (@($expressionParts).Count -gt 0) {
		$queryParams = @{
			'expression' = $expressionParts -join ' AND '
		}
		$invParams.QueryParameters = $queryParams
	}
	
	(Invoke-CloudinairyApiCall @invParams).resources
}