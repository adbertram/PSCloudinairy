@{
	RootModule        = 'PSCloudinairy.psm1'
	ModuleVersion     = '0.1'
	GUID              = '40dd44c4-4c35-490f-af15-5e744be48e2d'
	Author            = 'Adam Bertram'
	CompanyName       = 'TechSnips, LLC'
	Copyright         = '(c) 2018 TechSnips, LLC. All rights reserved.'
	Description       = 'PSCloudinairy is a module that allows you to interact with the Cloudinairy API service in a number of different ways with PowerShell.'
	RequiredModules   = @()
	FunctionsToExport = @('*')
	VariablesToExport = @()
	AliasesToExport   = @()
	PrivateData       = @{
		PSData = @{
			Tags       = @('Cloudinairy', 'REST')
			ProjectUri = 'https://github.com/adbertram/PSCloudinairy'
		}
	}
}