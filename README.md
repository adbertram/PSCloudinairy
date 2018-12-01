# PSCloudinairy
A PowerShell module to interact with the Cloudinairy API

## How to Use

1. Create an API key [here](https://cloudinary.com/console/settings/security).

2. Open up your PowerShell console.

3. Copy this module to your preferred $env:PSModulePath folder.

4. Install the Cloudinairy SDK in the module folder by running `Install-CloudinairySDK`.

5. Save the cloud name, API secret and API key to the registry.

  `Save-CloudinairyApiAuthInfo -CloudName <CloudName> -ApiKey <ApiKey> -ApiSecret <ApiSecret>`

6. Run `Connect-Cloudinairy`.

7. Run any of the functions in the module to interact with your Cloudinary account!
