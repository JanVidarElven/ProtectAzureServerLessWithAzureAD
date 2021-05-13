# Get Access Token using Managed Identity

How to get Access Token using Managed Identity in Azure Functions.

```powershell

    # Check if running with MSI (in Azure) or Interactive User (local VS Code)
    If ($env:MSI_SECRET) {
        
        # Get Managed Service Identity from Function App Environment Settings
        $msiEndpoint = $env:MSI_ENDPOINT
        $msiSecret = $env:MSI_SECRET

        # Specify URI and Token AuthN Request Parameters
        $apiVersion = "2017-09-01"
        $resourceUri = "https://graph.microsoft.com"
        $tokenAuthUri = $msiEndpoint + "?resource=$resourceUri&api-version=$apiVersion"

        # Authenticate with MSI and get Token
        $tokenResponse = Invoke-RestMethod -Method Get -Headers @{"Secret"="$msiSecret"} -Uri $tokenAuthUri
        # Convert Access Token to Secure String
        $secureAccessToken = ConvertTo-SecureString ($tokenResponse.access_token) -AsPlainText -Force
        Write-Host "Successfully retrieved Access Token for Microsoft Graph using MSI."

        Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/me" -Authentication OAuth -Token $secureAccessToken
        
    }

```