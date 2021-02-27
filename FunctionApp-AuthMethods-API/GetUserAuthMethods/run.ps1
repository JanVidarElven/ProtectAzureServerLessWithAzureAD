using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)

# Write to the Azure Functions log stream.
Write-Host "PowerShell HTTP trigger function processed a request for User Auth Methods."

# Check if Authorization Header and get Access Token
$AuthHeader = $Request.Headers.'Authorization'
If ($AuthHeader) {
    $parts = $AuthHeader.Split(" ")
    $accessToken = $parts[1]
    $jwt = $accessToken | Get-JWTDetails
}

# Just some Informational Output for Debugging, remove when not needed
Write-Host $jwt.scp 
Write-Host $jwt.roles 
Write-Host ($jwt.scp -notmatch "Phone.Write")
Write-Host ($jwt.roles -notcontains "Phone.Write.All")

# Check for user principal name parameter
If ($Request.Params.userUpn) {
    $userUpn = $Request.Params.vmName
}

# Check Correct Authorization Scopes and/or Roles
If (($jwt.scp -notmatch "user_impersonation") -and ($jwt.roles -notcontains "application_impersonation")) {
    $statusCode = [HttpStatusCode]::Forbidden
    $responseBody = "You are not Authorized!"
} else {

    # Set some Variables for Authentication
    $tenantID = "elven.onmicrosoft.com"
    $scopes = "UserAuthenticationMethod.Read.All", "UserAuthenticationMethod.ReadWrite.All", "User.ReadBasic.All"

    # Check if running with MSI (in Azure) or Interactive User (local VS Code)
    If ($env:MSI_SECRET) {
        
        # Get Managed Service Identity from Function App Environment Setttings
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

        # Connect to Graph with MSI Token
        Connect-MgGraph -AccessToken $tokenResponse.access_token

    } else {

        # Connect to Graph Interactively using Device Code Flow
        Connect-MgGraph -Scopes $scopes -TenantId $tenantID -ForceRefresh
    }

    Select-MgProfile -Name "beta"
            
    If (-Not (Get-Module Microsoft.Graph.Identity.Signins)) { Import-Module Microsoft.Graph.Identity.Signins }

    # Either use ErrorActionPreference or use ErrorAction Stop individually
    #$Global:ErrorActionPreference = 1
    try {
        If (($jwt.scp -match "Phone.Read") -or ($jwt.roles -contains "Phone.Read.All")) {
            $userPhoneMethods = Get-MgUserAuthenticationPhoneMethod -UserId $userUpn -ErrorAction Stop
            $responseBody = $userPhoneMethods | Select-Object Id, PhoneNumber, PhoneType, SmsSignInState | ConvertTo-Json
            $statusCode = [HttpStatusCode]::OK
        }                
    }
    catch [Microsoft.Graph.PowerShell.Runtime.RestException] {
        $statusCode = [HttpStatusCode]::BadRequest
        $responseBody = $_.Exception
    }
    catch {
        $statusCode = [HttpStatusCode]::NotFound
        Write-Host -Object "No User by UPN $userUpn was found." 
        $responseBody = "No User by UPN $userUpn was found."                
    }

}     

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $statusCode
    Body = $responseBody
})
