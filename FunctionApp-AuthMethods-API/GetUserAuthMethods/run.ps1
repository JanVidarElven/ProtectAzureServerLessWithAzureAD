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
Write-Host "Calling user is authorized with the following scopes:" $jwt.scp 
Write-Host "Calling user is authorized with the following roles:" $jwt.roles 
Write-Host ($jwt.scp -notmatch "Phone.Write")
Write-Host ($jwt.roles -notcontains "Phone.Write.All")

# Check for user principal name parameter
If ($Request.Params.userUpn) {
    $userUpn = $Request.Params.userUpn
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

    # If requesting preview APIs, use beta endpoint
    Select-MgProfile -Name "beta"
            
    If (-Not (Get-Module Microsoft.Graph.Identity.Signins)) { Import-Module Microsoft.Graph.Identity.Signins }

    # Initialize Response Body for value array
    $responseBody = @{
        value = @(
        )
    }

    # Either use ErrorActionPreference or use ErrorAction Stop individually
    #$Global:ErrorActionPreference = 1

    try {
        If (($jwt.scp -match "Phone.Read") -or ($jwt.roles -contains "Phone.Read.All")) {
            $userPhoneMethods = Get-MgUserAuthenticationPhoneMethod -UserId $userUpn -ErrorAction Stop
            #$responseBody = $userPhoneMethods | Select-Object Id, PhoneNumber, PhoneType, SmsSignInState | ConvertTo-Json
            $responseBody.value += $userPhoneMethods | Select-Object @{Name = "Type" ; Expression = {"phoneAuthenticationMethod"}}, Id, PhoneNumber, PhoneType, SmsSignInState
            $statusCode = [HttpStatusCode]::OK
        }                
        If (($jwt.scp -match "Authenticator.Read") -or ($jwt.roles -contains "Authenticator.Read.All")) {         
            $userAuthenticatorMethods = Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId $userUpn -ErrorAction Stop
            $responseBody.value += $userAuthenticatorMethods | Select-Object @{Name = "Type" ; Expression = {"microsoftAuthenticatorAuthenticationMethod"}}, Id, displayName, phoneAppVersion, clientAppName, deviceTag
            $statusCode = [HttpStatusCode]::OK
        }          
        If (($jwt.scp -match "Hello.Read") -or ($jwt.roles -contains "Hello.Read.All")) {
            $userHelloMethods = Get-MgUserAuthenticationWindowHello -UserId $userUpn -ErrorAction Stop
            $responseBody.value += $userHelloMethods | Select-Object @{Name = "Type" ; Expression = {"windowsHelloForBusinessAuthenticationMethod"}}, Id, displayName, keyStrength
            $statusCode = [HttpStatusCode]::OK
        }          
        If (($jwt.scp -match "Fido2.Read") -or ($jwt.roles -contains "Fido2.Read.All")) {
            $userFido2Methods = Get-MgUserAuthenticationFido2Method -UserId $userUpn -ErrorAction Stop
            $responseBody.value += $userFido2Methods | Select-Object @{Name = "Type" ; Expression = {"fido2AuthenticationMethod"}}, Id, displayName, model, attestationCertificates, attestationLevel
            $statusCode = [HttpStatusCode]::OK
        }          
        If (($jwt.scp -match "Email.Read") -or ($jwt.roles -contains "Email.Read.All")) {
            $userEmailMethods = Get-MgUserAuthenticationEmailMethod -UserId $userUpn -ErrorAction Stop
            $responseBody.value += $userEmailMethods | Select-Object @{Name = "Type" ; Expression = {"emailAuthenticationMethod"}}, Id, emailAddress
            $statusCode = [HttpStatusCode]::OK
        }          
        If (($jwt.scp -match "Password.Read") -or ($jwt.roles -contains "Password.Read.All")) {
            $userPasswordMethods = Get-MgUserAuthenticationPasswordMethod -UserId $userUpn -ErrorAction Stop
            $responseBody.value += $userPasswordMethods | Select-Object @{Name = "Type" ; Expression = {"passwordAuthenticationMethod"}}, Id, password
            $statusCode = [HttpStatusCode]::OK
        }          
        If (($jwt.scp -match "TemporaryAccessPass.Read") -or ($jwt.roles -contains "TemporaryAccessPass.Read.All")) {
            $userTAPMethods = Get-MgUserAuthenticationTemporaryAccessPassMethod -UserId $userUpn -ErrorAction Stop
            $responseBody.value += $userTAPMethods | Select-Object @{Name = "Type" ; Expression = {"temporaryAccessPassAuthenticationMethod"}}, Id, startDateTime, lifeTimeInMinutes, isUsableOnce, isUsable
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
