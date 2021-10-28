<#
This is an API wrapper to be used with FortiGates.
Author: Bradley Rose
Initial Creation Date: 2021-10-26
#>

class FortiGate
{
    <#
        .SYNOPSIS
        Generates a FG Object to be utilized throughout your actions.
        .DESCRIPTION
        This class generated a FortiGate object with properties:
        - $ipAddress: The IPv4 address of the target FortiGate
        - $session: The sessionID that is presented following a successful login.
        - $port: The port to be used for communication with the FG. Defaults to 443
        - $urlBase: The base URL used for API communications. The specific URI changes within each function per the API call required.
    #>

    [IpAddress]$ipAddress
    [Microsoft.PowerShell.Commands.WebRequestSession]$session
    [Int]$port = 443
    [String]$urlBase
    [String]$cookie
}

function FGLogin($fgIP, $fgPort)
{
    <#
        .SYNOPSIS
        Logs into a FortiGate device.
        .DESCRIPTION
        Logs into a FortiGate device with specified credentials. This API is NOT programmed to utilize API tokens. Things to note here:
        - The credentials specified **must** have API access within the FG (System Settings > Administrators > [Username] > JSON API Access). 
        - The default port is 443. If this is different, you must specify your HTTPS access port in the function call. See below examples.
        - The returned object is the entire "FortiGate" object, and not just the session. In order to perform other functions with this logged in 
            session, you must provide the $returnedObject.session variable from your primary script file.
        .EXAMPLE
        FG-Login('192.168.0.100')

        Logs into a FortiGate at 192.168.0.100.
        .EXAMPLE
        FG-Login('192.168.0.100',8443)

        Logs into a FortiGate at 192.168.0.100:8443
    #>

    $fg = [FortiGate]::new()
    $fg.ipAddress = $fgIP
    if ($fgPort)
    {
        $fg.port = $fgPort
    }
    $fg.urlBase = "https://$($fg.ipAddress)`:$($fg.port)/"

    $Credentials = Get-Credential -Message 'Please enter administrative credentials for your FortiGate'
    $uri = $fg.urlBase + "logincheck"


    $PostParameters = @{
        "username" = "$($Credentials.username)";
        "secretkey" = "$($Credentials.GetNetworkCredential().password)";
        }

    $results = Invoke-WebRequest -Method POST -Uri $uri -Body $PostParameters -SessionVariable FortigateSession

    $fg.session = $FortigateSession
    $fg.cookie = ($FortigateSession.Cookies.GetCookies("https://$($fg.ipAddress)") | Where-Object { $_.name -eq "ccsrftoken" }).value.replace("`"", "")
    return $fg
}

function FGLogout($fg)
{
    
    <#
        .SYNOPSIS
        Logs out of a FortiGate device.
        .DESCRIPTION
        Logs out of a FortiGate device with a specified session.
        .EXAMPLE
        FG-Logout($fg.session)

        Logs out of an existing FortiGate object stored at $fg.
    #>

    $uri = $fg.urlBase + "logout"
    $results = Invoke-WebRequest -Method POST -Uri $uri

}

function Get-SystemGlobalSettings($fg)
{
    <#
        .SYNOPSIS
        Gets global system settings.
        .DESCRIPTION
        Gets global system settings. (get system global)
        (https://BaseAPIUrl/api/v2/cmdb/system/global)
        .EXAMPLE
        Get-SystemGlobal($fg)
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/system/global"
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-SystemGlobalSettings($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets global system settings.
        .DESCRIPTION
        Sets global system settings. 
            FG# config system global
            FG(global)# set X
        (https://BaseAPIUrl/api/v2/cmdb/system/global)
        .EXAMPLE
        $globalSettings = @{"hostname" = "newHostname";}
        Set-SystemGlobal $fg $globalSettings
    #>
    
    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $uri = $fg.urlBase + "api/v2/cmdb/system/global"
    $jsonSettings = $settings | ConvertTo-Json -Compress
    Try
    {
        Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings -ErrorAction SilentlyContinue
    }
    Catch [System.Net.WebException]
    {
        Write-Host "Connection closed due to admin-sport change! Check JSON data for admin-sport value."
    }
}

function Get-SystemStatus($fg)
{
    <#
        .SYNOPSIS
        Gets system status.
        .DESCRIPTION
        Gets system status. (get system status)
        (https://BaseAPIUrl/api/v2/monitor/system/status)
        .EXAMPLE
        Get-SystemGlobal($fg)
    #>

    $uri = $fg.urlBase + "api/v2/monitor/system/status"
    return Invoke-RestMethod -Method GET $uri -WebSession $fg.session
}

<#
    This does nothing more than ignore self-signed certificate errors.
    Just leave this at the bottom of the file.
#>

if (-not("dummy" -as [type])) {
    add-type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class Dummy {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }

    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(Dummy.ReturnTrue);
    }
}
"@
}

[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [dummy]::GetDelegate()