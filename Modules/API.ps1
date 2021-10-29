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

    Invoke-WebRequest -Method POST -Uri $uri -Body $PostParameters -SessionVariable FortigateSession | Out-Null

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
    Invoke-WebRequest -Method POST -Uri $uri | Out-Null

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
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    Catch [System.Net.WebException]
    {
        Write-Host -BackgroundColor Black -ForegroundColor Cyan "Connection closed due to admin-sport change! Check JSON data for admin-sport value."
    }
}


function Get-SystemGlobalSettings($fg)
{
    <#
        .SYNOPSIS
        Gets System AutoInstall Settings.
        .DESCRIPTION
        Sets system auto installation settings for firmware and configuration via USB stick. 
            FG# get system auto-install
        (https://BaseAPIUrl/api/v2/cmdb/system/auto-install)
        .EXAMPLE
        Get-SystemAutoInstall $fg
    #>
    $uri = $fg.urlBase + "api/v2/cmdb/system/auto-install"
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-SystemAutoInstall($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets System AutoInstall Settings.
        .DESCRIPTION
        Sets system auto installation settings for firmware and configuration via USB stick. 
            FG# config system auto-install
            FG(global)# set X
        (https://BaseAPIUrl/api/v2/cmdb/system/auto-install)
        .EXAMPLE
        $autoInstallSettings = @{"auto-install-config" = "disable";"auto-install-image" = "disable";}
        Set-SystemAutoInstall $fg $autoInstallSettings
    #>
    
    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $uri = $fg.urlBase + "api/v2/cmdb/system/auto-install"
    $jsonSettings = $settings | ConvertTo-Json -Compress
    return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
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

function Get-SystemDNS($fg)
{
    <#
        .SYNOPSIS
        Gets system DNS settings.
        .DESCRIPTION
        Sets system DNS settings. 
            FG# get system dns
        (https://BaseAPIUrl/api/v2/cmdb/system/dns)
        .EXAMPLE
        Get-SystemAutoInstall $fg
    #>
    $uri = $fg.urlBase + "api/v2/cmdb/system/dns"
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-SystemDNS($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets System DNS settings.
        .DESCRIPTION
        Sets system DNS settings. 
            FG# config system dns
            FG(global)# set X
        (https://BaseAPIUrl/api/v2/cmdb/system/dns)
        .EXAMPLE
        $dnsSettings = @{"primary" = "10.69.69.69";"secondary" = "192.168.69.69";"domain" = @({"domain" = "domain.name";})}
        Set-SystemDNS $fg $dnsSettings
    #>
    
    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $uri = $fg.urlBase + "api/v2/cmdb/system/dns"
    $jsonSettings = $settings | ConvertTo-Json -Compress
    return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
}

function Get-SystemSettings($fg)
{
    <#
        .SYNOPSIS
        Gets system settings.
        .DESCRIPTION
        Gets system settings. 
            FG# get system settings
        (https://BaseAPIUrl/api/v2/cmdb/system/settings)
        .EXAMPLE
        Get-SystemSettings $fg
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/system/settings"
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-SystemSettings($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets System settings.
        .DESCRIPTION
        Sets system settings.
            FG# config system settings
            FG(global)# set X
        (https://BaseAPIUrl/api/v2/cmdb/system/settings)
        .EXAMPLE
        $systemSettings = @{"gui-ap-profile" = "disable";}
        Set-SystemSettings $fg $systemSettings
    #>
    
    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $uri = $fg.urlBase + "api/v2/cmdb/system/settings"
    $jsonSettings = $settings | ConvertTo-Json -Compress
    return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
}
function Get-DHCPServer($fg)
{
    <#
        .SYNOPSIS
        Gets DHCP server settings.
        .DESCRIPTION
        Gets DHCP server settings. 
            FG# get system dns
        (https://BaseAPIUrl/api/v2/cmdb/system.dhcp/server)
        .EXAMPLE
        Get-DHCPServer $fg
    #>
    $uri = $fg.urlBase + "api/v2/cmdb/system.dhcp/server"
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Get-SNMPSysInfo($fg)
{
    <#
        .SYNOPSIS
        Gets SNMP sysinfo settings.
        .DESCRIPTION
        Gets SNMP sysinfo settings. 
            FG# get system snmp sysinfo
        (https://BaseAPIUrl/api/v2/cmdb/system.snmp/sysinfo)
        .EXAMPLE
        Get-SNMPSysInfo $fg
    #>
    $uri = $fg.urlBase + "api/v2/cmdb/system.snmp/sysinfo"
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Get-SNMPUser($fg)
{
    <#
        .SYNOPSIS
        Gets SNMP user settings.
        .DESCRIPTION
        Gets SNMP user settings. 
            FG# get system snmp user
        (https://BaseAPIUrl/api/v2/cmdb/system.snmp/user)
        .EXAMPLE
        Get-SNMPUser $fg
    #>
    $uri = $fg.urlBase + "api/v2/cmdb/system.snmp/user"
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-SNMPSysInfo($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets SNMP sysinfo settings.
        .DESCRIPTION
        Sets SNMP sysinfo settings. 
            FG# config system snmp sysinfo
            FG (sysinfo) # set X
        (https://BaseAPIUrl/api/v2/cmdb/system.snmp/sysinfo)
        .EXAMPLE
        $snmpSysInfo = @{"status" = "enable";}
        Set-SNMPSysInfo $fg $snmpSysInfo
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $uri = $fg.urlBase + "api/v2/cmdb/system.snmp/sysinfo"
    $jsonSettings = $settings | ConvertTo-Json -Compress
    return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
}

function Set-SNMPUser($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets SNMP user settings.
        .DESCRIPTION
        Sets SNMP user settings. 
            FG# config system snmp user
            FG (user) # edit "snmpUser"
            FG (snmpUser) # set X
        (https://BaseAPIUrl/api/v2/cmdb/system.snmp/user)
        .EXAMPLE
        $snmpUser = @{"name" = "PCAVPNv3";"status" = "enable";"notify-hosts" = "10.69.69.69";"events" = "intf-ip";}
        Set-SNMPUser $fg $snmpUser
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/system.snmp/user"

    try {Invoke-RestMethod -Method GET ($uri + "/$($settings.name)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null}
    catch [System.InvalidOperationException] {
        Write-Host -BackgroundColor Black -ForegroundColor Yellow "SNMP user $($settings.name) does not exist. Creating SNMP user $($settings.name)"
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
    return Invoke-RestMethod ($uri + "/$($settings.name)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
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