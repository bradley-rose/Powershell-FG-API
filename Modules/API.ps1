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
    [String]$hostname
}

function FGLogin($fgIP, $port, $username, $password)
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
    if ($port)
    {
        $fg.port = $port
    }
    $fg.urlBase = "https://$($fg.ipAddress)`:$($fg.port)/"

    if ($NULL -eq $username -AND $NULL -eq $password){
        $Credentials = Get-Credential -Message 'Please enter administrative credentials for your FortiGate'
        $uri = $fg.urlBase + "logincheck"
        $PostParameters = @{
            "username" = "$($Credentials.username)";
            "secretkey" = "$($Credentials.GetNetworkCredential().password)";
            }
    }
    else {
        $uri = $fg.urlBase + "logincheck"
        $PostParameters = @{
            "username" = "$($username)";
            "secretkey" = "$($password)";
            }
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
    Invoke-RestMethod -Method POST -WebSession $fg.session -Uri $uri | Out-Null
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
        Set-SystemGlobalSettings $fg $globalSettings
    #>
    
    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $uri = $fg.urlBase + "api/v2/cmdb/system/global"
    $jsonSettings = $settings | ConvertTo-Json -Compress
    return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
}


function Get-SystemAutoInstall($fg)
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

function Set-DHCPServer($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets DHCP server.
        .DESCRIPTION
        Sets DHCP server.
            FG# config system dhcp server
            FG(server)# edit 1
            FG (1)# set X
        (https://BaseAPIUrl/api/v2/cmdb/system.dhcp/server)
        .EXAMPLE
        $dhcpServer = @{"id"="1";"default-gateway"="10.69.69.1";"netmask"="255.255.255.0";"interface"="intName";"ip-range"=@(@{"id"=1;"start-ip"="10.69.69.69";"end-ip"="10.69.69.169";})}
        Set-DHCPServer $fg $dhcpServer
    #>
    
    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $uri = $fg.urlBase + "api/v2/cmdb/system.dhcp/server/" + $settings.id
    $jsonSettings = $settings | ConvertTo-Json -Compress
    return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
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

function Get-SNMPUser($fg, $specific)
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
        .EXAMPLE
        Get-SNMPUser $fg "specificSNMPuser"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/system.snmp/user"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
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

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($settings.name)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($settings.name)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Get-LocalCertificate($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets local certificate.
        .DESCRIPTION
        Gets local certificate. 
            FG# get vpn certificate local
        (https://BaseAPIUrl/api/v2/cmdb/vpn.certificate/local)
        .EXAMPLE
        Get-LocalCertificate $fg
        .EXAMPLE
        Get-LocalCertificate $fg "certificateName"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/vpn.certificate/local"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Get-Interface($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets system interface.
        .DESCRIPTION
        Gets system interface. 
            FG# get sys int
        (https://BaseAPIUrl/api/v2/cmdb/system/interface)
        .EXAMPLE
        Get-Interface $fg 
        .EXAMPLE
        Get-Interface $fg "interfaceName"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/system/interface"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-Interface($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets interface settings.
        .DESCRIPTION
        Sets interface settings. 
            FG# config system int 
            FG (interface) # edit interfaceName
            FG (interfaceName) # set X
        (https://BaseAPIUrl/api/v2/cmdb/system/interface)
        .EXAMPLE
        $intSettings = @{"name"="internal";"allowaccess"="https http ssh ping";"mode"="dhcp";"status" = "enable";}
        Set-Interface $fg $intSettings
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/system/interface"

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($settings.name)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($settings.name)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Get-NTP($fg)
{
    <#
        .SYNOPSIS
        Gets NTP settings.
        .DESCRIPTION
        Gets NTP settings. 
            FG# get system ntp
        (https://BaseAPIUrl/api/v2/cmdb/system/ntp)
        .EXAMPLE
        Get-NTP $fg
    #>
    $uri = $fg.urlBase + "api/v2/cmdb/system/ntp"
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json) 
}

function Set-NTP($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets NTP settings.
        .DESCRIPTION
        Sets NTP settings. 
            FG# config system ntp
            FG (ntp) # set X
        (https://BaseAPIUrl/api/v2/cmdb/system/ntp)
        .EXAMPLE
        $ntp = @{"server-mode" = "disable";}
        Set-NTP $fg $ntp
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $uri = $fg.urlBase + "api/v2/cmdb/system/ntp"
    $jsonSettings = $settings | ConvertTo-Json -Compress
    return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
}

function Get-CACert($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets CA Certificate.
        .DESCRIPTION
        Gets CA Certificate. 
            FG# get vpn certificate ca
        (https://BaseAPIUrl/api/v2/cmdb/vpn.certificate/ca)
        .EXAMPLE
        Get-CACert $fg 
        .EXAMPLE
        Get-CACert $fg "certName"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/vpn.certificate/ca"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-CACert($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets CA Certificate.
        .DESCRIPTION
        Sets CA Certificate. 
            FG# config vpn certificate ca
            FG (ca)# edit certName
            FG (certName)# set X
        (https://BaseAPIUrl/api/v2/cmdb/vpn.certificate/ca)
        .EXAMPLE
        $certInfo = @{"ca"="-----BEGIN CERTIFICATE-----ASDFASDF-----END CERTIFICATE-----";"name"="certName"}
        Set-CACert $fg $certInfo
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/certificate/ca"

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($settings.name)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($settings.name)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Get-RemoteCert($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets remote Certificate.
        .DESCRIPTION
        Gets remote Certificate. 
            FG# get vpn certificate remote
        (https://BaseAPIUrl/api/v2/cmdb/vpn.certificate/remote)
        .EXAMPLE
        Get-RemoteCert $fg 
        .EXAMPLE
        Get-RemoteCert $fg "certName"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/vpn.certificate/remote"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-RemoteCert($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets remote Certificate.
        .DESCRIPTION
        Sets remote Certificate. 
            FG# config vpn certificate remote
            FG (remote)# edit certName
            FG (certName)# set X
        (https://BaseAPIUrl/api/v2/cmdb/vpn.certificate/remote)
        .EXAMPLE
        $certInfo = @{"remote"="-----BEGIN CERTIFICATE-----ASDFASDF-----END CERTIFICATE-----";"name"="certName"}
        Set-RemoteCert $fg $certInfo
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/vpn.certificate/remote"

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($settings.name)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($settings.name)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Get-FirewallAddress($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets firewall address objects.
        .DESCRIPTION
        Gets firewall address objects. 
            FG# get firewall address
        (https://BaseAPIUrl/api/v2/cmdb/firewall/address)
        .EXAMPLE
        Get-FirewallAddress $fg 
        .EXAMPLE
        Get-FirewallAddress $fg "addrName"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/firewall/address"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)

}

function Get-FirewallAddressGroup($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets firewall address group objects.
        .DESCRIPTION
        Gets firewall address group objects. 
            FG# get firewall addrgrp
        (https://BaseAPIUrl/api/v2/cmdb/firewall/addrgrp)
        .EXAMPLE
        Get-FirewallAddress $fg 
        .EXAMPLE
        Get-FirewallAddress $fg "addrgrpName"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/firewall/addrgrp"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Remove-FirewallAddress($fg, $specific)
{
    <#
        .SYNOPSIS
        Removes firewall address objects.
        .DESCRIPTION
        Removes firewall address objects. 
            FG# config firewall address
            FG (address)# delete "addrName" 
        (https://BaseAPIUrl/api/v2/cmdb/firewall/address)
        .EXAMPLE
        Remove-FirewallAddress $fg "addrName" 
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/firewall/address/" + $specific
    try 
    {
        Invoke-RestMethod -Method GET $uri -WebSession $fg.session | Out-Null
        Write-Host -BackgroundColor Black -ForegroundColor Yellow "$($fg.hostname)`: Address group $($specific) deleted."
        return ((Invoke-RestMethod -Method DELETE $uri -WebSession $fg.session).results | ConvertTo-Json)
    }
    catch
    {
        Write-Host -BackgroundColor Black -ForegroundColor Green "$($fg.hostname)`: Address $($specific) does not exist."
    }
}

function Remove-FirewallAddressGroup($fg, $specific)
{
    <#
        .SYNOPSIS
        Removes firewall address group objects.
        .DESCRIPTION
        Removes firewall address group objects. 
            FG# config firewall addrgrp
            FG (address)# delete "grpname" 
        (https://BaseAPIUrl/api/v2/cmdb/firewall/addrgrp)
        .EXAMPLE
        Remove-FirewallAddressGroup $fg "grpName" 
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/firewall/addrgrp/" + $specific
    try 
    {
        Invoke-RestMethod -Method GET $uri -WebSession $fg.session | Out-Null
        Write-Host -BackgroundColor Black -Foreground-Color Yellow "$($fg.hostname)`: Address group $($specific) deleted."
        return ((Invoke-RestMethod -Method DELETE $uri -WebSession $fg.session).results | ConvertTo-Json)
    }
    catch
    {
        Write-Host -BackgroundColor Black -ForegroundColor Green "$($fg.hostname)`: Address group $($specific) does not exist."
    }
}

function Set-FirewallAddress($fg, $settings)
{
        <#
        .SYNOPSIS
        Sets firewall address objects.
        .DESCRIPTION
        Sets firewall address objects. 
            FG# config firewall address
            FG (address)# edit "addrName" 
            FG (addrName)# set X
        (https://BaseAPIUrl/api/v2/cmdb/firewall/address)
        .EXAMPLE
        $addr = @{"name" = "addrName";"subnet"="10.69.69.0 255.255.255.0";}
        Set-FirewallAddress $fg $addr 
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/firewall/address"

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($settings.name)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($settings.name)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Set-FirewallAddressGroup($fg, $settings)
{
        <#
        .SYNOPSIS
        Sets firewall address group objects.
        .DESCRIPTION
        Sets firewall address group objects. 
            FG# config firewall addrgrp
            FG (address)# edit "grpname" 
            FG (addrName)# set X
        (https://BaseAPIUrl/api/v2/cmdb/firewall/addrgrp)
        .EXAMPLE
        $addrgrp = @{"name" = "grpName";"member"=@(@{"name"="addr1";};@{"name"="addr2";};)}
        Set-FirewallAddressGroup $fg $addrgrp 
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/firewall/addrgrp"

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($settings.name)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($settings.name)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Get-VPNPhase1($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets VPN IPsec Phase 1.
        .DESCRIPTION
        Gets VPN IPsec Phase 1.
            FG# get vpn ipsec phase1-interface
        (https://BaseAPIUrl/api/v2/cmdb/vpn.ipsec/phase1-interface)
        .EXAMPLE
        Get-VPNPhase1 $fg 
        .EXAMPLE
        Get-VPNPhase1 $fg "Phase1Name"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/vpn.ipsec/phase1-interface"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Get-VPNPhase2($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets VPN IPsec Phase 2.
        .DESCRIPTION
        Gets VPN IPsec Phase 2.
            FG# get vpn ipsec phase2-interface
        (https://BaseAPIUrl/api/v2/cmdb/vpn.ipsec/phase2-interface)
        .EXAMPLE
        Get-VPNPhase2 $fg 
        .EXAMPLE
        Get-VPNPhase2 $fg "Phase2Name"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/vpn.ipsec/phase2-interface"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-VPNPhase1($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets VPN IPsec Phase1 interface..
        .DESCRIPTION
        Sets VPN IPsec Phase1 interface. 
            FG# config vpn ipsec phase1-interface
            FG(phase1-interface)# edit phase1Name
            FG(phase1Name)# set X
        (https://BaseAPIUrl/api/v2/cmdb/vpn.ipsec/phase1-interface)
        .EXAMPLE
        $phase1VPN = @{"name" = "vpnName";}
        Set-VPNPhase1 $fg $phase1VPN
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/vpn.ipsec/phase1-interface"

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($settings.name)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($settings.name)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Set-VPNPhase2($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets VPN Phase II interface.
        .DESCRIPTION
        Sets VPN Phase II interface. 
            FG# config vpn ipsec phase2-interface
            FG(phase2-interface)# edit phase2Name
            FG(phase2Name)# set X
        (https://BaseAPIUrl/api/v2/cmdb/vpn.ipsec/phase2-interface)
        .EXAMPLE
        $phase2VPN = @{"name" = "vpnName";}
        Set-VPNPhase2 $fg $phase2VPN
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/vpn.ipsec/phase2-interface"

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($settings.name)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($settings.name)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }

}

function Get-FirewallPolicy($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets firewall policy.
        .DESCRIPTION
        Gets firewall policy. 
            FG# get firewall policy
        (https://BaseAPIUrl/api/v2/cmdb/firewall/policy)
        .EXAMPLE
        Get-FirewallAddress $fg 
        .EXAMPLE
        Get-FirewallAddress $fg "policyName"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/firewall/policy"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-FirewallPolicy($fg,$settings)
{
    <#
        .SYNOPSIS
        Sets firewall policy
        .DESCRIPTION
        Sets firewall policy. 
            FG# config firewall policy
            FG (policy)# edit 1 
            FG (1)# set X
        (https://BaseAPIUrl/api/v2/cmdb/firewall/policy)
        .EXAMPLE
        $policy = @{"id" = "1";"action"="accept"}
        Set-FirewallPolicy $fg $policy 
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/firewall/policy"

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($settings.policyid)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($settings.policyid)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Get-StaticRoute($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets static route.
        .DESCRIPTION
        Gets static route. 
            FG# get router static 
        (https://BaseAPIUrl/api/v2/cmdb/router/static)
        .EXAMPLE
        Get-StaticRoute $fg 
        .EXAMPLE
        Get-StaticRoute $fg "1"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/router/static"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-StaticRoute ($fg,$settings)
{
    <#
        .SYNOPSIS
        Sets static route
        .DESCRIPTION
        Sets static route. 
            FG# config router static
            FG (static)# edit 1 
            FG (1)# set X
        (https://BaseAPIUrl/api/v2/cmdb/router/static)
        .EXAMPLE
        $route = @{"id" = "1";"dstaddr"="addrObj"}
        Set-RouterStatic $fg $route 
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/router/static/" + $settings.'seq-num'

    try {
        Invoke-RestMethod -Method GET ($uri) -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri) -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        $uri = $fg.urlBase + "api/v2/cmdb/router/static"
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Get-BGPRoute($fg)
{
    <#
        .SYNOPSIS
        Gets BGP configuration.
        .DESCRIPTION
        Gets BGP configuration. 
            FG# get router bgp 
        (https://BaseAPIUrl/api/v2/cmdb/router/bgp)
        .EXAMPLE
        Get-BGPRoute $fg 
    #>
    $uri = $fg.urlBase + "api/v2/cmdb/router/bgp"
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-BGPRoute($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets BGP configuration.
        .DESCRIPTION
        Sets BGP configuration. 
            FG# config router bgp 
        (https://BaseAPIUrl/api/v2/cmdb/router/bgp)
        .EXAMPLE
        $bgp = @{"as"=12345;}
        Set-BGPRoute $fg $bgp
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $uri = $fg.urlBase + "api/v2/cmdb/router/bgp"
    $jsonSettings = $settings | ConvertTo-Json -Compress
    return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
}

function Get-RouteMap($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets route maps.
        .DESCRIPTION
        Gets route maps. 
            FG# get router route-map 
        (https://BaseAPIUrl/api/v2/cmdb/router/route-map)
        .EXAMPLE
        Get-RouteMap $fg 
        .EXAMPLE
        Get-RouteMap $fg "routeMapName"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/router/route-map"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-RouteMap($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets route map
        .DESCRIPTION
        Sets route map. 
            FG# config router route-map
            FG (route-map)# edit routeMapName
            FG (routeMapName)# set X
        (https://BaseAPIUrl/api/v2/cmdb/router/route-map)
        .EXAMPLE
        $routeMap = @{"name" = "routeMap";}
        Set-RouteMap $fg $routeMap 
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/router/route-map"

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($settings.name)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($settings.name)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Set-LDAPUser($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets LDAP user configuration
        .DESCRIPTION
        Sets LDAP user configuration 
            FG# config user ldap
            FG (ldap)# edit username
            FG (username)# set X
        (https://BaseAPIUrl/api/v2/cmdb/user/ldap)
        .EXAMPLE
        $ldap = @{"server" = "10.69.69.69";}
        Set-LDAPUser $fg $ldap 
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/user/ldap"

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($settings.name)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($settings.name)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Get-UserGroup($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets user group.
        .DESCRIPTION
        Gets user group. 
            FG# get user group 
        (https://BaseAPIUrl/api/v2/cmdb/user/group)
        .EXAMPLE
        Get-UserGroup $fg 
        .EXAMPLE
        Get-UserGroup $fg "groupName"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/user/group"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Set-UserGroup($fg, $settings)
{
    <#
        .SYNOPSIS
        Sets user group
        .DESCRIPTION
        Sets user group 
            FG# config user group
            FG (group)# edit groupName
            FG (groupName)# set X
        (https://BaseAPIUrl/api/v2/cmdb/user/group)
        .EXAMPLE
        $userGroup = @{"name" = "groupName";}
        Set-LDAPUser $fg $userGroup 
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/user/group"

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($settings.name)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($settings.name)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Set-SystemAdmin($fg,$settings,$name)
{
    <#
        .SYNOPSIS
        Set system administrator user
        .DESCRIPTION
        Sets system administrator user
            FG# config system admin
            FG (group)# edit adminName
            FG (groupName)# set X
        (https://BaseAPIUrl/api/v2/cmdb/system/admin)
        .EXAMPLE
        $adminConfig = @{"name" = "adminName";}
        Set-SystemAdmin $fg $adminConfig 
    #>

    $headers = @{"Content-Type" = "application/json"; "X-CSRFTOKEN" = $fg.cookie}
    $jsonSettings = $settings | ConvertTo-Json -Compress
    $uri = $fg.urlBase + "api/v2/cmdb/system/admin"

    if ($NULL -ne $name)
    {
        $adminName = $name
    }
    else {
        $adminName = $settings.name
    }

    try {
        Invoke-RestMethod -Method GET ($uri + "/$($adminName)") -WebSession $fg.session -ErrorAction SilentlyContinue | Out-Null
        return Invoke-RestMethod ($uri + "/$($adminName)") -Headers $headers -WebSession $fg.session -Method PUT -Body $jsonSettings
    }
    catch [System.InvalidOperationException] {
        return Invoke-RestMethod $uri -Headers $headers -WebSession $fg.session -Method POST -Body $jsonSettings
    }
}

function Get-SystemAdmin($fg, $specific)
{
    <#
        .SYNOPSIS
        Gets system admin.
        .DESCRIPTION
        Gets system admin. 
            FG# get system admin 
        (https://BaseAPIUrl/api/v2/cmdb/system/admin)
        .EXAMPLE
        Get-UserGroup $fg 
        .EXAMPLE
        Get-UserGroup $fg "adminName"
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/system/admin"
    if ($specific)
    {
        $uri += "/$($specific)"
    }
    return ((Invoke-RestMethod -Method GET $uri -WebSession $fg.session).results | ConvertTo-Json)
}

function Remove-SystemAdmin($fg, $specific)
{
    <#
        .SYNOPSIS
        Removes system administrator account.
        .DESCRIPTION
        Removes system administrator account.
            FG# config system admin
            FG (address)# delete "adminName" 
        (https://BaseAPIUrl/api/v2/cmdb/system/admin)
        .EXAMPLE
        Remove-SystemAdmin $fg "adminName" 
    #>

    $uri = $fg.urlBase + "api/v2/cmdb/system/admin/" + $specific
    try 
    {
        Invoke-RestMethod -Method GET $uri -WebSession $fg.session | Out-Null
        Write-Host -BackgroundColor Black -ForegroundColor Yellow "$($fg.hostname)`: System admin $($specific) deleted."
        return ((Invoke-RestMethod -Method DELETE $uri -WebSession $fg.session).results | ConvertTo-Json)
    }
    catch
    {
        Write-Host -BackgroundColor Black -ForegroundColor Green "$($fg.hostname)`: System admin $($specific) does not exist."
    }
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