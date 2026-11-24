function Get-FreeLocalPort {
    param(
        [string]$HostAddress = '127.0.0.1',
        [int]$StartPort = 8080,
        [int]$MaxOffset = 20
    )

    $probeHost = if ($HostAddress -eq 'localhost' -or $HostAddress -eq '0.0.0.0' -or $HostAddress -eq '::') {
        '127.0.0.1'
    } else {
        $HostAddress
    }

    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($probeHost, [ref]$ip)) {
        return $StartPort
    }

    for ($i = 0; $i -lt $MaxOffset; $i++) {
        $port = $StartPort + $i
        if ($port -gt 65535) {
            break
        }
        $listener = [System.Net.Sockets.TcpListener]::new($ip, $port)
        try {
            $listener.ExclusiveAddressUse = $true
            $listener.Start()
            return $port
        } catch [System.Net.Sockets.SocketException] {
            continue
        } finally {
            $listener.Stop()
        }
    }

    return $StartPort
}
