param (
    # Network interface alias (eg. WiFi, Ethernet)
    [Parameter(Mandatory=$true)]
    [string]
    $interfaceAlias = 'WiFi',
    # Resolve hostname of RemoteAddr?
    [Parameter(Mandatory=$false)]
    [bool]
    $useAbusedipdb
)

# Abused IP DB api key REQUIRED FOR ABUSEDIPDB LOOKUP TO WORK
# Create a free account at https://www.abuseipdb.com/ for 1000 requests a day
$apiKey = ""
$ipAddress = (Get-NetIPAddress -InterfaceAlias $interfaceAlias -AddressFamily IPv4).ipaddress

class CSVRows {
    [object]${State}
    [object]${ProcessName}
    [object]${LocalPort}
    [object]${LocalAddress}
    [object]${RemotePort}
    [object]${RemoteAddress}
    [object]${countryCode}
    [object]${Hostnames}
    [object]${domain}
    [object]${isp}
    [object]${abuseConfidenceScore}
    [object]${isWhiteListed}
}   

function Get-AbuseIPdb {
    param (
        [string]$apiKey,
        [string]$remoteAddr
    )
    $body = @{
        "ipAddress"     = $remoteAddr
        "maxAgeInDays"  = '90'
    }
    $header = @{
        "Key"           = $apiKey
        "Accept"        = "application/json"
    }
    $abuseipdb = curl https://api.abuseipdb.com/api/v2/check -Headers $header -Method GET -Body $body
    $abuseipdb = $abuseipdb | ConvertFrom-Json 
    $abuseipdb.data 
}

# Get all TCP connections on device IP (no multicast, 0.0.0.0)
$tcpArray = Get-NetTCPConnection -LocalAddress $ipAddress  

# Get headers
$headers = 'State,ProcessName,LocalPort,LocalAddress,RemotePort,RemoteAddress,countryCode,Hostnames,isp,domain,abuseConfidenceScore,isWhiteListed'
$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12 = $headers.Split(',')

[system.collections.arraylist] $TCPConnections = foreach ($tcp in $tcpArray){
    # Write Progress
    $i = $i+1 # Write-Progress counter

    $prcsname = (Get-Process -Id $tcp.OwningProcess).ProcessName # OwningProcessName
    if ($useAbusedipdb -eq $true) {
        if ($tcp.$6 -notmatch "^10\.((0\.){2}([1-9]|[1-9]\d|[12]\d\d)|0\.([1-9]|[1-9]\d|[12]\d\d)\.([1-9]?\d|[12]\d\d)|([1-9]|[1-9]\d|[12]\d\d)(\.([1-9]?\d|[12]\d\d)){2})") {
            $lookup = Get-AbuseIPdb $apiKey $tcp.$6
        }

    }
    
    Write-Progress -Activity 'looking up...' -Status $tcp.$6 -PercentComplete ($i/$tcpArray.Length*100)

    $row    = [CSVRows]::new()
    $row.$1 =   $tcp.$1
    $row.$2 =   $prcsname
    $row.$3 =   $tcp.$3
    $row.$4 =   $tcp.$4
    $row.$5 =   $tcp.$5
    $row.$6 =   $tcp.$6
    $row.$7 =   $lookup.$7
    if ($lookup.$8) {
        $row.$8 =   $lookup.$8[0].ToString()
    } else {
        $row.$8 =   ''
    }
    $row.$9 =   $lookup.$9
    $row.$10=   $lookup.$10
    $row.$11=   $lookup.$11
    $row.$12=   $lookup.$12
    $row
}
$TCPConnections | Format-Table -AutoSize
$TCPConnections | Export-Csv -Path C:\temp\tcpconnectionsreport.csv -Delimiter ";" -Encoding UTF8
