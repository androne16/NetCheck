<#
A comprehensive network testing and diagnostic script developed by AJ.
All output will be saved into separate text files under: C:\temp\netcheck\

Features Included:

1. Network:
    - Display interface properties.
    - Collect adapter details for troubleshooting.

2. NTP:
    - Test local NTP server against nz.pool.ntp.org.
    - Validate time synchronization accuracy.

3. Wi-Fi:
    - Show wireless interface properties.
    - Generate error report for connectivity issues.

4. Ping Test:
    - Ping multiple websites for connectivity.
    - Measure latency and packet loss.
    - Jitter measurement (currently not implemented).

5. MTU:
    - Test maximum MTU and MMS for optimal packet size.

6. DNS:
    - Display public IP address.
    - Verify DNS resolution and functionality.
    - Verbose output for troubleshooting.
    - Measure DNS query delay.

7. Network Scan:
    - Discover active IP addresses on local subnet.
    - Collect MAC addresses and vendor details.
    - Skip invalid MACs and duplicate entries.
    - Only include hosts that respond to ping.

8. Speed Test:
    - Perform iPerf speed tests to NZ and AU servers (server availability may vary).
    - Log download and upload speeds.

9. Logging:
    - All results saved in structured text files for review.
    - Error handling and warnings for missing data.

Future Enhancements:
    - Implement jitter calculation.
    - Add graphical summary of results.
    - Optional export to CSV or HTML report.
#>
[CmdletBinding()]
param(
    [Alias('h')][switch]$help,
    [Alias('n')][switch]$Network,
    [Alias('i')][switch]$Internet,
    [Alias('p')][switch]$Ping,
    [Alias('m')][switch]$MTU,
    [Alias('d')][switch]$DNS,
    [Alias('w')][switch]$WiFi,
    [Alias('ips')][switch]$IPScan,
    [Alias('s')][switch]$SpeedTest,
    [Alias('pd')][switch]$PingDrop,
    [Alias('hr')][string]$hours = "1",
    [string]$ip = "1.1.1.1"
)
## job management
## Default run all if no parameters set
if (-not ($help -or $Network -or $Internet -or $pingDrop -or $Ping -or $MTU -or $DNS -or $WiFi -or $SpeedTest -or $IPScan)) {
    $Network = $true
    $Internet = $true
    $Ping = $true
    $MTU = $true
    $DNS = $true
    $WiFi = $true
    $SpeedTest = $true
	Write-Host ""
    Write-Host "Default options: Netcheck.ps1 -Network -Internet -Ping -MTU -DNS -WiFi -Speedtest"
	Write-Host ""
	Write-Host "For more options, Run Netcheck.ps1 -help"
	Write-Host ""
}
# Start jobs and collect job handles
$jobResults = @()
foreach ($job in $selectedJobs) {
    $jobResult = $job.Job  # Already started in your $jobs array
    $jobResults += $jobResult
}
## Housekeeping
if (-not ($help)) {
    Remove-Item -Recurse -Force "C:\temp\netcheck\" -ErrorAction SilentlyContinue
    $OutputDir = "C:\temp\netcheck\"
    if (-Not (Test-Path $OutputDir)) {
        New-Item -Path $OutputDir -ItemType Directory | Out-Null
    }
}

if ($help) {
    Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    Write-Host "Welcome to Netcheck. A complex network checking tool for PowerShell."
    Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    Write-Host "Findings will be saved in individual files under: $OutputDir"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "    -h -help             Show this help message and exit"
    Write-Host ""
    Write-Host "    -n -Network          Tests and outputs various network statuses"
    Write-Host "	                     Output: Interface.txt, status.txt, ports.txt"
    Write-Host ""
    Write-Host "    -i -Internet         Tests internet services (SMTP, public IP, blacklist check, NTP)"
    Write-Host "                     	 Output: SMTP.txt, PublicIP.txt, Blacklist.txt, NTP.txt"
    Write-Host ""
    Write-Host "    -p -Ping             Pings various internet addresses to verify connectivity"
    Write-Host "                 	     Output: ping.txt"
    Write-Host ""
    Write-Host "    -m -MTU              Tests MTU settings on the router"
    Write-Host "            	         Output: MTU.txt"
    Write-Host ""
    Write-Host "    -d -DNS              Checks DNS functionality and performance"
    Write-Host "	                     Output: DNS.txt"
    Write-Host ""
    Write-Host "    -w -WiFi             Outputs Wi-Fi configuration and diagnostics"
    Write-Host "                     	 Output: wifi.txt, Certs.txt, wlan-report-latest.html"
    Write-Host ""
    Write-Host "    -ips -IPScan         Scans local network devices and resolves MAC vendors"
    Write-Host "                     	 Output: IPlist.txt"
    Write-Host ""
    Write-Host "    -s -SpeedTest        Runs internet speed test using iPerf against NZ/AU servers"
    Write-Host "                    	 Output: Speed test.txt"
    Write-Host ""
    Write-Host "    -pd -PingDrop        Ping test to a specific IP for a set number of hours"
    Write-Host "        	-ip          IP address to ping (default: 1.1.1.1)"
    Write-Host "       		-hours       Hours to ping for (default: 1)"
    Write-Host "            	         Output: ping_log.txt"
    Write-Host "            	         Example: .\Netcheck.ps1 -pingdrop -ip 8.8.8.8 -hours 2"
    Write-Host ""
	Write-Host "    -v -Verbose          Show progress bar while jobs are running"
	Write-Host ""
    Write-Host "Default usage: if no commands specified"
    Write-Host "    .\Netcheck.ps1 -Network -Internet -Ping -MTU -DNS -WiFi -SpeedTest"
    exit
}

if ($PingDrop) {
    Start-Job -Name 'pingdrop' -ScriptBlock {
        param($ip, $hours)
        $endTime = (Get-Date).AddHours([double]$hours)
        $logFile = "C:\temp\netcheck\Ping Drop.txt"
        while ((Get-Date) -lt $endTime) {
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $result = Test-Connection -ComputerName $ip -Count 1 -ErrorAction SilentlyContinue
            if ($result) {
                "$timestamp - Reply from $($result.Address): time=$($result.ResponseTime)ms" | Out-File -FilePath $logFile -Append
            } else {
                "$timestamp - Request timed out" | Out-File -FilePath $logFile -Append
            }
            Start-Sleep -Seconds 1
        }
	} -ArgumentList $ip, $hours
}

if ($Network) {
	Start-Job -Name 'NetJob' -ScriptBlock {
		Echo "Getting Network settings"
		ipconfig /all > C:\temp\netcheck\Interface.txt
		Echo "Getting DNS Cache"
		ipconfig /displaydns >> C:\temp\netcheck\Interface.txt
		Echo "Checking DNS State"
		netsh dns show state >> C:\temp\netcheck\Interface.txt
		Get-NetConnectionProfile >> C:\temp\netcheck\Interface.txt
		Echo "Checking Network Status and open ports"
		netstat -s > C:\temp\netcheck\status.txt
		netstat -a -b > C:\temp\netcheck\ports.txt
	}
}

if ($Internet) {
	Start-Job -Name 'InternetJob' -ScriptBlock {
		
		Write-Host "Getting public IP address..."
		$output = nslookup myip.opendns.com resolver1.opendns.com
		$output | Out-File -FilePath C:\temp\netcheck\PublicIP.txt

		# Get last IP match (public IP)
		$matches = ($output | Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}").Matches
		$ip = $matches[-1].Value

		Write-Host "Getting geo-location information for public IP..."

		# Query ip-api.com for geo-location info
		$response = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip"

		# Extract useful details
		$geoInfo = @{
			IP        = $response.query
			Country   = $response.country
			Region    = $response.regionName
			City      = $response.city
			ISP       = $response.isp
			Latitude  = $response.lat
			Longitude = $response.lon
		}

		# Save details to file
		$outputPath = "C:\temp\netcheck\GeoLocation.txt"
		$geoInfo | Out-File -FilePath $outputPath

		# Reverse IP for DNSBL lookup
		$ipParts = $ip.Split('.')
		[array]::Reverse($ipParts)
		$reversedIp = [string]::Join('.', $ipParts)

		# Blacklists
		$blacklists = @(".cbl.abuseat.org", ".zen.spamhaus.org", ".dnsbl.sorbs.net")

		foreach ($blacklist in $blacklists) {
			$lookupHost = "$reversedIp$blacklist"
			try {
				$result = [System.Net.Dns]::GetHostEntry($lookupHost)
				"IP address $ip is LISTED in $blacklist." >> C:\temp\netcheck\Blacklist.txt
			} catch {
				"IP address $ip is NOT listed in $blacklist." >> C:\temp\netcheck\Blacklist.txt
			}
		}
		
		Write-host "Checking NTP"
		date > C:\temp\netcheck\NTP.txt
		if ((w32tm /query /configuration) -match "The service has not been started") {
			"NTP Service not started. Starting service." >> C:\temp\netcheck\NTP.txt
			net start w32time
		}

		$NTP = w32tm /query /configuration | Select-String -Pattern "NtpServer:" | ForEach-Object { $_.ToString().Split(":")[1].Trim().Split(",")[0] }
		"NTP Server $NTP" >> C:\temp\netcheck\NTP.txt
		w32tm /stripchart /computer:$NTP /samples:5 >> C:\temp\netcheck\NTP.txt
		w32tm /stripchart /computer:nz.pool.ntp.org /samples:5 >> C:\temp\netcheck\NTP.txt
	}
	Start-Job -Name 'SMTP' -ScriptBlock {
		$outputFile = "C:\temp\netcheck\SMTP.txt"
		$outDir     = [System.IO.Path]::GetDirectoryName($outputFile)
		if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }
		
		"Testing SMTP" | Out-File -FilePath $outputFile -Append
		Test-NetConnection -ComputerName smtp.office365.com -Port 25 -InformationAction SilentlyContinue 2>&1 | Out-File -FilePath $outputFile -Append
		Test-NetConnection -ComputerName smtp.office365.com -Port 587 -InformationAction SilentlyContinue 2>&1 | Out-File -FilePath $outputFile -Append
		Test-NetConnection -ComputerName smtp.gmail.com -Port 465 -InformationAction SilentlyContinue 2>&1 | Out-File -FilePath $outputFile -Append
	}
}

if ($Ping) {
	Start-Job -Name 'PingJob' -ScriptBlock {
		$logFile = "C:\temp\netcheck\ping.txt"
		Echo "Testing ping results to various endpoints" > $logFile
		ping -n 30 1.1.1.1 >> $logFile
		ping 8.8.8.8 >> $logFile
		ping westpac.co.nz >> $logFile
		ping trademe.co.nz >> $logFile
		ping stuff.co.nz >> $logFile
		ping facebook.com >> $logFile
		ping google.com >> $logFile
		Echo "Testing Trace Route" >> $logFile
		tracert 8.8.8.8 >> $logFile
	}
}

if ($MTU) {
	Start-Job -Name 'MTUJob' -ScriptBlock {
		$logFile = "C:\temp\netcheck\MTU.txt"
		Echo "Testing MTU" > $logFile
		Echo "MTU 1452" >> $logFile
		ping -l 1424 -f 1.1.1.1 >> $logFile
		Echo "MTU 1492" >> $logFile
		ping -l 1464 -f 1.1.1.1 >> $logFile
		Echo "MTU 1500" >> $logFile
		ping -l 1472 -f 1.1.1.1 >> $logFile
		Echo "Jumbo Packets" >> $logFile
		ping -l 65000 1.1.1.1 >> $logFile
	}
}

if ($DNS) {
    Start-Job -Name 'DNSJob' -ScriptBlock {
        $outputFile = "C:\temp\netcheck\DNS.txt"
        $outDir     = [System.IO.Path]::GetDirectoryName($outputFile)
        if (-not (Test-Path $outDir)) { New-Item -Path $outDir -ItemType Directory -Force | Out-Null }

        $ProgressPreference = 'SilentlyContinue'
        $WarningPreference  = 'SilentlyContinue'

        ipconfig /flushdns | Out-Null

        $hostname  = 'google.com'
        $startTime = Get-Date
        try {
            # Suppress errors & warnings
            $null = Resolve-DnsName -Name $hostname -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        } catch {
            # Avoid $hostname: parsing by delimiting variable
            "Resolve-DnsName failed for ${hostname}: $($_.Exception.Message)" | Out-File -FilePath $outputFile -Append
        }
        $endTime  = Get-Date
        $duration = $endTime - $startTime
        "DNS lookup time for ${hostname}: $duration" | Out-File -FilePath $outputFile -Append

        "DNS test" | Out-File -FilePath $outputFile -Append
        # Suppress stderr (red text) from nslookup
        nslookup google.com        2>&1 | Out-File -FilePath $outputFile -Append
        nslookup trademe.co.nz     2>&1 | Out-File -FilePath $outputFile -Append
        nslookup stuff.co.nz       2>&1 | Out-File -FilePath $outputFile -Append
        nslookup facebook.com      2>&1 | Out-File -FilePath $outputFile -Append

        "DNS Debug mode" | Out-File -FilePath $outputFile -Append
        nslookup -d2 google.com    2>$null | Out-File -FilePath $outputFile -Append

        $numberOfTests    = 10
        $totalMeasurement = 0.0
        $i = 0

        # Prefer CIM over deprecated WMI
        $primaryDnsServer = (Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
                             Where-Object { $_.DNSServerSearchOrder } |
                             Select-Object -ExpandProperty DNSServerSearchOrder -First 1)

        while ($i -lt $numberOfTests) {
            $measurement = (Measure-Command {
                Resolve-DnsName www.bing.com -Server $primaryDnsServer -Type A -DnsOnly `
                    -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
            }).TotalSeconds
            $totalMeasurement += $measurement
            $i++
        }

        $average = [math]::Round(($totalMeasurement / $numberOfTests), 4)
        "DNS resolution delay. $primaryDnsServer < www.bing.com" | Out-File -FilePath $outputFile -Append
        $average | Out-File -FilePath $outputFile -Append
    }
}

if ($WiFi) {
	Start-Job -Name 'WiFiJob' -ScriptBlock {
		CertUtil -store -silent My > C:\temp\netcheck\Certs.txt
		certutil -store -silent -user My >> C:\temp\netcheck\Certs.txt

		Echo "Getting Wifi information"
		NetSh WLAN Show All > C:\temp\netcheck\wifi.txt

		netsh wlan show wlanreport | Out-Null
		Copy-Item "C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html" -Destination "C:\temp\netcheck\wlan-report-latest.html" -Force
	}
}

if ($IPScan) {
	Start-Job -Name 'IPScanJob' -ScriptBlock {
		$apiKey = "01jv0n5e8kx3b1f0qjsfnawjah01jv0n9h75h7w85409vm0q5me8vhn57j26kcme"
		$outputDir = "C:\temp\netcheck\"
		if (-not (Test-Path $outputDir)) {
			New-Item -Path $outputDir -ItemType Directory | Out-Null
		}
		
		function Get-LocalSubnet {
			$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
				$_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*'
			} | Select-Object -ExpandProperty IPAddress | Select-Object -First 1)

			if (-not $localIP) {
				Write-Warning "No local IP found."
				return $null
			}

			$octets = $localIP -split '\.'
			if ($octets.Count -ge 3) {
				return "$($octets[0]).$($octets[1]).$($octets[2])"
			} else {
				Write-Warning "Unexpected IP format: $localIP"
				return $null
			}
		}
		
		function Ping-IP($ip) {
			Test-Connection -ComputerName $ip -Count 1 -ErrorAction SilentlyContinue | Out-Null
			return $true
		}

		function Get-MacDetails($mac) {
			$url = "https://api.maclookup.app/v2/macs/$($mac)?apiKey=$($apiKey)"
			try {
				return Invoke-RestMethod -Uri $url -Method Get
			} catch {
				return $null
			}
		}

		$localSubnet = Get-LocalSubnet
		if (-not $localSubnet) {
			Write-Error "Local subnet could not be determined. Aborting scan."
			return
		}
		$seenMacs = @{}
		1..254 | ForEach-Object {
			$ipToPing = "$localSubnet.$_"
			
			if (Ping-IP $ipToPing) {  # Only proceed if ping succeeds
				$arpEntry = Get-NetNeighbor -IPAddress $ipToPing
				if ($arpEntry) {
					$macAddress = $arpEntry.LinkLayerAddress
					
					# Skip invalid MACs and duplicates
					if ($macAddress -ne '00-00-00-00-00-00' -and -not $seenMacs.ContainsKey($macAddress)) {
						$seenMacs[$macAddress] = $true
						
						if ($macAddress -match '^[0-9A-Fa-f]{2}([-:])[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}$') {
							$macDetails = Get-MacDetails $macAddress
							$vendor = if ($macDetails) { $macDetails.company } else { "Unknown" }
							$output = "IP: $ipToPing, MAC: $macAddress, Vendor: $vendor"
						} else {
							$output = "IP: $ipToPing, MAC: $macAddress, Vendor: Invalid MAC format"
						}
						
						Add-Content -Path "$outputDir\IPlist.txt" -Value $output
					}
				}
			}
		}
	}
}

if ($SpeedTestJob) {
	Start-Job -Name 'SpeedTestJob' -ScriptBlock {
	## Speed test ##
	Echo "Running a speed test" 
	
	if (-Not (Test-Path -Path "C:\temp\iperf-3.1.3-win64\")) {
		Invoke-WebRequest -Uri "https://iperf.fr/download/windows/iperf-3.1.3-win64.zip" -OutFile "C:\temp\iperf.zip"
		Expand-Archive -LiteralPath "C:\temp\iperf.zip" -DestinationPath "C:\temp"
		Remove-Item "C:\temp\iperf.zip"
	}

	cd "C:\Temp\iperf-3.1.3-win64"

	$clients = @(
		@{ Address = "akl.linetest.nz"; Ports = 5300..5309 },
		@{ Address = "chch.linetest.nz"; Ports = 5201..5210 },
		@{ Address = "speedtest.syd12.au.leaseweb.net"; Ports = 5201..5210 },
		@{ Address = "syd.proof.ovh.net"; Ports = 5201..5210 }
	)

	$outputFile = "c:\temp\netcheck\Speed test.txt"
	Write-Output "Download Speed" > $outputFile

		function Test-Speed {
			param (
				[string]$client,
				[int[]]$ports,
				[bool]$reverse
			)

			foreach ($port in $ports) {
				if ($reverse) {
					$result = & .\iperf3.exe --client $client --port $port --parallel 10 --reverse --verbose
				} else {
					$result = & .\iperf3.exe --client $client --port $port --parallel 10 --verbose
				}

				if ($result -match "iperf Done.") {
					$result | Select-Object -Last 4 | Select-Object -First 2 | Out-File -Append -FilePath $outputFile
					Add-Content -Path $outputFile -Value "$client"
					Add-Content -Path $outputFile -Value "$port"
					return $true
				} elseif ($result -match "iperf3: error") {
					Start-Sleep -Seconds 20
				} else {
					Add-Content -Path $outputFile -Value "iPerf failed to get speed."
					Add-Content -Path $outputFile -Value $result
					return $false
				}
			}
			return $false
		}

		$d = 0
		while ($d -lt $clients.Count) {
			if (Test-Speed -client $clients[$d].Address -ports $clients[$d].Ports -reverse $true) {
				break
			}
			$d++
		}

		Write-Output "Upload Speed" >> $outputFile
		$u = 0
		while ($u -lt $clients.Count) {
			if (Test-Speed -client $clients[$u].Address -ports $clients[$u].Ports -reverse $false) {
				break
			}
			$u++
		}
	; 
	write-host "SpeedTestJob completed" 
	}
}

get-job