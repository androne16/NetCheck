<#
A comprahencive network testing script developed by AJ
Output of the following commands will be placed into seperate txt files in c:\temp\netcheck\

Functions currently included. 

Network 
	interface properties. 

NTP
	Test NTP server vs nz.pool.ntp.org

Wifi 
	interface properties. 
	Error report. 

Ping test
	Pinging multiple websites. 
	Jitter (not currently working).

MTU
	Testing max MTU and MMS

DNS	
	Public ip address
	Checking DNS is operating as intended
	Verbose output. 
	Testing DNS delay. 
	
Network scan. 
	Ip address's, mac address and vendors
	
speedtest
	Iperf speedtest to NZ and AU servers. Changes with avalability 
#>

## Paramitors
param (
	[switch]$help,
	[switch]$Network,
	[switch]$Internet,
	[switch]$PacketDrop,
	[switch]$Ping,
	[switch]$MTU,
	[switch]$DNS,
	[switch]$WiFi,
	[switch]$NetworkScan,
	[switch]$SpeedTest
)

## Hous keeping. cleanup old net check files before running. 
if (-not ($help)) {
	Rmdir -r c:\temp\netcheck\
	$OutputDir = "C:\temp\netcheck\"
	if (-Not (Test-Path $OutputDir)) {
		&New-Item -Path $OutputDir -ItemType Directory | Out-Null
	}
}

if ($help) {
	Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	Write-Host "Welcome to Netcheck. A complex network checking tool for Powershell."
	Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
	Write-Host "Findings will be found in individual files in $outputDIR"
	Write-Host ""
	Write-Host "Options:"
	Write-Host "	-help            Show this help message and exit"
	Write-Host "	-Network         Tests and outputs various network statuses"
	Write-Host "	-PacketDrop      Sends continuous pings to 8.8.8.8 for 1 hour to check for packet loss."
	Write-Host "	-Internet        Tests various internet services, including SMTP availability,"
	Write-Host "                         public IP address detection, and block list checks."
	Write-Host "	-Ping            Pings various internet addresses to verify connectivity"
	Write-Host "                         issues with routing or session stantup."
	Write-Host "	-MTU             Tests the MTU settings on the router."
	Write-Host "	-DNS             Checks DNS functionality." 
	Write-Host "	-Wifi            Output wi-fi issues."
	Write-Host "	-NetworkScan     Scan network devices and mac addresses with vendors." 
	Write-Host "	-speedtest       Internet speed test against NZ or AU servers."
	Write-Host ""
	Write-Host "Default options: Netcheck.ps1 -Network -Internet -Ping -MTU -DNS -WiFi -Speedtest"	
	exit
}

# Define jobs
$jobs = @(
    @{ Name = 'NetJob'; Script = { 
		## IP Config ##
		Echo "Getting Network settings"
		Ipconfig /all > c:\temp\netcheck\Interface.txt
		## Check DNS Cache ##
		Echo "Getting DNS Cache"
		ipconfig /displaydns >> c:\temp\netcheck\Interface.txt
		## Check DNS State
		Echo "Checnking DNS State"
		netsh dns show state >> c:\temp\netcheck\Interface.txt
		Get-NetConnectionProfile >> c:\temp\netcheck\Interface.txt
		## Network Profile ##
		## Check network status and ports. 
		Echo "Checking Network Status and open ports"
		Netstat -s > c:\temp\netcheck\status.txt
		netstat -a -b > c:\temp\netcheck\ports.txt 
		; "Network Job completed" 
		} 
	},
	
    @{ Name = 'InternetJob'; Script = { 
		## Test Port 25 SMTP outbound access 
		Echo "Testing SMTP"
		Test-NetConnection -ComputerName smtp.office365.com -Port 25 -InformationAction SilentlyContinue > c:\temp\netcheck\SMTP.txt
		
		# blacklistcheck.ps1 - PowerShell script to check
		## Get Public ip address ##
		Echo "Checking IP Black list"
		$IP = nslookup myip.opendns.com resolver1.opendns.com
		Echo "Getting public ip address"
		Echo Public ip address > c:\temp\netcheck\PublicIP.txt
		$output | Out-File -FilePath c:\temp\netcheck\PublicIP.txt -Append

		# Reverse the IP address: 1.2.3.4 becomes 4.3.2.1
		$ipParts = $ip.Split('.')
		[array]::Reverse($ipParts)
		$reversedIp = [string]::Join('.', $ipParts)

		# List of blacklists to perform checks on
		$blacklists = @(
			".cbl.abuseat.org",
			".zen.spamhaus.org",
			".dnsbl.sorbs.net"
			# Add more blacklists here if needed
		)		
		
		Echo "Checking if public ip address $ip is in a black list" > c:\temp\netcheck\Backlist.txt
		# Perform DNS lookups for each blacklist
		foreach ($blacklist in $blacklists) {
			$lookupHost = "$reversedIp$blacklist"
			try {
				$result = [System.Net.Dns]::GetHostEntry($lookupHost)
				Echo "IP address $ip is listed in $lookupHost." >> c:\temp\netcheck\Backlist.txt
			} catch {
				Echo "IP address $ip is not listed in $lookupHost." >> c:\temp\netcheck\Backlist.txt
			}
		}
		## Check system time and NTP access
		Echo "Checking Network Time Proticole"
		date > c:\temp\netcheck\NTP.txt
		If ((w32tm /query /configuration) -eq "The following error occurred: The service has not been started. (0x80070426)") {
			Echo NTP Service not started. Starting service. >> c:\temp\netcheck\NTP.txt
			net start w32time
		}
		$NTP = w32tm /query /configuration | Select-String -Pattern "NtpServer:" | ForEach-Object { $_.ToString().Split(":")[1].Trim().Split(",")[0] }
		echo NTP Server $NTP >> c:\temp\netcheck\NTP.txt
		w32tm /stripchart /computer:$NTP /samples:5 >> c:\temp\netcheck\NTP.txt
		w32tm /stripchart /computer:nz.pool.ntp.org /samples:5 >> c:\temp\netcheck\NTP.txt

		## Jitter ##
		# $pingResults = ping -n 30 1.1.1.1 | Select-String -Pattern 'time=' | % {($_.Line.split(' = ')[-1]).split('ms')[0]}
		# $average = ($pingResults | Measure-Object -Average).Average
		# $standardDeviation = [Math]::Sqrt(($pingResults | % { [Math]::Pow(($_ - $average), 2) } | Measure-Object -Sum).Sum / $pingResults.Count)
		# $standardDeviation > c:\temp\netcheck\Jitter.txt 
		;"Internet Job completed" 
		} 
	},
	
    @{ Name = 'PacketDropJob'; Script = { 
		$host = "8.8.8.8"  # Replace with the IP address or hostname you want to test
		$logFile = "c:\temp\netcheck\Internet outages.txt"
		$endTime = (Get-Date).AddHours(1)
		
		## Test packet drop for 1 hour
		while ((Get-Date) -lt $endTime) {
			$result = Test-NetConnection -ComputerName $host -InformationAction SilentlyContinue
			$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
			if (-not $result.PingSucceeded) {
				Add-Content -Path $logFile -Value "$timestamp - Ping failed"
			}
			Start-Sleep -Seconds 1  # Wait for 1 second before the next ping
		}
		Write-Host "Network test completed. Check the log file at $logFile for details."
		;
		"Packet Drop Job completed" 
		} 
	},
	
    @{ Name = 'PingJob'; Script = { 
		## Ping test ##	
		Echo "Testing ping results to verious endpoints" 
		ping -n 30 1.1.1.1 > c:\temp\netcheck\ping.txt
		ping 8.8.8.8 >> c:\temp\netcheck\ping.txt
		ping westpac.co.nz >> c:\temp\netcheck\ping.txt
		ping trademe.co.nz >> c:\temp\netcheck\ping.txt
		ping stuff.co.nz >> c:\temp\netcheck\ping.txt
		ping facebook.com >> c:\temp\netcheck\ping.txt
		ping google.com >> c:\temp\netcheck\ping.txt
		
		## Test route to Google DNS ##
		Echo "Testing Trace Route"
		tracert 8.8.8.8 >> c:\temp\netcheck\ping.txt
		; 
		"Ping Job completed" 
		} 
	},
	
    @{ Name = 'MTUJob'; Script = { 
		## Test 1452 MTU ##
		Echo "Testing MTU"
		Echo MTU 1452 > c:\temp\netcheck\MTU.txt
		ping -l 1424 -f 1.1.1.1 >> c:\temp\netcheck\MTU.txt
		## Test 1492 MTU ##
		Echo MTU 1492 >> c:\temp\netcheck\MTU.txt
		ping -l 1464 -f 1.1.1.1 >> c:\temp\netcheck\MTU.txt
		## Test 1500 MTU ##
		Echo MTU 1500 >> c:\temp\netcheck\MTU.txt
		ping -l 1472 -f 1.1.1.1 >> c:\temp\netcheck\MTU.txt
		## Test large packet size of 65000 ##
		Echo Jumbo Packets >> c:\temp\netcheck\MTU.txt
		ping -l 65000 1.1.1.1 >> c:\temp\netcheck\MTU.txt
		; 
		"MTU Job completed" 
		} 
	},
	
    @{ Name = 'DNSJob'; Script = { 
		## Clear DNS Cache
		Ipconfig /flushdns | Out-Null
		Ipconfig /flushdns | Out-Null
		Ipconfig /flushdns | Out-Null
		
		## Get DNS lookup time
		$hostname = "google.com"
		$outputFile = "c:\temp\netcheck\DNS.txt"
		$startTime = Get-Date
		$dnsResult = Resolve-DnsName -Name $hostname
		$endTime = Get-Date
		$duration = $endTime - $startTime
		$output = "DNS lookup time for ${hostname}: $duration"

		# Write the output to an external file
		$output | Out-File -FilePath $outputFile -Append

		## DNS lookup ##
		Echo DNS test >> c:\temp\netcheck\DNS.txt
		nslookup google.com >> c:\temp\netcheck\DNS.txt
		nslookup trademe.co.nz >> c:\temp\netcheck\DNS.txt
		nslookup stuff.co.nz >> c:\temp\netcheck\DNS.txt
		nslookup facebook.com >> c:\temp\netcheck\DNS.txt

		## Debug DNS lookup ##
		Echo DNS Debug mode >> c:\temp\netcheck\DNS.txt
		nslookup -d2 google.com >> c:\temp\netcheck\DNS.txt
		
		## Variables ##
		$numberoftests = 10
		$totalmeasurement = 0
		$i = 0
		
		## Get the primary DNS server address from the primary network interface ##
		$primaryDnsServer = (Get-WmiObject -Query "SELECT DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True").DNSServerSearchOrder | Select-Object -First 1

		## Clear DNS Cache
		Ipconfig /flushdns | Out-Null
		Ipconfig /flushdns | Out-Null
		Ipconfig /flushdns | Out-Null
		
		## Perform multiple tests ##
		while ($i -ne $numberoftests) {
			$measurement = (Measure-Command {Resolve-DnsName www.bing.com -Server $primaryDnsServer -Type A}).TotalSeconds
			$totalmeasurement += $measurement
			$i += 1
		}

		## Calculate average response time ##
		$totalmeasurement = $totalmeasurement / $numberoftests
		Echo DNS resolution delay. $primaryDnsServer "<" www.bing.com >> c:\temp\netcheck\DNS.txt
		Echo $totalmeasurement >> c:\temp\netcheck\DNS.txt
		; 
		"DNSJob completed" 
		} 
	},
	
    @{ Name = 'WiFiJob'; Script = { 
		## Certificates ##
		CertUtil -store -silent My > c:\temp\netcheck\Certs.txt
		certutil -store -silent -user My >> c:\temp\netcheck\Certs.txt

		## Show Wireless Lan ##
		Echo "Getting Wifi information"
		NetSh WLAN Show All > c:\temp\netcheck\wifi.txt

		## Wireless Lan report ##
		netsh wlan show wlanreport | Out-Null
		copy C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html c:\temp\netcheck\wlan-report-latest.html
		; 
		"WiFiJob completed" 
		} 
	},
	
    @{ Name = 'NetworkScanJob'; Script = { 
		# Function to get the local subnet
		$apiKey = "01jv0n5e8kx3b1f0qjsfnawjah01jv0n9h75h7w85409vm0q5me8vhn57j26kcme"
		$outputDir = "c:\temp\netcheck\"
		function Get-LocalSubnet {
			try {
				# Get the default gateway
				$gateway = (Get-NetRoute | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | Select-Object -ExpandProperty NextHop)[0]

				if ($null -eq $gateway -or $gateway -eq '') {
					throw "No valid gateway found."
				}

				# Get the local IP address associated with the gateway
				$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
					$_.IPAddress -like '192.168.*.*' -or $_.IPAddress -like '10.*.*.*' -or $_.IPAddress -like '172.16.*.*'
				} | Where-Object {
					$_.InterfaceIndex -eq (Get-NetRoute | Where-Object { $_.NextHop -eq $gateway } | Select-Object -ExpandProperty InterfaceIndex)
				} | Select-Object -ExpandProperty IPAddress)[0]

				if ($null -eq $localIP -or $localIP -eq '') {
					throw "No valid local IP address found."
				}

				# Determine the local subnet
				$localSubnet = $localIP -replace '\.\d+$'

				if ($null -eq $localSubnet -or $localSubnet -eq '') {
					throw "Failed to determine local subnet."
				}

				return $localSubnet
			} catch {
				Write-Error $_
				return $null
			}
		}

		# Function to ping an IP address
		function Ping-IP($ip) {
			try {
				Test-Connection -ComputerName $ip -Count 1 -ErrorAction SilentlyContinue | Out-Null
				return $true
			} catch {
				return $false
			}
		}

		# Function to get MAC address details from maclookup.app
		function Get-MacDetails($mac) {
			$url = "https://api.maclookup.app/v2/macs/$($mac)?apiKey=$($apiKey)"
			Write-Host "Requesting MAC details for $mac from $url"
			try {
				$response = Invoke-RestMethod -Uri $url -Method Get
				return $response
			} catch {
				Write-Host "Error fetching MAC details for $mac"
				Write-Host $_.Exception.Message
				return $null
			}
		}

		# Get the local subnet
		$localSubnet = Get-LocalSubnet
		Write-Host "Scanning subnet: $localSubnet"

		# Scan the subnet and get ARP table
		1..254 | ForEach-Object {
			$ipToPing = "$localSubnet.$_"
			if (Ping-IP $ipToPing) {
				$arpEntry = Get-NetNeighbor -IPAddress $ipToPing
				if ($arpEntry) {
					$macAddress = $arpEntry.LinkLayerAddress
					# Ensure MAC address is in the correct format
					if ($macAddress -match '^[0-9A-Fa-f]{2}([-:])[0-9A-Fa-f]{2}(\1[0-9A-Fa-f]{2}){4}$') {
						$macDetails = Get-MacDetails $macAddress
						if ($macDetails) {
							$output = "IP: $ipToPing, MAC: $macAddress, Vendor: $($macDetails.company)"
							Write-Host $output
							Add-Content -Path "c:\temp\netcheck\IPlist.txt" -Value $output
						}
					} else {
						Write-Host "Invalid MAC address format: $macAddress"
					}
				}
			}
		}
		; 
		"NetworkScanJob completed" 
		} 
	},
	
    @{ Name = 'SpeedTestJob'; Script = { 
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

		if (Test-Path -Path "C:\Temp\iperf-3.1.3-win64\iperf3.exe" -PathType Leaf) {
			Add-Content -Path $outputFile -Value "File exists"

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
		} else {
			Add-Content -Path $outputFile -Value "File does not exist in both areas. Please check the file path."
		}
		; 
		"SpeedTestJob completed" 
		} 
	}
)

## job management
## Default run all if no parameters set
if (-not ($help -or $Network -or $Internet -or $packetDrop -or $Ping -or $MTU -or $DNS -or $WiFi -or $NetworkScan -or $SpeedTest)) {
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

# Filter jobs based on command-line arguments
$selectedJobs = @()
if ($Network) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'NetJob' } }
if ($PacketDrop) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'PacketDropJob' } }
if ($Internet) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'InternetJob' } }
if ($Ping) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'PingJob' } }
if ($MTU) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'MTUJob' } }
if ($DNS) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'DNSJob' } }
if ($WiFi) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'WiFiJob' } }
if ($NetworkScan) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'NetworkScanJob' } }
if ($SpeedTest) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'SpeedTestJob' } }

# Start jobs and collect output
$jobResults = @()
foreach ($job in $selectedJobs) {
    $jobResult = Start-Job -Name $job.Name -ScriptBlock $job.Script
    $jobResults += $jobResult
}

# Wait for jobs to complete and output results
$jobResults | ForEach-Object {
    $result = Receive-Job -Job $_ -Wait
    Write-Output $result
    Remove-Job -Job $_
}

# Monitor progress
#while ($true) {
#    $runningJobs = Get-Job | Where-Object { $_.State -eq 'Running' }
#    $completedJobs = Get-Job | Where-Object { $_.State -eq 'Completed' }
#    $totalJobs = $selectedJobs.Count
#    $completedCount = $completedJobs.Count
#
#    # Calculate progress percentage
#    $progressPercent = [math]::Round(($completedCount / $totalJobs) * 100)
#
#    # Display progress bar
#    Write-Progress -Activity "Running Jobs" -Status "$completedCount of $totalJobs completed" -PercentComplete $progressPercent
#
#    # Exit loop if all jobs are completed
#    if ($completedCount -eq $totalJobs) {
#       break
#    }
#    Start-Sleep -Seconds 1
#}

# Clean up completed jobs
Get-Job | Where-Object { $_.State -eq 'Completed' } | Remove-Job

