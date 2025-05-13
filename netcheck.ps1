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

## Hous keeping. cleanup old net check files before running. 
rmdir -r c:\temp\netcheck\
mkdir c:\temp\netcheck\
cd c:\temp\netcheck\
$apiKey = "01jv0n5e8kx3b1f0qjsfnawjah01jv0n9h75h7w85409vm0q5me8vhn57j26kcme"
$outputDir = "c:\temp\netcheck\"

$Netjob = {
	
	## IP Config ##
	Echo "Getting Network settings"
	Ipconfig /all > c:\temp\netcheck\Interface.txt
	## Check DNS Cache ##
	Echo "Getting DNS Cache"
	ipconfig /displaydns >> $outputDir\Interface.txt
	## Check DNS State
	Echo "Checnking DNS State"
	netsh dns show state >> $outputDir\Interface.txt
	Get-NetConnectionProfile >> $outputDir\Interface.txt
	## Network Profile ##
	## Check network status and ports. 
	Echo "Checking Network Status and open ports"
	Netstat -s > $outputDir\status.txt
	netstat -a -b > $outputDir\ports.txt
	## Check system time and NTP access
	Echo "Checking Network Time Proticole"
	date > $outputDir\NTP.txt
	If ((w32tm /query /configuration) -eq "The following error occurred: The service has not been started. (0x80070426)") {
		Echo NTP Service not started. Starting service. >> $outputDir\NTP.txt
		net start w32time
	}
	$NTP = w32tm /query /configuration | Select-String -Pattern "NtpServer:" | ForEach-Object { $_.ToString().Split(":")[1].Trim().Split(",")[0] }
	echo NTP Server $NTP >> $outputDir\NTP.txt
	w32tm /stripchart /computer:$NTP /samples:5 >> $outputDir\NTP.txt
	w32tm /stripchart /computer:nz.pool.ntp.org /samples:5 >> $outputDir\NTP.txt
	## Test Port 25 SMTP outbound access 
	Echo "Testing SMTP"
	Test-NetConnection -ComputerName smtp.office365.com -Port 25 > $outputDir\SMTP.txt
	
	# blacklistcheck.ps1 - PowerShell script to check
	# an IP address blacklist status
	Echo "Checking IP Black list"
	$IP = (Invoke-WebRequest -uri "https://api.ipify.org/").Content

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
	Echo Checking if public ip address $ip is in a black list > $outputDir\Backlist.txt
	# Perform DNS lookups for each blacklist
	foreach ($blacklist in $blacklists) {
		$lookupHost = "$reversedIp$blacklist"
		try {
			$result = [System.Net.Dns]::GetHostEntry($lookupHost)
			Echo "IP address $ip is listed in $lookupHost." >> $outputDir\Backlist.txt
		} catch {
			Echo "IP address $ip is not listed in $lookupHost." >> $outputDir\Backlist.txt
		}
	}
}

$Internetjob = {
	$host = "8.8.8.8"  # Replace with the IP address or hostname you want to test
	$logFile = "$outputDir\Internet outages.txt"
	$endTime = (Get-Date).AddHours(1)

	# Ensure the directory exists
	if (-not (Test-Path -Path "$outputDir")) {
		New-Item -Path "$outputDir" -ItemType Directory
	}

	while ((Get-Date) -lt $endTime) {
		$result = Test-NetConnection -ComputerName $host -InformationLevel "Detailed"
		$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
		
		if (-not $result.PingSucceeded) {
			Add-Content -Path $logFile -Value "$timestamp - Ping failed"
		}
		
		Start-Sleep -Seconds 1  # Wait for 1 second before the next ping
	}

	Write-Host "Network test completed. Check the log file at $logFile for details."
}

$Pingjob = {
	## Ping test ##	
	Echo "Testing ping results to verious endpoints" 
	ping -n 30 1.1.1.1 > $outputDir\ping.txt
	ping 8.8.8.8 >> $outputDir\ping.txt
	ping westpac.co.nz >> $outputDir\ping.txt
	ping trademe.co.nz >> $outputDir\ping.txt
	ping stuff.co.nz >> $outputDir\ping.txt
	ping facebook.com >> $outputDir\ping.txt
	ping google.com >> $outputDir\ping.txt
	
	## Test route to Google DNS ##
	Echo "Testing Trace Route"
	tracert 8.8.8.8 >> $outputDir\ping.txt
	## Jitter ##
	# $pingResults = ping -n 30 1.1.1.1 | Select-String -Pattern 'time=' | % {($_.Line.split(' = ')[-1]).split('ms')[0]}
	# $average = ($pingResults | Measure-Object -Average).Average
	# $standardDeviation = [Math]::Sqrt(($pingResults | % { [Math]::Pow(($_ - $average), 2) } | Measure-Object -Sum).Sum / $pingResults.Count)
	# $standardDeviation > c:\temp\netcheck\Jitter.txt
}

$MTUjob = {
	## Test 1452 MTU ##
	Echo "Testing MTU"
	Echo MTU 1452 > $outputDir\MTU.txt
	ping -l 1424 -f 1.1.1.1 >> $outputDir\MTU.txt
	## Test 1492 MTU ##
	Echo MTU 1492 >> $outputDir\MTU.txt
	ping -l 1464 -f 1.1.1.1 >> $outputDir\MTU.txt
	## Test 1500 MTU ##
	Echo MTU 1500 >> $outputDir\MTU.txt
	ping -l 1472 -f 1.1.1.1 >> $outputDir\MTU.txt
	## Test large packet size of 65000 ##
	Echo Jumbo Packets >> $outputDir\MTU.txt
	ping -l 65000 1.1.1.1 >> $outputDir\MTU.txt
}

$DNSjob = {
	## Clear DNS Cache
	Echo "Clearing DNS"
	Ipconfig /cleardns 
	Ipconfig /cleardns 
	Ipconfig /cleardns 
	
	## Get DNS lookup time
	$hostname = "google.com"
	$outputFile = "$outputDir\DNS.txt"

	$startTime = Get-Date
	$dnsResult = Resolve-DnsName -Name $hostname
	$endTime = Get-Date
	$duration = $endTime - $startTime

	$output = "DNS lookup time for ${hostname}: $duration"
	Write-Output $output

	# Write the output to an external file
	$output | Out-File -FilePath $outputFile -Append

	Write-Output "DNS lookup time has been written to $outputFile"

	
	## Get Public ip address ##
	Echo "Getting public ip address"
	Echo Public ip address > $outputDir\DNS.txt
	nslookup myip.opendns.com resolver1.opendns.com >> $outputDir\DNS.txt

	## DNS lookup ##
	Echo "testing DNS"
	Echo DNS test >> $outputDir\DNS.txt
	nslookup google.com >> $outputDir\DNS.txt
	nslookup trademe.co.nz >> $outputDir\DNS.txt
	nslookup stuff.co.nz >> $outputDir\DNS.txt
	nslookup facebook.com >> $outputDir\DNS.txt

	## Debug DNS lookup ##
	Echo DNS Debug mode >> $outputDir\DNS.txt
	nslookup -d2 google.com >> $outputDir\DNS.txt

	## Get the primary DNS server address from the primary network interface ##
	$primaryInterface = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceAlias -notlike '*Loopback*' } | Select-Object -First 1
	$primaryDnsServer = $primaryInterface | Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses | Select-Object -First 1

	## Variables ##
	$numberoftests = 10
	$totalmeasurement = 0
	$i = 0

	## Clear DNS Cache
	Ipconfig /cleardns 
	Ipconfig /cleardns 
	Ipconfig /cleardns 
	
	## Perform multiple tests ##
	while ($i -ne $numberoftests) {
		$measurement = (Measure-Command {Resolve-DnsName www.bing.com -Server $primaryDnsServer -Type A}).TotalSeconds
		$totalmeasurement += $measurement
		$i += 1
	}

	## Calculate average response time ##
	$totalmeasurement = $totalmeasurement / $numberoftests
	Echo DNS resolution delay. $primaryDnsServer "<" www.bing.com >> $outputDir\DNS.txt
	Echo $totalmeasurement >> $outputDir\DNS.txt
}

$NetworkScanjob = {
	# Function to get the local subnet
	function Get-LocalSubnet {
		$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
			$_.IPAddress -like '192.168.*.*' -or $_.IPAddress -like '10.*.*.*' -or $_.IPAddress -like '172.16.*.*'
		} | Select-Object -ExpandProperty IPAddress)[0]
		$localSubnet = $localIP -replace '\.\d+$'
		return $localSubnet
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
						Add-Content -Path "$outputDir\IPlist.txt" -Value $output
					}
				} else {
					Write-Host "Invalid MAC address format: $macAddress"
				}
			}
		}
	}
}

$wifijob = {
	## Certificates ##
	CertUtil -store -silent My > $outputDir\Certs.txt
	certutil -store -silent -user My >> $outputDir\Certs.txt

	## Show Wireless Lan ##
	Echo "Getting Wifi information"
	NetSh WLAN Show All > $outputDir\wifi.txt

	## Wireless Lan report ##
	netsh wlan show wlanreport
	copy C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html $outputDir\wlan-report-latest.html
}

$speedtestjob = {
	## Speed test ##
	Echo "Running a speed test" 
	if (-not (test-path -path "$outputDir\")) {
		mkdir $outputDir\
	}
	
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

	$outputFile = "$outputDir\Speed test.txt"
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
}

param (
    [string[]]$R
)

# Define jobs
$jobs = @(
    @{ Name = 'NetJob'; Script = { Start-Sleep -Seconds 5 } },
    @{ Name = 'InternetJob'; Script = { Start-Sleep -Seconds 5 } },
    @{ Name = 'PingJob'; Script = { Start-Sleep -Seconds 5 } },
    @{ Name = 'MTUJob'; Script = { Start-Sleep -Seconds 5 } },
    @{ Name = 'DNSJob'; Script = { Start-Sleep -Seconds 5 } },
    @{ Name = 'WiFiJob'; Script = { Start-Sleep -Seconds 5 } },
    @{ Name = 'NetworkScanJob'; Script = { Start-Sleep -Seconds 5 } },
    @{ Name = 'SpeedTestJob'; Script = { Start-Sleep -Seconds 5 } }
)

# Filter jobs based on command-line arguments
if ($R) {
    $jobs = $jobs | Where-Object { $R -contains $_.Name }
}

# Start jobs
foreach ($job in $jobs) {
    Start-Job -Name $job.Name -ScriptBlock $job.Script
}

# Monitor progress
while ($true) {
    $runningJobs = Get-Job | Where-Object { $_.State -eq 'Running' }
    $completedJobs = Get-Job | Where-Object { $_.State -eq 'Completed' }
    $totalJobs = $jobs.Count
    $completedCount = $completedJobs.Count

    # Calculate progress percentage
    $progressPercent = [math]::Round(($completedCount / $totalJobs) * 100)

    # Display progress bar
    Write-Progress -Activity "Running Jobs" -Status "$completedCount of $totalJobs completed" -PercentComplete $progressPercent

    # Exit loop if all jobs are completed
    if ($completedCount -eq $totalJobs) {
        break
    }

    Start-Sleep -Seconds 1
}

# Clean up completed jobs
Get-Job | Where-Object { $_.State -eq 'Completed' } | Remove-Job

