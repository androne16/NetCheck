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
	Ip address's and Arp table on network. (Not working 100% of the time)
	
speedtest
	Iperf speedtest to NZ and AU servers. Changes with avalability 
#>

## Hous keeping. cleanup old net check files before running. 
rmdir -r c:\temp\netcheck\
mkdir c:\temp\netcheck\
cd c:\temp\netcheck\

$Netjob = {
	## IP Config ##
	Ipconfig /all > c:\temp\netcheck\Interface.txt
	## Network Profile ##
	Get-NetConnectionProfile >> c:\temp\netcheck\Interface.txt
	## Check system time and NTP access
	date > c:\temp\netcheck\NTP.txt
	If ((w32tm /query /configuration) -eq "The following error occurred: The service has not been started. (0x80070426)") {
		Echo NTP Service not started. Starting service. >> c:\temp\netcheck\NTP.txt
		net start w32time
	}
	$NTP = w32tm /query /configuration | Select-String -Pattern "NtpServer:" | ForEach-Object { $_.ToString().Split(":")[1].Trim().Split(",")[0] }
	echo NTP Server $NTP >> c:\temp\netcheck\NTP.txt
	w32tm /stripchart /computer:$NTP /samples:5 >> c:\temp\netcheck\NTP.txt
	w32tm /stripchart /computer:nz.pool.ntp.org /samples:5 >> c:\temp\netcheck\NTP.txt
	## Test Port 25 SMTP outbound access 
	Test-NetConnection -ComputerName smtp.office365.com -Port 25 > c:\temp\netcheck\SMTP.txt
	
	# blacklistcheck.ps1 - PowerShell script to check
	# an IP address blacklist status
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
	Echo Checking if public ip address $ip is in a black list > c:\temp\netcheck\Backlist.txt
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
}

$Pingjob = {
	## Ping test ##
	Ping.exe -n 30 1.1.1.1 > c:\temp\netcheck\ping.txt
	ping.exe 8.8.8.8 >> c:\temp\netcheck\ping.txt
	ping.exe westpac.co.nz >> c:\temp\netcheck\ping.txt
	ping.exe trademe.co.nz >> c:\temp\netcheck\ping.txt
	ping.exe stuff.co.nz >> c:\temp\netcheck\ping.txt
	ping.exe facebook.com >> c:\temp\netcheck\ping.txt
	Ping.exe google.com >> c:\temp\netcheck\ping.txt
	## Test route to Google DNS ##
	tracert 8.8.8.8 >> c:\temp\netcheck\ping.txt
	## Jitter ##
	$pingResults = ping -n 30 1.1.1.1 | Select-String -Pattern 'time=' | % {($_.Line.split(' = ')[-1]).split('ms')[0]}
	$average = ($pingResults | Measure-Object -Average).Average
	$standardDeviation = [Math]::Sqrt(($pingResults | % { [Math]::Pow(($_ - $average), 2) } | Measure-Object -Sum).Sum / $pingResults.Count)
	$standardDeviation > c:\temp\netcheck\Jitter.txt
}

$MTUjob = {
	## Test 1452 MTU ##
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
}

$DNSjob = {
	## Clear DNS Cache
	Ipconfig /cleardns 
	Ipconfig /cleardns 
	Ipconfig /cleardns 
	
	## Get Public ip address ##
	Echo Public ip address > c:\temp\netcheck\DNS.txt
	nslookup myip.opendns.com resolver1.opendns.com >> c:\temp\netcheck\DNS.txt

	## DNS lookup ##
	Echo DNS test >> c:\temp\netcheck\DNS.txt
	nslookup google.com >> c:\temp\netcheck\DNS.txt
	nslookup trademe.co.nz >> c:\temp\netcheck\DNS.txt
	nslookup stuff.co.nz >> c:\temp\netcheck\DNS.txt
	nslookup facebook.com >> c:\temp\netcheck\DNS.txt

	## Debug DNS lookup ##
	Echo DNS Debug mode >> c:\temp\netcheck\DNS.txt
	nslookup -d2 google.com >> c:\temp\netcheck\DNS.txt

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
	Echo DNS resolution delay. $primaryDnsServer "<" www.bing.com >> c:\temp\netcheck\DNS.txt
	Echo $totalmeasurement >> c:\temp\netcheck\DNS.txt
}

$Networkjob = {
	## IP network scan ##
	$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -like '192.168.*.*' -or $_.IPAddress -like '10.*.*.*' -or $_.IPAddress -like '172.16.*.*'} | Select-Object -ExpandProperty IPAddress)[0] -replace '\.\d+$' 
	1..254 | % {ping -n 1 -w 1000 $IP"."$_ | Select-String "Reply from" } > C:\temp\netcheck\IPlist.txt

	## Arp table ##
	Arp -a > c:\temp\netcheck\arp.txt
}

$wifijob = {
	## Certificates ##
	CertUtil -store -silent My > c:\temp\netcheck\Certs.txt
	certutil -store -silent -user My >> c:\temp\netcheck\Certs.txt

	## Show Wireless Lan ##
	NetSh WLAN Show All > c:\temp\netcheck\wifi.txt

	## Wireless Lan report ##
	netsh wlan show wlanreport
	copy C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html c:\temp\netcheck\wlan-report-latest.html
}

$speedtestjob = {
	## Spped test ##
	if (Test-Path -Path "C:\temp\iperf-3.1.3-win64\") {
		Write-Output "File exists"
	} else {
		wget https://iperf.fr/download/windows/iperf-3.1.3-win64.zip -outfile c:\temp\iperf.zip
		Expand-Archive -LiteralPath C:\temp\iperf.Zip -DestinationPath C:\temp
		rm C:\temp\iperf.Zip
	}

	cd C:\Temp\iperf-3.1.3-win64

	$Client0 = "202.137.240.193"
	$Client1 = "speedtest4.nownz.co.nz"
	$Client2 = "198.142.237.65"
	$Client3 = "198.142.237.97"

	$d = 1
	Write-output "Download Speed" > "c:\temp\netcheck\Speed test.txt"
	if (Test-Path -Path "C:\Temp\iperf-3.1.3-win64\iperf3.exe" -PathType Leaf) {
		Echo "File exists" >> "c:\temp\netcheck\Speed test.txt"
		while($d -ne 10)
		{
			$Download = & .\iperf3.exe --client $client0 --parallel 10 --reverse --verbose
			if (($Download | Select-Object -Last 1) -eq "iperf Done.") {
				$Download | Select-Object -Last 4 | Select-Object -First 2 | Write-Output >> "c:\temp\netcheck\Speed test.txt"
				Echo $Client0 >> "c:\temp\netcheck\Speed test.txt"
				$d = 10
			} else {
				if (($Download | Select-Object -Last 1) -eq "iperf3: error - the server is busy running a test. try again later" -or ($Download | Select-Object -Last 1) -eq "iperf3: error - unable to create a new stream: Permission denied" -or ($Download | Select-Object -Last 1) -eq "iperf3: error - unable to connect to server: Connection refused" -or ($Download | Select-Object -Last 1) -eq "iperf3: error - unable to connect to server: Connection timed out" -or ($Download | Select-Object -Last 1) -eq "iperf3: error - control socket has closed unexpectedly" -or ($Download | Select-Object -Last 1) -eq "iperf3: error - unable to receive control message: Connection reset by peer") { 
						Start-Sleep -Seconds 20
						$d++
						If ($d -eq 3) {
							$Client0 = $client1
						}
						If ($d -eq 5) {
							$Client0 = $client2
						}
						If ($d -eq 8) {
							$Client0 = $client3
						}
					
				} else {
					Write-output "iPerf failed to get download speed." >> "c:\temp\netcheck\Speed test.txt"
					write-output $Download >> "c:\temp\netcheck\Speed test.txt"
					$d = 10
					
				}
			}
		}

		$u = 1
		Write-output "Upload Speed" >> "c:\temp\netcheck\Speed test.txt"
		while($u -ne 10)
		{
			$Upload = & .\iperf3.exe --client $Client0 --parallel 10 --verbose
			if (($Upload | Select-Object -Last 1) -eq "iperf Done.") {
				$Upload | Select-Object -Last 4 | Select-Object -First 2 | Write-output >> "c:\temp\netcheck\Speed test.txt"
				$u = 10
			} else {
				if (($Upload | Select-Object -Last 1) -eq "iperf3: error - the server is busy running a test. try again later" -or ($Upload | Select-Object -Last 1) -eq "iperf3: error - unable to create a new stream: Permission denied" -or ($Upload | Select-Object -Last 1) -eq "iperf3: error - unable to connect to server: Connection refused"		-or ($Upload | Select-Object -Last 1) -eq "iperf3: error - unable to connect to server: Connection timed out" -or ($Upload | Select-Object -Last 1) -eq "iperf3: error - control socket has closed unexpectedly" -or ($Upload | Select-Object -Last 1) -eq "iperf3: error - unable to receive control message: Connection reset by peer") { 
					Start-Sleep -Seconds 30 
					$u++
					If ($u -eq 3) {
							$Client0 = $client1
						}
					If ($u -eq 5) {
							$Client0 = $client2
						}
					If ($u -eq 8) {
							$Client0 = $client3
						}
					} else {
						Write-output "iPerf failed to get upload speed." >> "c:\temp\netcheck\Speed test.txt"
						Write-output $Upload >> "c:\temp\netcheck\Speed test.txt"
						$u = 10
					}
				}
			}
		}
	else {
		Echo "File does not exist in both areas. Please check the file path." >> "c:\temp\netcheck\Speed test.txt"
	}
}

start-job $NetJob | out-null
start-job $Pingjob | out-null
start-job $MTUjob | out-null
start-job $DNSjob | out-null
start-job $wifijob | out-null
start-job $Networkjob | out-null
start-job $speedtestjob | out-null