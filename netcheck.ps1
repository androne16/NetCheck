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

param (
    [switch]$help,
    [switch]$Network,
    [switch]$Internet,
    [switch]$PacketDrop,
    [switch]$Ping,
    [switch]$MTU,
    [switch]$DNS,
    [switch]$WiFi,
    [switch]$IPScan,
    [switch]$SpeedTest,
    [switch]$pingdrop,
	[switch]$Verbose,
    [string]$ip = "8.8.8.8",
    [string]$hours = "1"
)

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
    Write-Host "    -help            Show this help message and exit"
    Write-Host ""
    Write-Host "    -Network         Tests and outputs various network statuses"
    Write-Host "                     Output: Interface.txt, status.txt, ports.txt"
    Write-Host ""
    Write-Host "    -PacketDrop      Sends continuous pings to 8.8.8.8 for 1 hour to check for packet loss"
    Write-Host "                     Output: Internet outages.txt"
    Write-Host ""
    Write-Host "    -Internet        Tests internet services (SMTP, public IP, blacklist check, NTP)"
    Write-Host "                     Output: SMTP.txt, PublicIP.txt, Blacklist.txt, NTP.txt"
    Write-Host ""
    Write-Host "    -Ping            Pings various internet addresses to verify connectivity"
    Write-Host "                     Output: ping.txt"
    Write-Host ""
    Write-Host "    -MTU             Tests MTU settings on the router"
    Write-Host "                     Output: MTU.txt"
    Write-Host ""
    Write-Host "    -DNS             Checks DNS functionality and performance"
    Write-Host "                     Output: DNS.txt"
    Write-Host ""
    Write-Host "    -WiFi            Outputs Wi-Fi configuration and diagnostics"
    Write-Host "                     Output: wifi.txt, Certs.txt, wlan-report-latest.html"
    Write-Host ""
    Write-Host "    -IPScan          Scans local network devices and resolves MAC vendors"
    Write-Host "                     Output: IPlist.txt"
    Write-Host ""
    Write-Host "    -SpeedTest       Runs internet speed test using iPerf against NZ/AU servers"
    Write-Host "                     Output: Speed test.txt"
    Write-Host ""
    Write-Host "    -PingDrop        Ping test to a specific IP for a set number of hours"
    Write-Host "        -ip          IP address to ping (default: 1.1.1.1)"
    Write-Host "        -hours       Hours to ping for (default: 1)"
    Write-Host "                     Output: ping_log.txt"
    Write-Host "                     Example: .\Netcheck.ps1 -pingdrop -ip 8.8.8.8 -hours 2"
    Write-Host ""
	Write-Host "    -Verbose         Show progress bar while jobs are running"
	Write-Host ""
    Write-Host "Default usage: if no commands specified"
    Write-Host "    .\Netcheck.ps1 -Network -Internet -Ping -MTU -DNS -WiFi -SpeedTest"
    exit
}


$jobs = @(
    @{
        Name = 'pingdrop'
        Job = Start-Job -Name 'pingdrop' -ScriptBlock {
            param($ip, $hours)
            $endTime = (Get-Date).AddHours([double]$hours)
            $logFile = "C:\temp\netcheck\ping_log.txt"
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
    },

    @{
        Name = 'NetJob'
        Job = Start-Job -Name 'NetJob' -ScriptBlock {
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
    },

    @{
        Name = 'InternetJob'
        Job = Start-Job -Name 'InternetJob' -ScriptBlock {
            Echo "Testing SMTP"
            Test-NetConnection -ComputerName smtp.office365.com -Port 25 -InformationAction SilentlyContinue > C:\temp\netcheck\SMTP.txt

            Echo "Getting public IP address"
            $output = nslookup myip.opendns.com resolver1.opendns.com
            $output | Out-File -FilePath C:\temp\netcheck\PublicIP.txt

            $ip = ($output | Select-String -Pattern "\d{1,3}(\.\d{1,3}){3}").Matches.Value
            $ipParts = $ip.Split('.')
            [array]::Reverse($ipParts)
            $reversedIp = [string]::Join('.', $ipParts)

            $blacklists = @(".cbl.abuseat.org", ".zen.spamhaus.org", ".dnsbl.sorbs.net")
            foreach ($blacklist in $blacklists) {
                $lookupHost = "$reversedIp$blacklist"
                try {
                    $result = [System.Net.Dns]::GetHostEntry($lookupHost)
                    "IP address $ip is listed in $lookupHost." >> C:\temp\netcheck\Blacklist.txt
                } catch {
                    "IP address $ip is not listed in $lookupHost." >> C:\temp\netcheck\Blacklist.txt
                }
            }

            Echo "Checking NTP"
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
    },

	@{
        Name = 'PacketDropJob'
        Job = Start-Job -Name 'PacketDropJob' -ScriptBlock {
            $host = "8.8.8.8"
            $logFile = "C:\temp\netcheck\Internet outages.txt"
            $endTime = (Get-Date).AddHours(1)

            while ((Get-Date) -lt $endTime) {
                $result = Test-NetConnection -ComputerName $host -InformationAction SilentlyContinue
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                if (-not $result.PingSucceeded) {
                    Add-Content -Path $logFile -Value "$timestamp - Ping failed"
                }
                Start-Sleep -Seconds 1
            }
        }
    },

    @{
        Name = 'PingJob'
        Job = Start-Job -Name 'PingJob' -ScriptBlock {
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
    },

    @{
        Name = 'MTUJob'
        Job = Start-Job -Name 'MTUJob' -ScriptBlock {
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
    },

    @{
        Name = 'DNSJob'
        Job = Start-Job -Name 'DNSJob' -ScriptBlock {
            $outputFile = "C:\temp\netcheck\DNS.txt"
            Ipconfig /flushdns | Out-Null

            $hostname = "google.com"
            $startTime = Get-Date
            $dnsResult = Resolve-DnsName -Name $hostname
            $endTime = Get-Date
            $duration = $endTime - $startTime
            "DNS lookup time for ${hostname}: $duration" | Out-File -FilePath $outputFile -Append

            Echo "DNS test" >> $outputFile
            nslookup google.com >> $outputFile
            nslookup trademe.co.nz >> $outputFile
            nslookup stuff.co.nz >> $outputFile
            nslookup facebook.com >> $outputFile

            Echo "DNS Debug mode" >> $outputFile
            nslookup -d2 google.com >> $outputFile

            $numberoftests = 10
            $totalmeasurement = 0
            $i = 0
            $primaryDnsServer = (Get-WmiObject -Query "SELECT DNSServerSearchOrder FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True").DNSServerSearchOrder | Select-Object -First 1

            while ($i -ne $numberoftests) {
                $measurement = (Measure-Command {Resolve-DnsName www.bing.com -Server $primaryDnsServer -Type A}).TotalSeconds
                $totalmeasurement += $measurement
                $i += 1
            }

            $average = $totalmeasurement / $numberoftests
            "DNS resolution delay. $primaryDnsServer < www.bing.com" >> $outputFile
            $average >> $outputFile
        }
    },

    @{
        Name = 'WiFiJob'
        Job = Start-Job -Name 'WiFiJob' -ScriptBlock {
            CertUtil -store -silent My > C:\temp\netcheck\Certs.txt
            certutil -store -silent -user My >> C:\temp\netcheck\Certs.txt

            Echo "Getting Wifi information"
            NetSh WLAN Show All > C:\temp\netcheck\wifi.txt

            netsh wlan show wlanreport | Out-Null
            Copy-Item "C:\ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html" -Destination "C:\temp\netcheck\wlan-report-latest.html" -Force
        }
    },

    @{
        Name = 'NetworkScanJob'
        Job = Start-Job -Name 'NetworkScanJob' -ScriptBlock {
            $apiKey = "01jv0n5e8kx3b1f0qjsfnawjah01jv0n9h75h7w85409vm0q5me8vhn57j26kcme"
            $outputDir = "C:\temp\netcheck\"
            if (-not (Test-Path $outputDir)) {
                New-Item -Path $outputDir -ItemType Directory | Out-Null
            }

            function Get-LocalSubnet {
                $gateway = (Get-NetRoute | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | Select-Object -ExpandProperty NextHop)[0]
                $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
                    $_.IPAddress -like '192.168.*.*' -or $_.IPAddress -like '10.*.*.*' -or $_.IPAddress -like '172.16.*.*'
                } | Where-Object {
                    $_.InterfaceIndex -eq (Get-NetRoute | Where-Object { $_.NextHop -eq $gateway } | Select-Object -ExpandProperty InterfaceIndex)
                } | Select-Object -ExpandProperty IPAddress)[0]
                return $localIP -replace '\.\d+$'
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
            1..254 | ForEach-Object {
                $ipToPing = "$localSubnet.$_"
                if (Ping-IP $ipToPing) {
                    $arpEntry = Get-NetNeighbor -IPAddress $ipToPing
                    if ($arpEntry) {
                        $macAddress = $arpEntry.LinkLayerAddress
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
    },

    @{
        Name = 'SpeedTestJob'
        Job = Start-Job -Name 'SpeedTestJob' -ScriptBlock {
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
if ($Pingdrop) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'pingdrop' } }
if ($Network) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'NetJob' } }
if ($PacketDrop) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'PacketDropJob' } }
if ($Internet) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'InternetJob' } }
if ($Ping) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'PingJob' } }
if ($MTU) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'MTUJob' } }
if ($DNS) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'DNSJob' } }
if ($WiFi) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'WiFiJob' } }
if ($IPScan) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'NetworkScanJob' } }
if ($SpeedTest) { $selectedJobs += $jobs | Where-Object { $_.Name -eq 'SpeedTestJob' } }

# Start jobs and collect job handles
$jobResults = @()
foreach ($job in $selectedJobs) {
    $jobResult = $job.Job  # Already started in your $jobs array
    $jobResults += $jobResult
}

# Monitor progress
if ($Verbose) {
    while ($true) {
        $runningJobs = $jobResults | Where-Object { $_.State -eq 'Running' }
        $completedJobs = $jobResults | Where-Object { $_.State -eq 'Completed' }
        $totalJobs = $jobResults.Count
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
}

# Wait for jobs to complete and output results
foreach ($job in $jobResults) {
    $result = Receive-Job -Job $job -Wait
    Write-Output $result
    Remove-Job -Job $job
}

