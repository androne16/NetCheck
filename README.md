NetCheck
NetCheck is a comprehensive network testing script developed in PowerShell. It provides various network diagnostic tools to help you analyze and troubleshoot network issues effectively.

**Features**
Network Interface Properties: Displays detailed properties of network interfaces.
.NTP Test: Compares NTP server time with nz.pool.ntp.org.
.WiFi Interface Properties: Shows properties of WiFi interfaces.
.Error Report: Generates a report of detected errors.
.Ping Test: Pings multiple websites to check connectivity.
.MTU Testing: Tests maximum MTU and MMS.
.DNS Testing: Checks if DNS is operating as intended and measures DNS delay.
.Network Scan: Scans the network for IP addresses and ARP table entries.
.Speed Test: Performs speed tests using iPerf to NZ and AU servers.

**Installation**
1. Clone the repository:
	git clone https://github.com/androne16/NetCheck.git
2. Navigate to the project directory:
	cd NetCheck

**Usage**
Run the script using PowerShell:
	.\netcheck.ps1

The output of the commands will be placed into separate text files in C:\temp\netcheck\.

**Contributing**
Contributions are welcome! Please fork the repository and submit a pull request.

**License**
This project is licensed under the Unlicense. See the LICENSE file for details.