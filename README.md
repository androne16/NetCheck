NetCheck
NetCheck is a comprehensive network testing and diagnostic script developed in PowerShell. It provides a suite of tools to analyze, troubleshoot, and validate network performance and configuration.

Features
Network

Display detailed properties of all network interfaces.
Collect adapter details for troubleshooting.

NTP

Compare local NTP server time with nz.pool.ntp.org.
Validate time synchronization accuracy.

Wi-Fi

Show wireless interface properties.
Generate error reports for connectivity issues.

Ping Test

Ping multiple websites to check connectivity.
Measure latency and packet loss.
Jitter measurement (currently not implemented).

MTU

Test maximum MTU and MMS for optimal packet size.

DNS

Display public IP address.
Verify DNS resolution and functionality.
Verbose output for troubleshooting.
Measure DNS query delay.

Network Scan

Discover active IP addresses on the local subnet.
Collect MAC addresses and vendor details.
Skip invalid MACs and duplicate entries.
Only include hosts that respond to ping.

Speed Test

Perform iPerf speed tests to NZ and AU servers (server availability may vary).
Log download and upload speeds.

Logging

All results saved in structured text files under C:\temp\netcheck\.
Error handling and warnings for missing data.


Installation

Clone the repository:

git clone https://github.com/androne16/NetCheck.git


Navigate to the project directory:

cd NetCheck


Usage
Run the script using PowerShell:
.\netcheck.ps1

All output files will be saved in:
C:\temp\netcheck\


Contributing
Contributions are welcome!
Please fork the repository and submit a pull request with your improvements.

License
This project is licensed under the Unlicense.
See the LICENSE file for details.