# NetCheck

NetCheck is a PowerShell-based network testing and diagnostics script that runs a collection of checks and writes results to structured files for review.

Features
- Network interface and configuration dump (IP, routes, open ports)
- Public IP, geo lookup and DNS blacklist checks
- NTP tests against local server and `nz.pool.ntp.org`
- Wi‑Fi diagnostics and certificate listing (includes `wlan-report-latest.html`)
- Ping tests (multiple hosts, traceroute)
- Jitter testing (latency variation per endpoint)
- MTU probing
- DNS resolution checks and timing
- Local IP subnet scan with MAC vendor lookup
- iPerf-based speed tests (auto-downloads iPerf if missing)
- Optional long-running ping-drop monitoring

Requirements
- Windows (PowerShell)
- PowerShell 5.1 or newer recommended
- Internet access for external lookups and speed tests
- Optional: run as Administrator for full Wi‑Fi and certificate checks

What the script generates
All output is written to `C:\temp\netcheck\` by default. Typical files produced:

- `Interface.txt` (ipconfig, netsh, DNS cache)
- `status.txt`, `ports.txt` (netstat output)
- `PublicIP.txt`, `GeoLocation.txt`, `Blacklist.txt`
- `NTP.txt`
- `SMTP_*.txt` (SMTP connectivity checks)
- `ping.txt`, `Ping Drop.txt` (continuous ping)
- `Jitter.txt` (jitter, latency, packet loss summary)
- `MTU.txt`
- `DNS.txt`
- `wifi.txt`, `Certs.txt`, `wlan-report-latest.html`
- `IPlist.txt` (scanned local IPs w/ MAC vendor)
- `Speed test.txt` (iPerf results)

Usage
Clone the repository and run the script from PowerShell:

```
git clone https://github.com/androne16/NetCheck.git
cd NetCheck
.\Netcheck.ps1
```

If no switches are provided, the script runs the default set (network, internet, ping, jitter, MTU, DNS, WiFi, speedtest, SMTP).

Project versions
- `netcheck.ps1` (stable): full network diagnostics workflow.
- `netcheck.jitter.ps1` (jitter project track): focused, test-friendly implementation for developing and validating jitter metrics.

Jitter project (build/test split)
- Build track: develop jitter logic in `netcheck.jitter.ps1` without impacting the stable script.
- Test track: run repeatable CLI tests with configurable targets/sample count and review `Jitter.txt` output.

Run jitter project from CLI
```
# Default jitter test targets
.\netcheck.jitter.ps1

# Custom run for test validation
.\netcheck.jitter.ps1 -Target 1.1.1.1,8.8.8.8 -Samples 20 -IntervalMs 1000 -Verbose
```

Jitter output
- Output path: `C:\temp\netcheck\Jitter.txt`
- Metrics per target:
  - sent/received/loss%
  - min/avg/max latency (ms)
  - jitter (average absolute RTT delta in ms)

Common switches (examples):

- `-h`, `-help` : show help and exit
- `-n`, `-Network` : network/interface checks -> `Interface.txt`, `status.txt`, `ports.txt`
- `-i`, `-Internet` : public IP, geo, blacklist, NTP -> `PublicIP.txt`, `GeoLocation.txt`, `Blacklist.txt`, `NTP.txt`
- `-@`, `-SMTP` : SMTP port checks -> `SMTP_*.txt`
- `-p`, `-Ping` : ping multiple hosts -> `ping.txt`
- `-j`, `-Jitter` : jitter/latency consistency test -> `Jitter.txt` (supports `-JitterSamples`, `-JitterIntervalMs`)
- `-m`, `-MTU` : MTU tests -> `MTU.txt`
- `-d`, `-DNS` : DNS checks and timing -> `DNS.txt`
- `-w`, `-WiFi` : Wi‑Fi diagnostics -> `wifi.txt`, `Certs.txt`, `wlan-report-latest.html`
- `-ips`, `-IPScan` : local subnet scan -> `IPlist.txt`
- `-s`, `-SpeedTest` : iPerf speed tests -> `Speed test.txt` (downloads iPerf if needed)
- `-pd`, `-PingDrop` : long-running ping test to a specific IP
  - use `-ip` to specify the address (default `1.1.1.1`) and `-hours` to set duration (default `1`)

Notes
- iPerf is automatically downloaded to `C:\temp\iperf-3.1.3-win64\` if missing.
- The script calls external APIs (e.g., `ip-api.com`, `maclookup.app`) for geo and MAC vendor lookups.
- Some checks (certificate store, `netsh wlan` reports) require Administrator privileges.

Contributing
- Contributions welcome. Fork, make changes, and open a pull request.

License
- This project is licensed under the Unlicense. See the `LICENSE` file for details.

