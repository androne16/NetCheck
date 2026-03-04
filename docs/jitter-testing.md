# Jitter Testing in `NetCheck`

## Overview
`NetCheck` supports jitter testing in two ways:

- Main workflow: `netcheck.ps1 -Jitter`
- Isolated project track: `netcheck.jitter.ps1`

## Main script usage
```powershell
.\netcheck.ps1 -Jitter
```

Optional tuning:
```powershell
.\netcheck.ps1 -Jitter -JitterSamples 20 -JitterIntervalMs 1000
```

## Standalone jitter project usage
```powershell
.\netcheck.jitter.ps1 -Samples 20 -IntervalMs 1000 -PassThru
```

## Output
Both approaches write jitter results to:

`C:\temp\netcheck\Jitter.txt`

Metrics include:
- sent / received / loss %
- min / avg / max latency (ms)
- jitter (average absolute RTT delta)
