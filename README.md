# df-1

runs recon on public domains

## Scan and download a report

Run the script without a domain and enter one or more domains when prompted:

```powershell
& ".\.venv\Scripts\python.exe" .\main.py --no-color
```

Enter domains separated by commas, for example:

```text
example.com, example.org
```

Each investigation immediately creates both reports using the domain and UTC scan time:

```text
<user-home>/Downloads/report/example.com_<UTC-date-time>_domain_history.json
<user-home>/Downloads/report/example.com_<UTC-date-time>_domain_history.csv
```

Multiple domains receive separate timestamped filenames for each entered domain.

You can also provide a domain directly:

```powershell
& ".\.venv\Scripts\python.exe" .\main.py example.com --no-color
```

## Tests

```powershell
& ".\.venv\Scripts\python.exe" -m pytest -q tests/test_domain_forensics.py
```
