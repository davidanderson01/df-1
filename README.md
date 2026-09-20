# df-1

runs recon on public domains

## Scan and download a report

Run the script without a domain and enter one or more domains when prompted:

```powershell
& ".\.venv\Scripts\python.exe" .\main.py --no-color
```

Enter domains separated by commas, for example:

```text
elevatecraft.com, example.org
```

Each investigation immediately creates both reports. A single domain uses:

```text
Downloads/report/domain_history.json
Downloads/report/domain_history.csv
```

Multiple domains receive separate filenames such as `elevatecraft.com_domain_history.json` and `example.org_domain_history.csv`.

You can also provide a domain directly:

```powershell
& ".\.venv\Scripts\python.exe" .\main.py elevatecraft.com --no-color
```

## Tests

```powershell
& "C:\Users\david\AppData\Local\Microsoft\WindowsApps\python.exe" -m pytest -q tests/test_domain_forensics.py
```
