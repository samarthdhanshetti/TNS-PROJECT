# File Integrity Monitoring & Tampering Detection

A beginner-friendly cybersecurity project using Python SHA-256 hashing, a JSON baseline, JSONL audit logging, and a Streamlit dashboard.

## Requirements
- Python 3.11 or 3.12 recommended
- Windows, macOS, or Linux
- Internet access for the first installation of Python packages

## Windows setup
Open Command Prompt or the VS Code terminal, then run these commands one at a time from the folder where you want the project:

```bat
cd FileIntegrityMonitor
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m streamlit run app.py
```

If `cd FileIntegrityMonitor` fails, first navigate to the parent folder that contains this project folder. The dashboard usually opens at http://localhost:8501.

## How to test
1. Open the dashboard.
2. Review the three sample files inside `monitored_files/`.
3. Tick the trust checkbox and click **Create / Reset Baseline** once.
4. Click **Scan Files Now**. It should report no changes.
5. Open `monitored_files/config.txt`, change `debug=false` to `debug=true`, save it, then scan again. Expect `MODIFIED`.
6. Restore `debug=false` if you want, then scan. Because the baseline is unchanged, the file should still be reported as modified until you restore the exact original contents.
7. Delete `monitored_files/security_policy.txt` and scan. Expect `DELETED`.
8. Create `monitored_files/notes.txt` containing `test file` and scan. Expect `NEW_FILE`.
9. Review the audit history in the dashboard.

Do not reset the baseline between test cases unless you intentionally want to accept the current state as trusted.

## Files generated automatically
- `baseline.json`: trusted file hashes recorded when you create/reset a baseline.
- `audit.jsonl`: append-only-style local event history (not tamper-proof).

## Security notes
This is an educational prototype. The audit log and baseline are stored locally and can be changed by someone with sufficient permissions. For a real system, restrict access, store baseline hashes securely, use protected/remote logs, and consider continuous monitoring.
