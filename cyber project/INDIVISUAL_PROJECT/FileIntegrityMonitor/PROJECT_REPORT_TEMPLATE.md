# Project Report: File Integrity Monitoring & Tampering Detection

## 1. Abstract
This project demonstrates file integrity monitoring using SHA-256 cryptographic hashes. The application records a trusted baseline for files in a selected folder and compares later scans against that baseline. It identifies modified, newly created, and deleted files and records events in a local JSON Lines audit log. A Streamlit dashboard presents scan results and audit history. This is an educational prototype and is not intended to replace enterprise endpoint security controls.

## 2. Introduction
File integrity monitoring helps identify unexpected changes to important files. A file hash acts as a content fingerprint: when the file contents change, its SHA-256 hash will normally change too.

## 3. Problem Statement
Manual checking of important files is time-consuming and may fail to reveal unauthorized or accidental changes. A simple tool is needed to compare files with a known trusted state and report differences.

## 4. Objectives
- Calculate SHA-256 hashes for monitored files.
- Create and store a trusted baseline.
- Detect modified, new, and deleted files.
- Record scan events in an audit log.
- Present results through a simple dashboard.
- Evaluate the tool with repeatable test cases.

## 5. Tools and Technologies
- Python
- `hashlib` for SHA-256
- `json` and `pathlib` for baseline and file handling
- Streamlit for the user interface
- Pandas for displaying tables

## 6. System Design
Monitored folder → SHA-256 hashing → baseline comparison → event classification → audit log → dashboard.

## 7. Implementation
Describe the roles of `calculate_hash`, `create_baseline`, `scan_files`, and `write_audit_event` in your own words. Include screenshots of the dashboard and each test.

## 8. Testing and Results
Fill this table with your actual results; do not claim tests passed until you have run them.

| Test | Action | Expected event | Actual result |
|---|---|---|---|
| 1 | Scan without changes | Clean scan | Fill in |
| 2 | Edit `config.txt` | MODIFIED | Fill in |
| 3 | Delete `security_policy.txt` | DELETED | Fill in |
| 4 | Add `notes.txt` | NEW_FILE | Fill in |
| 5 | Review audit history | Events listed | Fill in |

Detection rate = detected introduced changes / total introduced changes × 100%.

False-positive rate = unchanged scans incorrectly reported as changes / total unchanged scans × 100%.

Audit logging completeness = detected change events correctly logged / total detected change events × 100%.

## 9. Limitations
- Scans run only when a user clicks the scan button.
- The local baseline and audit log can be altered by a sufficiently privileged user.
- Hash differences do not identify the person who changed a file or establish whether the change was malicious.
- This prototype does not provide enterprise alerting or access-control enforcement.

## 10. Future Scope
- Add continuous monitoring with a file-system watcher.
- Protect baseline records with digital signatures or secure storage.
- Send logs to a remote, access-controlled logging service.
- Add notifications and user/role access control.

## 11. Conclusion
Summarize what the implementation detected during your actual tests, what you learned about hashing and baselines, and which limitations you would address next.

## 12. References
- Python `hashlib` documentation: https://docs.python.org/3/library/hashlib.html
- Python `pathlib` documentation: https://docs.python.org/3/library/pathlib.html
- Streamlit documentation: https://docs.streamlit.io/
