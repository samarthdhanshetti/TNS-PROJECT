import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
MONITORED_DIR = ROOT / "monitored_files"
BASELINE_FILE = ROOT / "baseline.json"
AUDIT_FILE = ROOT / "audit.jsonl"

st.set_page_config(page_title="File Integrity Monitor", page_icon="🛡️", layout="wide")


def current_time():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def calculate_hash(file_path: Path) -> str:
    """Return the SHA-256 hash of a file's contents."""
    digest = hashlib.sha256()
    with file_path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(4096), b""):
            digest.update(chunk)
    return digest.hexdigest()


def get_current_files():
    """Return relative file paths mapped to SHA-256 hashes."""
    results = {}
    MONITORED_DIR.mkdir(parents=True, exist_ok=True)

    for path in sorted(MONITORED_DIR.rglob("*")):
        # Skip symbolic links so the monitor does not follow them outside the folder.
        if path.is_symlink() or not path.is_file():
            continue
        relative_path = path.relative_to(MONITORED_DIR).as_posix()
        results[relative_path] = calculate_hash(path)

    return results


def write_audit_event(event, file_path="", old_hash="", new_hash=""):
    """Append one JSON record per line to the local audit log."""
    record = {
        "timestamp_utc": current_time(),
        "event": event,
        "file": file_path,
        "baseline_sha256": old_hash,
        "current_sha256": new_hash,
    }
    with AUDIT_FILE.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record, ensure_ascii=False) + "\n")


def load_baseline():
    if not BASELINE_FILE.exists():
        return None
    try:
        data = json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
            raise ValueError("Baseline format is invalid.")
        return data
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        st.error(f"Could not read baseline.json: {exc}")
        return None


def create_baseline():
    files = get_current_files()
    baseline = {
        "created_at_utc": current_time(),
        "hash_algorithm": "SHA-256",
        "files": files,
    }
    temporary_file = BASELINE_FILE.with_suffix(".tmp")
    temporary_file.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    temporary_file.replace(BASELINE_FILE)
    write_audit_event("BASELINE_CREATED", new_hash=f"{len(files)} files recorded")
    return len(files)


def scan_files():
    baseline = load_baseline()
    if baseline is None:
        return [], 0, "Create a baseline before scanning."

    expected = baseline["files"]
    current = get_current_files()
    events = []

    for name in sorted(expected.keys() - current.keys()):
        events.append({"Event": "DELETED", "File": name,
                       "Baseline SHA-256": expected[name], "Current SHA-256": ""})

    for name in sorted(current.keys() - expected.keys()):
        events.append({"Event": "NEW_FILE", "File": name,
                       "Baseline SHA-256": "", "Current SHA-256": current[name]})

    for name in sorted(expected.keys() & current.keys()):
        if expected[name] != current[name]:
            events.append({"Event": "MODIFIED", "File": name,
                           "Baseline SHA-256": expected[name], "Current SHA-256": current[name]})

    if events:
        for item in events:
            write_audit_event(
                item["Event"],
                item["File"],
                item["Baseline SHA-256"],
                item["Current SHA-256"],
            )
        return events, len(current), None

    write_audit_event("CLEAN_SCAN", new_hash=f"{len(current)} files checked")
    return [], len(current), None


def read_audit_log():
    if not AUDIT_FILE.exists():
        return []
    records = []
    with AUDIT_FILE.open("r", encoding="utf-8") as log_file:
        for line in log_file:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                # Ignore malformed lines rather than crashing the dashboard.
                continue
    return records


st.title("🛡️ File Integrity Monitoring & Tampering Detection")
st.caption("Cybersecurity training project • Local demonstration only")

st.info(
    "The application calculates SHA-256 hashes of files in `monitored_files/` "
    "and compares them with a trusted baseline. It detects content changes, "
    "new files, and deleted files."
)

if not MONITORED_DIR.exists():
    MONITORED_DIR.mkdir(parents=True, exist_ok=True)

baseline = load_baseline()
current_count = len(get_current_files())

col1, col2, col3 = st.columns(3)
col1.metric("Files currently monitored", current_count)
col2.metric("Baseline status", "Created" if baseline else "Not created")
col3.metric("Audit records", len(read_audit_log()))

st.subheader("1. Baseline")
st.warning(
    "Create the baseline only when the files are in a state you trust. "
    "Resetting it after a detected change accepts the current files as the new reference."
)
trusted = st.checkbox("I have reviewed the files and trust their current contents.")
if st.button("Create / Reset Baseline", type="primary", disabled=not trusted):
    count = create_baseline()
    st.success(f"Baseline created with {count} file(s).")
    st.rerun()

st.subheader("2. Scan for changes")
if st.button("Scan Files Now"):
    results, checked_count, error = scan_files()
    if error:
        st.error(error)
    elif results:
        st.error(f"Detected {len(results)} change(s) while checking {checked_count} current file(s).")
        st.dataframe(pd.DataFrame(results), use_container_width=True, hide_index=True)
    else:
        st.success(f"No changes detected. Checked {checked_count} file(s).")

st.subheader("3. Current baseline")
baseline = load_baseline()
if baseline:
    st.write(f"Baseline created (UTC): `{baseline.get('created_at_utc', 'unknown')}`")
    baseline_rows = [
        {"File": name, "SHA-256": digest}
        for name, digest in sorted(baseline["files"].items())
    ]
    if baseline_rows:
        st.dataframe(pd.DataFrame(baseline_rows), use_container_width=True, hide_index=True)
    else:
        st.write("The baseline currently contains no files.")
else:
    st.write("No baseline exists yet. Create one above.")

st.subheader("4. Audit history")
audit_records = read_audit_log()
if audit_records:
    audit_df = pd.DataFrame(audit_records).sort_values("timestamp_utc", ascending=False)
    st.dataframe(audit_df, use_container_width=True, hide_index=True)
    st.download_button(
        "Download audit history (CSV)",
        data=audit_df.to_csv(index=False).encode("utf-8"),
        file_name="audit_history.csv",
        mime="text/csv",
    )
    st.download_button(
        "Download raw audit log (JSONL)",
        data=AUDIT_FILE.read_bytes(),
        file_name="audit.jsonl",
        mime="application/json",
    )
else:
    st.write("No audit events have been recorded yet.")

st.divider()
st.caption(
    "Limitations: this demo scans when you click the scan button; it does not monitor continuously. "
    "SHA-256 detects content differences but cannot identify who made a change or prove intent. "
    "For real deployments, protect the baseline and send logs to a separate, access-controlled system."
)
