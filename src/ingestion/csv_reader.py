import csv
from datetime import datetime
from pathlib import Path

from detector.events import NetworkFlow

REQUIRED_COLUMNS = {
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "flags",
    "bytes",
}

def read_csv_flows(path: str | Path):
    path = Path(path)

    if not path.is_file():
        raise FileNotFoundError(f"CSV file not found: {path}")

    with path.open("r", newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)

        columns = set(reader.fieldnames or [])
        missing = REQUIRED_COLUMNS - columns
        if missing:
            raise ValueError(f"Missing CSV columns: {sorted(missing)}")

        for row in reader:
            yield NetworkFlow(
                timestamp=_parse_timestamp(row["timestamp"]),
                src_ip=row["src_ip"].strip(),
                dst_ip=row["dst_ip"].strip(),
                src_port=int(row["src_port"]),
                dst_port=int(row["dst_port"]),
                protocol=row["protocol"].strip().upper(),
                flags=row["flags"].strip().upper(),
                bytes_count=int(row["bytes"]),
            )

def _parse_timestamp(value: str) -> datetime:
    value = value.strip()

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue

    raise ValueError(f"Unsupported timestamp format: {value}")
