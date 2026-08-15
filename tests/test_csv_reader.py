import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from ingestion.csv_reader import read_csv_flows


class CSVReaderTests(unittest.TestCase):

    def test_read_valid_csv(self):
        content = (
            "timestamp,src_ip,dst_ip,src_port,dst_port,protocol,flags,bytes\n"
            "2026-08-15T10:00:00,10.0.0.5,10.0.0.10,40000,443,TCP,ACK,1200\n"
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "flows.csv"
            path.write_text(content, encoding="utf-8")

            flows = list(read_csv_flows(path))

        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].dst_port, 443)
        self.assertEqual(flows[0].protocol, "TCP")

    def test_missing_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.csv"
            path.write_text("src_ip,dst_ip\n10.0.0.1,10.0.0.2\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                list(read_csv_flows(path))


if __name__ == "__main__":
    unittest.main()
