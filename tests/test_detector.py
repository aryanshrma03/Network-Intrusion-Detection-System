import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from detector.engine import NIDSEngine
from detector.events import NetworkFlow


class NIDSTests(unittest.TestCase):

    def test_empty_engine(self):
        result = NIDSEngine().evaluate()
        self.assertEqual(result.score, 0)
        self.assertEqual(result.severity, "NORMAL")

    def test_normal_traffic(self):
        engine = NIDSEngine()
        now = datetime.now()

        for i in range(3):
            result = engine.add_flow(
                NetworkFlow(
                    timestamp=now + timedelta(seconds=i * 3),
                    src_ip="10.0.0.5",
                    dst_ip="10.0.0.10",
                    src_port=40000 + i,
                    dst_port=443,
                    protocol="TCP",
                    flags="ACK",
                )
            )

        self.assertLess(result.score, 40)

    def test_port_scan_detection(self):
        engine = NIDSEngine()
        now = datetime.now()

        for i in range(15):
            result = engine.add_flow(
                NetworkFlow(
                    timestamp=now + timedelta(milliseconds=i * 100),
                    src_ip="10.0.0.50",
                    dst_ip="10.0.0.10",
                    src_port=45000 + i,
                    dst_port=20 + i,
                    protocol="TCP",
                    flags="SYN",
                )
            )

        self.assertIn("Possible port-scan pattern detected.", result.reasons)

    def test_syn_burst_is_high_risk(self):
        engine = NIDSEngine()
        now = datetime.now()

        for i in range(25):
            result = engine.add_flow(
                NetworkFlow(
                    timestamp=now + timedelta(milliseconds=i * 100),
                    src_ip="10.0.0.50",
                    dst_ip="10.0.0.10",
                    src_port=45000 + i,
                    dst_port=443,
                    protocol="TCP",
                    flags="SYN",
                )
            )

        self.assertGreaterEqual(result.score, 60)
        self.assertIn(result.severity, {"HIGH", "CRITICAL"})

    def test_score_capped(self):
        engine = NIDSEngine()
        now = datetime.now()

        for i in range(100):
            result = engine.add_flow(
                NetworkFlow(
                    timestamp=now,
                    src_ip="10.0.0.50",
                    dst_ip=f"10.0.1.{(i % 200) + 1}",
                    src_port=40000 + i,
                    dst_port=(i % 100) + 1,
                    protocol="TCP",
                    flags="SYN",
                )
            )

        self.assertLessEqual(result.score, 100)


if __name__ == "__main__":
    unittest.main()
