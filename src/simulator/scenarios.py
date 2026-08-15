from datetime import datetime, timedelta

from detector.events import NetworkFlow

def normal_traffic():
    base = datetime.now()
    flows = []

    for i in range(5):
        flows.append(
            NetworkFlow(
                timestamp=base + timedelta(seconds=i * 2),
                src_ip="10.0.0.20",
                dst_ip="10.0.0.10",
                src_port=40000 + i,
                dst_port=443,
                protocol="TCP",
                flags="ACK",
                bytes_count=900 + i * 50,
            )
        )

    return flows

def suspicious_traffic():
    base = datetime.now()
    flows = []

    # Synthetic metadata only; no network packets are transmitted.
    for i in range(25):
        flows.append(
            NetworkFlow(
                timestamp=base + timedelta(milliseconds=i * 150),
                src_ip="10.0.0.50",
                dst_ip="10.0.0.10",
                src_port=45000 + i,
                dst_port=20 + i,
                protocol="TCP",
                flags="SYN",
                bytes_count=60,
            )
        )

    return flows
