from collections import Counter
from dataclasses import dataclass
from datetime import timedelta

from detector.events import NetworkFlow

@dataclass
class DetectionResult:
    score: int
    severity: str
    reasons: list[str]
    flow_count: int
    unique_sources: int
    unique_destinations: int
    unique_destination_ports: int
    syn_count: int
    icmp_count: int

class NIDSEngine:
    """Explainable sliding-window network intrusion detector."""

    def __init__(self, window_seconds: int = 10):
        self.window_seconds = window_seconds
        self.flows: list[NetworkFlow] = []

    def reset(self):
        self.flows.clear()

    def add_flow(self, flow: NetworkFlow) -> DetectionResult:
        self.flows.append(flow)
        return self.evaluate()

    def evaluate(self) -> DetectionResult:
        if not self.flows:
            return DetectionResult(0, "NORMAL", [], 0, 0, 0, 0, 0, 0)

        now = self.flows[-1].timestamp
        cutoff = now - timedelta(seconds=self.window_seconds)
        recent = [flow for flow in self.flows if flow.timestamp >= cutoff]

        score = 0
        reasons = []

        source_port_map = {}
        source_dest_map = {}
        source_flow_count = Counter()

        for flow in recent:
            source_port_map.setdefault(flow.src_ip, set()).add(flow.dst_port)
            source_dest_map.setdefault(flow.src_ip, set()).add(flow.dst_ip)
            source_flow_count[flow.src_ip] += 1

        # Port scan: one source touches many destination ports.
        if any(len(ports) >= 12 for ports in source_port_map.values()):
            score += 35
            reasons.append("Possible port-scan pattern detected.")
        elif any(len(ports) >= 7 for ports in source_port_map.values()):
            score += 18
            reasons.append("Unusual destination-port diversity detected.")

        syn_count = sum(flow.is_tcp_syn for flow in recent)
        if syn_count >= 20:
            score += 30
            reasons.append("High-rate TCP SYN activity detected.")
        elif syn_count >= 10:
            score += 18
            reasons.append("Elevated TCP SYN activity detected.")

        icmp_count = sum(flow.is_icmp for flow in recent)
        if icmp_count >= 15:
            score += 20
            reasons.append("High-rate ICMP activity detected.")

        if len(recent) >= 40:
            score += 25
            reasons.append("Very high network-flow rate detected.")
        elif len(recent) >= 20:
            score += 12
            reasons.append("Elevated network-flow rate detected.")

        if any(len(destinations) >= 10 for destinations in source_dest_map.values()):
            score += 20
            reasons.append("One source contacted many destination hosts.")

        privileged_ports = {
            flow.dst_port
            for flow in recent
            if 1 <= flow.dst_port <= 1024
        }
        if len(privileged_ports) >= 8:
            score += 10
            reasons.append("Multiple privileged service ports were targeted.")

        score = min(100, score)

        if score >= 80:
            severity = "CRITICAL"
        elif score >= 60:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        elif score >= 20:
            severity = "LOW"
        else:
            severity = "NORMAL"

        return DetectionResult(
            score=score,
            severity=severity,
            reasons=reasons,
            flow_count=len(recent),
            unique_sources=len({f.src_ip for f in recent}),
            unique_destinations=len({f.dst_ip for f in recent}),
            unique_destination_ports=len({f.dst_port for f in recent}),
            syn_count=syn_count,
            icmp_count=icmp_count,
        )
