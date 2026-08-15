from dataclasses import dataclass
from datetime import datetime

@dataclass(frozen=True)
class NetworkFlow:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flags: str = ""
    bytes_count: int = 0

    @property
    def is_tcp_syn(self) -> bool:
        flags = self.flags.upper().replace(" ", "")
        return self.protocol.upper() == "TCP" and flags in {"SYN", "S"}

    @property
    def is_icmp(self) -> bool:
        return self.protocol.upper() == "ICMP"
