import customtkinter as ctk
from tkinter import filedialog, messagebox

from components.controls import create_controls
from components.event_log import EventLog
from components.header import create_header
from components.risk_meter import RiskMeter
from config.theme import load_theme
from detector.engine import NIDSEngine
from ingestion.csv_reader import read_csv_flows
from simulator.scenarios import normal_traffic, suspicious_traffic

load_theme()

class NIDSApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Network Intrusion Detection System")
        self.root.geometry("1050x800")
        self.root.minsize(900, 700)

        self.engine = NIDSEngine()
        self.path_var = ctk.StringVar()

        create_header(self.root)

        self.path_entry = ctk.CTkEntry(
            self.root,
            textvariable=self.path_var,
            placeholder_text="Select a network-flow CSV...",
            height=42,
            font=("Segoe UI", 12),
            corner_radius=10,
        )
        self.path_entry.pack(fill="x", padx=30, pady=(4, 4))

        create_controls(
            self.root,
            self.browse,
            self.analyze,
            self.simulate_normal,
            self.simulate_intrusion,
            self.reset,
        )

        self.risk = RiskMeter(self.root)
        self.log = EventLog(self.root)

        self.stats = ctk.CTkLabel(
            self.root,
            text="Flows: 0 | Sources: 0 | Destinations: 0 | Ports: 0 | SYN: 0 | ICMP: 0",
            text_color="#9aa4b2",
            font=("Segoe UI", 11),
        )
        self.stats.pack(anchor="w", padx=30, pady=(2, 5))

        ctk.CTkLabel(
            self.root,
            text="⚠ Defensive analyzer only. Simulations generate local metadata and do not send network traffic.",
            text_color="#9aa4b2",
            font=("Segoe UI", 11),
        ).pack(anchor="w", padx=30, pady=(0, 18))

        self.reset()

    def browse(self):
        path = filedialog.askopenfilename(
            title="Select Network Flow CSV",
            filetypes=[
                ("CSV Files", "*.csv"),
                ("All Files", "*.*"),
            ],
        )
        if path:
            self.path_var.set(path)

    def analyze(self):
        path = self.path_var.get().strip()

        if not path:
            messagebox.showwarning("Input Required", "Select a flow CSV first.")
            return

        try:
            flows = list(read_csv_flows(path))
        except (FileNotFoundError, ValueError) as exc:
            messagebox.showerror("CSV Error", str(exc))
            return
        except Exception as exc:
            messagebox.showerror("Analysis Error", str(exc))
            return

        self._run_flows(flows, "CSV")

    def simulate_normal(self):
        self._run_flows(normal_traffic(), "NORMAL SIMULATION")

    def simulate_intrusion(self):
        self._run_flows(suspicious_traffic(), "INTRUSION SIMULATION")

    def _run_flows(self, flows, source):
        self.engine.reset()
        self.log.clear()

        if not flows:
            self.log.add("[INFO] No flow records found.")
            self._update(self.engine.evaluate())
            return

        for flow in flows:
            result = self.engine.add_flow(flow)
            self.log.add(
                f"[{source}] {flow.protocol:<5} "
                f"{flow.src_ip}:{flow.src_port} → "
                f"{flow.dst_ip}:{flow.dst_port} "
                f"flags={flow.flags}"
            )

        self._update(result)

        self.log.add("")
        if result.reasons:
            self.log.add(f"[ALERT] Severity: {result.severity}")
            for reason in result.reasons:
                self.log.add(f"  • {reason}")
        else:
            self.log.add("[INFO] No strong intrusion pattern detected.")

    def reset(self):
        self.engine.reset()
        self.log.clear()
        self.path_var.set("")

        result = self.engine.evaluate()
        self._update(result)

        self.log.add("[INFO] NIDS reset and ready.")

    def _update(self, result):
        self.risk.update(result)
        self.stats.configure(
            text=(
                f"Flows: {result.flow_count} | "
                f"Sources: {result.unique_sources} | "
                f"Destinations: {result.unique_destinations} | "
                f"Ports: {result.unique_destination_ports} | "
                f"SYN: {result.syn_count} | "
                f"ICMP: {result.icmp_count}"
            )
        )

    def run(self):
        self.root.mainloop()
