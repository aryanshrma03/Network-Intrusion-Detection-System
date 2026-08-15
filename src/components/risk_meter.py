import customtkinter as ctk

class RiskMeter:
    def __init__(self, parent):
        self.frame = ctk.CTkFrame(parent, corner_radius=14)
        self.frame.pack(fill="x", padx=30, pady=8)

        row = ctk.CTkFrame(self.frame, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=(14, 5))

        self.severity = ctk.CTkLabel(row, text="NORMAL",
                                     font=("Segoe UI", 18, "bold"))
        self.severity.pack(side="left")

        self.score = ctk.CTkLabel(row, text="0 / 100",
                                  font=("Segoe UI", 18, "bold"))
        self.score.pack(side="right")

        self.progress = ctk.CTkProgressBar(self.frame, height=14, corner_radius=7)
        self.progress.pack(fill="x", padx=18, pady=(4, 16))
        self.progress.set(0)

    def update(self, result):
        self.severity.configure(text=f"Severity: {result.severity}")
        self.score.configure(text=f"{result.score} / 100")
        self.progress.set(result.score / 100)
