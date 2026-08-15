import customtkinter as ctk

class EventLog:
    def __init__(self, parent):
        self.frame = ctk.CTkFrame(parent, corner_radius=14)
        self.frame.pack(fill="both", expand=True, padx=30, pady=8)

        ctk.CTkLabel(self.frame, text="Detection Event Log",
                     font=("Segoe UI", 14, "bold")).pack(
                         anchor="w", padx=15, pady=(12, 5)
                     )

        self.box = ctk.CTkTextbox(self.frame, height=250)
        self.box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.box.configure(state="disabled")

    def clear(self):
        self.box.configure(state="normal")
        self.box.delete("1.0", "end")
        self.box.configure(state="disabled")

    def add(self, message):
        self.box.configure(state="normal")
        self.box.insert("end", message + "\n")
        self.box.see("end")
        self.box.configure(state="disabled")
