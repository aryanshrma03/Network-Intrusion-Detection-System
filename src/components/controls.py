import customtkinter as ctk

def create_controls(parent, browse_command, analyze_command, normal_command, suspicious_command, reset_command):
    frame = ctk.CTkFrame(parent, fg_color="transparent")
    frame.pack(fill="x", padx=30, pady=8)

    ctk.CTkButton(frame, text="Open CSV", command=browse_command,
                  width=110, height=42, corner_radius=10).pack(side="left")

    ctk.CTkButton(frame, text="Analyze CSV", command=analyze_command,
                  width=125, height=42, corner_radius=10).pack(side="left", padx=8)

    ctk.CTkButton(frame, text="Normal Simulation", command=normal_command,
                  width=150, height=42, corner_radius=10).pack(side="left")

    ctk.CTkButton(frame, text="Intrusion Simulation", command=suspicious_command,
                  width=155, height=42, corner_radius=10).pack(side="left", padx=8)

    ctk.CTkButton(frame, text="Reset", command=reset_command,
                  width=90, height=42, corner_radius=10,
                  fg_color="#3b3f46", hover_color="#4b5058").pack(side="right")
